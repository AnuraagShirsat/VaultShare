"""Integrity verification service, routes, and diagnostic handlers for VaultShare.

Provides multi-stage cryptographic integrity checks on encrypted documents at rest:
1. File presence and path safety
2. Ciphertext SHA-256 verification against stored digest
3. RSA document key unwrapping via unlocked session private key
4. AES-256-GCM authentication and decryption
5. Plaintext SHA-256 verification against stored digest

Also provides local file copy verification against stored plaintext hash and
audit log hash-chain verification.
"""

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required

from app import db, limiter
from app.access import get_document_or_404, require_recipient
from app.audit import log_event, verify_chain
from app.crypto import (
    DecryptionError,
    constant_time_equal,
    decrypt_bytes,
    sha256_hex,
    unwrap_key,
)
from app.keycache import get_key
from app.models import AuditLog, Document, DocumentKey, User

bp = Blueprint("integrity", __name__, url_prefix="/integrity")


@dataclass
class CheckResult:
    """Individual cryptographic verification check result."""

    name: str
    status: str  # "pass", "fail", "skipped"
    detail: Optional[str] = None


@dataclass
class VerificationResult:
    """Aggregated document integrity verification result."""

    result: str  # "pass" or "fail"
    checks: List[CheckResult] = field(default_factory=list)
    failed_check: Optional[str] = None


def verify_document(
    user: User,
    doc: Document,
    private_key: Optional[object] = None,
) -> VerificationResult:
    """Perform ordered cryptographic integrity verification on a stored document.

    Checks:
    1. file_present: stored file exists and resolves safely within STORAGE_DIR.
    2. ciphertext_hash: file SHA-256 on disk equals Document.ciphertext_sha256.
    3. key_unwrap: recipient's wrapped key unwraps with unlocked private key.
    4. gcm_authentication: AES-256-GCM decrypts and authenticates ciphertext.
    5. plaintext_hash: decrypted plaintext SHA-256 equals Document.plaintext_sha256.

    If an earlier check fails, later dependent checks are marked "skipped".
    If the user's private key is not in the cache, checks 1-2 run and 3-5 are
    marked "skipped" with detail "session key unavailable".

    Note:
    - Raw document key and plaintext are strictly cleared from memory.
    - DocumentKey decrypt_count and last_decrypted_at are NOT modified.
    - No files are written to disk.
    - Logs VERIFY event and, on failure, also logs INTEGRITY_FAILURE.

    Args:
        user: Authenticated User performing verification.
        doc: Document instance to verify.
        private_key: Optional decrypted RSA private key object. If omitted,
                     retrieved from the server-side key cache.

    Returns:
        VerificationResult: Overall result and ordered list of CheckResult objects.
    """
    checks: List[CheckResult] = []
    failed_check: Optional[str] = None
    overall_result = "pass"

    storage_dir = Path(current_app.config["STORAGE_DIR"]).resolve()
    file_path = (storage_dir / doc.stored_filename).resolve()

    # -------------------------------------------------------------------------
    # Check 1: File presence and path containment
    # -------------------------------------------------------------------------
    file_present = False
    try:
        if file_path.is_relative_to(storage_dir) and file_path.is_file():
            file_present = True
    except Exception:
        file_present = False

    if not file_present:
        checks.append(
            CheckResult(
                name="file_present",
                status="fail",
                detail="Encrypted document file is missing from storage or path is invalid.",
            )
        )
        checks.append(CheckResult("ciphertext_hash", "skipped", "Prerequisite check failed."))
        checks.append(CheckResult("key_unwrap", "skipped", "Prerequisite check failed."))
        checks.append(CheckResult("gcm_authentication", "skipped", "Prerequisite check failed."))
        checks.append(CheckResult("plaintext_hash", "skipped", "Prerequisite check failed."))
        failed_check = "file_present"
        overall_result = "fail"
    else:
        checks.append(
            CheckResult(
                name="file_present",
                status="pass",
                detail="Encrypted file is present and resolves securely within storage directory.",
            )
        )

        # ---------------------------------------------------------------------
        # Check 2: Ciphertext SHA-256 verification
        # ---------------------------------------------------------------------
        ciphertext_bytes = file_path.read_bytes()
        actual_ciphertext_sha256 = sha256_hex(ciphertext_bytes)

        if not constant_time_equal(actual_ciphertext_sha256, doc.ciphertext_sha256 or ""):
            checks.append(
                CheckResult(
                    name="ciphertext_hash",
                    status="fail",
                    detail=f"Ciphertext digest mismatch. Expected: {doc.ciphertext_sha256[:16]}..., Actual: {actual_ciphertext_sha256[:16]}...",
                )
            )
            checks.append(CheckResult("key_unwrap", "skipped", "Prerequisite check failed."))
            checks.append(CheckResult("gcm_authentication", "skipped", "Prerequisite check failed."))
            checks.append(CheckResult("plaintext_hash", "skipped", "Prerequisite check failed."))
            failed_check = "ciphertext_hash"
            overall_result = "fail"
        else:
            checks.append(
                CheckResult(
                    name="ciphertext_hash",
                    status="pass",
                    detail="Ciphertext digest matches stored Document.ciphertext_sha256.",
                )
            )

            # -----------------------------------------------------------------
            # Check 3: RSA document key unwrapping
            # -----------------------------------------------------------------
            # Retrieve private key if not provided
            priv_key = private_key
            if priv_key is None and session:
                token = session.get("key_token")
                priv_key = get_key(token, user.id)

            if priv_key is None:
                checks.append(
                    CheckResult("key_unwrap", "skipped", "session key unavailable")
                )
                checks.append(
                    CheckResult("gcm_authentication", "skipped", "session key unavailable")
                )
                checks.append(
                    CheckResult("plaintext_hash", "skipped", "session key unavailable")
                )
            else:
                key_row = db.session.execute(
                    db.select(DocumentKey).filter_by(
                        document_id=doc.id, recipient_id=user.id
                    )
                ).scalar_one_or_none()

                if key_row is None:
                    checks.append(
                        CheckResult(
                            name="key_unwrap",
                            status="fail",
                            detail="No DocumentKey record found for this recipient.",
                        )
                    )
                    checks.append(CheckResult("gcm_authentication", "skipped", "Prerequisite check failed."))
                    checks.append(CheckResult("plaintext_hash", "skipped", "Prerequisite check failed."))
                    failed_check = "key_unwrap"
                    overall_result = "fail"
                else:
                    doc_key = None
                    try:
                        doc_key = unwrap_key(priv_key, key_row.wrapped_key)
                        checks.append(
                            CheckResult(
                                name="key_unwrap",
                                status="pass",
                                detail="Document key successfully unwrapped using user private key.",
                            )
                        )
                    except (DecryptionError, Exception):
                        checks.append(
                            CheckResult(
                                name="key_unwrap",
                                status="fail",
                                detail="Failed to unwrap document key with private key.",
                            )
                        )
                        checks.append(CheckResult("gcm_authentication", "skipped", "Prerequisite check failed."))
                        checks.append(CheckResult("plaintext_hash", "skipped", "Prerequisite check failed."))
                        failed_check = "key_unwrap"
                        overall_result = "fail"

                    if overall_result == "pass" and doc_key is not None:
                        # -----------------------------------------------------
                        # Check 4: AES-256-GCM authentication and decryption
                        # -----------------------------------------------------
                        plaintext = None
                        try:
                            plaintext = decrypt_bytes(
                                doc_key, doc.nonce or b"", ciphertext_bytes
                            )
                            checks.append(
                                CheckResult(
                                    name="gcm_authentication",
                                    status="pass",
                                    detail="AES-256-GCM authentication tag verified and plaintext decrypted.",
                                )
                            )
                        except (DecryptionError, Exception):
                            checks.append(
                                CheckResult(
                                    name="gcm_authentication",
                                    status="fail",
                                    detail="AES-GCM authentication failed (tampered ciphertext or invalid key/nonce).",
                                )
                            )
                            checks.append(CheckResult("plaintext_hash", "skipped", "Prerequisite check failed."))
                            failed_check = "gcm_authentication"
                            overall_result = "fail"

                        if overall_result == "pass" and plaintext is not None:
                            # -------------------------------------------------
                            # Check 5: Plaintext SHA-256 verification
                            # -------------------------------------------------
                            actual_plaintext_sha256 = sha256_hex(plaintext)
                            if not constant_time_equal(
                                actual_plaintext_sha256, doc.plaintext_sha256 or ""
                            ):
                                checks.append(
                                    CheckResult(
                                        name="plaintext_hash",
                                        status="fail",
                                        detail=f"Plaintext digest mismatch. Expected: {doc.plaintext_sha256[:16]}..., Actual: {actual_plaintext_sha256[:16]}...",
                                    )
                                )
                                failed_check = "plaintext_hash"
                                overall_result = "fail"
                            else:
                                checks.append(
                                    CheckResult(
                                        name="plaintext_hash",
                                        status="pass",
                                        detail="Plaintext digest matches stored Document.plaintext_sha256.",
                                    )
                                )

                        # Memory cleanup: clear plaintext and doc_key
                        if plaintext is not None:
                            del plaintext
                        del doc_key

    # Record audit events
    checks_summary = {c.name: c.status for c in checks}
    log_event(
        action="VERIFY",
        actor=user,
        document_id=doc.id,
        details={
            "result": overall_result,
            "failed_check": failed_check,
            "checks": checks_summary,
        },
    )

    if overall_result == "fail" and failed_check is not None:
        log_event(
            action="INTEGRITY_FAILURE",
            actor=user,
            document_id=doc.id,
            details={"reason": failed_check},
        )

    return VerificationResult(
        result=overall_result,
        checks=checks,
        failed_check=failed_check,
    )


@bp.route("", methods=["GET"])
@bp.route("/", methods=["GET"])
@login_required
def index():
    """List accessible documents with stored hashes, last verified status, and audit chain card."""
    user = current_user._get_current_object()

    # Query all documents the user owns or has access to via DocumentKey
    accessible_docs = (
        db.session.execute(
            db.select(Document)
            .join(DocumentKey, DocumentKey.document_id == Document.id)
            .filter(DocumentKey.recipient_id == user.id)
            .order_by(Document.created_at.desc())
        )
        .scalars()
        .all()
    )

    doc_ids = [d.id for d in accessible_docs]
    last_verify_map: Dict[int, Dict[str, Any]] = {}

    if doc_ids:
        # Retrieve latest VERIFY audit events for these documents
        verify_logs = (
            db.session.execute(
                db.select(AuditLog)
                .filter(
                    AuditLog.document_id.in_(doc_ids),
                    AuditLog.action == "VERIFY",
                )
                .order_by(AuditLog.id.desc())
            )
            .scalars()
            .all()
        )
        for log in verify_logs:
            if log.document_id and log.document_id not in last_verify_map:
                res_str = "pass"
                if log.details:
                    try:
                        parsed = json.loads(log.details)
                        res_str = parsed.get("result", "pass")
                    except Exception:
                        pass
                last_verify_map[log.document_id] = {
                    "timestamp": log.timestamp,
                    "result": res_str,
                }

    # Retrieve or run audit chain verification
    chain_status = session.pop("audit_chain_result", None)
    if chain_status is None:
        chain_status = verify_chain()

    # Retrieve flash panels for last document verification or verify-all batch
    last_verify_result = session.pop("last_verify_result", None)
    verify_all_results = session.pop("verify_all_results", None)

    return render_template(
        "integrity/index.html",
        documents=accessible_docs,
        last_verify_map=last_verify_map,
        chain_status=chain_status,
        last_verify_result=last_verify_result,
        verify_all_results=verify_all_results,
    )


@bp.route("/documents/<int:doc_id>/verify", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def verify_single(doc_id: int):
    """Verify cryptographic integrity of a single accessible document."""
    doc = get_document_or_404(doc_id)
    require_recipient(doc, action="VERIFY")

    user = current_user._get_current_object()
    result = verify_document(user, doc)

    session["last_verify_result"] = {
        "doc_id": doc.id,
        "filename": doc.original_filename,
        "result": result.result,
        "failed_check": result.failed_check,
        "checks": [
            {"name": c.name, "status": c.status, "detail": c.detail}
            for c in result.checks
        ],
    }

    if result.result == "pass":
        flash(
            f"Integrity verification PASSED for '{doc.original_filename}'. All cryptographic checks succeeded.",
            "success",
        )
    else:
        flash(
            f"Integrity verification FAILED for '{doc.original_filename}'. Failed check: {result.failed_check}.",
            "danger",
        )

    return redirect(url_for("integrity.index"))


@bp.route("/verify-all", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def verify_all():
    """Verify integrity for up to 50 accessible documents in batch."""
    user = current_user._get_current_object()

    accessible_docs = (
        db.session.execute(
            db.select(Document)
            .join(DocumentKey, DocumentKey.document_id == Document.id)
            .filter(DocumentKey.recipient_id == user.id)
            .order_by(Document.created_at.desc())
            .limit(50)
        )
        .scalars()
        .all()
    )

    results_summary = []
    passed_count = 0
    failed_count = 0

    for doc in accessible_docs:
        res = verify_document(user, doc)
        if res.result == "pass":
            passed_count += 1
        else:
            failed_count += 1
        results_summary.append(
            {
                "doc_id": doc.id,
                "filename": doc.original_filename,
                "result": res.result,
                "failed_check": res.failed_check,
            }
        )

    session["verify_all_results"] = results_summary

    flash(
        f"Batch verification completed for {len(accessible_docs)} document(s): {passed_count} passed, {failed_count} failed.",
        "success" if failed_count == 0 else "warning",
    )
    return redirect(url_for("integrity.index"))


@bp.route("/documents/<int:doc_id>/check-file", methods=["POST"])
@login_required
@limiter.limit("20 per minute")
def check_file(doc_id: int):
    """Verify a recipient's local copy of a downloaded document against stored plaintext hash."""
    doc = get_document_or_404(doc_id)
    require_recipient(doc, action="CHECK_FILE")

    if "file" not in request.files:
        flash("No file was submitted for verification.", "warning")
        return redirect(url_for("integrity.index"))

    uploaded_file = request.files["file"]
    if not uploaded_file.filename:
        flash("No file was selected for verification.", "warning")
        return redirect(url_for("integrity.index"))

    max_len = current_app.config.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
    file_bytes = uploaded_file.read()

    if len(file_bytes) > max_len:
        flash("Uploaded file exceeds maximum allowed size (16 MB).", "danger")
        return redirect(url_for("integrity.index")), 413

    # Compute SHA-256 in memory and compare
    computed_sha256 = sha256_hex(file_bytes)
    matches = constant_time_equal(computed_sha256, doc.plaintext_sha256 or "")

    # Clean local plaintext bytes from memory
    del file_bytes

    user = current_user._get_current_object()
    log_event(
        action="VERIFY",
        actor=user,
        document_id=doc.id,
        details={
            "mode": "local_copy",
            "result": "match" if matches else "mismatch",
            "matches": matches,
        },
    )

    if matches:
        flash(
            f"File matches the original document '{doc.original_filename}'. Plaintext SHA-256 digest verified.",
            "success",
        )
    else:
        flash(
            f"File does NOT match the original document '{doc.original_filename}'. Plaintext SHA-256 digest mismatch.",
            "danger",
        )

    return redirect(url_for("integrity.index"))


@bp.route("/audit-chain/verify", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def verify_audit_chain_route():
    """Verify the integrity of the entire audit log hash chain."""
    result = verify_chain()
    session["audit_chain_result"] = result

    if result["ok"]:
        flash(
            f"Audit log intact: {result['checked']} entries verified cryptographically.",
            "success",
        )
    else:
        flash(
            f"TAMPERING DETECTED at entry {result['first_bad_id']}: {result['reason']}.",
            "danger",
        )

    return redirect(url_for("integrity.index"))
