"""Document management routes and handlers for VaultShare.

Handles document upload, AES-256-GCM encryption at rest, multi-recipient key
distribution via RSA-OAEP, access control, and revocation.

NOTE ON ACCESS REVOCATION LIMITATIONS:
Revocation deletes the recipient's wrapped DocumentKey row from the database,
preventing any future key unwrapping or file decryption through VaultShare.
However, it cannot retroactively purge or un-share copies the user previously
downloaded to their local device.
"""

from datetime import datetime, timezone
import io
from pathlib import Path
import secrets
from typing import List, Optional
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app import db, limiter
from app.access import get_document_or_404, require_owner, require_recipient
from app.audit import log_event
from app.crypto import (
    DecryptionError,
    constant_time_equal,
    decrypt_bytes,
    encrypt_bytes,
    generate_document_key,
    sha256_hex,
    unwrap_key,
    wrap_key,
)
from app.forms import DocumentUploadForm, ShareDocumentForm
from app.keycache import get_key
from app.models import AuditLog, Document, DocumentKey, User

bp = Blueprint("documents", __name__, url_prefix="/documents")
documents_bp = bp


def human_readable_size(size_bytes: int) -> str:
    """Convert integer byte size to human-readable string (e.g. 1.5 MB)."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0 or unit == "GB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size_bytes} B"


@bp.app_template_filter("filesize")
def filesize_filter(size_bytes: int) -> str:
    """Jinja filter to display human-readable file sizes."""
    return human_readable_size(size_bytes)


def is_allowed_extension(filename: str) -> bool:
    """Validate if file extension is present and permitted in configuration."""
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    allowed = current_app.config.get("ALLOWED_EXTENSIONS", set())
    return ext in allowed


def store_encrypted_document(
    owner: User,
    filename: str,
    data: bytes,
    mime_type: Optional[str] = None,
) -> Document:
    """Encrypt and write a document to disk and persist its metadata in the database.

    Args:
        owner: User instance who owns the document.
        filename: Original filename submitted by user.
        data: Plaintext file contents as bytes.
        mime_type: Optional MIME content type.

    Returns:
        Document: The created and committed Document model instance.

    Raises:
        ValueError: If file data is empty or path traversal is detected.
    """
    if not data:
        raise ValueError("Cannot encrypt and store an empty file.")

    # 1. Sanitize original filename for display only
    display_filename = secure_filename(filename) or "unnamed_document"

    # 2. Compute plaintext SHA-256 hash
    plaintext_sha256 = sha256_hex(data)

    # 3. Generate a fresh 256-bit symmetric document key
    doc_key = generate_document_key()

    # 4. Encrypt plaintext using AES-256-GCM
    nonce, ciphertext = encrypt_bytes(doc_key, data)

    # 5. Compute ciphertext SHA-256 hash
    ciphertext_sha256 = sha256_hex(ciphertext)

    # 6. Store ciphertext under a random filename (never user-controlled)
    storage_dir = Path(current_app.config["STORAGE_DIR"]).resolve()
    storage_dir.mkdir(parents=True, exist_ok=True)

    stored_filename = f"{secrets.token_hex(16)}.enc"
    file_path = (storage_dir / stored_filename).resolve()

    if not file_path.is_relative_to(storage_dir):
        raise ValueError("Path traversal attempt detected.")

    file_path.write_bytes(ciphertext)

    # 7. Wrap document key for the owner using their RSA public key
    wrapped_key = wrap_key(owner.public_key_pem, doc_key)
    # Clear raw document key from local memory
    del doc_key

    # 8. Create Document and initial DocumentKey records
    doc = Document(
        owner_id=owner.id,
        original_filename=display_filename,
        stored_filename=stored_filename,
        mime_type=mime_type or "application/octet-stream",
        size_bytes=len(data),
        nonce=nonce,
        plaintext_sha256=plaintext_sha256,
        ciphertext_sha256=ciphertext_sha256,
    )

    owner_key = DocumentKey(
        document=doc,
        recipient=owner,
        wrapped_key=wrapped_key,
        granted_by=owner,
    )

    # 9 & 10. Persist in a single transaction; delete file if commit fails
    try:
        db.session.add(doc)
        db.session.add(owner_key)
        db.session.flush()

        log_event(
            action="UPLOAD",
            actor=owner,
            document_id=doc.id,
            details={
                "original_filename": doc.original_filename,
                "size_bytes": doc.size_bytes,
                "mime_type": doc.mime_type,
            },
            commit=False,
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        if file_path.exists():
            try:
                file_path.unlink()
            except OSError:
                pass
        raise

    return doc


def share_document(
    owner: User,
    doc: Document,
    recipient_identifiers: List[str],
    owner_private_key: object,
    max_recipients: int = 20,
) -> dict:
    """Share a document with multiple recipients by wrapping the document key.

    All new recipient keys are created in a single transaction.

    Args:
        owner: User instance who owns the document.
        doc: Document instance to share.
        recipient_identifiers: List of recipient usernames or email addresses.
        owner_private_key: Decrypted RSA private key of the owner.
        max_recipients: Maximum recipients allowed per request (default: 20).

    Returns:
        dict: Summary containing lists for 'shared', 'skipped_existing',
              'skipped_self', and 'skipped_not_found'.

    Raises:
        ValueError: If recipient count exceeds limit or owner key cannot be unwrapped.
    """
    if len(recipient_identifiers) > max_recipients:
        raise ValueError(
            f"Cannot share with more than {max_recipients} recipients per request."
        )

    # 1. Fetch owner's DocumentKey
    owner_key_row = db.session.execute(
        db.select(DocumentKey).filter_by(
            document_id=doc.id,
            recipient_id=owner.id,
        )
    ).scalar_one_or_none()

    if not owner_key_row:
        raise ValueError("Owner key record not found for this document.")

    # 2. Unwrap the symmetric document key using owner's private key
    raw_doc_key = unwrap_key(owner_private_key, owner_key_row.wrapped_key)

    shared = []
    skipped_existing = []
    skipped_self = []
    skipped_not_found = []

    try:
        seen = set()
        for raw_id in recipient_identifiers:
            identifier = raw_id.strip()
            if not identifier:
                continue

            norm_id = identifier.lower()
            if norm_id in seen:
                continue
            seen.add(norm_id)

            recipient = db.session.execute(
                db.select(User).filter(
                    (User.username == identifier)
                    | (User.email == identifier.lower())
                )
            ).scalar_one_or_none()

            if recipient is None:
                skipped_not_found.append(identifier)
                continue

            if recipient.id == owner.id:
                skipped_self.append(recipient.username)
                continue

            existing_key = db.session.execute(
                db.select(DocumentKey).filter_by(
                    document_id=doc.id,
                    recipient_id=recipient.id,
                )
            ).scalar_one_or_none()

            if existing_key is not None:
                skipped_existing.append(recipient.username)
                continue

            # Wrap document key for the recipient
            wrapped_for_recipient = wrap_key(
                recipient.public_key_pem, raw_doc_key
            )

            new_key = DocumentKey(
                document_id=doc.id,
                recipient_id=recipient.id,
                wrapped_key=wrapped_for_recipient,
                granted_by_id=owner.id,
            )
            db.session.add(new_key)

            log_event(
                action="SHARE",
                actor=owner,
                document_id=doc.id,
                target_user_id=recipient.id,
                details={"recipient_username": recipient.username},
                commit=False,
            )
            shared.append(recipient.username)

        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    finally:
        del raw_doc_key

    return {
        "shared": shared,
        "skipped_existing": skipped_existing,
        "skipped_self": skipped_self,
        "skipped_not_found": skipped_not_found,
    }


def revoke_document_access(
    owner: User, doc: Document, target_user_id: int
) -> bool:
    """Revoke a user's access to a document by deleting their DocumentKey record.

    Args:
        owner: User instance who owns the document.
        doc: Document instance.
        target_user_id: User ID whose access should be revoked.

    Returns:
        bool: True if key was revoked, False if user had no access.

    Raises:
        ValueError: If owner attempts to revoke their own access.
    """
    if target_user_id == owner.id:
        raise ValueError("Cannot revoke the document owner's access.")

    key_row = db.session.execute(
        db.select(DocumentKey).filter_by(
            document_id=doc.id,
            recipient_id=target_user_id,
        )
    ).scalar_one_or_none()

    if key_row is None:
        return False

    db.session.delete(key_row)
    log_event(
        action="REVOKE",
        actor=owner,
        document_id=doc.id,
        target_user_id=target_user_id,
    )
    db.session.commit()
    return True


@bp.route("", methods=["GET"])
@bp.route("/", methods=["GET"])
@login_required
def index():
    """List documents owned by the user and documents shared with the user."""
    # Owned documents
    owned_documents = (
        db.session.execute(
            db.select(Document)
            .filter_by(owner_id=current_user.id)
            .order_by(Document.created_at.desc())
        )
        .scalars()
        .all()
    )

    # Documents shared with current user
    shared_keys = (
        db.session.execute(
            db.select(DocumentKey)
            .join(Document, DocumentKey.document_id == Document.id)
            .filter(
                DocumentKey.recipient_id == current_user.id,
                Document.owner_id != current_user.id,
            )
            .order_by(DocumentKey.granted_at.desc())
        )
        .scalars()
        .all()
    )

    return render_template(
        "documents/index.html",
        owned_documents=owned_documents,
        shared_keys=shared_keys,
    )


@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Upload and encrypt a new document."""
    form = DocumentUploadForm()
    if form.validate_on_submit():
        uploaded_file = form.document.data
        filename = uploaded_file.filename or ""

        # Validate file extension against allowlist
        if not is_allowed_extension(filename):
            allowed = sorted(current_app.config.get("ALLOWED_EXTENSIONS", []))
            flash(
                f"File extension not permitted. Allowed extensions: {', '.join(allowed)}",
                "danger",
            )
            return render_template("documents/upload.html", form=form), 400

        # Read file contents into memory
        file_bytes = uploaded_file.read()
        if not file_bytes:
            flash("Cannot upload an empty file.", "danger")
            return render_template("documents/upload.html", form=form), 400

        # Check maximum file size
        max_length = current_app.config.get(
            "MAX_CONTENT_LENGTH", 16 * 1024 * 1024
        )
        if len(file_bytes) > max_length:
            flash("File exceeds maximum allowed size (16 MB).", "danger")
            return render_template("documents/upload.html", form=form), 413

        user = current_user._get_current_object()
        doc = store_encrypted_document(
            owner=user,
            filename=filename,
            data=file_bytes,
            mime_type=uploaded_file.mimetype,
        )

        flash(
            f"Document '{doc.original_filename}' successfully encrypted and stored.",
            "success",
        )
        return redirect(url_for("documents.index"))

    return render_template("documents/upload.html", form=form)


@bp.route("/<int:doc_id>/manage", methods=["GET"])
@login_required
def manage(doc_id: int):
    """View access list and manage recipients for an owned document."""
    doc = get_document_or_404(doc_id)
    require_owner(doc, action="MANAGE")

    form = ShareDocumentForm()

    # Query all active key rows for this document
    keys = (
        db.session.execute(
            db.select(DocumentKey)
            .filter_by(document_id=doc.id)
            .order_by(DocumentKey.granted_at.asc())
        )
        .scalars()
        .all()
    )

    # Query other users for recipient selection
    other_users = (
        db.session.execute(
            db.select(User)
            .filter(User.id != current_user.id)
            .order_by(User.username.asc())
        )
        .scalars()
        .all()
    )

    return render_template(
        "documents/manage.html",
        doc=doc,
        keys=keys,
        form=form,
        other_users=other_users,
    )


@bp.route("/<int:doc_id>/share", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def share(doc_id: int):
    """Share document with specified recipients."""
    doc = get_document_or_404(doc_id)
    require_owner(doc, action="SHARE")

    form = ShareDocumentForm()
    if form.validate_on_submit():
        raw_recipients = form.recipients.data or ""
        recipients_list = [
            r.strip()
            for r in raw_recipients.replace(";", ",").split(",")
            if r.strip()
        ]

        token = session.get("key_token")
        owner_priv_key = get_key(token, current_user.id)
        if owner_priv_key is None:
            flash(
                "Your session key has expired. Please log in again to share documents.",
                "warning",
            )
            return redirect(
                url_for("auth.login", next=url_for("documents.manage", doc_id=doc.id))
            )

        try:
            summary = share_document(
                owner=current_user._get_current_object(),
                doc=doc,
                recipient_identifiers=recipients_list,
                owner_private_key=owner_priv_key,
            )

            parts = []
            if summary["shared"]:
                parts.append(f"Shared with {', '.join(summary['shared'])}.")
            skipped_msgs = []
            if summary["skipped_existing"]:
                skipped_msgs.append(
                    f"{', '.join(summary['skipped_existing'])} (already has access)"
                )
            if summary["skipped_self"]:
                skipped_msgs.append(
                    f"{', '.join(summary['skipped_self'])} (cannot share with self)"
                )
            if summary["skipped_not_found"]:
                skipped_msgs.append(
                    f"{', '.join(summary['skipped_not_found'])} (not found)"
                )

            if skipped_msgs:
                parts.append(f"Skipped: {', '.join(skipped_msgs)}.")

            msg = " ".join(parts) if parts else "No recipients processed."
            category = "success" if summary["shared"] else "info"
            flash(msg, category)
        except ValueError as err:
            flash(str(err), "danger")
        except Exception:
            flash("An error occurred while sharing the document.", "danger")

        return redirect(url_for("documents.manage", doc_id=doc.id))

    flash("Please specify valid recipients.", "warning")
    return redirect(url_for("documents.manage", doc_id=doc.id))


@bp.route("/<int:doc_id>/revoke/<int:user_id>", methods=["POST"])
@login_required
def revoke(doc_id: int, user_id: int):
    """Revoke a user's access to an owned document."""
    doc = get_document_or_404(doc_id)
    require_owner(doc, action="REVOKE")

    if user_id == current_user.id:
        flash("You cannot revoke your own access as the document owner.", "warning")
        return redirect(url_for("documents.manage", doc_id=doc.id))

    try:
        revoked = revoke_document_access(
            owner=current_user._get_current_object(),
            doc=doc,
            target_user_id=user_id,
        )
        if revoked:
            flash("Access has been successfully revoked.", "success")
        else:
            flash("User does not have access to this document.", "info")
    except ValueError as err:
        flash(str(err), "warning")

    return redirect(url_for("documents.manage", doc_id=doc.id))


def decrypt_document_for_user(
    user: User,
    doc: Document,
    private_key: Optional[object] = None,
) -> bytes:
    """Decrypt a document for an authorized recipient and record access metrics.

    Runs validation checks in order:
    1. Key row lookup
    2. Private key unwrapping of document key
    3. Storage file presence and path safety
    4. Ciphertext SHA-256 verification
    5. AES-256-GCM authentication and decryption
    6. Plaintext SHA-256 verification

    On any integrity failure, logs INTEGRITY_FAILURE and raises DecryptionError.
    On success, increments decrypt_count, updates last_decrypted_at, and logs DECRYPT.

    Args:
        user: Authorized User requesting decryption.
        doc: Document instance to decrypt.
        private_key: Optional decrypted RSA private key object.

    Returns:
        bytes: Decrypted plaintext contents.

    Raises:
        DecryptionError: If any integrity or cryptographic check fails.
    """
    key_row = db.session.execute(
        db.select(DocumentKey).filter_by(
            document_id=doc.id, recipient_id=user.id
        )
    ).scalar_one_or_none()

    if key_row is None:
        raise DecryptionError("User is not an authorized recipient.")

    # 1. Retrieve unlocked private key
    priv_key = private_key
    if priv_key is None and session:
        token = session.get("key_token")
        priv_key = get_key(token, user.id)

    if priv_key is None:
        raise DecryptionError("Session key unavailable. Please log in again.")

    # 2. Unwrap document key
    doc_key = None
    try:
        doc_key = unwrap_key(priv_key, key_row.wrapped_key)
    except Exception as exc:
        log_event(
            action="INTEGRITY_FAILURE",
            actor=user,
            document_id=doc.id,
            details={"reason": "key_unwrap_failed"},
        )
        raise DecryptionError("Document key unwrap failed.") from exc

    # 3. File presence
    storage_dir = Path(current_app.config["STORAGE_DIR"]).resolve()
    file_path = (storage_dir / doc.stored_filename).resolve()

    if not file_path.is_relative_to(storage_dir) or not file_path.is_file():
        log_event(
            action="INTEGRITY_FAILURE",
            actor=user,
            document_id=doc.id,
            details={"reason": "file_missing"},
        )
        del doc_key
        raise DecryptionError("Stored document file is missing.")

    # 4. Ciphertext hash
    ciphertext = file_path.read_bytes()
    if not constant_time_equal(sha256_hex(ciphertext), doc.ciphertext_sha256 or ""):
        log_event(
            action="INTEGRITY_FAILURE",
            actor=user,
            document_id=doc.id,
            details={"reason": "ciphertext_hash_mismatch"},
        )
        del doc_key
        raise DecryptionError("Ciphertext hash mismatch.")

    # 5. AES-GCM decryption
    plaintext = None
    try:
        plaintext = decrypt_bytes(doc_key, doc.nonce or b"", ciphertext)
    except Exception as exc:
        log_event(
            action="INTEGRITY_FAILURE",
            actor=user,
            document_id=doc.id,
            details={"reason": "gcm_auth_failed"},
        )
        del doc_key
        raise DecryptionError("AES-GCM authentication failed.") from exc
    finally:
        del doc_key

    # 6. Plaintext hash
    if not constant_time_equal(sha256_hex(plaintext), doc.plaintext_sha256 or ""):
        log_event(
            action="INTEGRITY_FAILURE",
            actor=user,
            document_id=doc.id,
            details={"reason": "plaintext_hash_mismatch"},
        )
        del plaintext
        raise DecryptionError("Plaintext hash mismatch.")

    # 7. Success: update metrics & log DECRYPT
    key_row.decrypt_count += 1
    key_row.last_decrypted_at = datetime.now(timezone.utc)
    log_event(
        action="DECRYPT",
        actor=user,
        document_id=doc.id,
        details={
            "original_filename": doc.original_filename,
            "size_bytes": doc.size_bytes,
        },
    )
    db.session.commit()
    return plaintext


@bp.route("/<int:doc_id>/download", methods=["POST"])
@login_required
@limiter.limit("30 per minute")
def download(doc_id: int):
    """Decrypt and download an authorized document."""
    doc = get_document_or_404(doc_id)
    require_recipient(doc, action="DOWNLOAD")

    user = current_user._get_current_object()
    try:
        plaintext = decrypt_document_for_user(user, doc)
        return send_file(
            io.BytesIO(plaintext),
            as_attachment=True,
            download_name=doc.original_filename,
            mimetype=doc.mime_type or "application/octet-stream",
        )
    except DecryptionError as exc:
        flash(f"Decryption failed: {exc}", "danger")
        return redirect(url_for("documents.index"))
    except Exception:
        flash("An error occurred during document download.", "danger")
        return redirect(url_for("documents.index"))


@bp.route("/<int:doc_id>/activity", methods=["GET"])
@login_required
def document_activity(doc_id: int):
    """View activity history for a specific document."""
    doc = get_document_or_404(doc_id)
    require_recipient(doc, action="VIEW_ACTIVITY")

    from app.activity import describe_event, visible_events_query

    user = current_user._get_current_object()
    query = (
        visible_events_query(user)
        .filter(AuditLog.document_id == doc.id)
        .order_by(AuditLog.id.desc())
    )

    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1

    per_page = 25
    total = db.session.execute(
        db.select(db.func.count()).select_from(query.subquery())
    ).scalar_one()

    events = (
        db.session.execute(
            query.limit(per_page).offset((page - 1) * per_page)
        )
        .scalars()
        .all()
    )

    doc_cache = {doc.id: doc.original_filename}
    described_events = [
        describe_event(e, user, doc_cache=doc_cache) for e in events
    ]

    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template(
        "activity/document_activity.html",
        doc=doc,
        events=described_events,
        page=page,
        total_pages=total_pages,
        total=total,
    )
