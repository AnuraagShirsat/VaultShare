"""Audit log routes, helpers, and tamper-evident history handlers for VaultShare.

Provides canonical hash computation, append-only hash chaining, database-level
immutability triggers, and full-chain cryptographic integrity verification.
"""

from datetime import datetime, timezone
import json
import threading
from typing import Any, Optional, Union
from flask import Blueprint, has_request_context, request

from app import db
from app.crypto import constant_time_equal, sha256_hex
from app.models import AuditLog, User

bp = Blueprint("audit", __name__, url_prefix="/audit")
audit_bp = bp

GENESIS_HASH = "0" * 64
_audit_lock = threading.Lock()


def canonical_timestamp(dt: Union[datetime, str]) -> str:
    """Format a datetime or ISO string canonically as '%Y-%m-%dT%H:%M:%S.%fZ' in UTC.

    Treats naive datetimes as UTC (e.g. SQLite returns naive timestamps).
    Guarantees that writing and verification format datetimes identically.

    Args:
        dt: A datetime object or an ISO format string.

    Returns:
        str: Standardized UTC ISO timestamp string with microsecond precision and 'Z'.
    """
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_entry_hash(prev_hash: str, fields: Union[dict, AuditLog]) -> str:
    """Compute the deterministic SHA-256 hash for an audit log entry.

    Hash is computed over prev_hash + "|" + canonical compact JSON of:
    {timestamp, actor_id, actor_username, action, document_id, target_user_id, details, ip_address}

    Args:
        prev_hash: 64-character hex string of the previous entry's hash.
        fields: AuditLog model instance or dict containing log fields.

    Returns:
        str: 64-character lowercase hexadecimal SHA-256 digest.
    """
    if isinstance(fields, AuditLog):
        ts = canonical_timestamp(fields.timestamp)
        payload = {
            "action": fields.action,
            "actor_id": fields.actor_id,
            "actor_username": fields.actor_username,
            "details": fields.details,
            "document_id": fields.document_id,
            "ip_address": fields.ip_address,
            "target_user_id": fields.target_user_id,
            "timestamp": ts,
        }
    else:
        raw_ts = fields.get("timestamp")
        ts = canonical_timestamp(raw_ts) if raw_ts is not None else ""
        payload = {
            "action": fields.get("action"),
            "actor_id": fields.get("actor_id"),
            "actor_username": fields.get("actor_username"),
            "details": fields.get("details"),
            "document_id": fields.get("document_id"),
            "ip_address": fields.get("ip_address"),
            "target_user_id": fields.get("target_user_id"),
            "timestamp": ts,
        }

    canonical_json = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    raw_bytes = f"{prev_hash}|{canonical_json}".encode("utf-8")
    return sha256_hex(raw_bytes)


def log_event(
    action: str,
    actor: Optional[Union[User, Any]] = None,
    document_id: Optional[int] = None,
    target_user_id: Optional[int] = None,
    details: Optional[Union[dict, str]] = None,
    commit: bool = True,
) -> AuditLog:
    """Record an action into the tamper-evident hash-chained audit log.

    Inside a threading lock:
    1. Flushes pending session changes so previous events in the open transaction are visible.
    2. Reads the most recent AuditLog entry to chain from its entry_hash (or GENESIS_HASH).
    3. Formats details canonically and computes entry_hash.
    4. Inserts the row and flushes so subsequent calls see it.

    Args:
        action: Event action name (e.g. REGISTER, LOGIN, LOGIN_FAILED, LOGOUT, UPLOAD, SHARE, REVOKE).
        actor: User object or None.
        document_id: Optional document ID.
        target_user_id: Optional recipient or target user ID.
        details: Optional dictionary or string of event context.
        commit: Whether to commit the transaction immediately (default True).

    Returns:
        AuditLog: The persisted audit log instance.
    """
    ip_address = None
    if has_request_context():
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            ip_address = forwarded_for.split(",")[0].strip()
        else:
            ip_address = request.remote_addr

    actor_id = getattr(actor, "id", None) if actor is not None else None
    actor_username = (
        getattr(actor, "username", None) if actor is not None else None
    )

    details_str = None
    if details is not None:
        if isinstance(details, (dict, list)):
            details_str = json.dumps(
                details, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            )
        else:
            details_str = str(details)

    with _audit_lock:
        # Flush so any rows added earlier in this open transaction are visible in DB
        db.session.flush()

        latest = db.session.execute(
            db.select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
        ).scalar_one_or_none()

        prev_hash = latest.entry_hash if latest is not None else GENESIS_HASH
        timestamp = datetime.now(timezone.utc).replace(tzinfo=None)

        entry_hash = compute_entry_hash(
            prev_hash,
            {
                "action": action,
                "actor_id": actor_id,
                "actor_username": actor_username,
                "details": details_str,
                "document_id": document_id,
                "ip_address": ip_address,
                "target_user_id": target_user_id,
                "timestamp": timestamp,
            },
        )

        audit_entry = AuditLog(
            action=action,
            actor_id=actor_id,
            actor_username=actor_username,
            document_id=document_id,
            target_user_id=target_user_id,
            details=details_str,
            ip_address=ip_address,
            timestamp=timestamp,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

        db.session.add(audit_entry)
        db.session.flush()
        if commit:
            db.session.commit()
        return audit_entry


def verify_chain() -> dict:
    """Verify cryptographic integrity and continuity of the entire audit log chain.

    Checks:
        (a) First row's prev_hash == GENESIS_HASH.
        (b) Each row's prev_hash equals the previous row's entry_hash.
        (c) Each row's entry_hash equals the recomputed hash from stored fields.
        (d) IDs are contiguous (no gaps indicating deleted rows).

    Returns:
        dict: {
            "ok": bool,
            "checked": int,
            "first_bad_id": Optional[int],
            "reason": Optional[str],
        }
        where reason is one of:
            - "genesis_mismatch"
            - "prev_hash_mismatch"
            - "entry_hash_mismatch"
            - "id_gap"

    KNOWN LIMITATION (TAIL TRUNCATION):
    Deleting the most recent entries (tail truncation) cannot be detected from
    the hash chain alone, as the remaining prefix remains internally valid.
    Detecting tail truncation requires external publication or anchoring of
    periodic log head hashes (e.g., via digital signatures or external witness logs).
    """
    rows = (
        db.session.execute(db.select(AuditLog).order_by(AuditLog.id.asc()))
        .scalars()
        .all()
    )

    if not rows:
        return {"ok": True, "checked": 0, "first_bad_id": None, "reason": None}

    expected_prev_hash = GENESIS_HASH
    prev_id = None
    checked_count = 0

    for idx, row in enumerate(rows):
        if idx == 0:
            if row.prev_hash != GENESIS_HASH:
                return {
                    "ok": False,
                    "checked": 0,
                    "first_bad_id": row.id,
                    "reason": "genesis_mismatch",
                }
            if row.id != 1:
                return {
                    "ok": False,
                    "checked": 0,
                    "first_bad_id": row.id,
                    "reason": "id_gap",
                }
        else:
            if row.id != prev_id + 1:
                return {
                    "ok": False,
                    "checked": checked_count,
                    "first_bad_id": row.id,
                    "reason": "id_gap",
                }
            if row.prev_hash != expected_prev_hash:
                return {
                    "ok": False,
                    "checked": checked_count,
                    "first_bad_id": row.id,
                    "reason": "prev_hash_mismatch",
                }

        computed_hash = compute_entry_hash(row.prev_hash, row)
        if not constant_time_equal(row.entry_hash, computed_hash):
            return {
                "ok": False,
                "checked": checked_count,
                "first_bad_id": row.id,
                "reason": "entry_hash_mismatch",
            }

        checked_count += 1
        expected_prev_hash = row.entry_hash
        prev_id = row.id

    return {
        "ok": True,
        "checked": checked_count,
        "first_bad_id": None,
        "reason": None,
    }
