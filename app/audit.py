"""Audit log routes, helpers, and tamper-evident history handlers for VaultShare."""

import json
from typing import Any, Optional, Union
import uuid
from flask import Blueprint, has_request_context, request

from app import db
from app.models import AuditLog, User

bp = Blueprint("audit", __name__, url_prefix="/audit")
audit_bp = bp


def log_event(
    action: str,
    actor: Optional[Union[User, Any]] = None,
    document_id: Optional[int] = None,
    target_user_id: Optional[int] = None,
    details: Optional[Union[dict, str]] = None,
    commit: bool = True,
) -> AuditLog:
    """Record an action into the tamper-evident audit log.

    Args:
        action: Event action name (e.g. REGISTER, LOGIN, LOGIN_FAILED, LOGOUT).
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
        # Retrieve client IP, taking proxy headers into account if present
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
            details_str = json.dumps(details, default=str)
        else:
            details_str = str(details)

    # TODO: Step 7 replaces placeholder hashing with cryptographic hash-chaining.
    prev_hash = "PENDING"
    entry_hash = uuid.uuid4().hex

    audit_entry = AuditLog(
        action=action,
        actor_id=actor_id,
        actor_username=actor_username,
        document_id=document_id,
        target_user_id=target_user_id,
        details=details_str,
        ip_address=ip_address,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
    )

    db.session.add(audit_entry)
    if commit:
        db.session.commit()
    else:
        db.session.flush()
    return audit_entry
