"""Access control helpers and security guards for VaultShare documents.

Implements strict ownership and recipient validation with silent 404 responses
to prevent document enumeration/existence leakage, and records ACCESS_DENIED
audit events.
"""

from flask import abort
from flask_login import current_user

from app import db
from app.audit import log_event
from app.models import Document, DocumentKey


def get_document_or_404(doc_id: int) -> Document:
    """Load a Document by ID or abort with 404."""
    doc = db.session.get(Document, doc_id)
    if doc is None:
        abort(404)
    return doc


def require_owner(doc: Document, action: str = "MANAGE") -> None:
    """Abort with 404 unless the current user is the owner of the document.

    Logs an ACCESS_DENIED audit event on failure without leaking document presence.
    """
    if not current_user.is_authenticated or current_user.id != doc.owner_id:
        actor = (
            current_user._get_current_object()
            if current_user.is_authenticated
            else None
        )
        log_event(
            action="ACCESS_DENIED",
            actor=actor,
            document_id=doc.id,
            details={"attempted_action": action, "reason": "not_owner"},
        )
        abort(404)


def require_recipient(doc: Document, action: str = "VIEW") -> DocumentKey:
    """Abort with 404 unless current user has a valid DocumentKey for the document.

    Returns:
        DocumentKey: The recipient's DocumentKey record.

    Raises:
        HTTPException: 404 Not Found if unauthorized.
    """
    # Use getattr to safely check current_user in case it is a proxy
    is_auth = getattr(current_user, "is_authenticated", False)
    actor = current_user._get_current_object() if is_auth else None

    key_row = None
    if is_auth:
        key_row = db.session.execute(
            db.select(DocumentKey).filter_by(
                document_id=doc.id,
                recipient_id=current_user.id,
            )
        ).scalar_one_or_none()

    if key_row is None:
        log_event(
            action="ACCESS_DENIED",
            actor=actor,
            document_id=doc.id,
            details={"attempted_action": action, "reason": "not_recipient"},
        )
        abort(404)

    return key_row
