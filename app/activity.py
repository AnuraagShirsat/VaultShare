"""Activity history query service, event description formatting, and CSV export utilities.

Provides user visibility filtering for immutable audit logs, human-friendly event
descriptions with detail whitelisting, formula injection prevention for CSV export,
and activity statistics calculation.
"""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import func

from app import db
from app.models import AuditLog, Document, DocumentKey, User

ALLOWED_ACTIONS = [
    "ALL",
    "UPLOAD",
    "UPLOAD_REJECTED",
    "SHARE",
    "REVOKE",
    "DECRYPT",
    "VERIFY",
    "INTEGRITY_FAILURE",
    "ACCESS_DENIED",
    "LOGIN",
    "LOGOUT",
    "LOGIN_FAILED",
    "LOGIN_LOCKED",
    "REGISTER",
    "ACTIVITY_EXPORT",
]


def visible_events_query(user: User):
    """Build a base SQLAlchemy query selecting AuditLog rows visible to the given user.

    Visibility rules:
    - Rows where actor_id == user.id (their own actions, including their own LOGIN/LOGOUT)
    - Rows whose document_id belongs to a document the user OWNS (any actor):
      UPLOAD, SHARE, REVOKE, DECRYPT, VERIFY, INTEGRITY_FAILURE, ACCESS_DENIED
    - Rows where target_user_id == user.id (e.g., 'alice shared X with you', 'alice revoked your access')
    - Never visible: other users' LOGIN, LOGOUT, LOGIN_FAILED, REGISTER events;
      events on documents the user does not own done by someone else;
      entries about documents the user has no relationship to.
    """
    owned_doc_ids = db.select(Document.id).filter_by(owner_id=user.id)
    return db.select(AuditLog).filter(
        db.or_(
            AuditLog.actor_id == user.id,
            AuditLog.target_user_id == user.id,
            AuditLog.document_id.in_(owned_doc_ids),
        )
    )


def sanitize_csv_cell(val: Any) -> str:
    """Sanitize a value for safe CSV output, preventing spreadsheet formula injection.

    Prefixes a single quote (') if the string begins with =, +, -, @, tab, or CR.
    """
    s = "" if val is None else str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def describe_event(
    entry: AuditLog,
    viewer: User,
    doc_cache: Optional[Dict[int, str]] = None,
    user_cache: Optional[Dict[int, str]] = None,
) -> Dict[str, Any]:
    """Produce human-readable event descriptions and UI metadata from an AuditLog entry.

    Args:
        entry: AuditLog record to format.
        viewer: The User viewing the event.
        doc_cache: Optional dictionary mapping document_id to original_filename.
        user_cache: Optional dictionary mapping user_id to username.

    Returns:
        dict: {
            "icon": str (Bootstrap icon class),
            "badge_color": str (success, warning, danger, secondary),
            "title": str,
            "subtitle": str,
            "when": str ("YYYY-MM-DD HH:MM UTC"),
            "ip_address": Optional[str],
            "document_name": Optional[str],
            "action": str,
            "entry_id": int,
        }
    """
    # 1. Parse details with strict whitelist - NEVER print raw JSON
    details_data: Dict[str, Any] = {}
    if entry.details:
        try:
            parsed = json.loads(entry.details)
            if isinstance(parsed, dict):
                details_data = parsed
        except Exception:
            pass

    # 2. Determine actor display name
    is_viewer_actor = entry.actor_id == viewer.id
    actor_name = "You" if is_viewer_actor else (entry.actor_username or "Unknown user")

    # 3. Resolve document filename
    doc_name = None
    if entry.document_id is not None:
        if doc_cache is not None and entry.document_id in doc_cache:
            doc_name = doc_cache[entry.document_id]
        else:
            doc = db.session.get(Document, entry.document_id)
            if doc:
                doc_name = doc.original_filename
                if doc_cache is not None:
                    doc_cache[entry.document_id] = doc_name
            else:
                doc_name = f"document #{entry.document_id}"

    # 4. Resolve target user display name
    target_name = None
    if entry.target_user_id is not None:
        if entry.target_user_id == viewer.id:
            target_name = "you"
        else:
            if user_cache is not None and entry.target_user_id in user_cache:
                target_name = user_cache[entry.target_user_id]
            else:
                target_user = db.session.get(User, entry.target_user_id)
                if target_user:
                    target_name = target_user.username
                    if user_cache is not None:
                        user_cache[entry.target_user_id] = target_name
                elif "recipient_username" in details_data:
                    target_name = details_data["recipient_username"]
                else:
                    target_name = f"user #{entry.target_user_id}"

    # 5. Format timestamp
    ts_utc = entry.timestamp
    if ts_utc.tzinfo is None:
        ts_utc = ts_utc.replace(tzinfo=timezone.utc)
    else:
        ts_utc = ts_utc.astimezone(timezone.utc)
    when_str = ts_utc.strftime("%Y-%m-%d %H:%M UTC")

    # 6. IP address: show ONLY on the user's own actions
    ip_display = entry.ip_address if is_viewer_actor else None

    # 7. Action-specific formatting
    action = entry.action
    badge_color = "secondary"
    icon = "bi-activity"
    title = f"{actor_name} performed {action}"
    subtitle = ""

    doc_display = doc_name or "document"

    if action == "UPLOAD":
        badge_color = "success"
        icon = "bi-cloud-arrow-up-fill"
        title = f"{actor_name} uploaded {doc_display}"
        size = details_data.get("size_bytes")
        if size:
            subtitle = f"Size: {size} bytes"

    elif action == "SHARE":
        badge_color = "success"
        icon = "bi-share-fill"
        target_display = target_name or "recipient"
        title = f"{actor_name} shared {doc_display} with {target_display}"

    elif action == "REVOKE":
        badge_color = "warning"
        icon = "bi-person-x-fill"
        if target_name == "you":
            title = f"{actor_name} revoked your access to {doc_display}"
        elif is_viewer_actor:
            title = f"You revoked {target_name or 'user'}'s access to {doc_display}"
        else:
            title = f"{actor_name} revoked {target_name or 'user'}'s access to {doc_display}"

    elif action == "DECRYPT":
        badge_color = "success"
        icon = "bi-unlock-fill"
        title = f"{actor_name} decrypted {doc_display}"

    elif action == "VERIFY":
        mode = details_data.get("mode")
        result = details_data.get("result")
        if mode == "local_copy":
            if result == "match":
                badge_color = "success"
                icon = "bi-file-earmark-check-fill"
                title = f"{actor_name} verified a local copy of {doc_display} (matched)"
            else:
                badge_color = "danger"
                icon = "bi-file-earmark-x-fill"
                title = f"Local copy verification failed for {doc_display} (digest mismatch)"
        else:
            if result == "pass":
                badge_color = "success"
                icon = "bi-shield-check"
                title = f"{actor_name} verified {doc_display} (all checks passed)"
            else:
                badge_color = "danger"
                icon = "bi-shield-x"
                failed_check = details_data.get("failed_check")
                check_desc = f" ({failed_check})" if failed_check else ""
                title = f"Integrity check failed for {doc_display}{check_desc}"

    elif action == "INTEGRITY_FAILURE":
        badge_color = "danger"
        icon = "bi-shield-slash-fill"
        reason = details_data.get("reason")
        reason_desc = f" ({reason})" if reason else ""
        title = f"Integrity check failed for {doc_display}{reason_desc}"

    elif action == "ACCESS_DENIED":
        badge_color = "warning"
        icon = "bi-slash-circle-fill"
        if is_viewer_actor:
            title = f"Access to {doc_display} was denied for you"
        else:
            title = f"Access to {doc_display} was denied for {actor_name}"

    elif action == "LOGIN":
        badge_color = "secondary"
        icon = "bi-box-arrow-in-right"
        title = f"{actor_name} logged in"

    elif action == "LOGOUT":
        badge_color = "secondary"
        icon = "bi-box-arrow-right"
        title = f"{actor_name} logged out"

    elif action == "LOGIN_FAILED":
        badge_color = "warning"
        icon = "bi-exclamation-octagon-fill"
        user_tried = entry.actor_username or "unknown user"
        title = f"Failed login attempt for {user_tried}"

    elif action == "LOGIN_LOCKED":
        badge_color = "danger"
        icon = "bi-lock-fill"
        user_tried = entry.actor_username or "unknown user"
        title = f"Account temporarily locked due to excessive failed logins for {user_tried}"

    elif action == "UPLOAD_REJECTED":
        badge_color = "danger"
        icon = "bi-shield-x"
        reason = details_data.get("reason", "security_policy")
        title = f"{actor_name} attempted upload rejected ({reason})"

    elif action == "REGISTER":
        badge_color = "secondary"
        icon = "bi-person-plus-fill"
        title = f"{actor_name} registered an account"

    elif action == "ACTIVITY_EXPORT":
        badge_color = "secondary"
        icon = "bi-file-earmark-spreadsheet-fill"
        count = details_data.get("row_count", 0)
        title = f"{actor_name} exported activity history ({count} events)"

    return {
        "icon": icon,
        "badge_color": badge_color,
        "title": title,
        "subtitle": subtitle,
        "when": when_str,
        "ip_address": ip_display,
        "document_name": doc_name,
        "action": action,
        "entry_id": entry.id,
    }
