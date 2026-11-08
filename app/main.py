"""Main application blueprint for general routes (landing, home, dashboard, activity history)."""

import csv
from datetime import datetime, timedelta, timezone
import io
from typing import Optional
from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from sqlalchemy import func

from app import db, limiter
from app.activity import (
    ALLOWED_ACTIONS,
    describe_event,
    sanitize_csv_cell,
    visible_events_query,
)
from app.audit import log_event
from app.models import AuditLog, Document, DocumentKey, User

bp = Blueprint("main", __name__)
main_bp = bp


@bp.route("/")
def index():
    """Render the landing / home page."""
    return render_template("index.html")


@bp.route("/dashboard")
@login_required
def dashboard():
    """Render the authenticated user security and document dashboard."""
    user = current_user._get_current_object()

    # 1. Stat cards metrics
    owned_count = db.session.execute(
        db.select(func.count(Document.id)).filter_by(owner_id=user.id)
    ).scalar_one()

    shared_count = db.session.execute(
        db.select(func.count(DocumentKey.id))
        .join(Document, DocumentKey.document_id == Document.id)
        .filter(
            DocumentKey.recipient_id == user.id,
            Document.owner_id != user.id,
        )
    ).scalar_one()

    # Decrypt total: counts only other recipients' decrypts of my documents
    other_decrypts_count = db.session.execute(
        db.select(func.coalesce(func.sum(DocumentKey.decrypt_count), 0))
        .join(Document, DocumentKey.document_id == Document.id)
        .filter(
            Document.owner_id == user.id,
            DocumentKey.recipient_id != user.id,
        )
    ).scalar_one()

    # Integrity failures on user's documents in the last 30 days
    owned_doc_ids = db.select(Document.id).filter_by(owner_id=user.id)
    thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
    integrity_failures_count = db.session.execute(
        db.select(func.count(AuditLog.id)).filter(
            AuditLog.document_id.in_(owned_doc_ids),
            AuditLog.timestamp >= thirty_days_ago,
            db.or_(
                AuditLog.action == "INTEGRITY_FAILURE",
                db.and_(
                    AuditLog.action == "VERIFY",
                    AuditLog.details.like('%"result":"fail"%'),
                ),
            ),
        )
    ).scalar_one()

    # 2. Recent activity: latest 10 visible events
    recent_events_rows = (
        db.session.execute(
            visible_events_query(user).order_by(AuditLog.id.desc()).limit(10)
        )
        .scalars()
        .all()
    )

    doc_cache = {}
    user_cache = {}
    recent_activity = [
        describe_event(e, user, doc_cache=doc_cache, user_cache=user_cache)
        for e in recent_events_rows
    ]

    # 3. Latest 10 owned documents with recipient metrics
    owned_documents = (
        db.session.execute(
            db.select(Document)
            .filter_by(owner_id=user.id)
            .order_by(Document.created_at.desc())
            .limit(10)
        )
        .scalars()
        .all()
    )

    # 4. Latest 10 documents shared with current user
    shared_keys = (
        db.session.execute(
            db.select(DocumentKey)
            .join(Document, DocumentKey.document_id == Document.id)
            .filter(
                DocumentKey.recipient_id == user.id,
                Document.owner_id != user.id,
            )
            .order_by(DocumentKey.granted_at.desc())
            .limit(10)
        )
        .scalars()
        .all()
    )

    return render_template(
        "dashboard.html",
        owned_count=owned_count,
        shared_count=shared_count,
        other_decrypts_count=other_decrypts_count,
        integrity_failures_count=integrity_failures_count,
        recent_activity=recent_activity,
        owned_documents=owned_documents,
        shared_keys=shared_keys,
    )


def _build_activity_query(user: User):
    """Build and filter visible events query from request query parameters."""
    query = visible_events_query(user)

    # Filter: Action
    action_param = request.args.get("action", "").strip()
    if action_param and action_param in ALLOWED_ACTIONS and action_param != "ALL":
        query = query.filter(AuditLog.action == action_param)

    # Filter: Document ID
    doc_id_param = request.args.get("document_id", type=int)
    if doc_id_param is not None:
        # Validate that document is accessible to this user
        has_access = db.session.execute(
            db.select(DocumentKey.id).filter_by(
                document_id=doc_id_param, recipient_id=user.id
            )
        ).scalar_one_or_none()
        if has_access is not None:
            query = query.filter(AuditLog.document_id == doc_id_param)

    # Filter: Date From (YYYY-MM-DD inclusive UTC)
    date_from_str = request.args.get("date_from", "").strip()
    if date_from_str:
        try:
            dt_from = datetime.strptime(date_from_str, "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
            query = query.filter(AuditLog.timestamp >= dt_from)
        except ValueError:
            pass

    # Filter: Date To (YYYY-MM-DD inclusive UTC, to end of day)
    date_to_str = request.args.get("date_to", "").strip()
    if date_to_str:
        try:
            dt_to = datetime.strptime(date_to_str, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, microsecond=999999, tzinfo=timezone.utc
            )
            query = query.filter(AuditLog.timestamp <= dt_to)
        except ValueError:
            pass

    # Filter: Only my actions
    my_actions = request.args.get("my_actions_only", "").strip().lower()
    if my_actions in ("1", "true", "on", "yes"):
        query = query.filter(AuditLog.actor_id == user.id)

    return query


@bp.route("/activity")
@login_required
def activity():
    """Render paginated, filterable activity history visible to the authenticated user."""
    user = current_user._get_current_object()
    query = _build_activity_query(user).order_by(AuditLog.id.desc())

    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    per_page = 25

    total = db.session.execute(
        db.select(func.count()).select_from(query.subquery())
    ).scalar_one()

    events_rows = (
        db.session.execute(
            query.limit(per_page).offset((page - 1) * per_page)
        )
        .scalars()
        .all()
    )

    doc_cache = {}
    user_cache = {}
    described_events = [
        describe_event(e, user, doc_cache=doc_cache, user_cache=user_cache)
        for e in events_rows
    ]

    total_pages = max(1, (total + per_page - 1) // per_page)

    # Accessible documents for filter dropdown
    accessible_docs = (
        db.session.execute(
            db.select(Document)
            .join(DocumentKey, DocumentKey.document_id == Document.id)
            .filter(DocumentKey.recipient_id == user.id)
            .order_by(Document.original_filename.asc())
        )
        .scalars()
        .all()
    )

    # Dictionary of current filter args for pagination links
    filter_args = {
        "action": request.args.get("action", ""),
        "document_id": request.args.get("document_id", ""),
        "date_from": request.args.get("date_from", ""),
        "date_to": request.args.get("date_to", ""),
        "my_actions_only": request.args.get("my_actions_only", ""),
    }

    return render_template(
        "activity/index.html",
        events=described_events,
        page=page,
        total_pages=total_pages,
        total=total,
        allowed_actions=ALLOWED_ACTIONS,
        accessible_docs=accessible_docs,
        filter_args=filter_args,
    )


@bp.route("/activity/export", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def export_activity():
    """Export filtered visible activity history as a CSV file (capped at 5000 rows)."""
    user = current_user._get_current_object()
    query = _build_activity_query(user).order_by(AuditLog.id.desc()).limit(5000)

    rows = db.session.execute(query).scalars().all()

    doc_cache = {}
    user_cache = {}

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)

    # Header
    writer.writerow(
        [
            "Timestamp (UTC)",
            "Action",
            "Description",
            "Document",
            "IP Address",
            "Entry ID",
        ]
    )

    for entry in rows:
        desc = describe_event(entry, user, doc_cache=doc_cache, user_cache=user_cache)
        writer.writerow(
            [
                sanitize_csv_cell(desc["when"]),
                sanitize_csv_cell(desc["action"]),
                sanitize_csv_cell(desc["title"]),
                sanitize_csv_cell(desc["document_name"] or ""),
                sanitize_csv_cell(desc["ip_address"] or ""),
                sanitize_csv_cell(desc["entry_id"]),
            ]
        )

    # Log export event (row count only, no contents)
    log_event(
        action="ACTIVITY_EXPORT",
        actor=user,
        details={"row_count": len(rows)},
    )

    csv_data = output.getvalue()
    timestamp_suffix = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"vaultshare_activity_{timestamp_suffix}.csv"

    response = Response(csv_data, mimetype="text/csv")
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
