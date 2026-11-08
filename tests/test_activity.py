"""Tests for VaultShare activity history, visibility rules, descriptions, and CSV export."""

from datetime import datetime, timedelta, timezone
import io
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from app import db
from app.activity import describe_event, sanitize_csv_cell, visible_events_query
from app.audit import log_event, verify_chain
from app.keycache import clear_cache
from app.models import AuditLog, Document, DocumentKey, User


@pytest.fixture(autouse=True)
def fast_rsa_keygen(monkeypatch):
    """Fast RSA keypair generator for testing."""

    def _fast_keygen():
        priv = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        pub_pem = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pub_pem, priv

    monkeypatch.setattr("app.auth.generate_rsa_keypair", _fast_keygen)
    clear_cache()
    yield
    clear_cache()


def register_user(client, app, username, email, password="SecurePassword123!"):
    """Helper to register a user account."""
    client.post(
        "/auth/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        },
    )
    with app.app_context():
        return db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one()


def login_user(client, username, password="SecurePassword123!"):
    """Helper to log in a user."""
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


def upload_document(client, app, filename="doc.pdf", content=b"Test file content"):
    """Helper to upload a document."""
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
    )
    with app.app_context():
        return db.session.execute(
            db.select(Document).filter_by(original_filename=filename)
        ).scalar_one()


def test_visibility_rules(client, app):
    """Test detailed activity visibility rules across owner, recipient, and third party."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)
    carol = register_user(client, app, "carol", "carol@example.com", password)

    # Alice uploads document
    login_user(client, "alice", password)
    doc = upload_document(client, app, "project.pdf", b"Classified")

    # Alice shares with Bob and Carol
    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})
    client.post(f"/documents/{doc.id}/share", data={"recipients": "carol"})

    # Bob downloads document
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "bob", password)
    client.post(f"/documents/{doc.id}/download")

    # Alice revokes Carol
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "alice", password)
    client.post(f"/documents/{doc.id}/revoke/{carol.id}", follow_redirects=True)

    with app.app_context():
        # Alice (Owner) visibility
        alice_events = db.session.execute(
            visible_events_query(alice)
        ).scalars().all()
        alice_actions = [e.action for e in alice_events]
        # Alice should see UPLOAD, SHARE to Bob, SHARE to Carol, Bob's DECRYPT, REVOKE Carol, and her own LOGIN/LOGOUT
        assert "UPLOAD" in alice_actions
        assert "DECRYPT" in alice_actions
        assert "REVOKE" in alice_actions
        # Alice does NOT see Bob's or Carol's logins
        other_logins = [
            e for e in alice_events
            if e.action in ("LOGIN", "LOGOUT", "REGISTER") and e.actor_id != alice.id
        ]
        assert len(other_logins) == 0

        # Bob (Recipient) visibility
        bob_events = db.session.execute(
            visible_events_query(bob)
        ).scalars().all()
        # Bob sees his own DECRYPT
        assert any(e.action == "DECRYPT" and e.actor_id == bob.id for e in bob_events)
        # Bob sees the SHARE event where he was the target
        assert any(e.action == "SHARE" and e.target_user_id == bob.id for e in bob_events)
        # Bob does NOT see Alice's share to Carol or Alice's revoke of Carol
        assert not any(e.action == "SHARE" and e.target_user_id == carol.id for e in bob_events)
        assert not any(e.action == "REVOKE" and e.target_user_id == carol.id for e in bob_events)
        # Bob does NOT see Alice's or Carol's login/logout
        assert not any(e.action == "LOGIN" and e.actor_id != bob.id for e in bob_events)

        # Carol (Revoked) visibility
        carol_events = db.session.execute(
            visible_events_query(carol)
        ).scalars().all()
        # Carol sees the SHARE event targeting her
        assert any(e.action == "SHARE" and e.target_user_id == carol.id for e in carol_events)
        # Carol sees the REVOKE event targeting her
        assert any(e.action == "REVOKE" and e.target_user_id == carol.id for e in carol_events)
        # Carol does NOT see Bob's DECRYPT
        assert not any(e.action == "DECRYPT" for e in carol_events)


def test_ip_address_privacy(client, app):
    """Test IP addresses appear ONLY on viewer's own actions and are hidden on others'."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)
    doc = upload_document(client, app, "doc.pdf")
    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})

    # Bob downloads
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "bob", password)
    client.post(f"/documents/{doc.id}/download")

    with app.app_context():
        # Alice views Bob's DECRYPT event
        decrypt_event = db.session.execute(
            db.select(AuditLog).filter_by(action="DECRYPT")
        ).scalar_one()

        desc_for_alice = describe_event(decrypt_event, alice)
        assert desc_for_alice["ip_address"] is None  # Hidden!

        desc_for_bob = describe_event(decrypt_event, bob)
        assert desc_for_bob["ip_address"] is not None  # Shown for Bob himself!


def test_describe_event_formatting_and_xss_safety(client, app):
    """Test describe_event uses 'You' for viewer, handles deleted documents, and escapes HTML."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    # Malicious XSS filename stored in database
    xss_filename = "<script>alert(1)</script>.pdf"
    with app.app_context():
        u = db.session.get(User, alice.id)
        doc = Document(
            owner_id=u.id,
            original_filename=xss_filename,
            stored_filename="xss.enc",
            size_bytes=100,
        )
        db.session.add(doc)
        db.session.flush()
        doc_key = DocumentKey(
            document=doc,
            recipient=u,
            wrapped_key=b"dummy_key",
            granted_by=u,
        )
        db.session.add(doc_key)
        upload_event = log_event(
            action="UPLOAD",
            actor=u,
            document_id=doc.id,
            details={"original_filename": xss_filename},
        )
        doc_id = doc.id
        event_id = upload_event.id

        desc = describe_event(upload_event, u)
        assert "You uploaded" in desc["title"]
        assert xss_filename in desc["title"]
        db.session.commit()

    # Verify Jinja escapes the rendered HTML while doc exists
    res = client.get("/activity")
    assert res.status_code == 200
    assert b"<script>alert(1)</script>" not in res.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in res.data

    # Now delete document to verify fallback
    with app.app_context():
        u = db.session.get(User, alice.id)
        doc = db.session.get(Document, doc_id)
        ev = db.session.get(AuditLog, event_id)
        db.session.delete(doc)
        db.session.commit()

        desc_deleted = describe_event(ev, u)
        assert f"document #{doc_id}" in desc_deleted["title"]


def test_activity_filters_and_pagination(client, app):
    """Test action, document, date range filters and pagination."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "filtered.pdf")

    # Filter by action: UPLOAD
    res_upload = client.get("/activity?action=UPLOAD")
    assert res_upload.status_code == 200
    assert b"UPLOAD" in res_upload.data

    # Filter by action: INVALID (should be ignored, returning 200)
    res_invalid = client.get("/activity?action=NON_EXISTENT_ACTION")
    assert res_invalid.status_code == 200

    # Filter by document_id
    res_doc = client.get(f"/activity?document_id={doc.id}")
    assert res_doc.status_code == 200
    assert b"filtered.pdf" in res_doc.data

    # Filter by date range
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    res_date = client.get(f"/activity?date_from={today_str}&date_to={today_str}")
    assert res_date.status_code == 200

    # Filter by only my actions
    res_my = client.get("/activity?my_actions_only=1")
    assert res_my.status_code == 200


def test_per_document_history_access_control(client, app):
    """Test per-document history access control for owner, recipient, non-recipient, and revoked user."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)
    carol = register_user(client, app, "carol", "carol@example.com", password)

    login_user(client, "alice", password)
    doc = upload_document(client, app, "doc_history.pdf")
    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})

    # 1. Owner can access
    res_owner = client.get(f"/documents/{doc.id}/activity")
    assert res_owner.status_code == 200
    assert b"History: doc_history.pdf" in res_owner.data

    # 2. Recipient can access
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "bob", password)
    res_recipient = client.get(f"/documents/{doc.id}/activity")
    assert res_recipient.status_code == 200

    # 3. Non-recipient gets 404
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "carol", password)
    res_denied = client.get(f"/documents/{doc.id}/activity")
    assert res_denied.status_code == 404

    # 4. Revoked user gets 404
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "alice", password)
    client.post(f"/documents/{doc.id}/revoke/{bob.id}", follow_redirects=True)

    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "bob", password)
    res_revoked = client.get(f"/documents/{doc.id}/activity")
    assert res_revoked.status_code == 404


def test_csv_export_endpoint(client, app):
    """Test CSV export endpoint methods, headers, row cap, formula injection, and audit logging."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    # Formula injection test: store document with formula name
    with app.app_context():
        u = db.session.get(User, alice.id)
        formula_doc = Document(
            owner_id=u.id,
            original_filename="=cmd|' /C calc'!A0.pdf",
            stored_filename="formula.enc",
            size_bytes=100,
        )
        db.session.add(formula_doc)
        db.session.flush()
        doc_key = DocumentKey(
            document=formula_doc,
            recipient=u,
            wrapped_key=b"dummy_key",
            granted_by=u,
        )
        db.session.add(doc_key)
        log_event(
            action="UPLOAD",
            actor=u,
            document_id=formula_doc.id,
            details={"original_filename": "=cmd|' /C calc'!A0.pdf"},
        )
        db.session.commit()

    # 1. GET gives 405 Method Not Allowed
    res_get = client.get("/activity/export")
    assert res_get.status_code == 405

    # 2. POST exports CSV with safe headers
    res_post = client.post("/activity/export")
    assert res_post.status_code == 200
    assert res_post.headers["Content-Type"].startswith("text/csv")
    assert res_post.headers["Cache-Control"] == "no-store"
    assert res_post.headers["X-Content-Type-Options"] == "nosniff"
    assert "attachment; filename=" in res_post.headers["Content-Disposition"]

    # 3. Formula injection character is prefixed with single quote
    csv_text = res_post.data.decode("utf-8")
    assert "'=cmd|' /C calc'!A0.pdf" in csv_text

    # 4. Verify ACTIVITY_EXPORT audit event was logged without contents
    with app.app_context():
        export_log = db.session.execute(
            db.select(AuditLog).filter_by(action="ACTIVITY_EXPORT")
        ).scalar_one_or_none()
        assert export_log is not None
        assert export_log.actor_id == alice.id
        assert "row_count" in export_log.details
        assert "=cmd" not in export_log.details

        # 5. Verify the audit log hash chain remains completely valid!
        chain = verify_chain()
        assert chain["ok"] is True
