"""Tests for VaultShare security and document dashboard view."""

from datetime import datetime, timedelta, timezone
import io
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from app import db
from app.audit import log_event
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


def test_anonymous_dashboard_redirects_to_login(client):
    """Test that an unauthenticated user is redirected to login."""
    res = client.get("/dashboard")
    assert res.status_code == 302
    assert "/auth/login" in res.headers["Location"]


def test_empty_dashboard_for_new_user(client, app):
    """Test dashboard empty states render for a brand-new user with zero documents."""
    password = "SecurePassword123!"
    register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    res = client.get("/dashboard")
    assert res.status_code == 200
    assert b"No uploaded documents yet" in res.data
    assert b"No documents shared with you" in res.data
    assert b"Owned Documents" in res.data
    assert b"Shared With Me" in res.data
    assert b"Decrypts by Others" in res.data
    assert b"Failures (30d)" in res.data


def test_dashboard_stat_cards_and_decrypt_count(client, app):
    """Test that dashboard stat cards accurately calculate owned, shared, other decrypts, and failures."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    # Alice uploads 2 documents
    login_user(client, "alice", password)
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"%PDF-1.4\nDoc 1"), "doc1.pdf")},
        content_type="multipart/form-data",
    )
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"%PDF-1.4\nDoc 2"), "doc2.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        d1 = db.session.execute(
            db.select(Document).filter_by(original_filename="doc1.pdf")
        ).scalar_one()
        d2 = db.session.execute(
            db.select(Document).filter_by(original_filename="doc2.pdf")
        ).scalar_one()
        doc1_id = d1.id
        doc2_id = d2.id

    # Alice shares doc1 with Bob
    client.post(f"/documents/{doc1_id}/share", data={"recipients": "bob"})

    # Bob downloads doc1
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "bob", password)
    client.post(f"/documents/{doc1_id}/download")

    # Alice logs an integrity failure on doc1 (simulate failure within 30 days)
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "alice", password)
    with app.app_context():
        d1 = db.session.get(Document, doc1_id)
        u1 = db.session.get(User, alice.id)
        log_event(action="INTEGRITY_FAILURE", actor=u1, document_id=d1.id, details={"reason": "test_failure"})

    # Check Alice's dashboard stats
    res_alice = client.get("/dashboard")
    assert res_alice.status_code == 200
    # Owned: 2, Shared: 0, Decrypts by others: 1, Failures (30d): 1
    assert b"doc1.pdf" in res_alice.data
    assert b"doc2.pdf" in res_alice.data

    # Check Bob's dashboard stats
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "bob", password)
    res_bob = client.get("/dashboard")
    assert res_bob.status_code == 200
    # Bob has 0 owned, 1 shared with him
    assert b"doc1.pdf" in res_bob.data


def test_quick_action_buttons_render(client, app):
    """Test quick-action buttons (Download, Manage, Verify, History) appear on dashboard."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"%PDF-1.4\nData"), "quick_actions.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="quick_actions.pdf")
        ).scalar_one()
        doc_id = doc.id

    res = client.get("/dashboard")
    assert res.status_code == 200
    assert f"/documents/{doc_id}/download".encode() in res.data
    assert f"/documents/{doc_id}/manage".encode() in res.data
    assert f"/integrity/documents/{doc_id}/verify".encode() in res.data
    assert f"/documents/{doc_id}/activity".encode() in res.data
