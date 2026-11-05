"""Tests for VaultShare document sharing, access control, and revocation."""

import io
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from app import db
from app.access import require_recipient
from app.crypto import decrypt_bytes, decrypt_private_key, unwrap_key
from app.documents import store_encrypted_document
from app.keycache import clear_cache
from app.models import AuditLog, Document, DocumentKey, User
from werkzeug.exceptions import HTTPException


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


def test_multi_recipient_sharing_and_decryption(client, app):
    """Test owner sharing with two recipients in one request.

    Verifies distinct wrapped keys and that each recipient can unwrap the key
    and decrypt the file plaintext.
    """
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)
    carol = register_user(client, app, "carol", "carol@example.com", password)

    login_user(client, "alice", password)
    payload = b"Top Secret Document Content for Multi-Recipient Test"
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(payload), "secret.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="secret.pdf")
        ).scalar_one()
        doc_id = doc.id

    res = client.post(
        f"/documents/{doc_id}/share",
        data={"recipients": "bob, carol@example.com"},
        follow_redirects=True,
    )
    assert res.status_code == 200

    with app.app_context():
        doc = db.session.get(Document, doc_id)
        alice_key_entry = db.session.execute(
            db.select(DocumentKey).filter_by(document_id=doc.id, recipient_id=alice.id)
        ).scalar_one()
        bob_key_entry = db.session.execute(
            db.select(DocumentKey).filter_by(document_id=doc.id, recipient_id=bob.id)
        ).scalar_one()
        carol_key_entry = db.session.execute(
            db.select(DocumentKey).filter_by(document_id=doc.id, recipient_id=carol.id)
        ).scalar_one()

        assert alice_key_entry.wrapped_key != bob_key_entry.wrapped_key
        assert bob_key_entry.wrapped_key != carol_key_entry.wrapped_key

        alice_priv = decrypt_private_key(
            alice.encrypted_private_key, alice.key_salt, alice.key_nonce, password
        )
        alice_doc_key = unwrap_key(alice_priv, alice_key_entry.wrapped_key)

        bob_priv = decrypt_private_key(
            bob.encrypted_private_key, bob.key_salt, bob.key_nonce, password
        )
        bob_doc_key = unwrap_key(bob_priv, bob_key_entry.wrapped_key)

        carol_priv = decrypt_private_key(
            carol.encrypted_private_key, carol.key_salt, carol.key_nonce, password
        )
        carol_doc_key = unwrap_key(carol_priv, carol_key_entry.wrapped_key)

        assert alice_doc_key == bob_doc_key == carol_doc_key

        storage_dir = Path(app.config["STORAGE_DIR"])
        file_path = storage_dir / doc.stored_filename
        ciphertext = file_path.read_bytes()
        decrypted = decrypt_bytes(bob_doc_key, doc.nonce, ciphertext)
        assert decrypted == payload


def test_non_owner_access_denied_and_logged(client, app):
    """Test non-owner cannot access manage, share, or revoke."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"Data"), "file.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="file.pdf")
        ).scalar_one()
        doc_id = doc.id

    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "bob", password)

    assert client.get(f"/documents/{doc_id}/manage").status_code == 404
    assert client.post(f"/documents/{doc_id}/share", data={"recipients": "carol"}).status_code == 404
    assert client.post(f"/documents/{doc_id}/revoke/{alice.id}").status_code == 404

    with app.app_context():
        denied_logs = (
            db.session.execute(
                db.select(AuditLog).filter_by(
                    action="ACCESS_DENIED", actor_username="bob", document_id=doc_id
                )
            )
            .scalars()
            .all()
        )
        assert len(denied_logs) >= 3


def test_user_without_access_gets_404(client, app):
    """Test user without access gets 404, not 403, via require_recipient."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"Secret"), "private.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="private.pdf")
        ).scalar_one()

        login_user(client, "bob", password)

        with pytest.raises(HTTPException) as exc_info:
            require_recipient(doc)
        assert exc_info.value.code == 404


def test_duplicate_share_no_duplicate_row(client, app):
    """Test sharing twice with the same user does not create duplicate DocumentKey row."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"Data"), "doc.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="doc.pdf")
        ).scalar_one()

    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})
    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})

    with app.app_context():
        key_count = db.session.execute(
            db.select(db.func.count(DocumentKey.id)).filter_by(
                document_id=doc.id, recipient_id=bob.id
            )
        ).scalar()
        assert key_count == 1


def test_revoke_deletes_row_and_subsequent_access_fails(client, app):
    """Test revoke deletes recipient row and subsequent access fails."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"Data"), "doc.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="doc.pdf")
        ).scalar_one()

    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})

    client.post(f"/documents/{doc.id}/revoke/{bob.id}", follow_redirects=True)

    with app.app_context():
        bob_key = db.session.execute(
            db.select(DocumentKey).filter_by(document_id=doc.id, recipient_id=bob.id)
        ).scalar_one_or_none()
        assert bob_key is None

        login_user(client, "bob", password)
        with pytest.raises(HTTPException) as exc_info:
            require_recipient(doc)
        assert exc_info.value.code == 404

