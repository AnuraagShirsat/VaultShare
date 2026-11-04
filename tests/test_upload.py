"""Tests for VaultShare document upload, AES-256-GCM encryption, and storage."""

import io
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
from sqlalchemy.exc import SQLAlchemyError

from app import db
from app.crypto import decrypt_bytes, sha256_hex, unwrap_key
from app.documents import store_encrypted_document
from app.keycache import clear_cache, get_key
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


@pytest.fixture
def logged_in_user(client, app):
    """Register and log in a test user, returning the user and client."""
    password = "AliceSecurePass123!"
    client.post(
        "/auth/register",
        data={
            "username": "alice",
            "email": "alice@example.com",
            "password": password,
            "confirm_password": password,
        },
    )
    client.post(
        "/auth/login",
        data={"username": "alice", "password": password},
    )
    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(username="alice")
        ).scalar_one()
    return user, client, password


def test_authenticated_upload_success_and_db_records(logged_in_user, app):
    """Test that authenticated upload stores the document, owner key, and audit log."""
    user, client, _ = logged_in_user
    payload = b"%PDF-1.4\nSensitive financial statements content for test."

    response = client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(payload), "financials.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"financials.pdf" in response.data
    assert b"successfully encrypted and stored" in response.data

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="financials.pdf")
        ).scalar_one_or_none()
        assert doc is not None
        assert doc.owner_id == user.id
        assert doc.size_bytes == len(payload)
        assert doc.stored_filename.endswith(".enc")
        assert len(doc.nonce) == 12
        assert doc.plaintext_sha256 == sha256_hex(payload)

        # Confirm DocumentKey created for owner
        key_entry = db.session.execute(
            db.select(DocumentKey).filter_by(
                document_id=doc.id, recipient_id=user.id
            )
        ).scalar_one_or_none()
        assert key_entry is not None
        assert key_entry.granted_by_id == user.id
        assert len(key_entry.wrapped_key) > 0

        # Confirm UPLOAD audit event logged
        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                action="UPLOAD", document_id=doc.id, actor_username=user.username
            )
        ).scalar_one_or_none()
        assert audit is not None


def test_file_on_disk_is_encrypted_and_hash_matches(logged_in_user, app):
    """Test that file stored on disk is ciphertext (no plaintext string) and matches hash."""
    user, client, _ = logged_in_user
    secret_marker = b"CONFIDENTIAL_MARKER_DO_NOT_LEAK_PLAINTEXT_12345"

    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(secret_marker), "classified.txt")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="classified.txt")
        ).scalar_one()

        storage_path = Path(app.config["STORAGE_DIR"]) / doc.stored_filename
        assert storage_path.exists()

        stored_bytes = storage_path.read_bytes()

        # Plaintext MUST NOT be in the stored ciphertext file
        assert secret_marker not in stored_bytes

        # Stored ciphertext hash must match sha256 of the file on disk
        assert sha256_hex(stored_bytes) == doc.ciphertext_sha256


def test_owner_can_unwrap_and_decrypt_uploaded_document(logged_in_user, app):
    """Test that owner's wrapped key and private key decrypt the stored file back to plaintext."""
    user, client, _ = logged_in_user
    original_data = b"Exact plaintext verification buffer for AES-GCM and RSA-OAEP."

    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(original_data), "verification.docx")},
        content_type="multipart/form-data",
    )

    with client.session_transaction() as sess:
        key_token = sess.get("key_token")

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="verification.docx")
        ).scalar_one()
        key_row = db.session.execute(
            db.select(DocumentKey).filter_by(
                document_id=doc.id, recipient_id=user.id
            )
        ).scalar_one()

        # Retrieve owner's decrypted private key from server key cache
        owner_priv_key = get_key(key_token, user.id)
        assert owner_priv_key is not None

        # Unwrap document key using owner's private key
        unwrapped_doc_key = unwrap_key(owner_priv_key, key_row.wrapped_key)

        # Decrypt ciphertext from storage
        file_path = Path(app.config["STORAGE_DIR"]) / doc.stored_filename
        ciphertext = file_path.read_bytes()
        decrypted_plaintext = decrypt_bytes(
            unwrapped_doc_key, doc.nonce, ciphertext
        )

        assert decrypted_plaintext == original_data


def test_disallowed_extension_rejected(logged_in_user, app):
    """Test that uploads with extensions outside the allowlist are rejected."""
    _, client, _ = logged_in_user

    res = client.post(
        "/documents/upload",
        data={
            "document": (
                io.BytesIO(b"malicious executable"),
                "malware.exe",
            )
        },
        content_type="multipart/form-data",
    )
    assert res.status_code == 400
    assert b"File extension not permitted" in res.data

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="malware.exe")
        ).scalar_one_or_none()
        assert doc is None


def test_empty_file_rejected(logged_in_user, app):
    """Test that 0-byte files are rejected."""
    _, client, _ = logged_in_user

    res = client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b""), "empty.pdf")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400
    assert b"Cannot upload an empty file" in res.data


def test_oversize_file_rejected(logged_in_user, app):
    """Test that files exceeding MAX_CONTENT_LENGTH are rejected."""
    _, client, _ = logged_in_user

    # Configure small max length for testing
    original_max = app.config["MAX_CONTENT_LENGTH"]
    app.config["MAX_CONTENT_LENGTH"] = 50  # 50 bytes

    try:
        large_data = b"A" * 100
        res = client.post(
            "/documents/upload",
            data={"document": (io.BytesIO(large_data), "oversize.pdf")},
            content_type="multipart/form-data",
        )
        assert res.status_code == 413
    finally:
        app.config["MAX_CONTENT_LENGTH"] = original_max


def test_anonymous_upload_redirects_to_login(client):
    """Test that anonymous upload requests are redirected to login."""
    res = client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"data"), "test.pdf")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 302
    assert "/auth/login" in res.headers["Location"]


def test_path_traversal_filename_does_not_escape_storage(logged_in_user, app):
    """Test that path traversal characters in filename do not escape storage directory."""
    user, client, _ = logged_in_user
    traversal_name = "../../escape.txt"

    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"traversal test"), traversal_name)},
        content_type="multipart/form-data",
    )

    with app.app_context():
        # In DB, filename is sanitized without path separators
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="escape.txt")
        ).scalar_one_or_none()
        assert doc is not None

        storage_dir = Path(app.config["STORAGE_DIR"]).resolve()
        stored_path = (storage_dir / doc.stored_filename).resolve()

        assert stored_path.is_relative_to(storage_dir)
        assert stored_path.exists()


def test_failed_db_commit_leaves_no_orphan_file_in_storage(logged_in_user, app, monkeypatch):
    """Test that if the DB commit fails, the written ciphertext file is deleted."""
    user, _, _ = logged_in_user
    storage_dir = Path(app.config["STORAGE_DIR"]).resolve()

    # Record initial files
    initial_files = set(storage_dir.glob("*.enc"))

    # Force db.session.commit to fail
    def _mock_commit():
        raise SQLAlchemyError("Simulated database failure during upload commit.")

    monkeypatch.setattr(db.session, "commit", _mock_commit)

    with app.app_context():
        with pytest.raises(SQLAlchemyError):
            store_encrypted_document(
                owner=user,
                filename="orphan_test.pdf",
                data=b"Data that should not orphan a file.",
            )

        # Verify no new .enc files remain in storage directory
        final_files = set(storage_dir.glob("*.enc"))
        assert final_files == initial_files
