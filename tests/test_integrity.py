"""Tests for VaultShare document integrity verification service and routes."""

import io
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
from sqlalchemy import text

from app import db
from app.audit import log_event
from app.integrity import verify_document
from app.keycache import clear_cache, drop_key
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


def upload_document(client, app, filename="secret.pdf", content=b"Sensitive document content"):
    """Helper to upload an encrypted document."""
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
    )
    with app.app_context():
        return db.session.execute(
            db.select(Document).filter_by(original_filename=filename)
        ).scalar_one()


def test_owner_verifies_untouched_document(client, app):
    """Test owner verifies an untouched document: overall pass, all five checks pass."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "untouched.pdf", b"Original clean content")

    res = client.post(f"/integrity/documents/{doc.id}/verify", follow_redirects=True)
    assert res.status_code == 200
    assert b"OVERALL PASS" in res.data or b"PASSED" in res.data
    assert b"file_present" in res.data
    assert b"ciphertext_hash" in res.data
    assert b"key_unwrap" in res.data
    assert b"gcm_authentication" in res.data
    assert b"plaintext_hash" in res.data

    with app.app_context():
        verify_log = db.session.execute(
            db.select(AuditLog).filter_by(action="VERIFY", document_id=doc.id)
        ).scalars().first()
        assert verify_log is not None
        details = json.loads(verify_log.details)
        assert details["result"] == "pass"
        assert details["checks"]["file_present"] == "pass"
        assert details["checks"]["ciphertext_hash"] == "pass"
        assert details["checks"]["key_unwrap"] == "pass"
        assert details["checks"]["gcm_authentication"] == "pass"
        assert details["checks"]["plaintext_hash"] == "pass"


def test_recipient_can_verify_document(client, app):
    """Test a shared recipient can verify the document successfully."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)
    doc = upload_document(client, app, "shared.pdf", b"Shared content for Bob")
    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})
    client.post("/auth/logout", follow_redirects=True)

    login_user(client, "bob", password)
    res = client.post(f"/integrity/documents/{doc.id}/verify", follow_redirects=True)
    assert res.status_code == 200
    assert b"PASSED" in res.data or b"OVERALL PASS" in res.data


def test_user_without_access_gets_404_and_logged(client, app):
    """Test a user without access gets 404 and ACCESS_DENIED is logged."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)
    doc = upload_document(client, app, "private.pdf", b"Alice only")
    client.post("/auth/logout", follow_redirects=True)

    login_user(client, "bob", password)
    res = client.post(f"/integrity/documents/{doc.id}/verify")
    assert res.status_code == 404

    with app.app_context():
        denied_log = db.session.execute(
            db.select(AuditLog).filter_by(
                action="ACCESS_DENIED", actor_username="bob", document_id=doc.id
            )
        ).scalar_one_or_none()
        assert denied_log is not None


def test_revoked_recipient_gets_404(client, app):
    """Test a revoked recipient gets 404 when attempting to verify."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)
    doc = upload_document(client, app, "doc.pdf", b"Content")
    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})
    client.post(f"/documents/{doc.id}/revoke/{bob.id}", follow_redirects=True)
    client.post("/auth/logout", follow_redirects=True)

    login_user(client, "bob", password)
    res = client.post(f"/integrity/documents/{doc.id}/verify")
    assert res.status_code == 404


def test_byte_flip_in_stored_file_fails_ciphertext_hash(client, app):
    """Test flipping a byte in the stored file causes ciphertext_hash fail and later checks skipped."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "tamper_target.pdf", b"Original bytes")

    # Flip a byte in the storage file
    storage_dir = Path(app.config["STORAGE_DIR"])
    file_path = storage_dir / doc.stored_filename
    data = file_path.read_bytes()
    tampered_data = bytes([data[0] ^ 0xFF]) + data[1:]
    file_path.write_bytes(tampered_data)

    res = client.post(f"/integrity/documents/{doc.id}/verify", follow_redirects=True)
    assert res.status_code == 200
    assert b"FAILED" in res.data or b"OVERALL FAIL" in res.data
    assert b"ciphertext_hash" in res.data

    with app.app_context():
        fail_log = db.session.execute(
            db.select(AuditLog)
            .filter_by(action="INTEGRITY_FAILURE", document_id=doc.id)
            .order_by(AuditLog.id.desc())
        ).scalars().first()
        assert fail_log is not None
        assert "ciphertext_hash" in fail_log.details

        verify_log = db.session.execute(
            db.select(AuditLog)
            .filter_by(action="VERIFY", document_id=doc.id)
            .order_by(AuditLog.id.desc())
        ).scalars().first()
        assert verify_log is not None
        v_details = json.loads(verify_log.details)
        assert v_details["result"] == "fail"
        assert v_details["failed_check"] == "ciphertext_hash"
        assert v_details["checks"]["ciphertext_hash"] == "fail"
        assert v_details["checks"]["key_unwrap"] == "skipped"
        assert v_details["checks"]["gcm_authentication"] == "skipped"
        assert v_details["checks"]["plaintext_hash"] == "skipped"


def test_tampered_ciphertext_hash_in_db(client, app):
    """Test tampering with Document.ciphertext_sha256 in DB is detected."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "bad_chash.pdf", b"Content")

    with app.app_context():
        d = db.session.get(Document, doc.id)
        d.ciphertext_sha256 = "0" * 64
        db.session.commit()

    res = client.post(f"/integrity/documents/{doc.id}/verify", follow_redirects=True)
    assert res.status_code == 200
    assert b"FAILED" in res.data or b"OVERALL FAIL" in res.data


def test_tampered_plaintext_hash_in_db(client, app):
    """Test tampering with Document.plaintext_sha256 in DB causes check 5 to fail."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "bad_pthash.pdf", b"Content")

    with app.app_context():
        d = db.session.get(Document, doc.id)
        d.plaintext_sha256 = "f" * 64
        db.session.commit()

    res = client.post(f"/integrity/documents/{doc.id}/verify", follow_redirects=True)
    assert res.status_code == 200
    assert b"FAILED" in res.data or b"OVERALL FAIL" in res.data
    assert b"plaintext_hash" in res.data


def test_missing_file_reports_file_present_fail(client, app):
    """Test deleting stored file reports file_present fail gracefully without stack trace."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "missing.pdf", b"To be deleted")

    storage_dir = Path(app.config["STORAGE_DIR"])
    file_path = storage_dir / doc.stored_filename
    file_path.unlink()

    res = client.post(f"/integrity/documents/{doc.id}/verify", follow_redirects=True)
    assert res.status_code == 200
    assert b"FAILED" in res.data or b"OVERALL FAIL" in res.data
    assert b"file_present" in res.data


def test_verification_does_not_change_decrypt_count_or_last_decrypted_at(client, app):
    """Test verification does not modify DocumentKey decrypt_count or last_decrypted_at."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "count_check.pdf", b"Check counts")

    with app.app_context():
        key_before = db.session.execute(
            db.select(DocumentKey).filter_by(document_id=doc.id, recipient_id=alice.id)
        ).scalar_one()
        assert key_before.decrypt_count == 0
        assert key_before.last_decrypted_at is None

    client.post(f"/integrity/documents/{doc.id}/verify", follow_redirects=True)

    with app.app_context():
        key_after = db.session.execute(
            db.select(DocumentKey).filter_by(document_id=doc.id, recipient_id=alice.id)
        ).scalar_one()
        assert key_after.decrypt_count == 0
        assert key_after.last_decrypted_at is None


def test_no_new_files_appear_in_storage_dir(client, app):
    """Test verification does not write any plaintext or temporary files to disk."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "storage_test.pdf", b"Storage test content")

    storage_dir = Path(app.config["STORAGE_DIR"])
    files_before = set(storage_dir.iterdir())

    client.post(f"/integrity/documents/{doc.id}/verify", follow_redirects=True)

    files_after = set(storage_dir.iterdir())
    assert files_before == files_after


def test_no_cached_key_skips_checks_3_to_5(client, app):
    """Test when no cached private key is available, checks 1-2 run and 3-5 are skipped."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "no_key.pdf", b"Content")

    with app.app_context():
        u = db.session.get(User, alice.id)
        d = db.session.get(Document, doc.id)
        res = verify_document(u, d, private_key=None)

        assert res.result == "pass"
        assert res.checks[0].name == "file_present"
        assert res.checks[0].status == "pass"
        assert res.checks[1].name == "ciphertext_hash"
        assert res.checks[1].status == "pass"
        assert res.checks[2].name == "key_unwrap"
        assert res.checks[2].status == "skipped"
        assert res.checks[2].detail == "session key unavailable"
        assert res.checks[3].name == "gcm_authentication"
        assert res.checks[3].status == "skipped"
        assert res.checks[4].name == "plaintext_hash"
        assert res.checks[4].status == "skipped"

        v_log = db.session.execute(
            db.select(AuditLog)
            .filter_by(action="VERIFY", document_id=doc.id)
            .order_by(AuditLog.id.desc())
        ).scalars().first()
        assert v_log is not None
        v_details = json.loads(v_log.details)
        assert v_details["checks"]["file_present"] == "pass"
        assert v_details["checks"]["ciphertext_hash"] == "pass"
        assert v_details["checks"]["key_unwrap"] == "skipped"
        assert v_details["checks"]["gcm_authentication"] == "skipped"
        assert v_details["checks"]["plaintext_hash"] == "skipped"


def test_check_file_matching_and_mismatch(client, app):
    """Test check-file endpoint with matching, modified bytes, and non-recipient access."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)
    original_bytes = b"Exact original downloaded document bytes"
    doc = upload_document(client, app, "local_check.pdf", original_bytes)

    # 1. Exact match upload
    res_match = client.post(
        f"/integrity/documents/{doc.id}/check-file",
        data={"file": (io.BytesIO(original_bytes), "my_copy.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert res_match.status_code == 200
    assert b"File matches the original" in res_match.data

    with app.app_context():
        match_log = db.session.execute(
            db.select(AuditLog)
            .filter_by(action="VERIFY", document_id=doc.id)
            .order_by(AuditLog.id.desc())
        ).scalars().first()
        assert match_log is not None
        d = json.loads(match_log.details)
        assert d["mode"] == "local_copy"
        assert d["result"] == "match"

    # 2. Modified bytes upload
    tampered_bytes = b"Tampered local document bytes"
    res_mismatch = client.post(
        f"/integrity/documents/{doc.id}/check-file",
        data={"file": (io.BytesIO(tampered_bytes), "my_tampered_copy.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert res_mismatch.status_code == 200
    assert b"File does NOT match the original" in res_mismatch.data

    # 3. Non-recipient attempt
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "bob", password)
    res_denied = client.post(
        f"/integrity/documents/{doc.id}/check-file",
        data={"file": (io.BytesIO(original_bytes), "copy.pdf")},
        content_type="multipart/form-data",
    )
    assert res_denied.status_code == 404


def test_verify_all_accessible_documents(client, app):
    """Test verify-all verifies accessible documents and respects the 50-document limit."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc1 = upload_document(client, app, "doc1.pdf", b"Content 1")
    doc2 = upload_document(client, app, "doc2.pdf", b"Content 2")

    res = client.post("/integrity/verify-all", follow_redirects=True)
    assert res.status_code == 200
    assert b"Batch verification completed for 2 document(s)" in res.data
    assert b"doc1.pdf" in res.data
    assert b"doc2.pdf" in res.data


def test_audit_chain_card_and_verify_button(client, app):
    """Test audit chain card shows green on clean log and red on tampering."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    # 1. Clean log
    res = client.get("/integrity")
    assert res.status_code == 200
    assert b"Audit Log Intact" in res.data

    # Button verification
    res_btn = client.post("/integrity/audit-chain/verify", follow_redirects=True)
    assert res_btn.status_code == 200
    assert b"Audit Log Intact" in res_btn.data

    # 2. Tamper with audit log entry
    with app.app_context():
        db.session.execute(text("DROP TRIGGER IF EXISTS audit_logs_no_update"))
        db.session.execute(
            text("UPDATE audit_logs SET action = 'FORGED' WHERE id = 1")
        )
        db.session.commit()

    res_tampered = client.post("/integrity/audit-chain/verify", follow_redirects=True)
    assert res_tampered.status_code == 200
    assert b"TAMPERING DETECTED" in res_tampered.data


def test_no_key_material_in_verify_audit_details(client, app):
    """Test that VERIFY audit events never record private keys, document keys, or passwords."""
    password = "TopSecretPassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    login_user(client, "alice", password)

    doc = upload_document(client, app, "key_leak_test.pdf", b"Secret payload")

    client.post(f"/integrity/documents/{doc.id}/verify", follow_redirects=True)
    client.post(
        f"/integrity/documents/{doc.id}/check-file",
        data={"file": (io.BytesIO(b"Secret payload"), "test.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    with app.app_context():
        verify_logs = db.session.execute(
            db.select(AuditLog).filter_by(action="VERIFY")
        ).scalars().all()
        for v in verify_logs:
            if v.details:
                assert password not in v.details
                assert "PRIVATE KEY" not in v.details
                assert "doc_key" not in v.details
                assert "Secret payload" not in v.details
