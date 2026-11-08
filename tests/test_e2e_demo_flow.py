"""End-to-end automated demo story test for VaultShare.

Demonstrates the complete user workflow:
1. Register and authenticate three users (alice, bob, carol).
2. Alice uploads a known plaintext document; verify ciphertext at rest.
3. Alice shares with Bob; Bob decrypts and downloads original bytes.
4. Verify DECRYPT audit event and intact hash chain.
5. Alice revokes Bob; Bob's subsequent download fails with 404.
6. Alice shares with Carol; tampering with ciphertext at rest causes download
   integrity failure and logs INTEGRITY_FAILURE.
7. Dropping database triggers and tampering with an audit row causes
   verify_chain and 'flask verify-audit' to detect tampering with exit code 1.
"""

import io
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from app import db
from app.audit import verify_chain
from app.keycache import clear_cache
from app.models import AuditLog, Document, DocumentKey, User


@pytest.fixture(autouse=True)
def fast_rsa_keygen(monkeypatch):
    """Speed up key generation during e2e testing while preserving cryptographic flow."""
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


def test_full_e2e_demo_flow(client, app, runner):
    """Execute complete VaultShare demo story from registration to tampering detection."""
    password = "DemoUserPass2026!#"

    # 1. Register three users: alice, bob, carol
    for username in ("alice", "bob", "carol"):
        resp = client.post(
            "/auth/register",
            data={
                "username": username,
                "email": f"{username}@example.com",
                "password": password,
                "confirm_password": password,
            },
            follow_redirects=True,
        )
        assert resp.status_code == 200

    with app.app_context():
        alice = db.session.execute(
            db.select(User).filter_by(username="alice")
        ).scalar_one()
        bob = db.session.execute(
            db.select(User).filter_by(username="bob")
        ).scalar_one()
        carol = db.session.execute(
            db.select(User).filter_by(username="carol")
        ).scalar_one()

    # Log in as Alice
    client.post(
        "/auth/login",
        data={"username": "alice", "password": password},
        follow_redirects=True,
    )

    # 2. Alice uploads a known plaintext document
    known_plaintext = b"Top Secret Quarterly Strategy Plaintext 2026 - Do Not Leak!"
    upload_resp = client.post(
        "/documents/upload",
        data={
            "document": (io.BytesIO(known_plaintext), "quarterly_strategy.txt"),
        },
        follow_redirects=True,
    )
    assert upload_resp.status_code == 200

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="quarterly_strategy.txt")
        ).scalar_one()
        doc_id = doc.id
        stored_filename = doc.stored_filename

        # Assert stored .enc file does NOT contain the plaintext
        storage_dir = Path(app.config["STORAGE_DIR"])
        enc_file = storage_dir / stored_filename
        assert enc_file.exists()
        enc_bytes = enc_file.read_bytes()
        assert known_plaintext not in enc_bytes

    # 3. Alice shares with Bob
    share_resp = client.post(
        f"/documents/{doc_id}/share",
        data={"recipients": "bob"},
        follow_redirects=True,
    )
    assert share_resp.status_code == 200

    # 4. Bob logs in and downloads document
    client.post("/auth/logout", follow_redirects=True)
    client.post(
        "/auth/login",
        data={"username": "bob", "password": password},
        follow_redirects=True,
    )

    download_resp = client.post(f"/documents/{doc_id}/download")
    assert download_resp.status_code == 200
    assert download_resp.data == known_plaintext

    # 5. Check DECRYPT audit row exists for Bob and hash chain verifies
    with app.app_context():
        decrypt_row = db.session.execute(
            db.select(AuditLog).filter_by(
                action="DECRYPT", actor_username="bob", document_id=doc_id
            )
        ).scalar_one_or_none()
        assert decrypt_row is not None

        chain_res = verify_chain()
        assert chain_res["ok"] is True

    # 6. Alice revokes Bob's access
    client.post("/auth/logout", follow_redirects=True)
    client.post(
        "/auth/login",
        data={"username": "alice", "password": password},
        follow_redirects=True,
    )

    revoke_resp = client.post(
        f"/documents/{doc_id}/revoke/{bob.id}",
        follow_redirects=True,
    )
    assert revoke_resp.status_code == 200

    # Bob attempts to download again -> 404 Not Found (silent denial)
    client.post("/auth/logout", follow_redirects=True)
    client.post(
        "/auth/login",
        data={"username": "bob", "password": password},
        follow_redirects=True,
    )

    denied_resp = client.post(f"/documents/{doc_id}/download")
    assert denied_resp.status_code == 404

    with app.app_context():
        denied_log = db.session.execute(
            db.select(AuditLog).filter_by(
                action="ACCESS_DENIED", actor_username="bob", document_id=doc_id
            )
        ).scalar_one_or_none()
        assert denied_log is not None

    # 7. Alice shares with Carol; simulate storage corruption / tampering
    client.post("/auth/logout", follow_redirects=True)
    client.post(
        "/auth/login",
        data={"username": "alice", "password": password},
        follow_redirects=True,
    )
    client.post(
        f"/documents/{doc_id}/share",
        data={"recipients": "carol"},
        follow_redirects=True,
    )

    # Flip one byte in the stored ciphertext file
    with app.app_context():
        enc_file = Path(app.config["STORAGE_DIR"]) / stored_filename
        corrupted_data = bytearray(enc_file.read_bytes())
        corrupted_data[0] ^= 0xFF
        enc_file.write_bytes(bytes(corrupted_data))

    # Carol logs in and attempts download -> fails with integrity error
    client.post("/auth/logout", follow_redirects=True)
    client.post(
        "/auth/login",
        data={"username": "carol", "password": password},
        follow_redirects=True,
    )

    tampered_download = client.post(
        f"/documents/{doc_id}/download", follow_redirects=True
    )
    # Redirects with flash message
    assert tampered_download.status_code == 200
    assert b"Decryption failed" in tampered_download.data

    with app.app_context():
        integrity_fail_log = db.session.execute(
            db.select(AuditLog).filter_by(
                action="INTEGRITY_FAILURE",
                actor_username="carol",
                document_id=doc_id,
            )
        ).scalar_one_or_none()
        assert integrity_fail_log is not None

    # 8. Direct audit tampering test: drop triggers and edit an audit row
    with app.app_context():
        raw_conn = db.engine.raw_connection()
        cursor = raw_conn.cursor()
        cursor.execute("DROP TRIGGER IF EXISTS audit_logs_no_update")
        cursor.execute("DROP TRIGGER IF EXISTS audit_logs_no_delete")
        cursor.execute(
            "UPDATE audit_logs SET details = ? WHERE id = 1",
            ('{"tampered": "unauthorized direct edit"}',),
        )
        raw_conn.commit()
        cursor.close()
        raw_conn.close()

        # verify_chain reports tampering
        tamper_check = verify_chain()
        assert tamper_check["ok"] is False
        assert tamper_check["first_bad_id"] == 1
        assert tamper_check["reason"] == "entry_hash_mismatch"

    # 'flask verify-audit' prints TAMPERING DETECTED and exits with code 1
    cli_result = runner.invoke(args=["verify-audit"])
    assert cli_result.exit_code == 1
    assert "TAMPERING DETECTED" in cli_result.output
