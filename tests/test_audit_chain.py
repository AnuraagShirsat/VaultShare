"""Tests for VaultShare tamper-proof hash-chained audit log and verification."""

from datetime import datetime, timezone
import io
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app import db
from app.audit import (
    GENESIS_HASH,
    canonical_timestamp,
    compute_entry_hash,
    log_event,
    verify_chain,
)
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


def test_first_event_genesis_and_chaining(app):
    """Test that the first event uses GENESIS_HASH and the second chains from the first."""
    with app.app_context():
        e1 = log_event(action="EVENT_ONE", details={"step": 1})
        e2 = log_event(action="EVENT_TWO", details={"step": 2})

        assert e1.prev_hash == GENESIS_HASH
        assert e2.prev_hash == e1.entry_hash
        assert e1.entry_hash != e2.entry_hash

        result = verify_chain()
        assert result["ok"] is True
        assert result["checked"] == 2
        assert result["first_bad_id"] is None
        assert result["reason"] is None


def test_loop_and_uncommitted_flushes_form_valid_chain(app):
    """Test multiple events logged in a loop with commit=False form an unbroken chain."""
    with app.app_context():
        for i in range(5):
            log_event(
                action=f"BATCH_{i}",
                details={"index": i},
                commit=False,
            )
        db.session.commit()

        result = verify_chain()
        assert result["ok"] is True
        assert result["checked"] == 5


def test_verify_chain_empty_log(app):
    """Test verify_chain returns ok with checked=0 on an empty audit log."""
    with app.app_context():
        result = verify_chain()
        assert result["ok"] is True
        assert result["checked"] == 0
        assert result["first_bad_id"] is None
        assert result["reason"] is None


def test_database_triggers_block_update_and_delete(app):
    """Test database-level triggers abort UPDATE and DELETE operations on audit_logs."""
    with app.app_context():
        log = log_event(action="IMMUTABLE_TEST", details="test data")
        log_id = log.id

        # UPDATE attempt must raise
        with pytest.raises(Exception) as exc_update:
            db.session.execute(
                text("UPDATE audit_logs SET action = 'TAMPERED' WHERE id = :id"),
                {"id": log_id},
            )
            db.session.commit()
        db.session.rollback()
        assert "audit log is immutable: updates are not allowed" in str(exc_update.value)

        # DELETE attempt must raise
        with pytest.raises(Exception) as exc_delete:
            db.session.execute(
                text("DELETE FROM audit_logs WHERE id = :id"),
                {"id": log_id},
            )
            db.session.commit()
        db.session.rollback()
        assert "audit log is immutable: deletes are not allowed" in str(exc_delete.value)


def test_tamper_detection_after_dropping_triggers(app):
    """Test verify_chain detects all forms of tampering after triggers are dropped."""
    with app.app_context():
        # Create 3 chained log entries
        e1 = log_event(action="LOG_1", details={"v": 1})
        e2 = log_event(action="LOG_2", details={"v": 2})
        e3 = log_event(action="LOG_3", details={"v": 3})

        assert verify_chain()["ok"] is True

        # Drop immutability triggers to simulate raw disk attacker
        db.session.execute(text("DROP TRIGGER IF EXISTS audit_logs_no_update"))
        db.session.execute(text("DROP TRIGGER IF EXISTS audit_logs_no_delete"))
        db.session.commit()

        # 1. Tamper details of row 2 -> entry_hash_mismatch at id 2
        orig_details = e2.details
        db.session.execute(
            text("UPDATE audit_logs SET details = :d WHERE id = 2"),
            {"d": '{"v":999}'},
        )
        db.session.commit()
        db.session.expire_all()

        res = verify_chain()
        assert res["ok"] is False
        assert res["first_bad_id"] == 2
        assert res["reason"] == "entry_hash_mismatch"

        # Restore details
        db.session.execute(
            text("UPDATE audit_logs SET details = :d WHERE id = 2"),
            {"d": orig_details},
        )
        db.session.commit()
        db.session.expire_all()
        assert verify_chain()["ok"] is True

        # 2. Tamper action of row 2 -> entry_hash_mismatch at id 2
        orig_action = e2.action
        db.session.execute(
            text("UPDATE audit_logs SET action = 'FORGED' WHERE id = 2")
        )
        db.session.commit()
        db.session.expire_all()

        res = verify_chain()
        assert res["ok"] is False
        assert res["first_bad_id"] == 2
        assert res["reason"] == "entry_hash_mismatch"

        # Restore action
        db.session.execute(
            text("UPDATE audit_logs SET action = :a WHERE id = 2"),
            {"a": orig_action},
        )
        db.session.commit()
        db.session.expire_all()
        assert verify_chain()["ok"] is True

        # 3. Tamper prev_hash of row 3 -> prev_hash_mismatch at id 3
        orig_prev = e3.prev_hash
        db.session.execute(
            text("UPDATE audit_logs SET prev_hash = :p WHERE id = 3"),
            {"p": "f" * 64},
        )
        db.session.commit()
        db.session.expire_all()

        res = verify_chain()
        assert res["ok"] is False
        assert res["first_bad_id"] == 3
        assert res["reason"] == "prev_hash_mismatch"

        # Restore prev_hash
        db.session.execute(
            text("UPDATE audit_logs SET prev_hash = :p WHERE id = 3"),
            {"p": orig_prev},
        )
        db.session.commit()
        db.session.expire_all()
        assert verify_chain()["ok"] is True

        # 4. Delete middle row (id 2) -> id_gap or prev_hash_mismatch
        db.session.execute(text("DELETE FROM audit_logs WHERE id = 2"))
        db.session.commit()
        db.session.expire_all()

        res = verify_chain()
        assert res["ok"] is False
        assert res["first_bad_id"] == 3
        assert res["reason"] in ("id_gap", "prev_hash_mismatch")


def test_chain_verifies_after_realistic_flow(client, app):
    """Test audit chain verifies after realistic workflow: register, login, upload, share, revoke."""
    password = "SecurePassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)

    payload = b"Top secret report content"
    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(payload), "report.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="report.pdf")
        ).scalar_one()

    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})
    client.post(f"/documents/{doc.id}/revoke/{bob.id}", follow_redirects=True)

    with app.app_context():
        res = verify_chain()
        assert res["ok"] is True
        # At least REGISTER (2), LOGIN (1), UPLOAD (1), SHARE (1), REVOKE (1)
        assert res["checked"] >= 6


def test_timestamps_survive_database_roundtrip(app):
    """Test that timestamps survive SQLite serialization and verify_chain passes after reload."""
    with app.app_context():
        for i in range(3):
            log_event(action=f"TS_TEST_{i}")

        # Evict everything from session cache to force reloading from SQLite
        db.session.expire_all()

        res = verify_chain()
        assert res["ok"] is True
        assert res["checked"] == 3


def test_no_key_material_in_audit_details(client, app):
    """Test that audit log details never contain encryption keys or passwords."""
    password = "SuperSecretPassword123!"
    alice = register_user(client, app, "alice", "alice@example.com", password)
    bob = register_user(client, app, "bob", "bob@example.com", password)

    login_user(client, "alice", password)

    client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"Private file"), "safe.pdf")},
        content_type="multipart/form-data",
    )

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="safe.pdf")
        ).scalar_one()

    client.post(f"/documents/{doc.id}/share", data={"recipients": "bob"})

    with app.app_context():
        logs = db.session.execute(db.select(AuditLog)).scalars().all()
        for log in logs:
            if log.details:
                # Key material keywords that must NEVER appear in details
                assert password not in log.details
                assert "PRIVATE KEY" not in log.details
                assert "doc_key" not in log.details
                assert "wrapped_key" not in log.details


def test_cli_verify_audit_command(runner, app):
    """Test 'flask verify-audit' CLI command output and exit codes."""
    # 1. Clean empty log
    result = runner.invoke(args=["verify-audit"])
    assert result.exit_code == 0
    assert "AUDIT LOG OK (0 entries verified)" in result.output

    # 2. Add legitimate entries
    with app.app_context():
        log_event(action="CLI_TEST_1")
        log_event(action="CLI_TEST_2")

    result = runner.invoke(args=["verify-audit"])
    assert result.exit_code == 0
    assert "AUDIT LOG OK (2 entries verified)" in result.output

    # 3. Tamper with database and verify failure
    with app.app_context():
        db.session.execute(text("DROP TRIGGER IF EXISTS audit_logs_no_update"))
        db.session.execute(
            text("UPDATE audit_logs SET action = 'CLI_TAMPERED' WHERE id = 1")
        )
        db.session.commit()

    result = runner.invoke(args=["verify-audit"])
    assert result.exit_code == 1
    assert "TAMPERING DETECTED at entry 1: entry_hash_mismatch" in result.output


def test_prev_hash_unique_constraint_prevents_fork(app):
    """Test that UNIQUE constraint on prev_hash prevents branching/forking the chain."""
    with app.app_context():
        log_event(action="ROOT")

        # Attempt to insert two rows with identical prev_hash
        fork1 = AuditLog(
            action="FORK_1",
            prev_hash="a" * 64,
            entry_hash="1" * 64,
        )
        fork2 = AuditLog(
            action="FORK_2",
            prev_hash="a" * 64,  # Duplicate prev_hash
            entry_hash="2" * 64,
        )
        db.session.add(fork1)
        db.session.commit()

        db.session.add(fork2)
        with pytest.raises(IntegrityError):
            db.session.commit()
        db.session.rollback()
