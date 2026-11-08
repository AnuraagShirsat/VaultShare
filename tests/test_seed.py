"""Tests for seed-demo and reset-db CLI commands."""

from pathlib import Path
import pytest
from sqlalchemy import func

from app import create_app, db
from app.audit import verify_chain
from app.models import AuditLog, Document, DocumentKey, User
from config import ProductionConfig


def test_seed_demo_empty_database(runner, app):
    """Test seed-demo on an empty database succeeds, chains correctly, and populates expected rows."""
    result = runner.invoke(args=["seed-demo"])
    assert result.exit_code == 0
    assert "AUDIT LOG OK" in result.output

    with app.app_context():
        # Assert user counts
        user_count = db.session.execute(db.select(func.count(User.id))).scalar_one()
        assert user_count == 3

        alice = db.session.execute(
            db.select(User).filter_by(username="alice")
        ).scalar_one()
        bob = db.session.execute(
            db.select(User).filter_by(username="bob")
        ).scalar_one()
        carol = db.session.execute(
            db.select(User).filter_by(username="carol")
        ).scalar_one()

        # Assert document count
        doc_count = db.session.execute(
            db.select(func.count(Document.id))
        ).scalar_one()
        assert doc_count == 3

        report_doc = db.session.execute(
            db.select(Document).filter_by(original_filename="Q3_Financial_Report.pdf")
        ).scalar_one()
        assert report_doc.owner_id == alice.id

        # Bob has decrypt_count == 2 on the report
        bob_report_key = db.session.execute(
            db.select(DocumentKey).filter_by(
                document_id=report_doc.id, recipient_id=bob.id
            )
        ).scalar_one()
        assert bob_report_key.decrypt_count == 2

        # Carol has no key row for the report (revoked)
        carol_report_key = db.session.execute(
            db.select(DocumentKey).filter_by(
                document_id=report_doc.id, recipient_id=carol.id
            )
        ).scalar_one_or_none()
        assert carol_report_key is None

        # Verify audit events
        access_denied_count = db.session.execute(
            db.select(func.count(AuditLog.id)).filter_by(action="ACCESS_DENIED")
        ).scalar_one()
        assert access_denied_count >= 1

        verify_count = db.session.execute(
            db.select(func.count(AuditLog.id)).filter_by(action="VERIFY")
        ).scalar_one()
        assert verify_count >= 1

        # Audit chain verification
        chain_res = verify_chain()
        assert chain_res["ok"] is True
        assert chain_res["checked"] >= 16


def test_seed_demo_refusal_and_reset_flag(runner, app):
    """Test seed-demo refuses when users exist without --reset, and succeeds with --reset."""
    # First seed
    res1 = runner.invoke(args=["seed-demo"])
    assert res1.exit_code == 0

    # Second seed without --reset refuses
    res2 = runner.invoke(args=["seed-demo"])
    assert res2.exit_code != 0
    assert "already contains users" in res2.output or "Use --reset" in res2.output

    # Third seed with --reset succeeds
    res3 = runner.invoke(args=["seed-demo", "--reset"])
    assert res3.exit_code == 0
    assert "AUDIT LOG OK" in res3.output

    with app.app_context():
        user_count = db.session.execute(db.select(func.count(User.id))).scalar_one()
        assert user_count == 3
        chain_res = verify_chain()
        assert chain_res["ok"] is True


def test_reset_db_requires_yes(runner, app):
    """Test reset-db refuses without --yes and succeeds with --yes."""
    res_no_yes = runner.invoke(args=["reset-db"])
    assert res_no_yes.exit_code != 0
    assert "--yes" in res_no_yes.output

    res_with_yes = runner.invoke(args=["reset-db", "--yes"])
    assert res_with_yes.exit_code == 0
    assert "Database reset complete" in res_with_yes.output


def test_commands_refuse_in_production(monkeypatch, tmp_path):
    """Test reset-db and seed-demo refuse to execute in production configuration."""
    monkeypatch.setenv(
        "SECRET_KEY", "a-very-secure-random-production-secret-key-12345"
    )

    class ProdTestConfig(ProductionConfig):
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{(tmp_path / 'prod.db').as_posix()}"
        STORAGE_DIR = str(tmp_path / "storage")

    prod_app = create_app(ProdTestConfig)
    prod_runner = prod_app.test_cli_runner()

    res_reset = prod_runner.invoke(args=["reset-db", "--yes"])
    assert res_reset.exit_code != 0
    assert "production" in res_reset.output.lower()

    res_seed = prod_runner.invoke(args=["seed-demo"])
    assert res_seed.exit_code != 0
    assert "production" in res_seed.output.lower()


def test_reset_db_removes_only_enc_files(runner, app):
    """Test reset-db removes only .enc files in STORAGE_DIR and preserves others."""
    storage_dir = Path(app.config["STORAGE_DIR"])
    storage_dir.mkdir(parents=True, exist_ok=True)

    enc_file = storage_dir / "test_document.enc"
    enc_file.write_bytes(b"encrypted ciphertext placeholder")

    text_file = storage_dir / "unrelated_document.txt"
    text_file.write_bytes(b"this file must survive reset-db")

    gitkeep = storage_dir / ".gitkeep"
    gitkeep.write_bytes(b"")

    res = runner.invoke(args=["reset-db", "--yes"])
    assert res.exit_code == 0

    assert not enc_file.exists()
    assert text_file.exists()
    assert gitkeep.exists()


def test_seeded_audit_rows_contain_no_key_material(runner, app):
    """Verify that seeded audit log entries contain no leaked key material."""
    res = runner.invoke(args=["seed-demo"])
    assert res.exit_code == 0

    with app.app_context():
        logs = (
            db.session.execute(db.select(AuditLog).order_by(AuditLog.id.asc()))
            .scalars()
            .all()
        )
        assert len(logs) >= 16

        for row in logs:
            row_str = f"{row.details} {row.action} {row.actor_username}"
            assert "BEGIN RSA PRIVATE KEY" not in row_str
            assert "BEGIN PRIVATE KEY" not in row_str
            assert "BEGIN PUBLIC KEY" not in row_str
            # No base64 RSA key blobs or hex private keys
            assert "encrypted_private_key" not in row_str
            assert "wrapped_key" not in row_str
