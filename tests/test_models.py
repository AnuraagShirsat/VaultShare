"""Tests for VaultShare database models."""

import json
import pytest
from sqlalchemy.exc import IntegrityError

from app import db, login_manager
from app.models import AuditLog, Document, DocumentKey, User


def test_create_user(app):
    """Test user creation, password hashing, and login integration."""
    with app.app_context():
        user = User(
            username="alice",
            email="alice@example.com",
            public_key_pem="-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----",
            encrypted_private_key=b"\x00\x01\x02testprivkey",
            key_salt=b"randomsalt16bytes",
            key_nonce=b"randomnonce12byte",
        )
        user.set_password("SecretPassword123!")
        db.session.add(user)
        db.session.commit()

        assert user.id is not None
        assert user.username == "alice"
        assert user.email == "alice@example.com"
        assert user.check_password("SecretPassword123!") is True
        assert user.check_password("WrongPassword") is False
        assert user.password_hash != "SecretPassword123!"
        assert user.created_at is not None
        assert user.created_at.tzinfo is not None  # Timezone-aware UTC
        assert user.is_authenticated is True
        assert user.get_id() == str(user.id)

        # Test Flask-Login user_loader
        loaded_user = login_manager.user_callback(str(user.id))
        assert loaded_user is not None
        assert loaded_user.id == user.id


def test_create_document(app):
    """Test document creation and relationship with owner."""
    with app.app_context():
        owner = User(
            username="bob",
            email="bob@example.com",
            public_key_pem="fake-pub-key-bob",
            encrypted_private_key=b"enc-priv-bob",
            key_salt=b"salt-bob-123456",
            key_nonce=b"nonce-bob-1234",
        )
        owner.set_password("BobPassword123!")
        db.session.add(owner)
        db.session.commit()

        doc = Document(
            owner_id=owner.id,
            original_filename="confidential.pdf",
            stored_filename="a1b2c3d4-stored.enc",
            mime_type="application/pdf",
            size_bytes=1048576,
            nonce=b"filenonce12bytes",
            plaintext_sha256=(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            ),
            ciphertext_sha256=(
                "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
            ),
        )
        db.session.add(doc)
        db.session.commit()

        assert doc.id is not None
        assert doc.owner.username == "bob"
        assert doc.created_at.tzinfo is not None
        assert doc in owner.documents


def test_create_document_key(app):
    """Test DocumentKey creation, tracking fields, and recipient relationships."""
    with app.app_context():
        owner = User(
            username="charlie",
            email="charlie@example.com",
            public_key_pem="fake-pub-charlie",
            encrypted_private_key=b"enc-priv-charlie",
            key_salt=b"salt-charlie-123",
            key_nonce=b"nonce-charlie-12",
        )
        owner.set_password("CharliePass123!")

        recipient = User(
            username="dave",
            email="dave@example.com",
            public_key_pem="fake-pub-dave",
            encrypted_private_key=b"enc-priv-dave",
            key_salt=b"salt-dave-123456",
            key_nonce=b"nonce-dave-12345",
        )
        recipient.set_password("DavePass123!")

        db.session.add_all([owner, recipient])
        db.session.commit()

        doc = Document(
            owner_id=owner.id,
            original_filename="secret.docx",
            stored_filename="random-uuid-secret.enc",
            mime_type=(
                "application/vnd.openxmlformats-officedocument"
                ".wordprocessingml.document"
            ),
            size_bytes=2048,
            nonce=b"12bytenonce!",
        )
        db.session.add(doc)
        db.session.commit()

        doc_key = DocumentKey(
            document_id=doc.id,
            recipient_id=recipient.id,
            wrapped_key=b"rsa-wrapped-aes-key-bytes",
            granted_by_id=owner.id,
        )
        db.session.add(doc_key)
        db.session.commit()

        assert doc_key.id is not None
        assert doc_key.decrypt_count == 0
        assert doc_key.last_decrypted_at is None
        assert doc_key.granted_at.tzinfo is not None
        assert doc_key.document == doc
        assert doc_key.recipient == recipient
        assert doc_key.granted_by == owner
        assert doc_key in doc.keys
        assert doc_key in recipient.received_keys


def test_unique_constraint_document_recipient(app):
    """Verify that a recipient cannot have duplicate key entries for the same document."""
    with app.app_context():
        user1 = User(
            username="user1",
            email="user1@example.com",
            public_key_pem="pub1",
            encrypted_private_key=b"priv1",
            key_salt=b"salt111111111111",
            key_nonce=b"nonce1111111",
        )
        user1.set_password("pass1")
        db.session.add(user1)
        db.session.commit()

        doc = Document(
            owner_id=user1.id,
            original_filename="doc1.txt",
            stored_filename="stored1.enc",
            size_bytes=100,
        )
        db.session.add(doc)
        db.session.commit()

        key1 = DocumentKey(
            document_id=doc.id,
            recipient_id=user1.id,
            wrapped_key=b"wrapped-key-1",
        )
        db.session.add(key1)
        db.session.commit()

        # Attempt to add duplicate (document_id, recipient_id)
        duplicate_key = DocumentKey(
            document_id=doc.id,
            recipient_id=user1.id,
            wrapped_key=b"duplicate-wrapped-key",
        )
        db.session.add(duplicate_key)

        with pytest.raises(IntegrityError):
            db.session.commit()

        db.session.rollback()


def test_create_audit_log(app):
    """Test AuditLog row creation and verify logs survive document deletion."""
    with app.app_context():
        actor = User(
            username="auditor",
            email="auditor@example.com",
            public_key_pem="pub-auditor",
            encrypted_private_key=b"priv-auditor",
            key_salt=b"salt-auditor-123",
            key_nonce=b"nonce-auditor-12",
        )
        actor.set_password("AuditorPass123!")
        db.session.add(actor)
        db.session.commit()

        doc = Document(
            owner_id=actor.id,
            original_filename="audit_target.txt",
            stored_filename="stored_audit.enc",
            size_bytes=500,
        )
        db.session.add(doc)
        db.session.commit()
        doc_id = doc.id

        details_json = json.dumps({"reason": "compliance check", "result": "success"})
        log = AuditLog(
            actor_id=actor.id,
            actor_username=actor.username,
            action="VERIFY",
            document_id=doc_id,
            target_user_id=None,
            details=details_json,
            ip_address="192.168.1.100",
            prev_hash="0000000000000000000000000000000000000000000000000000000000000000",
            entry_hash="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        )
        db.session.add(log)
        db.session.commit()

        assert log.id is not None
        assert log.timestamp.tzinfo is not None
        assert log.actor == actor
        assert log.actor_username == "auditor"
        assert log.action == "VERIFY"
        assert log.document_id == doc_id
        assert json.loads(log.details)["reason"] == "compliance check"

        # Delete the document and confirm the audit log row survives
        db.session.delete(doc)
        db.session.commit()

        surviving_log = db.session.get(AuditLog, log.id)
        assert surviving_log is not None
        assert surviving_log.document_id == doc_id
        assert surviving_log.actor_username == "auditor"
