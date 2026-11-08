"""Database models for VaultShare.

Defines SQLAlchemy ORM models:
- User: user credentials, RSA-3072 public key, encrypted private key, and scrypt/AES parameters.
- Document: metadata, storage paths, SHA-256 hashes, and encryption nonce.
- DocumentKey: wrapped document encryption key per recipient with access metrics.
- AuditLog: immutable, hash-chained log entries tracking all sensitive actions.
"""

from datetime import datetime, timezone
from typing import List, Optional
from flask_login import UserMixin
from sqlalchemy import (
    DDL,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    event,
    types,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from werkzeug.security import check_password_hash, generate_password_hash

from app import db


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class UTCDateTime(types.TypeDecorator):
    """DateTime type that guarantees timezone-aware UTC datetime values."""

    impl = types.DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None:
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)
        return value


class User(db.Model, UserMixin):
    """User account model storing authentication and cryptographic identity."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    email: Mapped[str] = mapped_column(
        String(120), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # RSA-3072 Keypair & Encryption Metadata
    public_key_pem: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_salt: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utc_now, nullable=False
    )

    # Relationships
    documents: Mapped[List["Document"]] = relationship(
        "Document",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    received_keys: Mapped[List["DocumentKey"]] = relationship(
        "DocumentKey",
        foreign_keys="[DocumentKey.recipient_id]",
        back_populates="recipient",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def set_password(self, password: str) -> None:
        """Hash and assign password using werkzeug.security."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        """Verify given plaintext password against stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f"<User id={self.id} username='{self.username}'>"


class Document(db.Model):
    """Uploaded document model storing file metadata and cryptographic hashes."""

    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_filename: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False
    )
    mime_type: Mapped[Optional[str]] = mapped_column(
        String(128), nullable=True, default="application/octet-stream"
    )
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)

    # AES-GCM file encryption nonce and integrity checksums
    nonce: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    plaintext_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ciphertext_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utc_now, nullable=False
    )

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="documents")
    keys: Mapped[List["DocumentKey"]] = relationship(
        "DocumentKey",
        back_populates="document",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<Document id={self.id} filename='{self.original_filename}'>"


class DocumentKey(db.Model):
    """Per-recipient wrapped encryption key and access log for a document."""

    __tablename__ = "document_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    document_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("documents.id", ondelete="CASCADE"), index=True, nullable=False
    )
    recipient_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    granted_by_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utc_now, nullable=False
    )
    decrypt_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_decrypted_at: Mapped[Optional[datetime]] = mapped_column(
        UTCDateTime, nullable=True
    )

    __table_args__ = (
        UniqueConstraint("document_id", "recipient_id", name="uq_document_recipient"),
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document", back_populates="keys")
    recipient: Mapped["User"] = relationship(
        "User", foreign_keys=[recipient_id], back_populates="received_keys"
    )
    granted_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[granted_by_id]
    )

    def __repr__(self) -> str:
        return (
            f"<DocumentKey id={self.id} doc_id={self.document_id} "
            f"recipient_id={self.recipient_id}>"
        )


class AuditLog(db.Model):
    """Tamper-evident, hash-chained log entry for security and data events."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        UTCDateTime, default=utc_now, nullable=False
    )
    actor_id: Mapped[Optional[int]] = mapped_column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_username: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)

    # Document ID is intentionally NOT a cascading foreign key so logs persist after document deletion
    document_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    target_user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    prev_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)

    actor: Mapped[Optional["User"]] = relationship("User", foreign_keys=[actor_id])

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} action='{self.action}' "
            f"actor='{self.actor_username}'>"
        )


# Immutability triggers on the audit_logs table to prevent UPDATE or DELETE
_audit_logs_no_update_ddl = DDL(
    """
    CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    BEGIN
        SELECT RAISE(ABORT, 'audit log is immutable: updates are not allowed');
    END;
    """
)

_audit_logs_no_delete_ddl = DDL(
    """
    CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    BEGIN
        SELECT RAISE(ABORT, 'audit log is immutable: deletes are not allowed');
    END;
    """
)

event.listen(AuditLog.__table__, "after_create", _audit_logs_no_update_ddl)
event.listen(AuditLog.__table__, "after_create", _audit_logs_no_delete_ddl)
