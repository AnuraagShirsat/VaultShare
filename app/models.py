"""Database models for VaultShare.

This module will hold SQLAlchemy ORM models:
- User: user credentials, RSA-3072 public key, and scrypt-encrypted private key.
- Document: metadata, storage paths, SHA-256 plaintext hash, and SHA-256 ciphertext hash.
- DocumentRecipient / SharedKey: per-recipient RSA-OAEP wrapped document keys.
- AuditLog: immutable, hash-chained log entries tracking all document and auth events.
"""

# Models will be implemented in subsequent steps.
