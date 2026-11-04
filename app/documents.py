"""Document management routes and handlers for VaultShare.

This module will hold:
- Document upload, random AES key generation, and AES-256-GCM encryption.
- Multi-recipient sharing and RSA-OAEP key wrapping.
- Document dashboard and metadata viewing.
- Decryption tracking and secure download endpoints.
- Access revocation by deleting recipient wrapped keys.
"""

from flask import Blueprint

bp = Blueprint("documents", __name__, url_prefix="/documents")
documents_bp = bp
