"""Audit log routes and tamper-evident history handlers for VaultShare.

This module will hold:
- Viewing immutable audit log entries across the application.
- Per-document and per-user activity history.
- Verification endpoint triggering hash-chain integrity verification.
"""

from flask import Blueprint

bp = Blueprint("audit", __name__, url_prefix="/audit")
audit_bp = bp
