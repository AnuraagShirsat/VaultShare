"""Audit log routes module for VaultShare.

This module exposes the audit blueprint for audit log views and verification.
"""

from app.audit import audit_bp, bp

__all__ = ["bp", "audit_bp"]
