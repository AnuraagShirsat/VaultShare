"""Authentication routes and session handlers for VaultShare.

This module will hold:
- User registration, login, and logout endpoints.
- User keypair generation on signup and password-derived private key unlocking on login.
- Session management and authentication guards using Flask-Login.
"""

from flask import Blueprint

bp = Blueprint("auth", __name__, url_prefix="/auth")
auth_bp = bp
