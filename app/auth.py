"""Authentication routes and session handlers for VaultShare.

Handles user registration, login, logout, password-protected RSA keypair
generation, unlocked key caching, and audit logging.

NOTE ON PASSWORD RECOVERY:
A forgotten password cannot be recovered because the user's RSA private key is
encrypted with a key derived from their password (via scrypt). Password reset
is intentionally omitted to maintain the zero-knowledge security guarantee.
"""

from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import func
from werkzeug.security import check_password_hash, generate_password_hash

from app import db, limiter
from app.audit import log_event
from app.crypto import (
    DecryptionError,
    decrypt_private_key,
    encrypt_private_key,
    generate_rsa_keypair,
)
from app.forms import LoginForm, RegistrationForm
from app.keycache import drop_key, get_key, store_key
from app.models import AuditLog, User

bp = Blueprint("auth", __name__, url_prefix="/auth")
auth_bp = bp

# Precomputed dummy password hash for timing attack mitigation
DUMMY_PASSWORD_HASH = generate_password_hash("dummy-vaultshare-timing-defense-password")
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW = timedelta(minutes=15)


def is_safe_url(target: str) -> bool:
    """Ensure the redirect target is on the same host and uses HTTP(S)."""
    if not target:
        return False
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (
        test_url.scheme in ("http", "https")
        and ref_url.netloc == test_url.netloc
    )


@bp.before_app_request
def verify_unlocked_key_session():
    """Ensure authenticated users retain an active unlocked private key in the cache.

    If the cache entry is missing or expired (e.g. 30-minute idle timeout or
    server restart), log out the user and prompt them to re-authenticate.
    """
    if current_user.is_authenticated:
        endpoint = request.endpoint or ""
        # Exempt static assets, login, and logout from the key cache requirement
        if (
            endpoint.startswith("static")
            or endpoint in ("auth.logout", "auth.login")
        ):
            return None

        token = session.get("key_token")
        priv_key = get_key(token, current_user.id)
        if priv_key is None:
            drop_key(token)
            logout_user()
            session.clear()
            flash(
                "Your session has expired. Please log in again to unlock your vault.",
                "warning",
            )
            return redirect(url_for("auth.login", next=request.path))


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit(
    "5 per hour",
    error_message="Too many registration attempts. Please try again later.",
)
def register():
    """Register a new user account with generated RSA-3072 keypair."""
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        email = form.email.data.strip().lower()
        password = form.password.data

        # 1. Generate RSA-3072 keypair for the user
        public_pem, private_key = generate_rsa_keypair()

        # 2. Encrypt the private key with a key derived from user's password
        encrypted_blob, salt, nonce = encrypt_private_key(private_key, password)

        # 3. Create User record (plaintext private key is NEVER saved)
        user = User(
            username=username,
            email=email,
            public_key_pem=public_pem.decode("utf-8"),
            encrypted_private_key=encrypted_blob,
            key_salt=salt,
            key_nonce=nonce,
        )
        user.set_password(password)

        db.session.add(user)
        db.session.commit()

        # 4. Record audit event
        log_event(
            action="REGISTER",
            actor=user,
            details={"username": user.username, "email": user.email},
        )

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(
    "5 per minute",
    error_message="Too many login attempts. Please try again in a minute.",
)
def login():
    """Authenticate user, unlock private key into cache, and establish session."""
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data.strip()
        password = form.password.data

        user = db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one_or_none()

        generic_error = "Invalid username or password."

        # User enumeration timing defense: simulate password check on non-existent account
        if user is None:
            check_password_hash(DUMMY_PASSWORD_HASH, password)
            log_event(
                action="LOGIN_FAILED",
                actor=None,
                details={"attempted_username": username},
            )
            flash(generic_error, "danger")
            return render_template("auth/login.html", form=form), 401

        # Per-account lockout check via audit logs
        now = datetime.now(timezone.utc)
        window_start = (now - LOCKOUT_WINDOW).replace(tzinfo=None)

        failed_attempts = db.session.execute(
            db.select(func.count(AuditLog.id)).filter(
                AuditLog.action == "LOGIN_FAILED",
                AuditLog.actor_id == user.id,
                AuditLog.timestamp >= window_start,
            )
        ).scalar_one()

        if failed_attempts >= LOCKOUT_THRESHOLD:
            # Record LOGIN_LOCKED only once per lockout window
            lock_logged = db.session.execute(
                db.select(func.count(AuditLog.id)).filter(
                    AuditLog.action == "LOGIN_LOCKED",
                    AuditLog.actor_id == user.id,
                    AuditLog.timestamp >= window_start,
                )
            ).scalar_one()
            if lock_logged == 0:
                log_event(
                    action="LOGIN_LOCKED",
                    actor=user,
                    details={
                        "attempted_username": username,
                        "reason": "lockout_threshold_exceeded",
                    },
                )
            flash(generic_error, "danger")
            return render_template("auth/login.html", form=form), 401

        # Verify password against hash
        if not user.check_password(password):
            log_event(
                action="LOGIN_FAILED",
                actor=user,
                details={"attempted_username": username},
            )
            flash(generic_error, "danger")
            return render_template("auth/login.html", form=form), 401

        # Attempt to decrypt private key with submitted password
        try:
            private_key = decrypt_private_key(
                user.encrypted_private_key,
                user.key_salt,
                user.key_nonce,
                password,
            )
        except DecryptionError:
            log_event(
                action="LOGIN_FAILED",
                actor=user,
                details={
                    "attempted_username": username,
                    "reason": "key_decrypt_failed",
                },
            )
            flash(generic_error, "danger")
            return render_template("auth/login.html", form=form), 401

        # Clear existing session data before setting new auth session (session fixation defense)
        session.clear()

        # Cache unlocked private key on the server
        token = store_key(user.id, private_key)
        session["key_token"] = token
        session.permanent = True

        login_user(user)
        log_event(action="LOGIN", actor=user)

        flash(f"Welcome back, {user.username}!", "success")

        next_page = request.args.get("next")
        if not next_page or not is_safe_url(next_page):
            next_page = url_for("main.dashboard")
        return redirect(next_page)

    return render_template("auth/login.html", form=form)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    """Discard unlocked private key from cache, end user session, and log event."""
    token = session.get("key_token")
    if token:
        drop_key(token)

    # Capture user object for audit logging prior to session destruction
    actor = current_user._get_current_object()
    log_event(action="LOGOUT", actor=actor)

    logout_user()
    session.clear()

    flash("You have been logged out.", "info")
    return redirect(url_for("main.index"))
