"""Tests for VaultShare authentication and keypair generation."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from app import db
from app.crypto import DecryptionError, decrypt_private_key
from app.keycache import clear_cache, drop_key, get_key
from app.models import AuditLog, User


@pytest.fixture(autouse=True)
def fast_rsa_keygen(monkeypatch):
    """Speed up RSA key generation during auth tests using a 1024-bit test key."""

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


def test_register_success_stores_encrypted_keypair(client, app):
    """Test successful user registration, keypair generation, and audit logging."""
    response = client.post(
        "/auth/register",
        data={
            "username": "alice",
            "email": "alice@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Registration successful" in response.data

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(username="alice")
        ).scalar_one_or_none()
        assert user is not None
        assert user.email == "alice@example.com"
        assert "BEGIN PUBLIC KEY" in user.public_key_pem

        # Crucial security check: private key is encrypted, never plaintext
        assert b"BEGIN PRIVATE KEY" not in user.encrypted_private_key
        assert b"BEGIN RSA PRIVATE KEY" not in user.encrypted_private_key
        assert len(user.key_salt) == 16
        assert len(user.key_nonce) == 12

        # Check audit log entry
        audit = db.session.execute(
            db.select(AuditLog).filter_by(
                action="REGISTER", actor_username="alice"
            )
        ).scalar_one_or_none()
        assert audit is not None
        assert "alice" in audit.details


def test_register_duplicate_username_and_email_rejected(client):
    """Test that duplicate username or email is rejected with a user-friendly error."""
    # First registration
    client.post(
        "/auth/register",
        data={
            "username": "duplicate_user",
            "email": "duplicate@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
        },
    )

    # Attempt duplicate username
    res_dup_username = client.post(
        "/auth/register",
        data={
            "username": "duplicate_user",
            "email": "other@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
        },
    )
    assert res_dup_username.status_code == 200
    assert b"That username is already taken" in res_dup_username.data

    # Attempt duplicate email (case-insensitive)
    res_dup_email = client.post(
        "/auth/register",
        data={
            "username": "different_user",
            "email": "DUPLICATE@example.com",
            "password": "SecurePassword123!",
            "confirm_password": "SecurePassword123!",
        },
    )
    assert res_dup_email.status_code == 200
    assert (
        b"An account with that email already exists" in res_dup_email.data
    )


def test_register_weak_password_rejected(client, app):
    """Test that passwords shorter than 12 characters are rejected."""
    response = client.post(
        "/auth/register",
        data={
            "username": "weak_pass_user",
            "email": "weak@example.com",
            "password": "short",
            "confirm_password": "short",
        },
    )
    assert response.status_code == 200
    assert (
        b"Password must be at least 12 characters long" in response.data
    )

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(username="weak_pass_user")
        ).scalar_one_or_none()
        assert user is None


def test_login_success_and_key_cached(client, app):
    """Test login success, key unlocking in cache, and session establishment."""
    # Register user
    client.post(
        "/auth/register",
        data={
            "username": "bob",
            "email": "bob@example.com",
            "password": "SecretBetaPassword123!",
            "confirm_password": "SecretBetaPassword123!",
        },
    )

    # Log in
    response = client.post(
        "/auth/login",
        data={
            "username": "bob",
            "password": "SecretBetaPassword123!",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b"Welcome, bob" in response.data or b"Welcome back, bob" in response.data

    with client.session_transaction() as sess:
        token = sess.get("key_token")
        assert token is not None

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(username="bob")
        ).scalar_one()
        cached_key = get_key(token, user.id)
        assert cached_key is not None

        # Verify audit log recorded LOGIN
        audit = db.session.execute(
            db.select(AuditLog).filter_by(action="LOGIN", actor_username="bob")
        ).scalar_one_or_none()
        assert audit is not None


def test_login_failure_generic_error(client, app):
    """Test that wrong password and nonexistent user produce the same generic error."""
    # Register user
    client.post(
        "/auth/register",
        data={
            "username": "charlie",
            "email": "charlie@example.com",
            "password": "SecretGammaPass123!",
            "confirm_password": "SecretGammaPass123!",
        },
    )

    generic_msg = b"Invalid username or password"

    # Wrong password for existing user
    res_wrong_pw = client.post(
        "/auth/login",
        data={
            "username": "charlie",
            "password": "IncorrectPassword999!",
        },
    )
    assert res_wrong_pw.status_code == 401
    assert generic_msg in res_wrong_pw.data

    # Unknown user
    res_unknown_user = client.post(
        "/auth/login",
        data={
            "username": "nobody_exists",
            "password": "SomePassword123!",
        },
    )
    assert res_unknown_user.status_code == 401
    assert generic_msg in res_unknown_user.data

    # Confirm LOGIN_FAILED events logged
    with app.app_context():
        failed_logs = (
            db.session.execute(
                db.select(AuditLog).filter_by(action="LOGIN_FAILED")
            )
            .scalars()
            .all()
        )
        assert len(failed_logs) >= 2


def test_dashboard_requires_login(client):
    """Test that accessing /dashboard anonymously redirects to login."""
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/auth/login" in response.headers["Location"]


def test_logout_clears_session_and_drops_cached_key(client, app):
    """Test that logout removes key from cache and terminates the session."""
    client.post(
        "/auth/register",
        data={
            "username": "dave",
            "email": "dave@example.com",
            "password": "SecretDeltaPass123!",
            "confirm_password": "SecretDeltaPass123!",
        },
    )
    client.post(
        "/auth/login",
        data={"username": "dave", "password": "SecretDeltaPass123!"},
    )

    with client.session_transaction() as sess:
        token = sess.get("key_token")

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(username="dave")
        ).scalar_one()
        assert get_key(token, user.id) is not None

    # Log out via POST
    res_logout = client.post("/auth/logout", follow_redirects=True)
    assert res_logout.status_code == 200
    assert b"You have been logged out" in res_logout.data

    # Ensure key was dropped from server cache
    with app.app_context():
        assert get_key(token, user.id) is None

        # Verify LOGOUT audit entry
        logout_audit = db.session.execute(
            db.select(AuditLog).filter_by(
                action="LOGOUT", actor_username="dave"
            )
        ).scalar_one_or_none()
        assert logout_audit is not None


def test_open_redirect_ignored(client):
    """Test that open redirect attempts via ?next= are sanitized."""
    client.post(
        "/auth/register",
        data={
            "username": "eve",
            "email": "eve@example.com",
            "password": "SecretEpsilonPass123!",
            "confirm_password": "SecretEpsilonPass123!",
        },
    )

    # Attempt redirect to external site
    res = client.post(
        "/auth/login?next=https://evil.com",
        data={"username": "eve", "password": "SecretEpsilonPass123!"},
    )
    assert res.status_code == 302
    assert res.headers["Location"].endswith("/dashboard")


def test_stored_private_key_decryptable_with_right_password_only(client, app):
    """Test that the stored encrypted private key can only be decrypted with correct password."""
    password = "CorrectUserPass123!"
    client.post(
        "/auth/register",
        data={
            "username": "frank",
            "email": "frank@example.com",
            "password": password,
            "confirm_password": password,
        },
    )

    with app.app_context():
        user = db.session.execute(
            db.select(User).filter_by(username="frank")
        ).scalar_one()

        # Decrypt with correct password -> succeeds
        priv_key = decrypt_private_key(
            user.encrypted_private_key,
            user.key_salt,
            user.key_nonce,
            password,
        )
        assert priv_key is not None

        # Decrypt with wrong password -> raises DecryptionError
        with pytest.raises(DecryptionError):
            decrypt_private_key(
                user.encrypted_private_key,
                user.key_salt,
                user.key_nonce,
                "WrongPassword999!",
            )


def test_expired_cached_key_forces_relogin(client, app):
    """Test that if the cached key expires or disappears, user is prompted to relogin."""
    client.post(
        "/auth/register",
        data={
            "username": "grace",
            "email": "grace@example.com",
            "password": "SecretZetaPass123!",
            "confirm_password": "SecretZetaPass123!",
        },
    )
    client.post(
        "/auth/login",
        data={"username": "grace", "password": "SecretZetaPass123!"},
    )

    # Simulate key cache eviction / restart
    with client.session_transaction() as sess:
        token = sess.get("key_token")
    drop_key(token)

    # Request dashboard with missing key in cache
    res = client.get("/dashboard", follow_redirects=True)
    assert res.status_code == 200
    assert b"Your session has expired" in res.data
    assert b"Log In" in res.data
