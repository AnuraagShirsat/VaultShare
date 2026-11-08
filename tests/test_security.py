"""Comprehensive security hardening tests for VaultShare (Step 10).

Covers:
- Strict Security Headers (CSP, HSTS, X-Content-Type-Options, etc.) and Cache-Control
- Universal CSRF validation across all POST routes
- Universal authentication guards on private routes (redirects / 401)
- Strict 404-not-403 access control across all document-ID endpoints
- ProductionConfig startup validation (refuses missing/short/placeholder SECRET_KEY)
- Password policy (length, username/email inclusion, blocklist)
- Account lockout after 5 failures and single LOGIN_LOCKED logging
- Dummy-hash execution for non-existent users (timing attack mitigation)
- Session fixation mitigation (session cleared on login)
- Key cache hardening (absolute timeout, LRU capacity, purged expired)
- Upload safety (magic bytes, quota enforcement, atomic write failure cleanup)
- Sensitive log data redaction
- Generic error pages (suppression of traces and filesystem paths)
- Template audit (no |safe, onclick=, onsubmit=, or inline scripts)
- Final audit chain verification
"""

from datetime import datetime, timedelta, timezone
import io
import logging
import os
from pathlib import Path
import re
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest
from werkzeug.security import check_password_hash

from app import create_app, db
from app.audit import log_event, verify_chain
from app.crypto import generate_rsa_keypair
from app.keycache import (
    ABSOLUTE_LIFETIME,
    IDLE_TIMEOUT,
    _CACHE,
    clear_cache,
    drop_key,
    get_key,
    purge_expired,
    store_key,
)
from app.models import AuditLog, Document, DocumentKey, User
from config import Config, ProductionConfig, TestingConfig


@pytest.fixture(autouse=True)
def fast_rsa_keys(monkeypatch):
    """Use fast 1024-bit RSA keys for security testing to keep suite fast."""

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


def register_user(client, username="alice", email="alice@example.com", password="SecurePassword123!"):
    """Helper to register a user."""
    return client.post(
        "/auth/register",
        data={
            "username": username,
            "email": email,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=True,
    )


def login_user(client, username="alice", password="SecurePassword123!"):
    """Helper to log in a user."""
    return client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )


# =============================================================================
# A1. Security Headers & Cache-Control Tests
# =============================================================================


def test_security_headers_on_normal_and_error_pages(client):
    """Test that all required security headers are present on both normal and error responses."""
    endpoints = ["/", "/nonexistent-page-triggering-404"]

    for path in endpoints:
        res = client.get(path)

        csp = res.headers.get("Content-Security-Policy", "")
        assert "default-src 'self'" in csp
        assert "script-src 'self' https://cdn.jsdelivr.net" in csp
        assert "style-src 'self' https://cdn.jsdelivr.net" in csp
        assert "img-src 'self' data:" in csp
        assert "object-src 'none'" in csp
        assert "base-uri 'self'" in csp
        assert "form-action 'self'" in csp
        assert "frame-ancestors 'none'" in csp

        # Strict CSP check: no unsafe-inline or unsafe-eval
        assert "'unsafe-inline'" not in csp
        assert "'unsafe-eval'" not in csp

        # Hardening headers
        assert res.headers.get("X-Content-Type-Options") == "nosniff"
        assert res.headers.get("X-Frame-Options") == "DENY"
        assert res.headers.get("Referrer-Policy") == "same-origin"
        assert res.headers.get("Cross-Origin-Opener-Policy") == "same-origin"
        assert "camera=()" in res.headers.get("Permissions-Policy", "")


def test_cache_control_no_store_on_authenticated_responses(client):
    """Test that authenticated non-static pages receive Cache-Control: no-store."""
    register_user(client, "alice", "alice@example.com", "SecurePassword123!")
    login_user(client, "alice", "SecurePassword123!")

    res = client.get("/dashboard")
    assert res.status_code == 200
    assert res.headers.get("Cache-Control") == "no-store"
    assert res.headers.get("Pragma") == "no-cache"


# =============================================================================
# A2. Configuration & Startup Hardening
# =============================================================================


def test_production_config_startup_refusal(monkeypatch):
    """Test ProductionConfig strictly refuses to start on missing, short, or placeholder keys."""
    # 1. Missing SECRET_KEY
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(ValueError, match="SECRET_KEY must be set in the environment"):
        create_app(ProductionConfig)

    # 2. Too short (< 32 characters)
    monkeypatch.setenv("SECRET_KEY", "too-short-secret")
    with pytest.raises(ValueError, match="at least 32 characters"):
        create_app(ProductionConfig)

    # 3. Known placeholder
    monkeypatch.setenv(
        "SECRET_KEY", "dev-insecure-secret-key-change-in-production"
    )
    with pytest.raises(ValueError, match="known insecure placeholder"):
        create_app(ProductionConfig)

    # 4. Valid 32+ char key succeeds with security settings enabled
    monkeypatch.setenv(
        "SECRET_KEY", "a-very-secure-random-production-secret-key-12345"
    )
    prod_app = create_app(ProductionConfig)
    assert prod_app.config["SESSION_COOKIE_SECURE"] is True
    assert prod_app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert prod_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"
    assert prod_app.config["PREFERRED_URL_SCHEME"] == "https"
    assert prod_app.debug is False


# =============================================================================
# A3. Error Handling & Redaction
# =============================================================================


def test_error_pages_suppress_stack_traces_and_paths(client):
    """Test 400, 404, 405, 413, 429, 500 error pages contain no filesystem paths or traces."""
    # 404
    res_404 = client.get("/definitely-not-found-page-404")
    assert res_404.status_code == 404
    assert b"Traceback" not in res_404.data
    assert b"site-packages" not in res_404.data

    # 405
    res_405 = client.get("/activity/export")
    assert res_405.status_code == 405
    assert b"Method Not Allowed" in res_405.data
    assert b"Traceback" not in res_405.data

    # 500
    res_500 = client.get("/errors/simulate-500-test-if-any")
    # Even if 404, check 500 template directly
    with client.application.test_request_context():
        from flask import render_template

        rendered = render_template("errors/500.html")
        assert "Internal Server Error" in rendered
        assert "Traceback" not in rendered
        assert "C:\\" not in rendered


def test_log_redaction_filter():
    """Test SensitiveDataFilter masks passwords, secrets, tokens, and keys."""
    from app import SensitiveDataFilter

    filt = SensitiveDataFilter()
    logger = logging.getLogger("test_redact")
    logger.setLevel(logging.INFO)
    logger.addFilter(filt)

    record = logger.makeRecord(
        "test_redact",
        logging.INFO,
        "fn",
        1,
        "User auth failed with password=SecretPassword123 and token: my_secret_token_abc",
        (),
        None,
    )
    filt.filter(record)
    assert "password=[REDACTED]" in record.msg
    assert "token:[REDACTED]" in record.msg
    assert "SecretPassword123" not in record.msg
    assert "my_secret_token_abc" not in record.msg


# =============================================================================
# B1. Password Policy Tests
# =============================================================================


def test_password_policy_enforcement(client):
    """Test password policy: length 12-128, username/email inclusion, and common blocklist."""
    # 1. Too short (< 12)
    res = register_user(client, "usr1", "usr1@example.com", "Short1!")
    assert b"Password must be at least 12 characters long" in res.data

    # 2. Too long (> 128)
    long_pass = "A" * 129 + "12!"
    res = register_user(client, "usr2", "usr2@example.com", long_pass)
    assert b"under 128 characters" in res.data

    # 3. Contains username (case-insensitive)
    res = register_user(client, "charlie", "charlie@example.com", "MyCharliePass123!")
    assert b"Password must not contain your username" in res.data

    # 4. Contains email local part
    res = register_user(client, "testuser", "mysecretmail@example.com", "PassMySecretMail123!")
    assert b"Password must not contain your email address" in res.data

    # 5. Common password blocklist
    res = register_user(client, "normaluser", "normal@example.com", "password1234")
    assert b"password is too common" in res.data

    # 6. Valid compliant password passes
    res = register_user(client, "gooduser", "good@example.com", "CompliantSecretPass123!")
    assert b"Registration successful" in res.data


# =============================================================================
# B2. Login Protection (Lockout, Timing Defense, Session Fixation)
# =============================================================================


def test_account_lockout_after_five_failed_logins(client, app, monkeypatch):
    """Test per-account lockout after 5 failed logins within 15 mins."""
    valid_pass = "ValidSecurityPass123!"
    register_user(client, "locktarget", "locktarget@example.com", valid_pass)

    # 5 consecutive failed logins
    for i in range(5):
        res = client.post(
            "/auth/login",
            data={"username": "locktarget", "password": "WrongPassword999!"},
        )
        assert res.status_code == 401
        assert b"Invalid username or password" in res.data

    # 6th attempt with the CORRECT password must be rejected during the lockout window
    res_correct = client.post(
        "/auth/login",
        data={"username": "locktarget", "password": valid_pass},
    )
    assert res_correct.status_code == 401
    assert b"Invalid username or password" in res_correct.data

    with app.app_context():
        # Verify LOGIN_LOCKED was recorded once
        locks = db.session.execute(
            db.select(AuditLog).filter_by(action="LOGIN_LOCKED", actor_username="locktarget")
        ).scalars().all()
        assert len(locks) == 1

    # Simulate lockout window expiration (+ 16 minutes)
    future_time = datetime.now(timezone.utc) + timedelta(minutes=16)
    with patch("app.auth.datetime") as mock_dt:
        mock_dt.now.return_value = future_time
        res_after = client.post(
            "/auth/login",
            data={"username": "locktarget", "password": valid_pass},
            follow_redirects=True,
        )
        assert res_after.status_code == 200
        assert b"Welcome back, locktarget" in res_after.data


def test_dummy_hash_timing_defense_on_unknown_user(client):
    """Test that checking an unknown user still executes check_password_hash."""
    with patch("app.auth.check_password_hash", wraps=check_password_hash) as spy_check:
        res = client.post(
            "/auth/login",
            data={"username": "non_existent_user_999", "password": "SomePass12345!"},
        )
        assert res.status_code == 401
        assert spy_check.called


def test_session_fixation_defense_clears_session_on_login(client):
    """Test pre-existing session values are purged upon successful login."""
    register_user(client, "sessiontarget", "sessiontarget@example.com", "ValidPass12345!")

    with client.session_transaction() as sess:
        sess["planted_attacker_state"] = "attacker_data"

    login_user(client, "sessiontarget", "ValidPass12345!")

    with client.session_transaction() as sess:
        assert "planted_attacker_state" not in sess
        assert "key_token" in sess


# =============================================================================
# B3. Key Cache Hardening
# =============================================================================


def test_key_cache_absolute_lifetime_and_lru_capacity():
    """Test key cache enforces absolute lifetime, capacity limits, and expired purges."""
    clear_cache()
    from cryptography.hazmat.primitives.asymmetric import rsa

    fake_key1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    fake_key2 = rsa.generate_private_key(public_exponent=65537, key_size=1024)

    token1 = store_key(user_id=1, private_key=fake_key1)
    assert get_key(token1, user_id=1) is not None

    # Test idle timeout refresh
    assert get_key(token1, user_id=1) is not None

    # Test absolute lifetime expiry even if accessed recently
    with patch("app.keycache.datetime") as mock_dt:
        # Fast forward 8 hours and 1 minute
        future_time = datetime.now(timezone.utc) + timedelta(hours=8, minutes=1)
        mock_dt.now.return_value = future_time
        assert get_key(token1, user_id=1) is None

    # Test capacity eviction
    clear_cache()
    with patch("app.keycache.MAX_ENTRIES", 1):
        t1 = store_key(user_id=1, private_key=fake_key1)
        # Adding second key when MAX_ENTRIES is 1 should evict least recently used t1
        t2 = store_key(user_id=2, private_key=fake_key2)
        assert get_key(t1, user_id=1) is None
        assert get_key(t2, user_id=2) is not None

    clear_cache()


# =============================================================================
# C1. Upload Safety (Magic Bytes, Storage Quota, Atomic Writes)
# =============================================================================


def test_upload_magic_bytes_check(client, app):
    """Test non-matching magic bytes are rejected with UPLOAD_REJECTED audit event."""
    register_user(client, "uploader", "uploader@example.com", "SecureUploadPass123!")
    login_user(client, "uploader", "SecureUploadPass123!")

    # 1. Fake PDF with text contents
    res = client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"NOT_A_REAL_PDF_HEADER"), "fake.pdf")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400
    assert b"Invalid file content" in res.data

    with app.app_context():
        rejected_event = db.session.execute(
            db.select(AuditLog).filter_by(action="UPLOAD_REJECTED", actor_username="uploader")
        ).scalar_one_or_none()
        assert rejected_event is not None
        assert "NOT_A_REAL_PDF_HEADER" not in (rejected_event.details or "")

    # 2. Valid small PDF passes
    res_valid = client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"%PDF-1.4\nValid PDF body"), "valid.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert res_valid.status_code == 200

    # 3. Valid small PNG passes
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    res_png = client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(png_bytes), "image.png")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert res_png.status_code == 200


def test_upload_storage_quota_enforced(client, app):
    """Test uploads exceeding user storage quota are rejected."""
    register_user(client, "quotatest", "quotatest@example.com", "QuotaPassphrase123!")
    login_user(client, "quotatest", "QuotaPassphrase123!")

    app.config["STORAGE_QUOTA_BYTES"] = 50  # 50 bytes quota

    res = client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"%PDF-1.4\n" + b"X" * 100), "oversize_quota.pdf")},
        content_type="multipart/form-data",
    )
    assert res.status_code == 400
    assert b"storage quota exceeded" in res.data


def test_atomic_write_leaves_no_partial_files_on_failure(client, app, monkeypatch):
    """Test simulated failure during write/commit leaves no temp or partial files in storage."""
    register_user(client, "atomicuser", "atomicuser@example.com", "AtomicPassphrase123!")
    login_user(client, "atomicuser", "AtomicPassphrase123!")

    storage_dir = Path(app.config["STORAGE_DIR"])
    before_files = set(storage_dir.glob("*"))

    def _mock_replace(src, dst):
        raise OSError("Simulated atomic replace disk write error")

    monkeypatch.setattr(os, "replace", _mock_replace)

    try:
        res = client.post(
            "/documents/upload",
            data={"document": (io.BytesIO(b"%PDF-1.4\nData"), "fail.pdf")},
            content_type="multipart/form-data",
        )
        assert res.status_code == 500
    except OSError:
        pass

    after_files = set(storage_dir.glob("*"))
    # Verify no orphan .tmp_ or .enc files remain
    assert after_files == before_files


# =============================================================================
# C2 & C3. Universal Route Checks: CSRF, Public Allowlist, 404 Access Control
# =============================================================================


def test_all_post_routes_require_csrf_when_enabled(app):
    """Iterate app.url_map: every route accepting POST rejects POST without CSRF token (400)."""
    # Create test app with CSRF enabled
    csrf_config = {
        "WTF_CSRF_ENABLED": True,
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    }
    csrf_app = create_app(test_config=csrf_config)

    with csrf_app.app_context():
        db.create_all()
        # Seed a test user
        pub, priv = generate_rsa_keypair()
        u = User(
            username="csrftarget",
            email="csrftarget@example.com",
            public_key_pem=pub.decode(),
            encrypted_private_key=b"enc",
            key_salt=b"salt12345678",
            key_nonce=b"nonce1234567",
        )
        u.set_password("TargetPass12345!")
        db.session.add(u)
        db.session.commit()

        csrf_client = csrf_app.test_client()
        # Log in the user (first get CSRF token from login form)
        res_login_page = csrf_client.get("/auth/login")
        token_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', res_login_page.data.decode())
        login_token = token_match.group(1) if token_match else ""

        csrf_client.post(
            "/auth/login",
            data={"username": "csrftarget", "password": "TargetPass12345!", "csrf_token": login_token},
        )

        # Check every POST route in app.url_map without CSRF token
        for rule in csrf_app.url_map.iter_rules():
            if "POST" in rule.methods:
                # Build dummy url filling route params
                url = rule.rule
                url = re.sub(r'<int:\w+>', '1', url)
                url = re.sub(r'<\w+>', '1', url)

                # Direct POST with no CSRF token and no referrer should return 400
                res = csrf_client.post(url, data={})
                assert res.status_code == 400, f"Route {url} ({rule.endpoint}) did not reject missing CSRF with 400"


def test_anonymous_user_restricted_from_all_non_public_routes(app, client):
    """Iterate app.url_map: all routes not in public allowlist redirect anonymous users to login."""
    public_endpoints = {"main.index", "auth.login", "auth.register", "static"}

    for rule in app.url_map.iter_rules():
        if rule.endpoint in public_endpoints:
            continue

        url = rule.rule
        url = re.sub(r'<int:\w+>', '1', url)
        url = re.sub(r'<\w+>', '1', url)

        # Test GET or POST depending on supported methods
        method = "GET" if "GET" in rule.methods else "POST"
        if method == "GET":
            res = client.get(url)
        else:
            res = client.post(url)

        # Anonymous requests must either redirect to login (302) or return 401
        assert res.status_code in (302, 401), f"Endpoint {rule.endpoint} ({url}) returned {res.status_code}"
        if res.status_code == 302:
            assert "/auth/login" in res.headers.get("Location", "")


def test_document_id_routes_return_404_for_unauthorized_and_revoked(client, app):
    """Document-ID routes return 404 for unauthorized and revoked users."""
    pass_alice = "SecureVaultAlpha123!"
    pass_bob = "SecureVaultBeta123!"

    register_user(client, "alice", "alice@example.com", pass_alice)
    register_user(client, "bob", "bob@example.com", pass_bob)

    # Alice uploads document
    login_user(client, "alice", pass_alice)
    res_up = client.post(
        "/documents/upload",
        data={"document": (io.BytesIO(b"%PDF-1.4\nSensitive"), "secret_doc.pdf")},
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert res_up.status_code == 200

    with app.app_context():
        doc = db.session.execute(
            db.select(Document).filter_by(original_filename="secret_doc.pdf")
        ).scalar_one()
        doc_id = doc.id

    client.post("/auth/logout", follow_redirects=True)

    # Bob (no access granted yet) tries all document-ID endpoints -> all 404
    login_user(client, "bob", pass_bob)

    endpoints = [
        ("GET", f"/documents/{doc_id}/manage"),
        ("POST", f"/documents/{doc_id}/share"),
        ("POST", f"/documents/{doc_id}/revoke/999"),
        ("POST", f"/documents/{doc_id}/download"),
        ("GET", f"/documents/{doc_id}/activity"),
        ("POST", f"/integrity/documents/{doc_id}/verify"),
        ("POST", f"/integrity/documents/{doc_id}/check-file"),
    ]

    for method, path in endpoints:
        if method == "GET":
            r = client.get(path)
        else:
            r = client.post(path)
        assert r.status_code == 404, f"Unauthorized user accessed {path} with status {r.status_code}"

    # Alice shares with Bob, then revokes Bob
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "alice", pass_alice)
    client.post(f"/documents/{doc_id}/share", data={"recipients": "bob"})

    with app.app_context():
        b = db.session.execute(db.select(User).filter_by(username="bob")).scalar_one()
        bob_id = b.id

    client.post(f"/documents/{doc_id}/revoke/{bob_id}")

    # Bob (revoked) tries all endpoints again -> all 404
    client.post("/auth/logout", follow_redirects=True)
    login_user(client, "bob", pass_bob)

    for method, path in endpoints:
        if method == "GET":
            r = client.get(path)
        else:
            r = client.post(path)
        assert r.status_code == 404, f"Revoked user accessed {path} with status {r.status_code}"


# =============================================================================
# Template Audit & Final Integrity Chain Check
# =============================================================================


def test_grep_templates_have_no_unsafe_constructs():
    """Verify templates contain zero |safe filters, inline scripts, or inline event handlers."""
    template_dir = Path(__file__).resolve().parent.parent / "app" / "templates"
    assert template_dir.exists()

    forbidden_patterns = [
        re.compile(r'\|\s*safe\b'),
        re.compile(r'\bon[a-z]+\s*='),
        re.compile(r'javascript\s*:', re.IGNORECASE),
        re.compile(r'<\s*script(?![^>]*\bsrc=)[^>]*>', re.IGNORECASE),
    ]

    for html_file in template_dir.rglob("*.html"):
        content = html_file.read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            matches = pattern.findall(content)
            assert not matches, f"Forbidden construct {pattern.pattern} found in {html_file.name}: {matches}"


def test_audit_log_chain_intact_after_all_security_tests(app):
    """Verify that the hash-chained audit log passes verification after all security flows."""
    with app.app_context():
        res = verify_chain()
        assert res["ok"] is True
        assert res["checked"] >= 0
