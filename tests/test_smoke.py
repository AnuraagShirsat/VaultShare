"""Smoke tests for VaultShare skeleton."""

import io

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import pytest

from app import db
from app.keycache import clear_cache
from app.models import User


# ---------------------------------------------------------------------------
# Fast RSA key-gen fixture (keeps test suite quick)
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fast_rsa_keygen(monkeypatch):
    """Speed up RSA keypair generation in smoke tests."""
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


# ---------------------------------------------------------------------------
# Existing smoke test
# ---------------------------------------------------------------------------

def test_home_page_returns_200(client):
    """Ensure that GET / returns HTTP 200 and contains VaultShare branding."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"VaultShare" in response.data
    assert b"A secure document distribution system" in response.data


# ---------------------------------------------------------------------------
# Get Started button routing tests
# ---------------------------------------------------------------------------

def test_get_started_anonymous_links_to_register(client, app):
    """Anonymous visitor: Get Started links to the registration URL."""
    with app.test_request_context():
        from flask import url_for
        register_url = url_for("auth.register")

    response = client.get("/")
    assert response.status_code == 200
    # The href must be the registration URL, not a bare "#"
    assert register_url.encode() in response.data


def test_get_started_anonymous_navigates_to_register(client):
    """Following the Get Started link as an anonymous user shows the registration form."""
    response = client.get("/auth/register")
    assert response.status_code == 200
    assert b"Register" in response.data
    # The registration form field must be present
    assert b"Username" in response.data or b"username" in response.data


def test_get_started_authenticated_links_to_dashboard(client, app):
    """Logged-in user: Get Started links to the dashboard URL, not the register URL."""
    password = "TestSmokePass2026!#"
    username = "smokeuser"

    # Register and log in
    client.post(
        "/auth/register",
        data={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=True,
    )
    client.post(
        "/auth/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )

    with app.test_request_context():
        from flask import url_for
        dashboard_url = url_for("main.dashboard")
        register_url = url_for("auth.register")

    response = client.get("/")
    assert response.status_code == 200

    html = response.data
    # Dashboard URL must be present in the Get Started button
    assert dashboard_url.encode() in html
    # Registration URL must NOT appear as the Get Started destination for authenticated users
    # (it may still appear in other nav links, so check the specific pattern)
    # The btn-primary button must point to dashboard, not register
    import re
    # Find all href values on elements with class btn-primary
    matches = re.findall(rb'href="([^"]+)"[^>]*class="[^"]*btn-primary[^"]*"', html)
    matches += re.findall(rb'class="[^"]*btn-primary[^"]*"[^>]*href="([^"]+)"', html)
    assert any(dashboard_url.encode() in m for m in matches), (
        f"No btn-primary link pointing to dashboard found. btn-primary hrefs: {matches}"
    )

