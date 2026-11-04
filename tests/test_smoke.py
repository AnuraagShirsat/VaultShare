"""Smoke tests for VaultShare skeleton."""


def test_home_page_returns_200(client):
    """Ensure that GET / returns HTTP 200 and contains VaultShare branding."""
    response = client.get("/")
    assert response.status_code == 200
    assert b"VaultShare" in response.data
    assert b"A secure document distribution system" in response.data
