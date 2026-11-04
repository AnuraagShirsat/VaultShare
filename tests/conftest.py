"""Pytest fixtures for VaultShare testing."""

import tempfile
import pytest

from app import create_app, db
from config import TestingConfig


@pytest.fixture
def app():
    """Create and configure a new Flask app instance for testing."""
    with tempfile.TemporaryDirectory() as temp_storage:
        # Override storage directory with temporary directory
        class TestConfig(TestingConfig):
            STORAGE_DIR = temp_storage
            SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
            WTF_CSRF_ENABLED = False
            TESTING = True

        test_app = create_app(TestConfig)

        with test_app.app_context():
            db.create_all()
            yield test_app
            db.session.remove()
            db.drop_all()


@pytest.fixture
def client(app):
    """Test client for VaultShare."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Test CLI runner for VaultShare."""
    return app.test_cli_runner()
