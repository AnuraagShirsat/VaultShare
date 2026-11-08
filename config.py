"""Configuration settings for VaultShare application."""

from datetime import timedelta
import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Automatically load environment variables from .env file if present
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base configuration."""

    # Security key for session signing and CSRF protection
    SECRET_KEY = os.environ.get(
        "SECRET_KEY", "dev-insecure-secret-key-change-in-production"
    )

    # Session security settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SESSION_COOKIE_SECURE = (
        os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1")
    )
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"

    # Database configuration (default to SQLite in instance/ directory)
    DATABASE_URI = os.environ.get(
        "DATABASE_URI"
    ) or f"sqlite:///{(BASE_DIR / 'instance' / 'vaultshare.db').as_posix()}"
    SQLALCHEMY_DATABASE_URI = DATABASE_URI
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Document storage directory and upload size limit (default: 16 MB)
    STORAGE_DIR = os.environ.get("STORAGE_DIR", str(BASE_DIR / "storage"))
    MAX_CONTENT_LENGTH = int(
        os.environ.get("MAX_CONTENT_LENGTH", 16 * 1024 * 1024)
    )
    STORAGE_QUOTA_BYTES = int(
        os.environ.get("STORAGE_QUOTA_BYTES", 100 * 1024 * 1024)
    )
    ALLOWED_EXTENSIONS = set(
        ext.strip().lower()
        for ext in os.environ.get(
            "ALLOWED_EXTENSIONS",
            "pdf,txt,docx,xlsx,pptx,png,jpg,jpeg,csv,md,zip",
        ).split(",")
        if ext.strip()
    )

    # Rate limiting
    RATELIMIT_DEFAULT = os.environ.get(
        "RATELIMIT_DEFAULT", "200 per day;50 per hour"
    )
    RATELIMIT_STORAGE_URI = "memory://"

    # Reverse proxy support
    TRUSTED_PROXY_COUNT = os.environ.get("TRUSTED_PROXY_COUNT")


class DevelopmentConfig(Config):
    """Development environment configuration."""

    DEBUG = True


class TestingConfig(Config):
    """Testing environment configuration."""

    TESTING = True
    DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    RATELIMIT_ENABLED = False


class ProductionConfigMeta(type):
    """Metaclass for ProductionConfig to enforce SECRET_KEY validation on attribute access."""

    KNOWN_PLACEHOLDERS = {
        "dev-insecure-secret-key-change-in-production",
        "change-me",
        "changeme",
        "secret",
        "secret-key",
        "your-secret-key-here",
        "default",
    }

    @property
    def SECRET_KEY(cls) -> str:
        """Enforce strict production SECRET_KEY rules from environment variables."""
        key = os.environ.get("SECRET_KEY", "").strip()
        if not key:
            raise ValueError(
                "SECRET_KEY must be set in the environment for production."
            )
        if len(key) < 32:
            raise ValueError(
                "Production SECRET_KEY must be at least 32 characters long."
            )
        if key.lower() in cls.KNOWN_PLACEHOLDERS:
            raise ValueError(
                "Production SECRET_KEY cannot be a known insecure placeholder."
            )
        return key


class ProductionConfig(Config, metaclass=ProductionConfigMeta):
    """Production environment configuration."""

    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PREFERRED_URL_SCHEME = "https"


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
