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

    # Rate limiting
    RATELIMIT_DEFAULT = os.environ.get(
        "RATELIMIT_DEFAULT", "200 per day;50 per hour"
    )
    RATELIMIT_STORAGE_URI = "memory://"


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


class ProductionConfig(Config):
    """Production environment configuration."""

    DEBUG = False
    TESTING = False
    SECRET_KEY = os.environ.get("SECRET_KEY")


config_by_name = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}
