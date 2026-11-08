"""VaultShare application package.

Provides the Flask application factory, initializes extensions,
registers CLI commands, and registers component blueprints.
"""

import logging
from logging.handlers import RotatingFileHandler
import os
import re
import sqlite3
import click
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import event
from sqlalchemy.engine import Engine

from config import config_by_name, Config, ProductionConfig, ProductionConfigMeta

# Initialize extensions
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)

# Configure login manager defaults
login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"


class SensitiveDataFilter(logging.Filter):
    """Filter to redact passwords, tokens, keys, and secrets from log messages."""

    REDACT_PATTERN = re.compile(
        r'(?i)\b(password|passwd|secret|token|key|authorization|cookie)\b\s*([:=])\s*([^\s,;&"\']+)',
    )

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.REDACT_PATTERN.sub(r"\1\2[REDACTED]", record.msg)
        if record.args:
            try:
                formatted = record.getMessage()
                record.msg = self.REDACT_PATTERN.sub(r"\1\2[REDACTED]", formatted)
                record.args = ()
            except Exception:
                pass
        return True


@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Enable foreign key constraints for SQLite connections."""
    if isinstance(dbapi_connection, sqlite3.Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


@login_manager.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    from app.models import User

    try:
        return db.session.get(User, int(user_id))
    except (ValueError, TypeError):
        return None


def register_commands(app: Flask):
    """Register custom CLI commands with the Flask application."""

    @app.cli.command("init-db")
    def init_db_command():
        """Initialize the database and create all tables."""
        os.makedirs(app.instance_path, exist_ok=True)
        storage_dir = app.config.get("STORAGE_DIR")
        if storage_dir:
            os.makedirs(storage_dir, exist_ok=True)

        from app import models  # noqa: F401

        db.create_all()
        click.echo("Initialized the database.")

    @app.cli.command("verify-audit")
    def verify_audit_command():
        """Verify the cryptographic integrity of the audit log hash chain."""
        import sys
        from app.audit import verify_chain

        result = verify_chain()
        if result["ok"]:
            click.echo(f"AUDIT LOG OK ({result['checked']} entries verified)")
            sys.exit(0)
        else:
            bad_id = result.get("first_bad_id")
            reason = result.get("reason")
            click.echo(f"TAMPERING DETECTED at entry {bad_id}: {reason}")
            sys.exit(1)


def create_app(config_class=None, test_config=None):
    """Application factory for VaultShare.

    Args:
        config_class: Configuration object, class, or environment name string.
        test_config: Dictionary or object with test configuration overrides.

    Returns:
        Configured Flask application instance.
    """
    app = Flask(__name__, instance_relative_config=True)

    # Apply configuration
    if test_config is not None:
        if isinstance(test_config, dict):
            app.config.from_object(Config)
            app.config.from_mapping(test_config)
        else:
            app.config.from_object(test_config)
    elif config_class is not None:
        if isinstance(config_class, str):
            config_class = config_by_name.get(config_class, config_by_name["default"])
        if isinstance(config_class, dict):
            app.config.from_object(Config)
            app.config.from_mapping(config_class)
        else:
            app.config.from_object(config_class)
    else:
        env_config = os.environ.get("FLASK_CONFIG", "default")
        app.config.from_object(
            config_by_name.get(env_config, config_by_name["default"])
        )

    # Ensure instance and storage folders exist
    os.makedirs(app.instance_path, exist_ok=True)
    storage_dir = app.config.get("STORAGE_DIR")
    if storage_dir:
        os.makedirs(storage_dir, exist_ok=True)

    # Validate production configuration if active
    is_prod = (
        config_class is ProductionConfig
        or (isinstance(config_class, type) and issubclass(config_class, ProductionConfig))
        or config_class == "production"
        or os.environ.get("FLASK_CONFIG") == "production"
    )
    if is_prod:
        # Evaluates property and raises ValueError if invalid
        ProductionConfigMeta.SECRET_KEY.fget(ProductionConfig)

    # Configure rotating file logging
    logs_dir = os.path.join(app.instance_path, "logs")
    os.makedirs(logs_dir, exist_ok=True)
    log_file = os.path.join(logs_dir, "app.log")
    file_handler = RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] in %(module)s: %(message)s"
        )
    )
    file_handler.addFilter(SensitiveDataFilter())
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

    # Configure reverse proxy support if TRUSTED_PROXY_COUNT is set
    proxy_count = app.config.get("TRUSTED_PROXY_COUNT")
    if proxy_count:
        try:
            p_count = int(proxy_count)
            if p_count > 0:
                from werkzeug.middleware.proxy_fix import ProxyFix

                app.wsgi_app = ProxyFix(
                    app.wsgi_app,
                    x_for=p_count,
                    x_proto=p_count,
                    x_host=p_count,
                    x_prefix=p_count,
                )
        except ValueError:
            pass

    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register custom CLI commands
    register_commands(app)

    # Import models so db metadata is fully populated
    from app import models  # noqa: F401

    # Register blueprints
    from app.main import bp as main_bp
    from app.auth import bp as auth_bp
    from app.documents import bp as documents_bp
    from app.audit import bp as audit_bp
    from app.integrity import bp as integrity_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(integrity_bp)

    @app.after_request
    def set_security_headers(response):
        """Inject strict security headers on all responses."""
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' https://cdn.jsdelivr.net",
            "style-src 'self' https://cdn.jsdelivr.net",
            "font-src 'self' https://cdn.jsdelivr.net",
            "img-src 'self' data:",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self'",
            "frame-ancestors 'none'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # Strict-Transport-Security only when HTTPS / production
        is_https = (
            app.config.get("PREFERRED_URL_SCHEME") == "https"
            or app.config.get("SESSION_COOKIE_SECURE") is True
            or (not app.debug and not app.testing)
        )
        if is_https:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        # Cache-Control: no-store on all authenticated (non-static) responses
        endpoint = request.endpoint or ""
        if current_user.is_authenticated and not endpoint.startswith("static"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"

        return response

    # Error Handlers
    from app.auth import is_safe_url

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        flash("Your session expired, please try again.", "warning")
        ref = request.referrer
        if ref and is_safe_url(ref):
            return redirect(ref)
        return (
            render_template(
                "errors/400.html",
                error_title="Session Expired",
                error_message="Your session expired, please try again.",
            ),
            400,
        )

    @app.errorhandler(400)
    def bad_request(e):
        return render_template("errors/400.html"), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return render_template("errors/401.html"), 401

    @app.errorhandler(403)
    def forbidden(e):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return render_template("errors/405.html"), 405

    @app.errorhandler(413)
    def file_too_large(e):
        return render_template("errors/413.html"), 413

    @app.errorhandler(429)
    def too_many_requests(e):
        return render_template("errors/429.html"), 429

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("errors/500.html"), 500

    return app
