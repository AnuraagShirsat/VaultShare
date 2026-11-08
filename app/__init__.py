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


def is_production_config(app: Flask) -> bool:
    """Determine whether the application is running in a production configuration."""
    if app.config.get("IS_PRODUCTION") is True:
        return True
    if os.environ.get("FLASK_CONFIG") == "production":
        return True
    return False


def perform_reset_db(app: Flask) -> int:
    """Drop all tables, delete only *.enc files in STORAGE_DIR, and recreate tables.

    Returns:
        int: Number of .enc files removed from STORAGE_DIR.
    """
    from pathlib import Path

    db.session.remove()
    db.drop_all()

    storage_dir = Path(app.config.get("STORAGE_DIR", "storage"))
    deleted_enc_count = 0
    if storage_dir.exists():
        for enc_file in storage_dir.glob("*.enc"):
            if enc_file.is_file():
                try:
                    enc_file.unlink()
                    deleted_enc_count += 1
                except OSError:
                    pass

    os.makedirs(app.instance_path, exist_ok=True)
    if storage_dir:
        os.makedirs(storage_dir, exist_ok=True)

    from app import models  # noqa: F401

    db.create_all()
    return deleted_enc_count


DEFAULT_DEMO_PASSWORD = "DemoVaultPass2026!#"


def seed_demo_data(app: Flask, demo_password: Optional[str] = None) -> dict:
    """Seed the database with standard demo accounts, documents, shares, and activity.

    Uses real service and security paths to construct a valid cryptographic audit chain.

    Args:
        app: Flask application instance.
        demo_password: Optional override for the demo password.

    Returns:
        dict: Seeding summary with created users, documents, and verify_chain result.
    """
    import sys
    from werkzeug.exceptions import HTTPException
    from flask_login import login_user

    from app.access import require_recipient
    from app.audit import log_event, verify_chain
    from app.crypto import (
        encrypt_private_key,
        generate_rsa_keypair,
    )
    from app.documents import (
        decrypt_document_for_user,
        revoke_document_access,
        share_document,
        store_encrypted_document,
    )
    from app.forms import COMMON_PASSWORDS
    from app.integrity import verify_document
    from app.models import User

    pwd = (
        demo_password
        or os.environ.get("DEMO_PASSWORD")
        or DEFAULT_DEMO_PASSWORD
    ).strip()

    # Password policy validation
    if len(pwd) < 12 or len(pwd) > 128:
        raise ValueError("Demo password must be between 12 and 128 characters.")
    if pwd.lower() in {p.lower() for p in COMMON_PASSWORDS}:
        raise ValueError("Demo password cannot be a common insecure password.")
    for uname in ("alice", "bob", "carol"):
        if uname in pwd.lower():
            raise ValueError(
                f"Demo password must not contain username '{uname}'."
            )

    # 1. Create three users: alice, bob, carol
    user_specs = [
        ("alice", "alice@example.com"),
        ("bob", "bob@example.com"),
        ("carol", "carol@example.com"),
    ]

    users = {}
    priv_keys = {}

    for username, email in user_specs:
        pub_pem, priv_key = generate_rsa_keypair()
        priv_keys[username] = priv_key
        enc_blob, salt, nonce = encrypt_private_key(priv_key, pwd)

        user = User(
            username=username,
            email=email,
            public_key_pem=pub_pem.decode("utf-8"),
            encrypted_private_key=enc_blob,
            key_salt=salt,
            key_nonce=nonce,
        )
        user.set_password(pwd)
        db.session.add(user)
        db.session.commit()

        log_event(
            action="REGISTER",
            actor=user,
            details={"username": user.username, "email": user.email},
        )
        users[username] = user

    # 2. Upload documents
    # alice uploads Q3_Financial_Report.pdf (minimal valid PDF) and Board_Minutes.txt
    pdf_content = (
        b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
        b"xref\n0 4\n0000000000 65535 f \n0000000010 00000 n \n0000000060 00000 n \n"
        b"0000000117 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF\n"
    )
    doc_report = store_encrypted_document(
        owner=users["alice"],
        filename="Q3_Financial_Report.pdf",
        data=pdf_content,
        mime_type="application/pdf",
    )

    minutes_content = (
        b"VaultShare Board of Directors Meeting Minutes\n"
        b"Confidential - Internal Use Only\n"
        b"Date: 2026-10-15\n"
        b"Status: Approved\n"
    )
    doc_minutes = store_encrypted_document(
        owner=users["alice"],
        filename="Board_Minutes.txt",
        data=minutes_content,
        mime_type="text/plain",
    )

    # bob uploads Project_Roadmap.txt
    roadmap_content = (
        b"VaultShare Engineering Roadmap\n"
        b"Q4 2026 Objectives:\n"
        b"1. Server-side key cache hardening\n"
        b"2. External audit chain anchoring\n"
    )
    doc_roadmap = store_encrypted_document(
        owner=users["bob"],
        filename="Project_Roadmap.txt",
        data=roadmap_content,
        mime_type="text/plain",
    )

    # 3. Share documents
    # alice shares Q3_Financial_Report.pdf with bob and carol
    share_document(
        owner=users["alice"],
        doc=doc_report,
        recipient_identifiers=["bob", "carol"],
        owner_private_key=priv_keys["alice"],
    )

    # alice shares Board_Minutes.txt with bob only
    share_document(
        owner=users["alice"],
        doc=doc_minutes,
        recipient_identifiers=["bob"],
        owner_private_key=priv_keys["alice"],
    )

    # bob shares Project_Roadmap.txt with alice
    share_document(
        owner=users["bob"],
        doc=doc_roadmap,
        recipient_identifiers=["alice"],
        owner_private_key=priv_keys["bob"],
    )

    # 4. Decryptions
    # bob decrypts Q3_Financial_Report.pdf twice
    decrypt_document_for_user(
        user=users["bob"], doc=doc_report, private_key=priv_keys["bob"]
    )
    decrypt_document_for_user(
        user=users["bob"], doc=doc_report, private_key=priv_keys["bob"]
    )

    # carol decrypts Q3_Financial_Report.pdf once
    decrypt_document_for_user(
        user=users["carol"], doc=doc_report, private_key=priv_keys["carol"]
    )

    # alice decrypts Project_Roadmap.txt once
    decrypt_document_for_user(
        user=users["alice"], doc=doc_roadmap, private_key=priv_keys["alice"]
    )

    # 5. Revocation & denied attempt
    # alice revokes carol's access to Q3_Financial_Report.pdf
    revoke_document_access(
        owner=users["alice"],
        doc=doc_report,
        target_user_id=users["carol"].id,
    )

    # carol attempts to download it (denied, producing an ACCESS_DENIED event)
    with app.test_request_context():
        login_user(users["carol"])
        try:
            require_recipient(doc_report, action="DOWNLOAD")
        except HTTPException:
            pass

    # 6. Integrity verification run on Q3_Financial_Report.pdf by alice
    verify_document(
        user=users["alice"], doc=doc_report, private_key=priv_keys["alice"]
    )

    # Clear private keys from memory
    del priv_keys

    # Verify audit chain
    chain_result = verify_chain()

    return {
        "users": users,
        "documents": [doc_report, doc_minutes, doc_roadmap],
        "demo_password": pwd,
        "chain_result": chain_result,
    }


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

    @app.cli.command("reset-db")
    @click.option("--yes", is_flag=True, help="Confirm database reset.")
    def reset_db_command(yes: bool):
        """Drop all tables, delete only *.enc files, and recreate tables."""
        import sys

        if is_production_config(app):
            click.echo(
                "Error: Refusing to reset database in production configuration.",
                err=True,
            )
            sys.exit(1)

        if not yes:
            click.echo(
                "Error: Refusing to reset database without --yes confirmation.",
                err=True,
            )
            sys.exit(1)

        deleted = perform_reset_db(app)
        click.echo(
            f"Database reset complete: dropped tables, removed {deleted} .enc "
            f"files, and recreated tables with immutability triggers."
        )

    @app.cli.command("seed-demo")
    @click.option(
        "--reset",
        is_flag=True,
        help="Reset database before seeding demo data.",
    )
    def seed_demo_command(reset: bool):
        """Seed demo users, documents, sharing permissions, and audit history."""
        import sys
        from sqlalchemy import func
        from app.models import User

        if is_production_config(app):
            click.echo(
                "Error: Refusing to seed demo data in production configuration.",
                err=True,
            )
            sys.exit(1)

        if reset:
            deleted = perform_reset_db(app)
            click.echo(
                f"Reset database before seeding (removed {deleted} .enc files)."
            )
        else:
            existing_count = db.session.execute(
                db.select(func.count(User.id))
            ).scalar_one()
            if existing_count > 0:
                click.echo(
                    "Error: Database already contains users. Use --reset to "
                    "re-initialize before seeding.",
                    err=True,
                )
                sys.exit(1)

        click.echo("Seeding demo data through genuine cryptographic service paths...")
        summary = seed_demo_data(app)

        click.echo("\n" + "=" * 70)
        click.echo("VaultShare Demo Data Seeding Complete")
        click.echo("=" * 70)

        click.echo("\nDemo Users (all use the same policy-compliant demo password):")
        click.echo(f"  Demo Password : {summary['demo_password']}\n")
        click.echo(f"  {'Username':<12} {'Email':<24} {'Status':<10}")
        click.echo(f"  {'-'*10:<12} {'-'*22:<24} {'-'*8:<10}")
        for uname, u in summary["users"].items():
            click.echo(f"  {uname:<12} {u.email:<24} {'Active':<10}")

        click.echo("\nDocuments & Access Distribution:")
        for doc in summary["documents"]:
            click.echo(f"  - Document: {doc.original_filename} (Owner: {doc.owner.username}, Size: {doc.size_bytes} B)")
            for key in doc.keys:
                click.echo(
                    f"      * Recipient: {key.recipient.username:<10} | "
                    f"Decrypt Count: {key.decrypt_count:<3} | "
                    f"Granted By: {key.granted_by.username if key.granted_by else 'N/A'}"
                )

        chain = summary["chain_result"]
        click.echo("\nAudit Log Cryptographic Verification:")
        if chain["ok"]:
            click.echo(f"  AUDIT LOG OK ({chain['checked']} entries verified)")
        else:
            click.echo(f"  TAMPERING DETECTED at entry {chain.get('first_bad_id')}: {chain.get('reason')}")
            sys.exit(1)

        click.echo("=" * 70 + "\n")

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
    app.config["IS_PRODUCTION"] = is_prod
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
