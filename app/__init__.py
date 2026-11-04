"""VaultShare application package.

Provides the Flask application factory, initializes extensions,
registers CLI commands, and registers component blueprints.
"""

import os
import sqlite3
import click
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import event
from sqlalchemy.engine import Engine

from config import config_by_name, Config

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

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(audit_bp)

    @app.errorhandler(429)
    def ratelimit_handler(e):
        from flask import flash, render_template
        from app.forms import LoginForm
        flash("Too many login attempts. Please try again in a minute.", "danger")
        return render_template("auth/login.html", form=LoginForm()), 429

    return app
