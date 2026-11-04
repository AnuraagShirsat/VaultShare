"""VaultShare application package.

Provides the Flask application factory, initializes extensions,
and registers component blueprints.
"""

import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

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


@login_manager.user_loader
def load_user(user_id):
    """User loader placeholder (implemented when User model is added)."""
    return None


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
        app.config.from_object(config_by_name.get(env_config, config_by_name["default"]))

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

    # Register blueprints
    from app.main import bp as main_bp
    from app.auth import bp as auth_bp
    from app.documents import bp as documents_bp
    from app.audit import bp as audit_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(documents_bp)
    app.register_blueprint(audit_bp)

    return app
