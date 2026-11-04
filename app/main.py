"""Main application blueprint for general routes (landing, home, dashboard)."""

from flask import Blueprint, render_template
from flask_login import login_required

bp = Blueprint("main", __name__)
main_bp = bp


@bp.route("/")
def index():
    """Render the home page."""
    return render_template("index.html")


@bp.route("/dashboard")
@login_required
def dashboard():
    """Render the authenticated user dashboard."""
    return render_template("dashboard.html")
