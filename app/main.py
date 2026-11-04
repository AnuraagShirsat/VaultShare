"""Main application blueprint for general routes (landing, home)."""

from flask import Blueprint, render_template

bp = Blueprint("main", __name__)
main_bp = bp


@bp.route("/")
def index():
    """Render the home page."""
    return render_template("index.html")
