"""Flask-WTF forms for VaultShare authentication and operations."""

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import (
    DataRequired,
    EqualTo,
    Length,
    Regexp,
    ValidationError,
)

from app import db
from app.models import User


class RegistrationForm(FlaskForm):
    """User registration form with username, email, and password validation."""

    username = StringField(
        "Username",
        validators=[
            DataRequired(message="Username is required."),
            Length(
                min=3,
                max=32,
                message="Username must be between 3 and 32 characters.",
            ),
            Regexp(
                r"^[a-zA-Z0-9_]+$",
                message="Username may only contain letters, numbers, and underscores.",
            ),
        ],
    )
    email = StringField(
        "Email",
        validators=[
            DataRequired(message="Email address is required."),
            Length(max=120, message="Email must be under 120 characters."),
            Regexp(
                r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
                message="Please provide a valid email address.",
            ),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[
            DataRequired(message="Password is required."),
            Length(
                min=12,
                message="Password must be at least 12 characters long for security.",
            ),
        ],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(message="Please confirm your password."),
            EqualTo("password", message="Passwords must match."),
        ],
    )
    submit = SubmitField("Register")

    def validate_username(self, field):
        """Ensure username is unique."""
        user = db.session.execute(
            db.select(User).filter_by(username=field.data)
        ).scalar_one_or_none()
        if user is not None:
            raise ValidationError(
                "That username is already taken. Please choose another."
            )

    def validate_email(self, field):
        """Ensure email is unique (compared case-insensitively)."""
        normalized_email = field.data.strip().lower() if field.data else ""
        user = db.session.execute(
            db.select(User).filter_by(email=normalized_email)
        ).scalar_one_or_none()
        if user is not None:
            raise ValidationError(
                "An account with that email already exists. Please log in."
            )


class LoginForm(FlaskForm):
    """User login form."""

    username = StringField(
        "Username",
        validators=[DataRequired(message="Username is required.")],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required.")],
    )
    submit = SubmitField("Log In")


class DocumentUploadForm(FlaskForm):
    """Document upload form."""

    document = FileField(
        "Choose File",
        validators=[DataRequired(message="Please select a file to upload.")],
    )
    submit = SubmitField("Upload and Encrypt")
