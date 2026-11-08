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

# Built-in blocklist of common insecure passwords
COMMON_PASSWORDS = {
    "password", "password123", "password1234", "123456789012", "1234567890123",
    "12345678901234", "qwertyuiop12", "qwertyuiopas", "administrator", "adminpassword",
    "welcome12345", "changeme1234", "letmein12345", "trustnoone12",
    "iloveyou1234", "monkey123456", "dragon123456", "master123456",
    "sunshine1234", "princess1234", "football1234", "baseball1234",
    "superman1234", "batman123456", "starwars1234", "correcthorse",
    "batteryhorse", "staplehorse1", "defaultpass1", "systemadmin1",
    "hunter2hunter2", "passphrase12", "security1234", "access123456",
    "secret123456", "database1234", "computer1234", "internet1234",
    "whatever1234", "login1234567", "testing12345", "testingpassword",
    "vaultshare12", "mysupersecret", "supersecret1", "supersecret12",
    "p@ssword1234", "p@ssw0rd1234", "passw0rd1234", "password12345",
    "111111111111", "000000000000", "abcdefghijkl", "zxcvbnmasdfg",
    "poiuytrewqqw", "qazwsxedcrfv", "1q2w3e4r5t6y", "vaultshare123",
    "changethispass", "dontuseinprod"
}


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
                max=128,
                message="Password must be at least 12 characters long and under 128 characters.",
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

    def validate_password(self, field):
        """Validate password strength, length, blocklist, and absence of user identifiers."""
        pwd = (field.data or "").strip()
        pwd_lower = pwd.lower()

        if pwd_lower in {p.lower() for p in COMMON_PASSWORDS}:
            raise ValidationError(
                "This password is too common. Please choose a more secure password."
            )

        if self.username.data:
            uname = self.username.data.strip().lower()
            if uname and uname in pwd_lower:
                raise ValidationError("Password must not contain your username.")

        if self.email.data:
            email = self.email.data.strip().lower()
            local_part = email.split("@")[0] if "@" in email else email
            if local_part and local_part in pwd_lower:
                raise ValidationError("Password must not contain your email address.")

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


class ShareDocumentForm(FlaskForm):
    """Form to grant document access to recipients."""

    recipients = StringField(
        "Recipients (usernames or emails, comma-separated)",
        validators=[
            DataRequired(message="Please enter at least one recipient.")
        ],
    )
    submit = SubmitField("Share Document")
