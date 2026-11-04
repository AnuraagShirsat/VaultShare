"""Document management routes and handlers for VaultShare.

Handles document upload, AES-256-GCM encryption at rest, owner key wrapping,
and document listing.
"""

from pathlib import Path
import secrets
from typing import Optional
from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app import db
from app.audit import log_event
from app.crypto import (
    encrypt_bytes,
    generate_document_key,
    sha256_hex,
    wrap_key,
)
from app.forms import DocumentUploadForm
from app.models import Document, DocumentKey, User

bp = Blueprint("documents", __name__, url_prefix="/documents")
documents_bp = bp


def human_readable_size(size_bytes: int) -> str:
    """Convert integer byte size to human-readable string (e.g. 1.5 MB)."""
    size = float(size_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024.0 or unit == "GB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size_bytes} B"


@bp.app_template_filter("filesize")
def filesize_filter(size_bytes: int) -> str:
    """Jinja filter to display human-readable file sizes."""
    return human_readable_size(size_bytes)


def is_allowed_extension(filename: str) -> bool:
    """Validate if file extension is present and permitted in configuration."""
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    allowed = current_app.config.get("ALLOWED_EXTENSIONS", set())
    return ext in allowed


def store_encrypted_document(
    owner: User,
    filename: str,
    data: bytes,
    mime_type: Optional[str] = None,
) -> Document:
    """Encrypt and write a document to disk and persist its metadata in the database.

    Args:
        owner: User instance who owns the document.
        filename: Original filename submitted by user.
        data: Plaintext file contents as bytes.
        mime_type: Optional MIME content type.

    Returns:
        Document: The created and committed Document model instance.

    Raises:
        ValueError: If file data is empty or path traversal is detected.
    """
    if not data:
        raise ValueError("Cannot encrypt and store an empty file.")

    # 1. Sanitize original filename for display only
    display_filename = secure_filename(filename) or "unnamed_document"

    # 2. Compute plaintext SHA-256 hash
    plaintext_sha256 = sha256_hex(data)

    # 3. Generate a fresh 256-bit symmetric document key
    doc_key = generate_document_key()

    # 4. Encrypt plaintext using AES-256-GCM
    nonce, ciphertext = encrypt_bytes(doc_key, data)

    # 5. Compute ciphertext SHA-256 hash
    ciphertext_sha256 = sha256_hex(ciphertext)

    # 6. Store ciphertext under a random filename (never user-controlled)
    storage_dir = Path(current_app.config["STORAGE_DIR"]).resolve()
    storage_dir.mkdir(parents=True, exist_ok=True)

    stored_filename = f"{secrets.token_hex(16)}.enc"
    file_path = (storage_dir / stored_filename).resolve()

    if not file_path.is_relative_to(storage_dir):
        raise ValueError("Path traversal attempt detected.")

    file_path.write_bytes(ciphertext)

    # 7. Wrap document key for the owner using their RSA public key
    wrapped_key = wrap_key(owner.public_key_pem, doc_key)
    # Clear raw document key from local memory
    del doc_key

    # 8. Create Document and initial DocumentKey records
    doc = Document(
        owner_id=owner.id,
        original_filename=display_filename,
        stored_filename=stored_filename,
        mime_type=mime_type or "application/octet-stream",
        size_bytes=len(data),
        nonce=nonce,
        plaintext_sha256=plaintext_sha256,
        ciphertext_sha256=ciphertext_sha256,
    )

    owner_key = DocumentKey(
        document=doc,
        recipient=owner,
        wrapped_key=wrapped_key,
        granted_by=owner,
    )

    # 9 & 10. Persist in a single transaction; delete file if commit fails
    try:
        db.session.add(doc)
        db.session.add(owner_key)
        db.session.flush()

        log_event(
            action="UPLOAD",
            actor=owner,
            document_id=doc.id,
            details={
                "original_filename": doc.original_filename,
                "size_bytes": doc.size_bytes,
                "mime_type": doc.mime_type,
            },
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        if file_path.exists():
            try:
                file_path.unlink()
            except OSError:
                pass
        raise

    return doc


@bp.route("", methods=["GET"])
@bp.route("/", methods=["GET"])
@login_required
def index():
    """List all documents owned by the current user."""
    documents = (
        db.session.execute(
            db.select(Document)
            .filter_by(owner_id=current_user.id)
            .order_by(Document.created_at.desc())
        )
        .scalars()
        .all()
    )
    return render_template("documents/index.html", documents=documents)


@bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Upload and encrypt a new document."""
    form = DocumentUploadForm()
    if form.validate_on_submit():
        uploaded_file = form.document.data
        filename = uploaded_file.filename or ""

        # Validate file extension against allowlist
        if not is_allowed_extension(filename):
            allowed = sorted(current_app.config.get("ALLOWED_EXTENSIONS", []))
            flash(
                f"File extension not permitted. Allowed extensions: {', '.join(allowed)}",
                "danger",
            )
            return render_template("documents/upload.html", form=form), 400

        # Read file contents into memory
        file_bytes = uploaded_file.read()
        if not file_bytes:
            flash("Cannot upload an empty file.", "danger")
            return render_template("documents/upload.html", form=form), 400

        # Check maximum file size
        max_length = current_app.config.get(
            "MAX_CONTENT_LENGTH", 16 * 1024 * 1024
        )
        if len(file_bytes) > max_length:
            flash("File exceeds maximum allowed size (16 MB).", "danger")
            return render_template("documents/upload.html", form=form), 413

        user = current_user._get_current_object()
        doc = store_encrypted_document(
            owner=user,
            filename=filename,
            data=file_bytes,
            mime_type=uploaded_file.mimetype,
        )

        flash(
            f"Document '{doc.original_filename}' successfully encrypted and stored.",
            "success",
        )
        return redirect(url_for("documents.index"))

    return render_template("documents/upload.html", form=form)
