"""Cryptographic operations and utilities for VaultShare.

Provides pure cryptographic functions using the cryptography library hazmat
primitives for AES-256-GCM document encryption, RSA-3072 keypair generation,
RSA-OAEP per-recipient key wrapping, scrypt password derivation, and SHA-256
integrity hashing.
"""

import hmac
import os
from typing import Tuple, Union
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class DecryptionError(Exception):
    """Generic exception raised when cryptographic decryption or validation fails."""

    def __init__(self, message: str = "Decryption failed."):
        super().__init__(message)


# ---------------------------------------------------------------------------
# 1. Document Encryption (AES-256-GCM)
# ---------------------------------------------------------------------------


def generate_document_key() -> bytes:
    """Generate a random 256-bit (32 bytes) symmetric key for document encryption."""
    return os.urandom(32)


def encrypt_bytes(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes]:
    """Encrypt plaintext using AES-256-GCM with a fresh 12-byte nonce.

    Args:
        key: 32-byte AES key.
        plaintext: Plaintext bytes to encrypt.

    Returns:
        Tuple[bytes, bytes]: (nonce, ciphertext) where ciphertext includes
        the 16-byte authentication tag appended.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_bytes(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext using the provided key and nonce.

    Args:
        key: 32-byte AES key.
        nonce: 12-byte AES-GCM nonce.
        ciphertext: Ciphertext bytes including the authentication tag.

    Returns:
        bytes: Decrypted plaintext.

    Raises:
        DecryptionError: If the key, nonce, or ciphertext is invalid or tampered with.
    """
    try:
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise DecryptionError("Decryption failed.") from exc


# ---------------------------------------------------------------------------
# 2. User Keypairs (RSA-3072)
# ---------------------------------------------------------------------------


def generate_rsa_keypair() -> Tuple[bytes, rsa.RSAPrivateKey]:
    """Generate an RSA-3072 keypair with public exponent 65537.

    Returns:
        Tuple[bytes, rsa.RSAPrivateKey]: (public_key_pem, private_key_object)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_pem, private_key


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key to unencrypted PKCS#8 PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(data: bytes) -> rsa.RSAPrivateKey:
    """Load an RSA private key from PKCS#8 PEM bytes.

    Args:
        data: PEM-encoded private key bytes.

    Returns:
        rsa.RSAPrivateKey: Loaded RSA private key object.

    Raises:
        DecryptionError: If the data cannot be parsed as a private key.
    """
    try:
        return serialization.load_pem_private_key(data, password=None)
    except Exception as exc:
        raise DecryptionError("Failed to load private key.") from exc


def load_public_key(pem: Union[bytes, str]) -> rsa.RSAPublicKey:
    """Load an RSA public key from SubjectPublicKeyInfo PEM bytes or string.

    Args:
        pem: PEM-encoded public key bytes or string.

    Returns:
        rsa.RSAPublicKey: Loaded RSA public key object.

    Raises:
        DecryptionError: If the public key cannot be parsed.
    """
    try:
        pem_bytes = pem.encode("utf-8") if isinstance(pem, str) else pem
        return serialization.load_pem_public_key(pem_bytes)
    except Exception as exc:
        raise DecryptionError("Failed to load public key.") from exc


# ---------------------------------------------------------------------------
# 3. Private Key Protection (Password-Derived)
# ---------------------------------------------------------------------------


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit symmetric key from a password and salt using scrypt.

    Parameters:
        n = 2**15 (32768), r = 8, p = 1, output length = 32 bytes.
    """
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**15,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_private_key(
    private_key: rsa.RSAPrivateKey, password: str
) -> Tuple[bytes, bytes, bytes]:
    """Encrypt an RSA private key with a password-derived key using scrypt and AES-256-GCM.

    Args:
        private_key: RSA private key object.
        password: User password.

    Returns:
        Tuple[bytes, bytes, bytes]: (encrypted_blob, salt, nonce)
    """
    salt = os.urandom(16)
    derived_key = derive_key_from_password(password, salt)
    serialized_pem = serialize_private_key(private_key)
    nonce, encrypted_blob = encrypt_bytes(derived_key, serialized_pem)
    return encrypted_blob, salt, nonce


def decrypt_private_key(
    encrypted_blob: bytes, salt: bytes, nonce: bytes, password: str
) -> rsa.RSAPrivateKey:
    """Decrypt an encrypted RSA private key using password, salt, and nonce.

    Args:
        encrypted_blob: Ciphertext of the private key with GCM tag.
        salt: 16-byte scrypt salt.
        nonce: 12-byte AES-GCM nonce.
        password: User password.

    Returns:
        rsa.RSAPrivateKey: Loaded RSA private key object.

    Raises:
        DecryptionError: If the password is wrong or data is tampered.
    """
    try:
        derived_key = derive_key_from_password(password, salt)
        serialized_pem = decrypt_bytes(derived_key, nonce, encrypted_blob)
        return load_private_key(serialized_pem)
    except DecryptionError:
        raise
    except Exception as exc:
        raise DecryptionError("Failed to decrypt private key.") from exc


# ---------------------------------------------------------------------------
# 4. Per-Recipient Key Wrapping (RSA-OAEP)
# ---------------------------------------------------------------------------


def wrap_key(public_key_pem: Union[bytes, str], document_key: bytes) -> bytes:
    """Wrap a document key using a recipient's RSA public key with RSA-OAEP (SHA-256).

    Args:
        public_key_pem: Recipient's RSA public key in PEM format.
        document_key: Symmetric document key bytes to wrap.

    Returns:
        bytes: Wrapped (encrypted) document key.
    """
    public_key = load_public_key(public_key_pem)
    return public_key.encrypt(
        document_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_key(private_key: rsa.RSAPrivateKey, wrapped_key: bytes) -> bytes:
    """Unwrap a document key using the recipient's RSA private key.

    Args:
        private_key: Recipient's RSA private key object.
        wrapped_key: Wrapped document key ciphertext.

    Returns:
        bytes: Unwrapped symmetric document key.

    Raises:
        DecryptionError: If unwrapping fails.
    """
    try:
        return private_key.decrypt(
            wrapped_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise DecryptionError("Key unwrapping failed.") from exc


# ---------------------------------------------------------------------------
# 5. Hashing & Constant-Time Verification
# ---------------------------------------------------------------------------


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 digest of data and return as lowercase hexadecimal string."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize().hex()


def constant_time_equal(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(a, b)
