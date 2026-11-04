"""Tests for VaultShare cryptographic module."""

import hashlib
import os
import pytest

from app.crypto import (
    DecryptionError,
    constant_time_equal,
    decrypt_bytes,
    decrypt_private_key,
    derive_key_from_password,
    encrypt_bytes,
    encrypt_private_key,
    generate_document_key,
    generate_rsa_keypair,
    load_public_key,
    sha256_hex,
    unwrap_key,
    wrap_key,
)


@pytest.fixture(scope="module")
def user1_keypair():
    """Module-scoped RSA-3072 keypair for user 1."""
    pub_pem, priv_key = generate_rsa_keypair()
    return pub_pem, priv_key


@pytest.fixture(scope="module")
def user2_keypair():
    """Module-scoped RSA-3072 keypair for user 2."""
    pub_pem, priv_key = generate_rsa_keypair()
    return pub_pem, priv_key


@pytest.fixture(scope="module")
def user3_keypair():
    """Module-scoped RSA-3072 keypair for user 3."""
    pub_pem, priv_key = generate_rsa_keypair()
    return pub_pem, priv_key


# ---------------------------------------------------------------------------
# AES-256-GCM Document Encryption Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "data_size,sample_data",
    [
        ("empty", b""),
        ("small", b"Small test payload for VaultShare AES-GCM encryption."),
        ("1mb", os.urandom(1024 * 1024)),
    ],
)
def test_aes_gcm_roundtrip(data_size: str, sample_data: bytes):
    """Test that AES-GCM roundtrip preserves data for empty, small, and ~1 MB inputs."""
    key = generate_document_key()
    assert len(key) == 32

    nonce, ciphertext = encrypt_bytes(key, sample_data)
    assert len(nonce) == 12
    # Ciphertext includes original payload + 16-byte GCM tag
    assert len(ciphertext) == len(sample_data) + 16

    decrypted = decrypt_bytes(key, nonce, ciphertext)
    assert decrypted == sample_data


def test_two_encryptions_produce_different_nonces_and_ciphertexts():
    """Test that encrypting the same plaintext twice generates fresh nonces and ciphertexts."""
    key = generate_document_key()
    plaintext = b"Identical plaintext across multiple encryptions."

    nonce1, ct1 = encrypt_bytes(key, plaintext)
    nonce2, ct2 = encrypt_bytes(key, plaintext)

    assert nonce1 != nonce2
    assert ct1 != ct2


def test_wrong_key_fails_decryption():
    """Test that attempting to decrypt with a different key raises DecryptionError."""
    key1 = generate_document_key()
    key2 = generate_document_key()
    nonce, ciphertext = encrypt_bytes(key1, b"Secret message.")

    with pytest.raises(DecryptionError):
        decrypt_bytes(key2, nonce, ciphertext)


def test_flipping_ciphertext_byte_fails_decryption():
    """Test that any modification to ciphertext triggers authentication tag mismatch."""
    key = generate_document_key()
    nonce, ciphertext = encrypt_bytes(key, b"Integrity protected data.")

    corrupted_ct = bytearray(ciphertext)
    corrupted_ct[0] ^= 0x01

    with pytest.raises(DecryptionError):
        decrypt_bytes(key, nonce, bytes(corrupted_ct))


def test_changing_nonce_fails_decryption():
    """Test that modifying the nonce prevents decryption."""
    key = generate_document_key()
    nonce, ciphertext = encrypt_bytes(key, b"Data with authentic nonce.")

    corrupted_nonce = bytearray(nonce)
    corrupted_nonce[0] ^= 0x01

    with pytest.raises(DecryptionError):
        decrypt_bytes(key, bytes(corrupted_nonce), ciphertext)


# ---------------------------------------------------------------------------
# RSA-3072 Keypair & Private Key Protection Tests
# ---------------------------------------------------------------------------


def test_rsa_keypair_generation_and_loading():
    """Test that RSA keypair generates at 3072 bits and public PEM can be loaded."""
    pub_pem, priv_key = generate_rsa_keypair()
    assert priv_key.key_size == 3072
    assert b"BEGIN PUBLIC KEY" in pub_pem

    loaded_pub = load_public_key(pub_pem)
    assert loaded_pub.key_size == 3072


def test_private_key_encrypt_decrypt_roundtrip_and_unwraps(user1_keypair):
    """Test encrypting and decrypting a private key with password, then unwrapping."""
    pub_pem, priv_key = user1_keypair
    password = "CorrectUserPassword123!"

    enc_blob, salt, nonce = encrypt_private_key(priv_key, password)
    assert len(salt) == 16
    assert len(nonce) == 12

    recovered_priv_key = decrypt_private_key(enc_blob, salt, nonce, password)
    assert recovered_priv_key.key_size == 3072

    # Verify recovered key can unwrap document keys
    doc_key = generate_document_key()
    wrapped_key = wrap_key(pub_pem, doc_key)
    unwrapped_key = unwrap_key(recovered_priv_key, wrapped_key)
    assert unwrapped_key == doc_key


def test_wrong_password_raises_decryption_error(user1_keypair):
    """Test that attempting to unlock private key with incorrect password fails."""
    _, priv_key = user1_keypair
    enc_blob, salt, nonce = encrypt_private_key(priv_key, "RightPassword123!")

    with pytest.raises(DecryptionError):
        decrypt_private_key(enc_blob, salt, nonce, "WrongPassword999!")


def test_same_password_different_salts_derive_different_keys():
    """Test that scrypt key derivation with distinct salts produces distinct keys."""
    password = "ConstantPassword456"
    salt1 = os.urandom(16)
    salt2 = os.urandom(16)

    key1 = derive_key_from_password(password, salt1)
    key2 = derive_key_from_password(password, salt2)

    assert key1 != key2
    assert len(key1) == 32
    assert len(key2) == 32


# ---------------------------------------------------------------------------
# RSA-OAEP Key Wrapping Tests
# ---------------------------------------------------------------------------


def test_wrap_unwrap_roundtrip_and_wrong_key_fails(user1_keypair, user2_keypair):
    """Test RSA-OAEP wrapping/unwrapping and verify unauthorized private key fails."""
    pub1, priv1 = user1_keypair
    _, priv2 = user2_keypair

    doc_key = generate_document_key()
    wrapped = wrap_key(pub1, doc_key)

    # Legitimate recipient unwraps successfully
    unwrapped = unwrap_key(priv1, wrapped)
    assert unwrapped == doc_key

    # Unauthorized recipient fails
    with pytest.raises(DecryptionError):
        unwrap_key(priv2, wrapped)


def test_wrapping_same_key_twice_gives_different_outputs(user1_keypair):
    """Test that OAEP randomized padding yields different ciphertexts for the same key."""
    pub1, _ = user1_keypair
    doc_key = generate_document_key()

    wrapped1 = wrap_key(pub1, doc_key)
    wrapped2 = wrap_key(pub1, doc_key)

    assert wrapped1 != wrapped2


# ---------------------------------------------------------------------------
# Hashing & Equality Tests
# ---------------------------------------------------------------------------


def test_sha256_hex_matches_known_test_vector():
    """Test that sha256_hex accurately matches standard test vector."""
    test_input = b"abc"
    expected_hex = hashlib.sha256(test_input).hexdigest()
    assert expected_hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    result_hex = sha256_hex(test_input)
    assert result_hex == expected_hex

    assert constant_time_equal(result_hex, expected_hex) is True
    assert constant_time_equal(result_hex, "0" * 64) is False


# ---------------------------------------------------------------------------
# End-to-End Crypto Flow Test
# ---------------------------------------------------------------------------


def test_full_crypto_flow(user1_keypair, user2_keypair, user3_keypair):
    """Full workflow: encrypt doc -> wrap for two recipients -> both decrypt -> third user cannot."""
    pub1, priv1 = user1_keypair
    pub2, priv2 = user2_keypair
    _, priv3 = user3_keypair

    original_document = (
        b"Top Secret Report: Quarterly Financial Audit and Strategic Roadmap."
    )

    # 1. Generate document key and encrypt payload
    doc_key = generate_document_key()
    nonce, ciphertext = encrypt_bytes(doc_key, original_document)

    # 2. Wrap document key for recipient 1 and recipient 2
    wrapped_for_user1 = wrap_key(pub1, doc_key)
    wrapped_for_user2 = wrap_key(pub2, doc_key)

    # 3. Recipient 1 unwraps and decrypts
    unwrapped_key1 = unwrap_key(priv1, wrapped_for_user1)
    decrypted_doc1 = decrypt_bytes(unwrapped_key1, nonce, ciphertext)
    assert decrypted_doc1 == original_document

    # 4. Recipient 2 unwraps and decrypts
    unwrapped_key2 = unwrap_key(priv2, wrapped_for_user2)
    decrypted_doc2 = decrypt_bytes(unwrapped_key2, nonce, ciphertext)
    assert decrypted_doc2 == original_document

    # 5. User 3 is not an authorized recipient and cannot unwrap either key
    with pytest.raises(DecryptionError):
        unwrap_key(priv3, wrapped_for_user1)

    with pytest.raises(DecryptionError):
        unwrap_key(priv3, wrapped_for_user2)
