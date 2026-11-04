"""Server-side unlocked private key cache for VaultShare.

NOTE ON ARCHITECTURE & LIMITATIONS:
This in-memory cache stores decrypted RSA private key objects keyed by a random
session token. This implementation is single-process only; running multiple workers
without a shared secure key store or restarting the server will invalidate the
cached keys, requiring authenticated users to log in again to unlock their private keys.
The private key object itself is NEVER sent to the client or stored in cookies.
"""

from datetime import datetime, timedelta, timezone
import secrets
import threading
from typing import Optional

# In-memory dictionary: token -> (user_id: int, private_key: object, expires_at: datetime)
_CACHE = {}
_LOCK = threading.Lock()
IDLE_TIMEOUT = timedelta(minutes=30)


def purge_expired() -> None:
    """Remove expired key entries from the in-memory cache."""
    now = datetime.now(timezone.utc)
    with _LOCK:
        expired_tokens = [
            token for token, (_, _, expires_at) in _CACHE.items() if now > expires_at
        ]
        for token in expired_tokens:
            del _CACHE[token]


def store_key(user_id: int, private_key: object) -> str:
    """Store decrypted private key in memory and return a secure random token.

    Args:
        user_id: User ID associated with the private key.
        private_key: Decrypted RSA private key object.

    Returns:
        str: Random URL-safe token to be saved in the Flask session.
    """
    purge_expired()
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + IDLE_TIMEOUT
    with _LOCK:
        _CACHE[token] = (user_id, private_key, expires_at)
    return token


def get_key(token: Optional[str], user_id: int) -> Optional[object]:
    """Retrieve private key from cache if token is valid, matches user_id, and unexpired.

    Refreshes the idle expiration time on successful access.

    Args:
        token: Session key token.
        user_id: Expected user ID.

    Returns:
        Private key object, or None if missing, expired, or mismatched.
    """
    if not token:
        return None

    purge_expired()
    now = datetime.now(timezone.utc)
    with _LOCK:
        entry = _CACHE.get(token)
        if entry is None:
            return None

        cached_user_id, private_key, expires_at = entry
        if cached_user_id != user_id or now > expires_at:
            _CACHE.pop(token, None)
            return None

        # Refresh idle timeout on use
        _CACHE[token] = (cached_user_id, private_key, now + IDLE_TIMEOUT)
        return private_key


def drop_key(token: Optional[str]) -> None:
    """Remove key entry from cache by token.

    Args:
        token: Session key token to discard.
    """
    if not token:
        return
    with _LOCK:
        _CACHE.pop(token, None)


def clear_cache() -> None:
    """Clear all cached keys (primarily useful for test teardown)."""
    with _LOCK:
        _CACHE.clear()
