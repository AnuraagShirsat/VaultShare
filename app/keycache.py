"""Server-side unlocked private key cache for VaultShare.

NOTE ON ARCHITECTURE & LIMITATIONS:
This in-memory cache stores decrypted RSA private key objects keyed by a random
session token. This implementation is single-process only; running multiple workers
without a shared secure key store or restarting the server will invalidate the
cached keys, requiring authenticated users to log in again to unlock their private keys.
The private key object itself is NEVER sent to the client or stored in cookies.

NOTE ON KEY ZEROING LIMITATION:
Python's memory management and garbage collection cannot guarantee deterministic
zeroing or purging of cryptographic key material from process memory upon removal.
Key purging in this cache is strictly best-effort.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hmac
import secrets
import threading
from typing import Dict, Optional


@dataclass
class _CacheEntry:
    """Internal key cache entry tracking timeouts and access history."""

    user_id: int
    private_key: object
    idle_expires_at: datetime
    absolute_expires_at: datetime
    last_accessed_at: datetime


# In-memory dictionary: token -> _CacheEntry
_CACHE: Dict[str, _CacheEntry] = {}
_LOCK = threading.Lock()

# Timeout configuration
IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_LIFETIME = timedelta(hours=8)
MAX_ENTRIES = 1000


def _purge_expired_locked(now: datetime) -> None:
    """Purge expired key entries from cache while caller holds _LOCK."""
    expired_tokens = [
        token
        for token, entry in _CACHE.items()
        if now > entry.idle_expires_at or now > entry.absolute_expires_at
    ]
    for token in expired_tokens:
        del _CACHE[token]


def purge_expired() -> None:
    """Remove expired key entries from the in-memory cache."""
    now = datetime.now(timezone.utc)
    with _LOCK:
        _purge_expired_locked(now)


def store_key(user_id: int, private_key: object) -> str:
    """Store decrypted private key in memory and return a secure random token.

    Enforces maximum cache capacity by purging expired entries, then evicting
    the least-recently-used entry if still full.

    Args:
        user_id: User ID associated with the private key.
        private_key: Decrypted RSA private key object.

    Returns:
        str: Random URL-safe token to be saved in the Flask session.
    """
    now = datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)

    with _LOCK:
        _purge_expired_locked(now)

        # Evict least recently used entry if at capacity
        if len(_CACHE) >= MAX_ENTRIES:
            lru_token = min(
                _CACHE.keys(), key=lambda t: _CACHE[t].last_accessed_at
            )
            del _CACHE[lru_token]

        _CACHE[token] = _CacheEntry(
            user_id=user_id,
            private_key=private_key,
            idle_expires_at=now + IDLE_TIMEOUT,
            absolute_expires_at=now + ABSOLUTE_LIFETIME,
            last_accessed_at=now,
        )

    return token


def get_key(token: Optional[str], user_id: int) -> Optional[object]:
    """Retrieve private key from cache if token is valid, matches user_id, and unexpired.

    Refreshes the idle expiration time on successful access, while strictly
    respecting absolute lifetime. Performs constant-time token comparison.

    Args:
        token: Session key token.
        user_id: Expected user ID.

    Returns:
        Private key object, or None if missing, expired, or mismatched.
    """
    if not token:
        return None

    now = datetime.now(timezone.utc)

    with _LOCK:
        _purge_expired_locked(now)

        # Constant-time token lookup
        matched_token = None
        matched_entry = None
        for cached_token, entry in list(_CACHE.items()):
            if hmac.compare_digest(cached_token, token):
                matched_token = cached_token
                matched_entry = entry
                break

        if matched_entry is None or matched_token is None:
            return None

        # Check user matching and expiration
        if (
            matched_entry.user_id != user_id
            or now > matched_entry.idle_expires_at
            or now > matched_entry.absolute_expires_at
        ):
            _CACHE.pop(matched_token, None)
            return None

        # Refresh idle timeout and last accessed timestamp
        matched_entry.idle_expires_at = now + IDLE_TIMEOUT
        matched_entry.last_accessed_at = now
        return matched_entry.private_key


def drop_key(token: Optional[str]) -> None:
    """Remove key entry from cache by token using constant-time comparison.

    Args:
        token: Session key token to discard.
    """
    if not token:
        return

    with _LOCK:
        matched_token = None
        for cached_token in list(_CACHE.keys()):
            if hmac.compare_digest(cached_token, token):
                matched_token = cached_token
                break

        if matched_token is not None:
            _CACHE.pop(matched_token, None)


def clear_cache() -> None:
    """Clear all cached keys (primarily useful for test teardown)."""
    with _LOCK:
        _CACHE.clear()
