"""
security.py — Rate limiting, input validation, and abuse protection.
All state is in-memory only. No persistence.
"""

import time
import asyncio
from collections import defaultdict

# ─── Constants ───────────────────────────────────────────────────────────────
MAX_MESSAGE_LENGTH   = 2000      # characters (encrypted payload can be larger)
MAX_USERNAME_LENGTH  = 24
MIN_USERNAME_LENGTH  = 2
MAX_SESSION_ID_LEN   = 32
MIN_SESSION_ID_LEN   = 4
RATE_LIMIT_WINDOW    = 5         # seconds
RATE_LIMIT_MAX_MSGS  = 10        # max messages per window per connection
IP_CONNECT_WINDOW    = 60        # seconds
IP_MAX_CONNECTS      = 20        # max connections per IP per window


class RateLimiter:
    """Per-connection message rate limiter (in-memory, asyncio-safe)."""

    def __init__(self):
        # connection_id -> list of timestamps
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def is_allowed(self, connection_id: str) -> bool:
        """Return True if connection is within rate limits."""
        async with self._lock:
            now = time.monotonic()
            window_start = now - RATE_LIMIT_WINDOW
            timestamps = self._buckets[connection_id]

            # Prune old timestamps
            self._buckets[connection_id] = [t for t in timestamps if t > window_start]

            if len(self._buckets[connection_id]) >= RATE_LIMIT_MAX_MSGS:
                return False

            self._buckets[connection_id].append(now)
            return True

    async def remove(self, connection_id: str) -> None:
        """Clean up when a connection closes."""
        async with self._lock:
            self._buckets.pop(connection_id, None)


class IPThrottle:
    """Per-IP connection throttle to prevent flooding."""

    def __init__(self):
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._lock = asyncio.Lock()

    async def is_allowed(self, ip: str) -> bool:
        async with self._lock:
            now = time.monotonic()
            window_start = now - IP_CONNECT_WINDOW
            self._buckets[ip] = [t for t in self._buckets[ip] if t > window_start]

            if len(self._buckets[ip]) >= IP_MAX_CONNECTS:
                return False

            self._buckets[ip].append(now)
            return True


def validate_username(username: str) -> tuple[bool, str]:
    """Validate username. Returns (ok, error_message)."""
    if not username or not isinstance(username, str):
        return False, "Username is required."
    stripped = username.strip()
    if len(stripped) < MIN_USERNAME_LENGTH:
        return False, f"Username must be at least {MIN_USERNAME_LENGTH} characters."
    if len(stripped) > MAX_USERNAME_LENGTH:
        return False, f"Username must be at most {MAX_USERNAME_LENGTH} characters."
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.")
    if not all(c in allowed for c in stripped):
        return False, "Username may only contain letters, numbers, _, -, and ."
    return True, ""


def validate_session_id(session_id: str) -> tuple[bool, str]:
    """Validate session ID format."""
    if not session_id or not isinstance(session_id, str):
        return False, "Session ID is required."
    stripped = session_id.strip()
    if len(stripped) < MIN_SESSION_ID_LEN:
        return False, f"Session ID must be at least {MIN_SESSION_ID_LEN} characters."
    if len(stripped) > MAX_SESSION_ID_LEN:
        return False, f"Session ID must be at most {MAX_SESSION_ID_LEN} characters."
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
    if not all(c in allowed for c in stripped):
        return False, "Session ID may only contain letters, numbers, _, and -."
    return True, ""


def validate_payload_length(payload: str) -> bool:
    """Encrypted payloads are base64, so allow larger limit than raw text."""
    # base64 overhead is ~4/3; encrypted message + IV + tag can be larger
    return len(payload) <= MAX_MESSAGE_LENGTH * 2


# Global singletons
rate_limiter = RateLimiter()
ip_throttle  = IPThrottle()
