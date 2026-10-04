"""
In-Memory Sliding Window Rate Limiter for DNSNetra Auth APIs
============================================================
Provides thread-safe request throttling to protect authentication endpoints
(captcha generation, login, signup, password reset) from automated abuse.
Leverages secure client IP resolution to prevent X-Forwarded-For spoofing.
Returns HTTP 429 with Retry-After header when rate limits are exceeded.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Optional

from fastapi import HTTPException, Request, status

from .trusted_proxy import get_client_ip

_LOCK = threading.Lock()
# Mapping of bucket_id -> deque of timestamps
_BUCKETS: dict[str, deque[float]] = {}
_MAX_BUCKETS = 10000


def check_rate_limit(
    key: str,
    action: str,
    max_requests: int,
    window_seconds: int,
) -> tuple[bool, int]:
    """
    Check if the client has exceeded allowed requests in the sliding window.
    Returns (is_allowed, retry_after_seconds).
    """
    now = time.time()
    bucket_id = f"{action}:{key}"

    with _LOCK:
        # Periodic cleanup if buckets grow excessively
        if len(_BUCKETS) > _MAX_BUCKETS:
            stale_keys = [
                k for k, q in _BUCKETS.items()
                if not q or (now - q[-1] > 300)
            ]
            for k in stale_keys:
                _BUCKETS.pop(k, None)

        if bucket_id not in _BUCKETS:
            _BUCKETS[bucket_id] = deque()

        timestamps = _BUCKETS[bucket_id]

        # Evict timestamps outside current window
        cutoff = now - window_seconds
        while timestamps and timestamps[0] < cutoff:
            timestamps.popleft()

        if len(timestamps) >= max_requests:
            oldest = timestamps[0]
            retry_after = max(1, int(oldest + window_seconds - now))
            return False, retry_after

        # Record this request
        timestamps.append(now)
        return True, 0


def reset_rate_limits():
    """Reset all rate limit tracking (primarily for testing)."""
    with _LOCK:
        _BUCKETS.clear()


def rate_limiter(action: str, max_requests: int = 10, window_seconds: int = 60) -> Callable:
    """
    FastAPI dependency factory enforcing rate limits using secure client IP.
    """
    async def dependency(request: Request):
        client_ip = get_client_ip(request)

        is_allowed, retry_after = check_rate_limit(
            key=client_ip,
            action=action,
            max_requests=max_requests,
            window_seconds=window_seconds,
        )

        if not is_allowed:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Too many requests for action '{action}'. Please retry in {retry_after} seconds.",
                headers={"Retry-After": str(retry_after)},
            )

    return dependency
