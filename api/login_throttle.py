"""Per-account login failure throttling.

In-process state, matching the existing rate limiter. Correct for the current
single-worker deployment; AUTH-16 tracks moving this to a shared store.

Schedule: 5 failures -> 60 s, 10 -> 300 s, 15+ -> 900 s.
"""

from __future__ import annotations

import threading
import time

_LOCK = threading.Lock()
_FAILURES: dict[str, tuple[int, float]] = {}
_MAX_KEYS = 10000


def _key(username: str) -> str:
    return username.strip().lower()


def _lock_seconds(count: int) -> int:
    if count < 5:
        return 0
    if count < 10:
        return 60
    if count < 15:
        return 300
    return 900


def is_locked(username: str) -> tuple[bool, int]:
    now = time.time()
    with _LOCK:
        count, locked_until = _FAILURES.get(_key(username), (0, 0.0))
        if locked_until > now:
            return True, max(1, int(locked_until - now))
        return False, 0


def record_failure(username: str) -> int:
    now = time.time()
    key = _key(username)
    with _LOCK:
        if len(_FAILURES) > _MAX_KEYS:
            for stale in [k for k, (_, until) in _FAILURES.items() if until < now][:1000]:
                _FAILURES.pop(stale, None)
        count = _FAILURES.get(key, (0, 0.0))[0] + 1
        lock_seconds = _lock_seconds(count)
        until = now + lock_seconds if lock_seconds else 0.0
        _FAILURES[key] = (count, until)
        return count


def reset(username: str) -> None:
    with _LOCK:
        _FAILURES.pop(_key(username), None)


def reset_all() -> None:
    with _LOCK:
        _FAILURES.clear()
