"""Shared helpers for authentication tests.

This module is imported by tests, never by production code.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Optional

from fastapi.testclient import TestClient

from api.captcha import (
    compute_challenge_signature,
    get_captcha_store,
    normalize_captcha_answer,
)
from api.sessions import create_session
from labeler.intel.reputation.connection import get_connection

TEST_PASSWORD = os.getenv("TEST_AUTH_PASSWORD", "PytestPass123!")
CAPTCHA_ANSWER = "TEST99"


def db(sql: str, params: tuple = ()) -> Any:
    """Run one statement and return rows (or None). Commits on success."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall() if cur.description else None
            conn.commit()
            return rows


def issue_captcha(answer: str = CAPTCHA_ANSWER) -> tuple[str, str]:
    """Register a challenge with a known answer in the active CAPTCHA store."""
    captcha_id = str(uuid.uuid4())
    expiry = time.time() + 300
    signature = compute_challenge_signature(
        captcha_id, normalize_captcha_answer(answer), int(expiry)
    )
    get_captcha_store().issue(captcha_id, signature, expiry)
    return captcha_id, answer


def login(
    client: TestClient,
    username: str,
    password: str = TEST_PASSWORD,
    *,
    expect: Optional[int] = 200,
):
    """POST /api/v1/auth/login with a freshly issued single-use CAPTCHA."""
    captcha_id, answer = issue_captcha()
    res = client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": password,
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    if expect is not None:
        assert res.status_code == expect, res.text
    return res


def bearer_for_user(user_id: int) -> dict[str, str]:
    """Create a real server-side session and return a bearer header."""
    raw_token, _ = create_session(user_id=user_id, user_agent="pytest")
    return {"Authorization": f"Bearer {raw_token}"}


def bearer_for_username(username: str) -> dict[str, str]:
    """Create a session for an existing username (used by integration scripts/tests)."""
    rows = db("SELECT id FROM dashboard_users WHERE lower(username) = lower(%s)", (username,))
    if not rows:
        raise RuntimeError(f"user '{username}' does not exist")
    return bearer_for_user(rows[0][0])
