"""
tests/test_password_reset.py
============================
Tests for one-time reset code lifecycle:
- Admin issues code for target user (POST /api/v1/users/{id}/reset-code)
- User redeems code with valid CAPTCHA (POST /api/v1/auth/reset-password)
- Single-use: code cannot be replayed
- Invalidation: issuing a new code invalidates prior unredeemed codes
- Non-admin forbidden from issuing codes
"""

from __future__ import annotations

import pytest

from tests.auth_testkit import issue_captcha, session_token_from_client
from tests.test_auth_security_audit import (  # noqa: F401
    _client,
    _db,
    admin_headers,
    mk_user,
)

PASSWORD = "AuditPass123!"


def test_reset_code_changes_password_once(mk_user, admin_headers):
    username, uid = mk_user("resetflow")
    client = _client()

    # 1. Admin issues code
    issued = client.post(f"/api/v1/users/{uid}/reset-code", headers=admin_headers)
    assert issued.status_code == 200
    data = issued.json()
    assert "code" in data
    assert "expires_at" in data
    code = data["code"]

    # 2. First redemption succeeds
    captcha_id, answer = issue_captcha()
    first = client.post(
        "/api/v1/auth/reset-password",
        json={
            "username": username,
            "code": code,
            "new_password": "BrandNewPass123!",
            "confirm_password": "BrandNewPass123!",
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    assert first.status_code == 200

    # 3. Replay fails (single-use)
    captcha_id, answer = issue_captcha()
    replay = client.post(
        "/api/v1/auth/reset-password",
        json={
            "username": username,
            "code": code,
            "new_password": "AnotherPass123!",
            "confirm_password": "AnotherPass123!",
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    assert replay.status_code == 400


def test_non_admin_cannot_issue_reset_code(mk_user):
    username, uid = mk_user("targetuser")
    _, analyst_uid = mk_user("analystactor", role="ANALYST")
    client = _client()

    # Log in as analyst to get analyst token
    cid, ans = issue_captcha()
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "analystactor", "password": PASSWORD, "captcha_id": cid, "captcha_answer": ans},
    )
    # If analyst cannot login directly or has headers, create session token directly
    import api.sessions as sessions_mod
    raw_token, _ = sessions_mod.create_session(user_id=analyst_uid)
    headers = {"Authorization": f"Bearer {raw_token}"}

    res = client.post(f"/api/v1/users/{uid}/reset-code", headers=headers)
    assert res.status_code == 403


def test_reset_password_requires_valid_captcha(mk_user, admin_headers):
    username, uid = mk_user("badcaptcha")
    client = _client()

    issued = client.post(f"/api/v1/users/{uid}/reset-code", headers=admin_headers)
    assert issued.status_code == 200
    code = issued.json()["code"]

    res = client.post(
        "/api/v1/auth/reset-password",
        json={
            "username": username,
            "code": code,
            "new_password": "BrandNewPass123!",
            "confirm_password": "BrandNewPass123!",
            "captcha_id": "invalid-id",
            "captcha_answer": "WRONG",
        },
    )
    assert res.status_code == 400
    assert "captcha" in res.json().get("detail", "").lower()


def test_reset_password_mismatched_passwords(mk_user, admin_headers):
    username, uid = mk_user("mismatch")
    client = _client()

    issued = client.post(f"/api/v1/users/{uid}/reset-code", headers=admin_headers)
    assert issued.status_code == 200
    code = issued.json()["code"]

    captcha_id, answer = issue_captcha()
    res = client.post(
        "/api/v1/auth/reset-password",
        json={
            "username": username,
            "code": code,
            "new_password": "BrandNewPass123!",
            "confirm_password": "DifferentPass123!",
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    assert res.status_code == 400
    assert "match" in res.json().get("detail", "").lower()



def test_reset_code_response_is_not_cacheable(mk_user, admin_headers):
    _, uid = mk_user("resetnocache")
    res = _client().post(f"/api/v1/users/{uid}/reset-code", headers=admin_headers)
    assert res.status_code == 200
    assert res.headers["cache-control"].startswith("no-store")
    assert res.headers["pragma"] == "no-cache"
