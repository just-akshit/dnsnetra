"""
tests/test_users_admin.py
=========================
Route-level tests for admin user lifecycle management endpoints.
Ensures backend route contracts match frontend usersApi client behavior.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import api.auth as auth
import api.sessions as sessions_mod
from api.main import app
from tests.auth_testkit import login, session_token_from_client
from tests.test_auth_security_audit import _client, _db, admin_headers, mk_user

PASSWORD = "AuditPass123!"


def test_admin_create_and_get_user(admin_headers, mk_user):
    client = _client()
    username = f"admin_created_{mk_user('tmp')[0]}"
    create_res = client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "username": username,
            "password": "CreatedUserPass123!",
            "role": "ANALYST",
            "status": "ACTIVE",
        },
    )
    assert create_res.status_code == 201
    created_id = create_res.json()["id"]
    mk_user.track_session(f"dummy_{created_id}")  # track for cleanup if needed

    try:
        get_res = client.get(f"/api/v1/users/{created_id}", headers=admin_headers)
        assert get_res.status_code == 200
        data = get_res.json()
        assert data["username"] == username
        assert data["role"] == "ANALYST"
        assert data["status"] == "ACTIVE"
        assert data["is_active"] is True
    finally:
        _db("DELETE FROM dashboard_users WHERE id = %s", (created_id,))


def test_admin_list_users_filtering(admin_headers, mk_user):
    client = _client()
    user_active, uid_active = mk_user("act", role="ANALYST", status="ACTIVE")
    user_pending, uid_pending = mk_user("pnd", role="ANALYST", status="PENDING")

    res = client.get("/api/v1/users?status=PENDING", headers=admin_headers)
    assert res.status_code == 200
    items = res.json()["items"]
    usernames = [u["username"] for u in items]
    assert user_pending in usernames
    assert user_active not in usernames


def test_admin_update_user_role(admin_headers, mk_user):
    client = _client()
    username, uid = mk_user("updaterole", role="ANALYST")

    res = client.patch(
        f"/api/v1/users/{uid}",
        headers=admin_headers,
        json={"role": "SUPPORT"},
    )
    assert res.status_code == 200
    assert res.json()["role"] == "SUPPORT"

    detail = client.get(f"/api/v1/users/{uid}", headers=admin_headers).json()
    assert detail["role"] == "SUPPORT"


def test_admin_approve_user(admin_headers, mk_user):
    client = _client()
    username, uid = mk_user("approveme", role="ANALYST", status="PENDING")

    res = client.post(
        f"/api/v1/users/{uid}/approve",
        headers=admin_headers,
        json={"role": "SUPPORT"},
    )
    assert res.status_code == 200

    detail = client.get(f"/api/v1/users/{uid}", headers=admin_headers).json()
    assert detail["status"] == "ACTIVE"
    assert detail["is_active"] is True
    assert detail["role"] == "SUPPORT"


def test_admin_disable_and_enable_user(admin_headers, mk_user):
    client = _client()
    username, uid = mk_user("toggle", role="ANALYST", status="ACTIVE")

    # Disable
    dis = client.post(f"/api/v1/users/{uid}/disable", headers=admin_headers)
    assert dis.status_code == 200
    detail = client.get(f"/api/v1/users/{uid}", headers=admin_headers).json()
    assert detail["status"] == "DISABLED"
    assert detail["is_active"] is False

    # Enable
    en = client.post(f"/api/v1/users/{uid}/enable", headers=admin_headers)
    assert en.status_code == 200
    detail = client.get(f"/api/v1/users/{uid}", headers=admin_headers).json()
    assert detail["status"] == "ACTIVE"
    assert detail["is_active"] is True


def test_admin_reset_user_password(admin_headers, mk_user):
    client = _client()
    username, uid = mk_user("pwdreset", role="ANALYST", status="ACTIVE")

    res = client.post(
        f"/api/v1/users/{uid}/reset-password",
        headers=admin_headers,
    )
    assert res.status_code == 200
    body = res.json()
    assert body["username"] == username
    assert body["temporary_password"]

    detail = client.get(f"/api/v1/users/{uid}", headers=admin_headers).json()
    assert detail["must_change_password"] is True


def test_admin_revoke_sessions(admin_headers, mk_user):
    client = _client()
    username, uid = mk_user("revokesess", role="ANALYST", status="ACTIVE")

    # Log in to create a real session
    user_client = _client()
    user_client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": PASSWORD,
            **_login_captcha(),
        },
    )
    token = session_token_from_client(user_client)
    # Session works
    assert user_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 200

    # Admin revokes sessions
    rev_res = client.post(f"/api/v1/users/{uid}/revoke-sessions", headers=admin_headers)
    assert rev_res.status_code == 200

    # Session is now invalid
    assert user_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def _login_captcha() -> dict:
    from tests.auth_testkit import issue_captcha
    cid, ans = issue_captcha()
    return {"captcha_id": cid, "captcha_answer": ans}

