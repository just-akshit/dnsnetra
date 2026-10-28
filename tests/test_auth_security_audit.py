"""
tests/test_auth_security_audit.py
=================================
Independent security audit of the authentication / authorization module.

Every test in this file encodes the behaviour the module *should* have.
Tests marked ``xfail`` reproduce a confirmed defect (AUTH-xx) and currently
fail; they turn green automatically once the defect is fixed (remove the
marker then). Tests that are not marked protect behaviour that already works.

Run:
    pytest tests/test_auth_security_audit.py -rxX

Findings are documented in ``docs/AUTH_SECURITY_AUDIT.md``.

Safety: every test creates throw-away ``audit_*`` users and deletes them (and
their sessions / audit rows) during teardown. No existing account is modified.
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

import api.auth as auth
import api.sessions as sessions_mod
from api.captcha import (
    compute_challenge_signature,
    get_captcha_secret,
    get_captcha_store,
    normalize_captcha_answer,
    set_captcha_store,
    verify_and_consume_captcha,
)
from api.main import app
from api.rate_limiter import reset_rate_limits
from labeler.intel.reputation.connection import get_connection
from tests.auth_testkit import issue_captcha

PASSWORD = "AuditPass123!"


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _db(sql: str, params=()):
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall() if cur.description else None
            conn.commit()
            return rows


@pytest.fixture(autouse=True)
def _clean_rate_limits():
    reset_rate_limits()
    yield
    reset_rate_limits()


@pytest.fixture
def mk_user():
    """Factory for disposable users; cleans up users, sessions and audit rows."""
    created: list[int] = []
    sessions: list[str] = []

    def _mk(name: str, role: str = "ANALYST", status: str = "ACTIVE", must_change: bool = False):
        username = f"audit_{name}_{uuid.uuid4().hex[:8]}"
        _db(
            """
            INSERT INTO dashboard_users
                (username, email, password_hash, hashed_password, role, status,
                 is_active, must_change_password, created_at, updated_at)
            VALUES (%s, %s, %s, NULL, %s, %s, %s, %s, NOW(), NOW())
            RETURNING id
            """,
            (
                username,
                f"{username}@dnsnetra.local",
                auth.hash_password(PASSWORD),
                role,
                status,
                status == "ACTIVE",
                must_change,
            ),
        )
        uid = _db("SELECT id FROM dashboard_users WHERE username = %s", (username,))[0][0]
        created.append(uid)
        return username, uid

    def _track_session(raw_token: str) -> str:
        sessions.append(raw_token)
        return raw_token

    _mk.track_session = _track_session  # type: ignore[attr-defined]
    yield _mk

    if created:
        _db("DELETE FROM audit_logs WHERE target_user_id = ANY(%s)", (created,))
        _db("DELETE FROM sessions WHERE user_id = ANY(%s)", (created,))
        _db("DELETE FROM dashboard_users WHERE id = ANY(%s)", (created,))
    for raw in sessions:
        _db("DELETE FROM sessions WHERE session_token_hash = %s", (sessions_mod.hash_session_token(raw),))


@pytest.fixture
def admin_headers(mk_user):
    """Real server-side ADMIN session for the seeded 'admin' account."""
    admin_id = _db("SELECT id FROM dashboard_users WHERE username = 'admin'")[0][0]
    token, _ = sessions_mod.create_session(user_id=admin_id)
    mk_user.track_session(token)
    return {"Authorization": f"Bearer {token}", "Origin": "http://localhost:3000"}


def _login_body(username: str, password: str = PASSWORD) -> dict:
    captcha_id, answer = issue_captcha()
    return {
        "username": username,
        "password": password,
        "captcha_id": captcha_id,
        "captcha_answer": answer,
    }


def _client(**kw) -> TestClient:
    return TestClient(app, raise_server_exceptions=False, **kw)


# ===========================================================================
# AUTH-01 / AUTH-05: no JWT path may exist
# ===========================================================================

LEGACY_PUBLISHED_SECRET = "dnsnetra-dev-test-jwt-secret-do-not-use-in-production"


def _force_legacy_default_env(monkeypatch) -> None:
    """Reproduce the shipped configuration: no secret, no explicit environment.

    Without this the local `.env` supplies a strong secret and the surviving
    JWT fallback hides behind it instead of being exercised.
    """
    for name in (
        "AUTH_SESSION_SECRET",
        "AUTH_SECRET_KEY",
        "JWT_SECRET",
        "DNSNETRA_ENV",
        "APP_ENV",
        "ENVIRONMENT",
    ):
        monkeypatch.delenv(name, raising=False)


def _legacy_token(claims: dict) -> str:
    return pyjwt.encode(claims, LEGACY_PUBLISHED_SECRET, algorithm="HS256")


def test_legacy_jwt_signed_with_published_secret_is_rejected(monkeypatch):
    _force_legacy_default_env(monkeypatch)
    forged = _legacy_token(
        {
            "sub": "admin",
            "role": "ADMIN",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }
    )
    res = _client().get("/api/v1/users?limit=1", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401


def test_token_without_expiry_is_rejected(monkeypatch):
    _force_legacy_default_env(monkeypatch)
    forged = _legacy_token({"sub": "admin", "role": "ADMIN"})
    res = _client().get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401


def test_jwt_role_claim_cannot_escalate_privileges(mk_user, monkeypatch):
    _force_legacy_default_env(monkeypatch)
    username, _ = mk_user("escalate", role="ANALYST")
    forged = _legacy_token({"sub": username, "role": "ADMIN"})
    res = _client().get("/api/v1/users?limit=1", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401


def test_jwt_is_revoked_when_sessions_are_revoked(mk_user, monkeypatch):
    _force_legacy_default_env(monkeypatch)
    username, uid = mk_user("revoke", role="ANALYST")
    forged = _legacy_token({"sub": username, "role": "ANALYST"})
    sessions_mod.revoke_all_user_sessions(uid)
    res = _client().get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401


# ===========================================================================
# AUTH-03: CAPTCHA is optional
# ===========================================================================

def test_login_requires_a_captcha(mk_user):
    username, _ = mk_user("nocaptcha")
    res = _client().post(
        "/api/v1/auth/login",
        json={"username": username, "password": PASSWORD},
    )
    assert res.status_code in (400, 422)


def test_oauth2_form_login_requires_a_captcha(mk_user):
    username, _ = mk_user("tokennocaptcha")
    res = _client().post("/api/v1/auth/token", data={"username": username, "password": PASSWORD})
    assert res.status_code in (400, 422)


# ===========================================================================
# AUTH-04: must_change_password is never enforced
# ===========================================================================

def test_must_change_password_blocks_privileged_access(mk_user):
    username, _ = mk_user("mustchange", role="ADMIN", must_change=True)
    client = _client()
    captcha_id, answer = issue_captcha()
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": PASSWORD,
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    assert login_res.status_code == 200
    token = login_res.json()["session_token"]
    res = client.get("/api/v1/users?limit=1", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 428
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["must_change_password"] is True


# ===========================================================================
# AUTH-07: approve bypasses lifecycle and admin guard
# ===========================================================================

def test_approve_rejects_non_pending_account(mk_user, admin_headers):
    _, uid = mk_user("disabled", status="DISABLED")
    res = _client().post(f"/api/v1/users/{uid}/approve", json={"role": "ANALYST"}, headers=admin_headers)
    assert res.status_code == 400


def test_approve_cannot_grant_admin_role(mk_user, admin_headers):
    _, uid = mk_user("pending", status="PENDING")
    _client().post(f"/api/v1/users/{uid}/approve", json={"role": "ADMIN"}, headers=admin_headers)
    role = _db("SELECT role FROM dashboard_users WHERE id = %s", (uid,))[0][0]
    assert role != "ADMIN"


# ===========================================================================
# AUTH-08: update_user invariants
# ===========================================================================

@pytest.mark.xfail(reason="AUTH-08: contradictory status/is_active leaks a DB constraint as HTTP 500", strict=False)
def test_contradictory_status_update_returns_4xx(mk_user, admin_headers):
    _, uid = mk_user("contradict")
    res = _client().patch(
        f"/api/v1/users/{uid}", json={"status": "ACTIVE", "is_active": False}, headers=admin_headers
    )
    assert res.status_code in (400, 422)


@pytest.mark.xfail(reason="AUTH-08: no-op role update revokes all live sessions", strict=False)
def test_noop_update_does_not_revoke_sessions(mk_user, admin_headers):
    username, uid = mk_user("noop", role="ANALYST")
    client = _client()
    token = client.post("/api/v1/auth/login", json=_login_body(username)).json()["session_token"]
    client.patch(f"/api/v1/users/{uid}", json={"role": "ANALYST"}, headers=admin_headers)
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 200


# ===========================================================================
# AUTH-06: X-Forwarded-For spoofing / rate-limit bypass
# ===========================================================================

@pytest.mark.xfail(reason="AUTH-06: left-most XFF hop is trusted (client-controlled)", strict=False)
def test_rate_limit_cannot_be_bypassed_with_spoofed_xff():
    proxy_client = _client(client=("127.0.0.1", 4444))  # peer is in TRUSTED_PROXIES
    codes = [
        proxy_client.get(
            "/api/v1/auth/captcha", headers={"X-Forwarded-For": f"203.0.113.{i}"}
        ).status_code
        for i in range(35)  # limit is 30/min
    ]
    assert 429 in codes


# ===========================================================================
# AUTH-09: configuration validation / TTL consistency
# ===========================================================================

def test_captcha_secret_must_not_use_dev_default_in_production(monkeypatch):
    monkeypatch.setenv("DNSNETRA_ENV", "production")
    monkeypatch.delenv("AUTH_CAPTCHA_SECRET", raising=False)
    monkeypatch.delenv("CAPTCHA_SECRET", raising=False)
    from api.captcha import get_captcha_secret

    with pytest.raises(RuntimeError):
        get_captcha_secret()


def test_env_example_placeholder_is_rejected_in_production(monkeypatch):
    from api import auth_config

    monkeypatch.setattr(auth_config, "is_production", lambda: True)
    monkeypatch.setenv(
        "AUTH_SESSION_SECRET",
        "change-this-in-production-session-secret-key-min-32-chars",
    )
    with pytest.raises(RuntimeError):
        auth_config.get_session_pepper()


def test_expires_in_matches_configured_session_ttl(mk_user, monkeypatch):
    username, _ = mk_user("ttl")
    monkeypatch.setenv("AUTH_SESSION_EXPIRE_MINUTES", "5")
    client = _client()
    res = client.post("/api/v1/auth/login", json=_login_body(username))
    assert res.status_code == 200
    assert res.json()["expires_in"] <= 300
    assert "Max-Age=86400" not in res.headers.get("set-cookie", "")


# ===========================================================================
# AUTH-10: CAPTCHA single-use is not atomic; consume() result ignored
# ===========================================================================

def test_captcha_rejects_when_consume_fails():
    original_store = get_captcha_store()

    class NonConsumingStore(type(original_store)):  # type: ignore[misc]
        def consume(self, challenge_id, expiry):
            return False  # e.g. racing request already consumed it

    store = NonConsumingStore()
    set_captcha_store(store)
    try:
        cid = str(uuid.uuid4())
        expiry = time.time() + 300
        answer = "ABC123"
        store.issue(
            cid,
            compute_challenge_signature(cid, normalize_captcha_answer(answer), int(expiry)),
            expiry,
        )
        ok, reason = verify_and_consume_captcha(cid, answer)
        assert ok is False, reason
    finally:
        set_captcha_store(original_store)


# ===========================================================================
# AUTH-12: username enumeration via timing
# ===========================================================================

@pytest.mark.xfail(reason="AUTH-12: unknown users skip password hashing (timing oracle)", strict=False)
def test_unknown_user_still_performs_a_dummy_hash(mk_user):
    username, _ = mk_user("timing")
    original = auth.verify_password
    calls = {"n": 0}

    def spy(plain, hashed):
        calls["n"] += 1
        return original(plain, hashed)

    auth.verify_password = spy
    try:
        auth.authenticate_user("definitely_missing_user_zzz", PASSWORD)
        assert calls["n"] == 1, "no dummy hash performed for unknown user"
        calls["n"] = 0
        auth.authenticate_user(username, "WrongPassword123!")
        assert calls["n"] == 1
    finally:
        auth.verify_password = original


# ===========================================================================
# AUTH-15: token-bearing responses must not be cacheable
# ===========================================================================

@pytest.mark.xfail(reason="AUTH-15: /auth/login response (contains token) has no Cache-Control", strict=False)
def test_login_response_is_not_cacheable(mk_user):
    username, _ = mk_user("cache")
    res = _client().post("/api/v1/auth/login", json=_login_body(username))
    assert "no-store" in (res.headers.get("cache-control") or "").lower()


@pytest.mark.xfail(reason="AUTH-14: session token is exposed in the JSON body alongside the HttpOnly cookie", strict=False)
def test_login_does_not_return_raw_session_token_in_body(mk_user):
    username, _ = mk_user("nobodytoken")
    res = _client().post("/api/v1/auth/login", json=_login_body(username))
    assert "session_token" not in res.json()


# ===========================================================================
# AUTH-17: password / username policy inconsistencies
# ===========================================================================

@pytest.mark.xfail(reason="AUTH-17: '_' is a special character but the policy rejects it", strict=False)
def test_underscore_counts_as_special_character():
    ok, reason = auth.validate_password_strength("Password_")
    assert ok, reason


@pytest.mark.xfail(reason="AUTH-17: '.admin.' bypasses the reserved-name list", strict=False)
def test_dotted_reserved_username_is_rejected():
    ok, reason = auth.validate_username(".admin.", is_signup=True)
    assert not ok, reason


# ===========================================================================
# Working behaviour (regression guards)
# ===========================================================================

def test_session_tokens_are_stored_only_as_hashes(mk_user):
    _, uid = mk_user("hash")
    raw, _ = sessions_mod.create_session(user_id=uid)
    rows = _db("SELECT session_token_hash FROM sessions WHERE user_id = %s", (uid,))
    assert rows and rows[0][0] == sessions_mod.hash_session_token(raw)
    assert raw not in rows[0][0]


def test_session_cookie_is_httponly_and_samesite(mk_user):
    username, _ = mk_user("cookie")
    res = _client().post("/api/v1/auth/login", json=_login_body(username))
    cookie = res.headers.get("set-cookie", "").lower()
    assert "httponly" in cookie
    assert "samesite=lax" in cookie


def test_disabled_user_session_is_rejected(mk_user):
    username, uid = mk_user("disabled_session")
    client = _client()
    token = client.post("/api/v1/auth/login", json=_login_body(username)).json()["session_token"]
    _db(
        "UPDATE dashboard_users SET status = 'DISABLED', is_active = false WHERE id = %s",
        (uid,),
    )
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 401


def test_csrf_blocks_cookie_authenticated_cross_site_post(mk_user):
    username, _ = mk_user("csrf")
    client = _client()
    client.post("/api/v1/auth/login", json=_login_body(username))
    res = client.post(
        "/api/v1/auth/logout", headers={"Origin": "https://evil.example"}, json={}
    )
    assert res.status_code == 403


def test_csrf_allows_same_origin_cookie_post(mk_user):
    username, _ = mk_user("csrf_ok")
    client = _client()
    client.post("/api/v1/auth/login", json=_login_body(username))
    res = client.post(
        "/api/v1/auth/logout", headers={"Origin": "http://localhost:3000"}, json={}
    )
    assert res.status_code == 200


def test_garbage_bearer_token_is_401():
    res = _client().get("/api/v1/auth/me", headers={"Authorization": "Bearer not-a-real-token"})
    assert res.status_code == 401
    assert res.headers.get("www-authenticate") == "Bearer"


def test_password_change_revokes_other_sessions(mk_user):
    username, _ = mk_user("rotate")
    first = _client()
    t1 = first.post("/api/v1/auth/login", json=_login_body(username)).json()["session_token"]
    second = _client()
    t2 = second.post("/api/v1/auth/login", json=_login_body(username)).json()["session_token"]

    res = first.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": PASSWORD,
            "new_password": "NewAuditPass456!",
            "confirm_password": "NewAuditPass456!",
        },
        headers={"Authorization": f"Bearer {t1}"},
    )
    assert res.status_code == 200
    assert second.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {t2}"}).status_code == 401
    assert first.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {t1}"}).status_code == 401
    # the freshly issued replacement session works
    assert first.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {res.json()['session_token']}"}).status_code == 200
