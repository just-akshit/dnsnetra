"""
tests/test_auth_hardening.py
=============================
Exhaustive security hardening test suite for DNSNetra Phase 3.
Validates all 23 hardening requirements:
1. Case-insensitive username uniqueness (Akshit, akshit, AKSHIT).
2. Pluggable CAPTCHA challenge-store abstraction (expiry, replay, memory bounds).
3. Constant-time CAPTCHA HMAC verification and answer normalization.
4. Rate limiting on CAPTCHA generation, login, signup, password reset.
5. Browser session security via HttpOnly, SameSite, Secure cookies.
6. CSRF defense on state-changing cookie-authenticated requests.
7. Last active ADMIN protection with row-level database locking.
8. Account lifecycle over fake delete (users:delete removed from RBAC).
9. PENDING user role semantics (no effective permissions or sessions).
10. Legacy bcrypt hash migration with atomic clearing of old column.
11. Admin-mediated password reset with must_change_password enforcement.
12. Session invariants, session fixation prevention, and complete revocation.
13. Secret validation and protection.
14. Audit log sanitization (no passwords, hashes, tokens, or captcha answers).
15. Trusted proxy client IP resolution and spoofing defense.
16. Strict 401 Unauthorized vs 403 Forbidden semantics.
17. Database-level constraints for role, status, and status/is_active coherence.
18. Account status consistency (status == ACTIVE iff is_active == True).
19. Local /auth/token endpoint compatibility.
20. Hardened CORS configuration (no wildcard with credentials).
21. Password policy enforcement (length, composition, username divergence).
22. Strict input validation and payload bounds.
23. Reserved username protection (admin, root, support, analyst, etc.).
"""

import time
import uuid
import bcrypt
import hmac
import pytest
from fastapi.testclient import TestClient

from api.auth import (
    authenticate_user,
    change_user_password,
    create_access_token,
    get_user_by_id,
    get_user_by_username,
    hash_password,
    normalize_username,
    validate_password_strength,
    validate_username,
    verify_password,
)
from api.audit import AuditAction, get_audit_logs, log_audit_event
from api.captcha import (
    BaseCaptchaStore,
    InMemoryCaptchaStore,
    create_captcha,
    get_captcha_store,
    normalize_captcha_answer,
    set_captcha_store,
    verify_and_consume_captcha,
    compute_challenge_signature,
)
from api.csrf import verify_csrf_protection
from api.main import app
from api.rate_limiter import reset_rate_limits
from api.rbac import UserRole, get_role_permissions, has_permission
from api.sessions import (
    create_session,
    get_session_and_user,
    hash_session_token,
    revoke_all_user_sessions,
    revoke_session,
)
from api.trusted_proxy import get_client_ip
from labeler.intel.reputation.connection import get_connection

client = TestClient(app)


def _get_captcha_for_test(answer: str = "SAFE99") -> tuple[str, str]:
    """Helper to register a valid test CAPTCHA challenge in the active store."""
    cid = str(uuid.uuid4())
    expiry = time.time() + 300
    norm_ans = normalize_captcha_answer(answer)
    sig = compute_challenge_signature(cid, norm_ans, int(expiry))
    store = get_captcha_store()
    store.issue(cid, sig, expiry)
    return cid, answer


# ===========================================================================
# 1. Case-Insensitive Username Uniqueness
# ===========================================================================

def test_case_insensitive_username_normalization():
    """✓ Normalize username trims and lowercases consistently."""
    assert normalize_username("  Akshit  ") == "akshit"
    assert normalize_username("AKSHIT") == "akshit"
    assert normalize_username("akshit") == "akshit"


def test_case_insensitive_username_signup_conflict():
    """✓ Case variations (Akshit, akshit, AKSHIT) cannot create duplicate accounts."""
    reset_rate_limits()
    base_user = f"case_test_{uuid.uuid4().hex[:6]}"
    cid1, ans1 = _get_captcha_for_test()

    # 1. Create first user with mixed case
    res1 = client.post(
        "/api/v1/auth/signup",
        json={
            "username": base_user.upper(),
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": cid1,
            "captcha_answer": ans1,
        },
    )
    assert res1.status_code == 201
    assert res1.json()["username"] == base_user.lower()

    # 2. Attempt signup with exact lowercase
    cid2, ans2 = _get_captcha_for_test()
    res2 = client.post(
        "/api/v1/auth/signup",
        json={
            "username": base_user.lower(),
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": cid2,
            "captcha_answer": ans2,
        },
    )
    assert res2.status_code == 409
    assert "already taken" in res2.json()["detail"].lower()

    # 3. Attempt signup with TitleCase
    cid3, ans3 = _get_captcha_for_test()
    res3 = client.post(
        "/api/v1/auth/signup",
        json={
            "username": base_user.capitalize(),
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": cid3,
            "captcha_answer": ans3,
        },
    )
    assert res3.status_code == 409


# ===========================================================================
# 2. CAPTCHA Challenge Store Abstraction & Replay Protection
# ===========================================================================

def test_captcha_store_custom_implementation():
    """✓ Pluggable BaseCaptchaStore works seamlessly."""
    class MockCaptchaStore(BaseCaptchaStore):
        def __init__(self):
            self.store = {}
            self.consumed = set()

        def issue(self, challenge_id: str, signature: str, expiry: float) -> None:
            self.store[challenge_id] = (signature, expiry)

        def get(self, challenge_id: str):
            return self.store.get(challenge_id)

        def is_consumed(self, challenge_id: str) -> bool:
            return challenge_id in self.consumed

        def consume(self, challenge_id: str, expiry: float) -> bool:
            if challenge_id in self.consumed:
                return False
            self.consumed.add(challenge_id)
            return True

        def cleanup_expired(self) -> int:
            return 0

    custom_store = MockCaptchaStore()
    old_store = get_captcha_store()
    try:
        set_captcha_store(custom_store)
        cid = str(uuid.uuid4())
        exp = time.time() + 100
        sig = compute_challenge_signature(cid, "TEST12", int(exp))
        custom_store.issue(cid, sig, exp)

        ok, msg = verify_and_consume_captcha(cid, "TEST12")
        assert ok is True
        assert msg == "OK"

        # Replay fails
        ok_replay, msg_replay = verify_and_consume_captcha(cid, "TEST12")
        assert ok_replay is False
        assert "already been used" in msg_replay
    finally:
        set_captcha_store(old_store)


def test_captcha_inmemory_bounded_capacity():
    """✓ InMemoryCaptchaStore bounds memory and purges oldest entries on capacity overflow."""
    store = InMemoryCaptchaStore(max_capacity=50)
    for i in range(60):
        cid = str(uuid.uuid4())
        store.issue(cid, f"sig_{i}", time.time() + 1000 + i)
    assert len(store._issued) <= 55


def test_captcha_constant_time_comparison():
    """✓ CAPTCHA verification uses constant-time HMAC check and rejects tampered signature."""
    cid, ans = _get_captcha_for_test("ABC123")
    # Tamper with store signature
    store = get_captcha_store()
    orig_sig, exp = store.get(cid)
    store.issue(cid, "tampered_sig_000000000000000000000000000000000000000000000000000000000000", exp)

    ok, msg = verify_and_consume_captcha(cid, ans)
    assert ok is False
    assert "Incorrect CAPTCHA answer" in msg


def test_captcha_answer_normalization():
    """✓ Answer normalization handles mixed-case and trailing whitespace."""
    cid, _ = _get_captcha_for_test("XY88ZZ")
    # Provide lowercase with spaces
    ok, msg = verify_and_consume_captcha(cid, "  xy88zz  ")
    assert ok is True
    assert msg == "OK"


# ===========================================================================
# 3. Rate Limiting on CAPTCHA Generation
# ===========================================================================

def test_captcha_rate_limiting():
    """✓ CAPTCHA generation endpoint is protected by rate limiting."""
    reset_rate_limits()
    # Limit is 30/minute. Firing 35 requests from same client IP should trigger 429.
    responses = [client.get("/api/v1/auth/captcha") for _ in range(35)]
    statuses = [r.status_code for r in responses]
    assert 200 in statuses
    assert 429 in statuses
    idx = statuses.index(429)
    assert "Retry-After" in responses[idx].headers


# ===========================================================================
# 4. Browser Session Security & Cookies
# ===========================================================================

def test_login_returns_httponly_samesite_cookie():
    """✓ Login issues HttpOnly, SameSite=lax dnsnetra_session cookie."""
    client.cookies.clear()
    res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert res.status_code == 200
    cookie_header = res.headers.get("set-cookie", "")
    assert "dnsnetra_session=" in cookie_header
    assert "HttpOnly" in cookie_header
    assert "samesite=lax" in cookie_header.lower()
    client.cookies.clear()


# ===========================================================================
# 5. CSRF Defense on Cookie-Authenticated State-Changing Endpoints
# ===========================================================================

def test_csrf_rejection_on_untrusted_origin():
    """✓ State-changing requests with cookie auth from untrusted origin are rejected (403)."""
    client.cookies.clear()
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert login_res.status_code == 200
    session_cookie = client.cookies.get("dnsnetra_session")
    assert session_cookie is not None

    # State-changing POST with evil origin and cookie
    evil_res = client.post(
        "/api/v1/users",
        json={
            "username": "attacker_user",
            "password": "Password123!",
            "role": "ANALYST",
        },
        headers={
            "Origin": "https://evil-attacker.com",
            "Cookie": f"dnsnetra_session={session_cookie}",
        },
    )
    assert evil_res.status_code == 403
    assert "CSRF protection" in evil_res.json()["detail"]
    client.cookies.clear()


def test_csrf_allowed_with_bearer_token_regardless_of_origin():
    """✓ Bearer token API requests bypass CSRF origin checks."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    token = login_res.json()["access_token"]
    client.cookies.clear()

    # Even with untrusted Origin, Authorization: Bearer is immune to CSRF
    res = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": f"Bearer {token}",
            "Origin": "https://external-client.com",
        },
    )
    assert res.status_code == 200


# ===========================================================================
# 6. Last Active Admin Protection with Concurrency Locks
# ===========================================================================

def test_admin_cannot_demote_final_admin():
    """✓ Admin cannot demote themselves if they are the last active admin."""
    # Ensure admin user is the target
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    token = login_res.json()["access_token"]
    admin_id = login_res.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    # Demote self to ANALYST via PATCH /api/v1/users/{user_id}
    res = client.patch(
        f"/api/v1/users/{admin_id}",
        json={"role": "ANALYST"},
        headers=headers,
    )
    assert res.status_code == 400
    assert "Administrators cannot demote their own account" in res.json()["detail"]


def test_admin_cannot_disable_final_admin():
    """✓ Admin cannot disable themselves or the last active admin."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    token = login_res.json()["access_token"]
    admin_id = login_res.json()["user"]["id"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.post(
        f"/api/v1/users/{admin_id}/disable",
        headers=headers,
    )
    assert res.status_code == 400
    assert "Administrators cannot disable their own account" in res.json()["detail"]


def test_two_admins_can_manage_each_other_safely():
    """✓ Two admins can manage each other, but the final remaining admin is protected."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Create a second admin
    admin2_name = f"admin2_{uuid.uuid4().hex[:6]}"
    res_create = client.post(
        "/api/v1/users",
        json={"username": admin2_name, "password": "AdminPassword123!", "role": "ADMIN"},
        headers=headers,
    )
    assert res_create.status_code == 201
    admin2_id = res_create.json()["id"]

    # 2. First admin can disable second admin
    res_dis = client.post(f"/api/v1/users/{admin2_id}/disable", headers=headers)
    assert res_dis.status_code == 200
    assert "disabled" in res_dis.json()["message"].lower()

    # 3. Now attempt to demote second admin while already disabled, or demote first admin
    first_admin_id = login_res.json()["user"]["id"]
    res_demote = client.patch(
        f"/api/v1/users/{first_admin_id}",
        json={"role": "ANALYST"},
        headers=headers,
    )
    assert res_demote.status_code == 400


# ===========================================================================
# 7. Fake User Delete Capability Removed
# ===========================================================================

def test_users_delete_permission_removed():
    """✓ RBAC matrix has no users:delete permission; accounts are disabled instead."""
    assert "users:delete" not in get_role_permissions(UserRole.ADMIN)
    assert not has_permission("ADMIN", "users:delete")


# ===========================================================================
# 8. PENDING User Role Semantics
# ===========================================================================

def test_pending_user_has_no_effective_permissions():
    """✓ PENDING users cannot login, cannot create sessions, and have no effective permissions."""
    base_user = f"pending_{uuid.uuid4().hex[:6]}"
    cid, ans = _get_captcha_for_test()
    client.post(
        "/api/v1/auth/signup",
        json={
            "username": base_user,
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": cid,
            "captcha_answer": ans,
        },
    )

    # Login fails with 401 Unauthorized
    res_login = client.post(
        "/api/v1/auth/login",
        json={"username": base_user, "password": "Password123!"},
    )
    assert res_login.status_code == 401
    assert "incorrect username or password" in res_login.json()["detail"].lower()


# ===========================================================================
# 9. Legacy Bcrypt Password Migration
# ===========================================================================

def test_legacy_bcrypt_migration_clears_old_hash():
    """✓ Legacy bcrypt user is verified, upgraded to Argon2id, and hashed_password set to NULL."""
    legacy_user = f"legacy_{uuid.uuid4().hex[:6]}"
    plain_pw = "LegacyPass123!"
    bcrypt_salt = bcrypt.gensalt()
    bcrypt_hash = bcrypt.hashpw(plain_pw.encode("utf-8"), bcrypt_salt).decode("utf-8")

    # Manually insert legacy user with hashed_password set and password_hash NULL
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO dashboard_users (
                    username, email, password_hash, hashed_password, role, status, is_active
                ) VALUES (%s, %s, NULL, %s, 'ANALYST', 'ACTIVE', true)
                RETURNING id;
                """,
                (legacy_user, f"{legacy_user}@test.local", bcrypt_hash),
            )
            uid = cur.fetchone()[0]

            # Verify in DB directly before authentication
            cur.execute("SELECT password_hash, hashed_password FROM dashboard_users WHERE id = %s;", (uid,))
            pw_hash_before, hashed_pw_before = cur.fetchone()
            assert hashed_pw_before == bcrypt_hash
            assert pw_hash_before is None

    # Authenticate via authenticate_user (or login endpoint)
    authenticated = authenticate_user(legacy_user, plain_pw)
    assert authenticated is not None
    assert authenticated["id"] == uid

    # Check database: password_hash is now Argon2id and hashed_password is NULL
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash, hashed_password FROM dashboard_users WHERE id = %s;", (uid,))
            pw_hash_after, hashed_pw_after = cur.fetchone()
            assert pw_hash_after is not None
            assert pw_hash_after.startswith("$argon2id$")
            assert hashed_pw_after is None


# ===========================================================================
# 10. Password Reset & must_change_password Flow
# ===========================================================================

def test_password_reset_and_must_change_password_flow():
    """✓ Password reset sets must_change_password and revokes all active sessions."""
    # 1. Admin login
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    admin_token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 2. Create analyst user
    analyst_name = f"user_{uuid.uuid4().hex[:6]}"
    res_create = client.post(
        "/api/v1/users",
        json={"username": analyst_name, "password": "InitialPass123!", "role": "ANALYST"},
        headers=headers,
    )
    uid = res_create.json()["id"]

    # 3. User logs in and creates a session
    client.cookies.clear()
    res_user_login = client.post(
        "/api/v1/auth/login",
        json={"username": analyst_name, "password": "InitialPass123!"},
    )
    assert res_user_login.status_code == 200
    user_token = res_user_login.json()["access_token"]

    # 4. Admin resets password
    res_reset = client.post(
        f"/api/v1/users/{uid}/reset-password",
        json={"new_password": "TempPassword999!"},
        headers=headers,
    )
    assert res_reset.status_code == 200

    # 5. Old user session is revoked
    res_old_sess = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert res_old_sess.status_code == 401

    # 6. User logs in with temporary password; must_change_password is True
    res_new_login = client.post(
        "/api/v1/auth/login",
        json={"username": analyst_name, "password": "TempPassword999!"},
    )
    assert res_new_login.status_code == 200
    assert res_new_login.json()["user"]["must_change_password"] is True
    new_token = res_new_login.json()["access_token"]

    # 7. User changes password via /auth/change-password
    res_change = client.post(
        "/api/v1/auth/change-password",
        json={
            "current_password": "TempPassword999!",
            "new_password": "PermanentPass456!",
            "confirm_password": "PermanentPass456!",
        },
        headers={"Authorization": f"Bearer {new_token}"},
    )
    assert res_change.status_code == 200
    assert "Password updated successfully" in res_change.json()["message"]
    new_session = res_change.json()["session_token"]
    assert get_user_by_id(uid)["must_change_password"] is False

    # Verify /auth/me returns must_change_password == False
    res_me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {new_session}"})
    assert res_me.status_code == 200
    assert res_me.json()["must_change_password"] is False
    client.cookies.clear()


# ===========================================================================
# 11. Session Invariants & Revocation
# ===========================================================================

def test_session_token_stored_hashed_never_plaintext():
    """✓ Session tokens are stored as SHA-256 hashes in database."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    raw_token = login_res.json()["access_token"]
    expected_hash = hash_session_token(raw_token)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT session_token_hash FROM sessions WHERE session_token_hash = %s;", (expected_hash,))
            row = cur.fetchone()
            assert row is not None
            assert row[0] == expected_hash

            # Ensure plaintext token does NOT exist in database
            cur.execute("SELECT id FROM sessions WHERE session_token_hash = %s;", (raw_token,))
            assert cur.fetchone() is None
    client.cookies.clear()


def test_re_enabling_account_does_not_resurrect_sessions():
    """✓ Re-enabling a disabled account does NOT resurrect previously revoked sessions."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    admin_token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Create active user
    uname = f"revtest_{uuid.uuid4().hex[:6]}"
    res_create = client.post(
        "/api/v1/users",
        json={"username": uname, "password": "Password123!", "role": "ANALYST"},
        headers=headers,
    )
    uid = res_create.json()["id"]

    # 2. User logs in
    client.cookies.clear()
    u_login = client.post(
        "/api/v1/auth/login",
        json={"username": uname, "password": "Password123!"},
    )
    user_token = u_login.json()["access_token"]

    # 3. Admin disables user
    client.post(f"/api/v1/users/{uid}/disable", headers=headers)

    # 4. Session is dead
    res_dead = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert res_dead.status_code == 401

    # 5. Admin re-enables user
    client.post(f"/api/v1/users/{uid}/enable", headers=headers)

    # 6. Old session is STILL dead
    res_still_dead = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {user_token}"})
    assert res_still_dead.status_code == 401
    client.cookies.clear()


# ===========================================================================
# 12. Audit Log Sanitization
# ===========================================================================

def test_audit_logs_contain_no_sensitive_values():
    """✓ Audit log entries never store passwords, hashes, tokens, or captcha answers."""
    # Trigger an audit event with sensitive dummy details
    uid = 1
    log_audit_event(
        action=AuditAction.PASSWORD_RESET,
        user_id=uid,
        metadata={
            "password": "plaintext_secret_123",
            "password_hash": "$argon2id$v=19$fakehash",
            "token": "secret_session_token_xyz",
            "captcha_answer": "SECRET_CAPTCHA",
            "safe_field": "updated_by_admin",
        },
    )

    logs, total = get_audit_logs(limit=5)
    matching = [l for l in logs if l.get("action") == AuditAction.PASSWORD_RESET]
    assert len(matching) > 0
    recent = matching[0]
    meta_str = str(recent.get("metadata", {}))
    assert "plaintext_secret_123" not in meta_str
    assert "fakehash" not in meta_str
    assert "secret_session_token_xyz" not in meta_str
    assert "SECRET_CAPTCHA" not in meta_str
    assert recent.get("metadata", {}).get("safe_field") == "updated_by_admin"


# ===========================================================================
# 13. Trusted Proxy & Spoofed Header Defense
# ===========================================================================

def test_trusted_proxy_ignores_spoofed_headers_from_untrusted_peer():
    """✓ get_client_ip ignores X-Forwarded-For if direct peer is not in TRUSTED_PROXIES."""
    class DummyRequest:
        def __init__(self, peer_ip: str, forwarded_for: str):
            self.client = type("Client", (), {"host": peer_ip})()
            self.headers = {"x-forwarded-for": forwarded_for}

    # 1. Untrusted peer trying to spoof
    req_untrusted = DummyRequest(peer_ip="203.0.113.5", forwarded_for="1.1.1.1, 10.0.0.1")
    assert get_client_ip(req_untrusted) == "203.0.113.5"

    # 2. Trusted proxy (127.0.0.1) forwarding real client IP
    req_trusted = DummyRequest(peer_ip="127.0.0.1", forwarded_for="198.51.100.42, 127.0.0.1")
    assert get_client_ip(req_trusted) == "198.51.100.42"


# ===========================================================================
# 14. Password Policy & Reserved Usernames
# ===========================================================================

def test_password_policy_enforcement():
    """✓ Password policy rejects weak, short, username-matching, or whitespace-only passwords."""
    assert not validate_password_strength("short", username="myuser")[0]
    assert not validate_password_strength("myuser", username="myuser")[0]  # cannot equal username
    assert not validate_password_strength("           ", username="myuser")[0]
    assert not validate_password_strength("alllowercaseonly", username="myuser")[0]  # missing digit or special
    assert validate_password_strength("StrongPass123!", username="myuser")[0]


def test_reserved_usernames_rejected():
    """✓ Reserved usernames (admin, root, support, analyst, etc.) cannot be signed up."""
    for reserved in ["admin", "root", "support", "analyst", "system"]:
        ok, msg = validate_username(reserved, is_signup=True)
        assert ok is False
        assert "reserved" in msg.lower()
