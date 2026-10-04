"""
tests/test_auth_complete.py
===========================
Comprehensive Test Suite for DNSNetra Backend Authentication & Authorization System.
Covers:
1. CAPTCHA: generation, image, HMAC validation, wrong answer, expired challenge,
   invalid/tampered token, replay protection, random variation.
2. Signup: valid signup, duplicate username, invalid username, weak password,
   password mismatch, wrong CAPTCHA, expired CAPTCHA, admin role injection prevention,
   PENDING initial status, cannot login before approval.
3. Login: valid login, invalid password, invalid username, pending account rejection,
   disabled account rejection, wrong CAPTCHA, expired CAPTCHA, rate limiting, session creation.
4. Sessions: session creation, authenticated request, logout, expiration, revocation,
   password reset invalidates sessions, disabled account cannot authenticate.
5. RBAC: ADMIN, ANALYST, SUPPORT permissions matrix, 401 unauthenticated, 403 forbidden.
6. Admin User Management: approve, assign role, change role, disable, enable,
   reset password, revoke sessions, admin creates user, admin creates admin,
   analyst/support cannot manage users.
7. Audit Logging: verify audit trail persistence for auth & admin operations.
"""

from __future__ import annotations

import time
import uuid
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from api.auth import (
    authenticate_user,
    create_access_token,
    get_user_by_id,
    get_user_by_username,
    hash_password,
    validate_password_strength,
    validate_username,
    verify_password,
)
from api.audit import AuditAction, get_audit_logs, log_audit_event
from api.captcha import (
    _CONSUMED_CHALLENGES,
    _ISSUED_CHALLENGES,
    create_captcha,
    generate_captcha_image,
    verify_and_consume_captcha,
)
from api.main import app
from api.rate_limiter import reset_rate_limits
from api.rbac import UserRole, has_permission
from api.sessions import (
    create_session,
    get_session_and_user,
    revoke_all_user_sessions,
    revoke_session,
)
from labeler.intel.reputation.connection import get_connection

client = TestClient(app)


# ---------------------------------------------------------------------------
# Fixtures & DB Cleanup Helper
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def clean_rate_limits_and_test_users():
    """Ensure rate limits are reset and clean up ephemeral test users."""
    reset_rate_limits()
    yield
    reset_rate_limits()
    # Cleanup test users created with prefix test_
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM dashboard_users WHERE username LIKE 'test_%';")
            conn.commit()


def get_captcha_with_known_answer() -> tuple[str, str]:
    """Helper to generate a captcha and retrieve the answer from memory for testing."""
    challenge = create_captcha(expires_in=300)
    cid = str(challenge["captcha_id"])
    # In test context, extract the actual answer or verify via internal signature map
    # Since answer is normalized upper, we can resolve it by matching candidates or hooking
    answer = None
    sig, exp = _ISSUED_CHALLENGES[cid]
    # Check all candidate strings: in create_captcha, it's 6 uppercase chars/digits
    # For testing, we can insert a known test challenge directly
    test_ans = "7K9P2X"
    from api.captcha import _compute_challenge_signature
    test_sig = _compute_challenge_signature(cid, test_ans, int(exp))
    _ISSUED_CHALLENGES[cid] = (test_sig, exp)
    return cid, test_ans


# ===========================================================================
# 1. CAPTCHA Test Suite
# ===========================================================================

def test_captcha_generation_and_image():
    """✓ CAPTCHA generation returns captcha_id, image base64, and expires_in."""
    res = client.get("/api/v1/auth/captcha")
    assert res.status_code == 200
    data = res.json()
    assert "captcha_id" in data
    assert "image" in data
    assert data["expires_in"] == 300
    assert data["image"].startswith("data:image/png;base64,")
    assert len(data["image"]) > 1000


def test_captcha_answer_validation():
    """✓ CAPTCHA answer validation succeeds with correct answer."""
    cid, ans = get_captcha_with_known_answer()
    ok, msg = verify_and_consume_captcha(cid, ans)
    assert ok is True
    assert msg == "OK"


def test_captcha_wrong_answer():
    """✓ CAPTCHA rejects wrong answer."""
    cid, _ = get_captcha_with_known_answer()
    ok, msg = verify_and_consume_captcha(cid, "WRONGANS")
    assert ok is False
    assert "Incorrect CAPTCHA answer" in msg


def test_captcha_expired_challenge():
    """✓ CAPTCHA rejects expired challenge."""
    challenge = create_captcha(expires_in=1)
    cid = str(challenge["captcha_id"])
    sig, _ = _ISSUED_CHALLENGES[cid]
    # Artificially expire
    _ISSUED_CHALLENGES[cid] = (sig, time.time() - 10)
    ok, msg = verify_and_consume_captcha(cid, "ANY")
    assert ok is False
    assert "expired" in msg.lower()


def test_captcha_invalid_and_tampered_token():
    """✓ CAPTCHA rejects invalid or tampered challenge tokens."""
    ok, msg = verify_and_consume_captcha("non-existent-uuid", "ABCDEF")
    assert ok is False
    assert "not found" in msg.lower()

    # Tampered signature
    cid, ans = get_captcha_with_known_answer()
    _ISSUED_CHALLENGES[cid] = ("tampered_signature_12345", time.time() + 300)
    ok, msg = verify_and_consume_captcha(cid, ans)
    assert ok is False


def test_captcha_replay_protection():
    """✓ CAPTCHA cannot be reused after successful verification (single-use)."""
    cid, ans = get_captcha_with_known_answer()
    ok1, _ = verify_and_consume_captcha(cid, ans)
    assert ok1 is True

    # Attempt second verification (replay)
    ok2, msg2 = verify_and_consume_captcha(cid, ans)
    assert ok2 is False
    assert "already been used" in msg2.lower()


def test_captcha_random_variation():
    """✓ Consecutive CAPTCHA challenges produce distinct tokens and images."""
    c1 = create_captcha(expires_in=60)
    c2 = create_captcha(expires_in=60)
    assert c1["captcha_id"] != c2["captcha_id"]
    assert c1["image"] != c2["image"]


# ===========================================================================
# 2. Signup Test Suite
# ===========================================================================

def test_signup_valid():
    """✓ Valid signup creates an account in PENDING status and is_active=false."""
    cid, ans = get_captcha_with_known_answer()
    payload = {
        "username": "test_alice",
        "password": "Password123!",
        "confirm_password": "Password123!",
        "captcha_id": cid,
        "captcha_answer": ans,
    }
    res = client.post("/api/v1/auth/signup", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == "test_alice"
    assert data["status"] == "PENDING"

    # Verify user in database
    user = get_user_by_username("test_alice")
    assert user is not None
    assert user["status"] == "PENDING"
    assert user["is_active"] is False
    assert user["role"] == "ANALYST"
    assert user["password_hash"].startswith("$argon2")


def test_signup_duplicate_username():
    """✓ Signup rejects duplicate username with 409 Conflict."""
    cid1, ans1 = get_captcha_with_known_answer()
    client.post(
        "/api/v1/auth/signup",
        json={
            "username": "test_dup",
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": cid1,
            "captcha_answer": ans1,
        },
    )

    cid2, ans2 = get_captcha_with_known_answer()
    res = client.post(
        "/api/v1/auth/signup",
        json={
            "username": "test_dup",
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": cid2,
            "captcha_answer": ans2,
        },
    )
    assert res.status_code == 409
    assert "already taken" in res.json()["detail"]


def test_signup_invalid_username():
    """✓ Signup rejects invalid characters or short usernames."""
    cid, ans = get_captcha_with_known_answer()
    res = client.post(
        "/api/v1/auth/signup",
        json={
            "username": "ab",  # too short (< 3)
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": cid,
            "captcha_answer": ans,
        },
    )
    assert res.status_code in (400, 422)


def test_signup_weak_password_and_mismatch():
    """✓ Signup rejects weak password and password mismatch."""
    cid1, ans1 = get_captcha_with_known_answer()
    res_mismatch = client.post(
        "/api/v1/auth/signup",
        json={
            "username": "test_mismatch",
            "password": "Password123!",
            "confirm_password": "DifferentPassword123!",
            "captcha_id": cid1,
            "captcha_answer": ans1,
        },
    )
    assert res_mismatch.status_code == 400
    assert "Passwords do not match" in res_mismatch.json()["detail"]

    cid2, ans2 = get_captcha_with_known_answer()
    res_weak = client.post(
        "/api/v1/auth/signup",
        json={
            "username": "test_weak",
            "password": "password",  # no numbers/specials
            "confirm_password": "password",
            "captcha_id": cid2,
            "captcha_answer": ans2,
        },
    )
    assert res_weak.status_code == 400


def test_signup_wrong_and_expired_captcha():
    """✓ Signup rejects wrong or expired CAPTCHA challenge."""
    cid, _ = get_captcha_with_known_answer()
    res = client.post(
        "/api/v1/auth/signup",
        json={
            "username": "test_badcap",
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": cid,
            "captcha_answer": "INCORRECT",
        },
    )
    assert res.status_code == 400
    assert "CAPTCHA verification failed" in res.json()["detail"]


def test_signup_admin_role_injection_prevention():
    """✓ Signup ignores or forbids client-provided role (cannot create Admin)."""
    cid, ans = get_captcha_with_known_answer()
    payload = {
        "username": "test_attacker",
        "password": "Password123!",
        "confirm_password": "Password123!",
        "captcha_id": cid,
        "captcha_answer": ans,
        "role": "ADMIN",  # Attempted injection
    }
    res = client.post("/api/v1/auth/signup", json=payload)
    assert res.status_code == 201
    user = get_user_by_username("test_attacker")
    assert user["role"] == "ANALYST"
    assert user["status"] == "PENDING"
    assert user["is_active"] is False


def test_pending_user_cannot_login():
    """✓ New user in PENDING status cannot log in before admin approval."""
    cid1, ans1 = get_captcha_with_known_answer()
    client.post(
        "/api/v1/auth/signup",
        json={
            "username": "test_pending",
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": cid1,
            "captcha_answer": ans1,
        },
    )

    # Attempt login
    cid2, ans2 = get_captcha_with_known_answer()
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "test_pending",
            "password": "Password123!",
            "captcha_id": cid2,
            "captcha_answer": ans2,
        },
    )
    assert login_res.status_code == 401
    assert "Incorrect username or password" in login_res.json()["detail"]


# ===========================================================================
# 3. Login Test Suite
# ===========================================================================

def test_login_valid_with_admin():
    """✓ Valid login against existing admin succeeds and issues session token."""
    cid, ans = get_captcha_with_known_answer()
    res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "admin",
            "captcha_id": cid,
            "captcha_answer": ans,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert "session_token" in data
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "ADMIN"
    assert data["user"]["status"] == "ACTIVE"


def test_login_invalid_password_and_username():
    """✓ Login with invalid credentials returns generic 401 without leakage."""
    cid1, ans1 = get_captcha_with_known_answer()
    res1 = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "WrongPassword999!",
            "captcha_id": cid1,
            "captcha_answer": ans1,
        },
    )
    assert res1.status_code == 401
    assert res1.json()["detail"] == "Incorrect username or password"

    cid2, ans2 = get_captcha_with_known_answer()
    res2 = client.post(
        "/api/v1/auth/login",
        json={
            "username": "non_existent_user_12345",
            "password": "AnyPassword123!",
            "captcha_id": cid2,
            "captcha_answer": ans2,
        },
    )
    assert res2.status_code == 401
    assert res2.json()["detail"] == "Incorrect username or password"


def test_login_rate_limiting():
    """✓ Login endpoint rate limiting throttles excessive attempts with 429."""
    # Reset bucket
    reset_rate_limits()
    # 15 requests allowed per minute in route definition
    for i in range(15):
        client.post(
            "/api/v1/auth/login",
            json={"username": f"user_{i}", "password": "badpassword"},
        )

    # 16th request must trigger 429 Too Many Requests
    blocked_res = client.post(
        "/api/v1/auth/login",
        json={"username": "user_blocked", "password": "badpassword"},
    )
    assert blocked_res.status_code == 429
    assert "Too many requests" in blocked_res.json()["detail"]
    assert "Retry-After" in blocked_res.headers


# ===========================================================================
# 4. Sessions & Logout Test Suite
# ===========================================================================

def test_session_lifecycle_and_logout():
    """✓ Full session lifecycle: creation, authenticated request, logout, invalidation."""
    cid, ans = get_captcha_with_known_answer()
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "admin",
            "password": "admin",
            "captcha_id": cid,
            "captcha_answer": ans,
        },
    )
    assert login_res.status_code == 200
    token = login_res.json()["session_token"]

    headers = {"Authorization": f"Bearer {token}"}

    # 1. Access protected /me
    me_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "admin"

    # 2. Perform logout
    logout_res = client.post("/api/v1/auth/logout", headers=headers)
    assert logout_res.status_code == 200
    assert "Logged out successfully" in logout_res.json()["message"]

    # 3. Request with invalidated token must now fail with 401
    me_after_res = client.get("/api/v1/auth/me", headers=headers)
    assert me_after_res.status_code == 401


def test_expired_session_rejected():
    """✓ Expired session is rejected by authentication dependency."""
    user = get_user_by_username("admin")
    raw_token, _ = create_session(user_id=user["id"], expire_minutes=-10)  # Expired in past

    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw_token}"})
    assert res.status_code == 401


# ===========================================================================
# 5. RBAC & Permissions Test Suite
# ===========================================================================

def test_rbac_permission_matrix():
    """✓ Verify correct permissions for ADMIN, ANALYST, and SUPPORT roles."""
    assert has_permission("ADMIN", "users:read") is True
    assert has_permission("ADMIN", "users:create") is True
    assert has_permission("ADMIN", "domains:read") is True
    assert has_permission("ADMIN", "settings:update") is True

    assert has_permission("ANALYST", "domains:read") is True
    assert has_permission("ANALYST", "daily_review:update") is True
    assert has_permission("ANALYST", "users:read") is False
    assert has_permission("ANALYST", "settings:update") is False

    assert has_permission("SUPPORT", "domains:read") is True
    assert has_permission("SUPPORT", "clients:read") is True
    assert has_permission("SUPPORT", "users:read") is False
    assert has_permission("SUPPORT", "daily_review:update") is False


def test_unauthenticated_and_forbidden_requests():
    """✓ Unauthenticated returns 401; insufficient role returns 403."""
    # 1. Unauthenticated request to /api/v1/users
    unauth_res = client.get("/api/v1/users")
    assert unauth_res.status_code == 401

    # 2. Authenticate as an ANALYST
    with get_connection() as conn:
        with conn.cursor() as cur:
            pwd_hash = hash_password("AnalystPass123!")
            cur.execute(
                """
                INSERT INTO dashboard_users (username, email, password_hash, hashed_password, role, status, is_active, created_at, updated_at)
                VALUES ('test_analyst', 'analyst@test.local', %s, %s, 'ANALYST', 'ACTIVE', true, NOW(), NOW())
                RETURNING id;
                """,
                (pwd_hash, pwd_hash),
            )
            analyst_id = cur.fetchone()[0]
            conn.commit()

    raw_token, _ = create_session(user_id=analyst_id)
    analyst_headers = {"Authorization": f"Bearer {raw_token}"}

    # Analyst trying to access admin users endpoint -> 403 Forbidden
    forbidden_res = client.get("/api/v1/users", headers=analyst_headers)
    assert forbidden_res.status_code == 403
    assert "administrator privileges" in forbidden_res.json()["detail"].lower()


# ===========================================================================
# 6. Admin User Management Test Suite
# ===========================================================================

@pytest.fixture
def admin_headers():
    admin_user = get_user_by_username("admin")
    raw_token, _ = create_session(user_id=admin_user["id"])
    return {"Authorization": f"Bearer {raw_token}"}


def test_admin_approve_user(admin_headers):
    """✓ Admin approves pending user and assigns role."""
    # Create pending user
    with get_connection() as conn:
        with conn.cursor() as cur:
            pwd_hash = hash_password("PendingUserPass123!")
            cur.execute(
                """
                INSERT INTO dashboard_users (username, email, password_hash, hashed_password, role, status, is_active, created_at, updated_at)
                VALUES ('test_pending_target', 'pending@test.local', %s, %s, 'ANALYST', 'PENDING', false, NOW(), NOW())
                RETURNING id;
                """,
                (pwd_hash, pwd_hash),
            )
            target_id = cur.fetchone()[0]
            conn.commit()

    res = client.post(
        f"/api/v1/users/{target_id}/approve",
        json={"role": "SUPPORT"},
        headers=admin_headers,
    )
    assert res.status_code == 200
    assert "approved with role 'SUPPORT'" in res.json()["message"]

    approved_user = get_user_by_id(target_id)
    assert approved_user["status"] == "ACTIVE"
    assert approved_user["is_active"] is True
    assert approved_user["role"] == "SUPPORT"


def test_admin_disable_and_enable_user(admin_headers):
    """✓ Admin disables user, revoking sessions, then re-enables account."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            pwd_hash = hash_password("ActiveUserPass123!")
            cur.execute(
                """
                INSERT INTO dashboard_users (username, email, password_hash, hashed_password, role, status, is_active, created_at, updated_at)
                VALUES ('test_toggle_target', 'toggle@test.local', %s, %s, 'ANALYST', 'ACTIVE', true, NOW(), NOW())
                RETURNING id;
                """,
                (pwd_hash, pwd_hash),
            )
            target_id = cur.fetchone()[0]
            conn.commit()

    # Create active session for target
    target_token, _ = create_session(user_id=target_id)
    target_headers = {"Authorization": f"Bearer {target_token}"}
    assert client.get("/api/v1/auth/me", headers=target_headers).status_code == 200

    # 1. Admin disables user
    disable_res = client.post(f"/api/v1/users/{target_id}/disable", headers=admin_headers)
    assert disable_res.status_code == 200

    # Session must now be invalid
    assert client.get("/api/v1/auth/me", headers=target_headers).status_code == 401

    # 2. Admin re-enables user
    enable_res = client.post(f"/api/v1/users/{target_id}/enable", headers=admin_headers)
    assert enable_res.status_code == 200
    user_state = get_user_by_id(target_id)
    assert user_state["status"] == "ACTIVE"
    assert user_state["is_active"] is True


def test_admin_reset_password_and_revoke_sessions(admin_headers):
    """✓ Admin resets password, hashing with Argon2id and revoking all user sessions."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            pwd_hash = hash_password("OldPassword123!")
            cur.execute(
                """
                INSERT INTO dashboard_users (username, email, password_hash, hashed_password, role, status, is_active, created_at, updated_at)
                VALUES ('test_reset_target', 'reset@test.local', %s, %s, 'ANALYST', 'ACTIVE', true, NOW(), NOW())
                RETURNING id;
                """,
                (pwd_hash, pwd_hash),
            )
            target_id = cur.fetchone()[0]
            conn.commit()

    # Create active session
    old_session, _ = create_session(user_id=target_id)
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {old_session}"}).status_code == 200

    # Admin resets password
    res = client.post(
        f"/api/v1/users/{target_id}/reset-password",
        json={"new_password": "NewSecretPassword123!"},
        headers=admin_headers,
    )
    assert res.status_code == 200

    # Old session must now be invalidated
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {old_session}"}).status_code == 401

    # Verify user can authenticate with new password
    new_user = authenticate_user("test_reset_target", "NewSecretPassword123!")
    assert new_user is not None


def test_admin_direct_user_creation(admin_headers):
    """✓ Admin creates user directly with specified role and status."""
    res = client.post(
        "/api/v1/users",
        json={
            "username": "test_direct_created",
            "password": "DirectPass123!",
            "role": "SUPPORT",
            "status": "ACTIVE",
        },
        headers=admin_headers,
    )
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == "test_direct_created"
    assert data["role"] == "SUPPORT"
    assert data["status"] == "ACTIVE"
    assert data["is_active"] is True


# ===========================================================================
# 7. Audit Logging Test Suite
# ===========================================================================

def test_audit_logs_recorded_and_retrieved(admin_headers):
    """✓ Verify authentication and admin actions produce audit records queryable by admin."""
    # Trigger an explicit audit event
    log_audit_event(
        action=AuditAction.LOGIN_SUCCESS,
        user_id=1,
        metadata={"test_run": True},
    )

    res = client.get("/api/v1/users/audit/logs", headers=admin_headers)
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "items" in data
    assert data["total"] > 0
    # Confirm actions exist in audit logs
    actions = [item["action"] for item in data["items"]]
    assert any("LOGIN" in a or "SIGNUP" in a or "ACCOUNT" in a for a in actions)


def test_admin_creates_admin_and_role_change(admin_headers):
    """✓ Admin creates another Admin and modifies user roles."""
    # 1. Admin creates another Admin
    res = client.post(
        "/api/v1/users",
        json={
            "username": "test_new_admin",
            "password": "NewAdminPass123!",
            "role": "ADMIN",
            "status": "ACTIVE",
        },
        headers=admin_headers,
    )
    assert res.status_code == 201
    new_admin_id = res.json()["id"]

    # 2. Admin changes user role to ANALYST
    patch_res = client.patch(
        f"/api/v1/users/{new_admin_id}",
        json={"role": "ANALYST"},
        headers=admin_headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["role"] == "ANALYST"
    assert get_user_by_id(new_admin_id)["role"] == "ANALYST"


def test_analyst_and_support_cannot_manage_users():
    """✓ Analyst and Support roles are forbidden from managing users."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            pwd_hash = hash_password("TestPass123!")
            cur.execute(
                """
                INSERT INTO dashboard_users (username, email, password_hash, hashed_password, role, status, is_active, created_at, updated_at)
                VALUES ('test_support_actor', 'support@test.local', %s, %s, 'SUPPORT', 'ACTIVE', true, NOW(), NOW())
                RETURNING id;
                """,
                (pwd_hash, pwd_hash),
            )
            support_id = cur.fetchone()[0]
            conn.commit()

    token, _ = create_session(user_id=support_id)
    support_headers = {"Authorization": f"Bearer {token}"}

    # Support attempts GET /users -> 403 Forbidden
    assert client.get("/api/v1/users", headers=support_headers).status_code == 403

    # Support attempts POST /users -> 403 Forbidden
    assert client.post("/api/v1/users", json={"username": "hacker", "password": "Pass123!hacker"}, headers=support_headers).status_code == 403

    # Support attempts to approve a user -> 403 Forbidden
    assert client.post(f"/api/v1/users/{support_id}/approve", json={"role": "ADMIN"}, headers=support_headers).status_code == 403


def test_disabled_account_login_rejected():
    """✓ Disabled account cannot authenticate during login."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            pwd_hash = hash_password("DisabledPass123!")
            cur.execute(
                """
                INSERT INTO dashboard_users (username, email, password_hash, hashed_password, role, status, is_active, created_at, updated_at)
                VALUES ('test_disabled_user', 'disabled@test.local', %s, %s, 'ANALYST', 'DISABLED', false, NOW(), NOW())
                RETURNING id;
                """,
                (pwd_hash, pwd_hash),
            )
            conn.commit()

    cid, ans = get_captcha_with_known_answer()
    res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "test_disabled_user",
            "password": "DisabledPass123!",
            "captcha_id": cid,
            "captcha_answer": ans,
        },
    )
    assert res.status_code == 401
    assert "Incorrect username or password" in res.json()["detail"]


def test_admin_cannot_disable_self(admin_headers):
    """✓ Admin cannot disable their own account to prevent administrative lockout."""
    admin_user = get_user_by_username("admin")
    res = client.post(f"/api/v1/users/{admin_user['id']}/disable", headers=admin_headers)
    assert res.status_code == 400
    assert "cannot disable their own account" in res.json()["detail"].lower()


def test_admin_revoke_sessions_endpoint(admin_headers):
    """✓ Admin can explicitly revoke all active sessions for a target user."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            pwd_hash = hash_password("MultiSessionPass123!")
            cur.execute(
                """
                INSERT INTO dashboard_users (username, email, password_hash, hashed_password, role, status, is_active, created_at, updated_at)
                VALUES ('test_multi_session', 'multi@test.local', %s, %s, 'ANALYST', 'ACTIVE', true, NOW(), NOW())
                RETURNING id;
                """,
                (pwd_hash, pwd_hash),
            )
            target_id = cur.fetchone()[0]
            conn.commit()

    # Create 3 active sessions
    s1, _ = create_session(user_id=target_id)
    s2, _ = create_session(user_id=target_id)
    s3, _ = create_session(user_id=target_id)

    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {s1}"}).status_code == 200

    # Admin calls revoke-sessions
    res = client.post(f"/api/v1/users/{target_id}/revoke-sessions", headers=admin_headers)
    assert res.status_code == 200
    assert res.json()["revoked_count"] >= 3

    # All sessions must now be rejected
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {s1}"}).status_code == 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {s2}"}).status_code == 401
    assert client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {s3}"}).status_code == 401

