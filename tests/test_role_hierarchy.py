"""
tests/test_role_hierarchy.py
============================
Tests for the SUPER_ADMIN role, the role hierarchy policy, and the
actor-vs-target matrix on every user-management route.
"""

from __future__ import annotations

import uuid

import pytest

from api.rbac import UserRole, get_role_permissions
from api.user_admin_policy import MANAGEABLE_ROLES, can_assign_role, can_manage
from tests.auth_testkit import auth_headers_for
from tests.test_auth_security_audit import _client, _db, mk_user


def test_super_admin_role_exists_and_inherits_admin_permissions():
    assert UserRole.SUPER_ADMIN.value == "SUPER_ADMIN"
    assert get_role_permissions("SUPER_ADMIN") >= get_role_permissions("ADMIN")


def test_database_role_constraint_allows_super_admin():
    definition = _db(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'dashboard_users'::regclass "
        "AND conname = 'chk_dashboard_users_role';"
    )[0][0]
    assert "SUPER_ADMIN" in definition


from api.user_admin_policy import can_assign_role, can_manage


def _actor(role: str, uid: int = 1) -> dict:
    return {"id": uid, "role": role}


def test_admin_can_manage_staff_only():
    for target_role in ("ANALYST", "SUPPORT"):
        ok, reason = can_manage(_actor("ADMIN"), _actor(target_role, 2))
        assert ok, reason


def test_admin_cannot_manage_admins_or_super_admins():
    for target_role in ("ADMIN", "SUPER_ADMIN"):
        ok, _ = can_manage(_actor("ADMIN"), _actor(target_role, 2))
        assert not ok


def test_super_admin_can_manage_everyone_else():
    for target_role in ("SUPER_ADMIN", "ADMIN", "ANALYST", "SUPPORT"):
        ok, reason = can_manage(_actor("SUPER_ADMIN"), _actor(target_role, 2))
        assert ok, reason


def test_nobody_can_manage_themselves():
    ok, _ = can_manage(_actor("SUPER_ADMIN", 5), _actor("SUPER_ADMIN", 5))
    assert not ok


def test_analyst_and_support_cannot_manage_anyone():
    for actor_role in ("ANALYST", "SUPPORT"):
        ok, _ = can_manage(_actor(actor_role), _actor("ANALYST", 2))
        assert not ok


def test_role_assignment_rules():
    assert can_assign_role("SUPER_ADMIN", "SUPER_ADMIN")[0]
    assert can_assign_role("SUPER_ADMIN", "ADMIN")[0]
    assert not can_assign_role("ADMIN", "ADMIN")[0]
    assert not can_assign_role("ADMIN", "SUPER_ADMIN")[0]
    assert can_assign_role("ADMIN", "ANALYST")[0]
    assert not can_assign_role("ANALYST", "ANALYST")[0]


def test_admin_cannot_promote_staff_to_admin():
    ok, _ = can_manage(_actor("ADMIN"), _actor("ANALYST", 2), new_role="ADMIN")
    assert not ok


# ---------------------------------------------------------------------------
# Route matrix: every actor role x target role for the management actions.
# ---------------------------------------------------------------------------

ROLES = ("SUPER_ADMIN", "ADMIN", "ANALYST", "SUPPORT")


def _allowed(actor_role: str, target_role: str) -> bool:
    return target_role in MANAGEABLE_ROLES.get(actor_role, set())


@pytest.mark.parametrize("actor_role", ROLES)
@pytest.mark.parametrize("target_role", ROLES)
@pytest.mark.parametrize("action", ["update", "deactivate", "reset"])
def test_management_matrix(mk_user, actor_role, target_role, action):
    _, actor_id = mk_user(f"matrix_actor_{actor_role}", role=actor_role)
    _, target_id = mk_user(f"matrix_target_{target_role}", role=target_role)
    headers = auth_headers_for(actor_id)
    client = _client()

    if action == "update":
        res = client.patch(
            f"/api/v1/users/{target_id}",
            json={"role": "ANALYST"},
            headers=headers,
        )
    elif action == "deactivate":
        res = client.post(f"/api/v1/users/{target_id}/disable", headers=headers)
    else:
        res = client.post(f"/api/v1/users/{target_id}/reset-password", headers=headers)

    expected = 200 if _allowed(actor_role, target_role) else 403
    assert res.status_code == expected, res.text


@pytest.mark.parametrize("actor_role", ROLES)
@pytest.mark.parametrize("new_role", ROLES)
def test_create_matrix(mk_user, actor_role, new_role):
    _, actor_id = mk_user(f"creator_{actor_role}", role=actor_role)
    headers = auth_headers_for(actor_id)
    username = f"test_created_{uuid.uuid4().hex[:10]}"

    res = _client().post(
        "/api/v1/users",
        headers=headers,
        json={
            "username": username,
            "password": "CreatedPass123!",
            "role": new_role,
            "status": "ACTIVE",
        },
    )

    expected = 201 if _allowed(actor_role, new_role) else 403
    assert res.status_code == expected, res.text


def test_enable_cannot_escalate_a_higher_tier_account(mk_user):
    _, admin_id = mk_user("enable_admin_actor", role="ADMIN")
    _, super_id = mk_user("enable_super_target", role="SUPER_ADMIN", status="DISABLED")

    res = _client().post(
        f"/api/v1/users/{super_id}/enable",
        headers=auth_headers_for(admin_id),
    )
    assert res.status_code == 403


def test_revoke_sessions_cannot_touch_a_higher_tier_account(mk_user):
    _, admin_id = mk_user("revoke_admin_actor", role="ADMIN")
    _, super_id = mk_user("revoke_super_target", role="SUPER_ADMIN")

    res = _client().post(
        f"/api/v1/users/{super_id}/revoke-sessions",
        headers=auth_headers_for(admin_id),
    )
    assert res.status_code == 403


def test_denied_management_writes_an_authorization_audit(mk_user):
    _, admin_id = mk_user("auditdenied_actor", role="ADMIN")
    _, super_id = mk_user("auditdenied_target", role="SUPER_ADMIN")

    res = _client().post(
        f"/api/v1/users/{super_id}/disable",
        headers=auth_headers_for(admin_id),
    )
    assert res.status_code == 403
    rows = _db(
        "SELECT action FROM audit_logs WHERE user_id = %s AND target_user_id = %s",
        (admin_id, super_id),
    )
    assert ("AUTHORIZATION_DENIED",) in rows


# ---------------------------------------------------------------------------
# Server-generated temporary password reset
# ---------------------------------------------------------------------------

from tests.auth_testkit import session_token_from_client
from tests.test_auth_security_audit import _login_body


def test_reset_returns_a_generated_password_once(mk_user):
    _, super_id = mk_user("superreset", role="SUPER_ADMIN")
    username, target_id = mk_user("resettarget", role="ANALYST")
    headers = auth_headers_for(super_id)

    res = _client().post(f"/api/v1/users/{target_id}/reset-password", headers=headers)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["username"] == username
    password = body["temporary_password"]
    assert len(password) >= 16
    assert res.headers["cache-control"].startswith("no-store")

    row = _db("SELECT must_change_password FROM dashboard_users WHERE id = %s", (target_id,))
    assert row[0][0] is True

    # The old password no longer works; the new one does.
    assert _client().post("/api/v1/auth/login", json=_login_body(username)).status_code == 401
    login_res = _client().post(
        "/api/v1/auth/login",
        json=_login_body(username, password),
    )
    assert login_res.status_code == 200

    # Audit never contains the password.
    audit = _db(
        "SELECT metadata::text FROM audit_logs WHERE target_user_id = %s",
        (target_id,),
    )
    assert all(password not in (m or "") for (m,) in audit)


def test_reset_rejects_self_and_writes_a_denial_audit(mk_user):
    _, super_id = mk_user("selfreset", role="SUPER_ADMIN")
    res = _client().post(
        f"/api/v1/users/{super_id}/reset-password",
        headers=auth_headers_for(super_id),
    )
    assert res.status_code == 403
    rows = _db(
        "SELECT action FROM audit_logs WHERE user_id = %s AND target_user_id = %s",
        (super_id, super_id),
    )
    assert ("AUTHORIZATION_DENIED",) in rows


def test_denied_reset_writes_audit_for_admin_targeting_super_admin(mk_user):
    _, admin_id = mk_user("adminactor2", role="ADMIN")
    _, super_id = mk_user("supertarget2", role="SUPER_ADMIN")
    res = _client().post(
        f"/api/v1/users/{super_id}/reset-password",
        headers=auth_headers_for(admin_id),
    )
    assert res.status_code == 403
    action = _db(
        "SELECT action FROM audit_logs WHERE user_id = %s AND target_user_id = %s",
        (admin_id, super_id),
    )
    assert ("AUTHORIZATION_DENIED",) in action


def test_reset_revokes_sessions_and_forces_password_change(mk_user):
    _, super_id = mk_user("superrevoke", role="SUPER_ADMIN")
    username, target_id = mk_user("revoketarget", role="ANALYST")

    target_client = _client()
    assert target_client.post("/api/v1/auth/login", json=_login_body(username)).status_code == 200
    old_token = session_token_from_client(target_client)

    res = _client().post(
        f"/api/v1/users/{target_id}/reset-password",
        headers=auth_headers_for(super_id),
    )
    assert res.status_code == 200, res.text
    temp_password = res.json()["temporary_password"]

    # The pre-reset session is dead.
    stale = target_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {old_token}"})
    assert stale.status_code == 401

    assert (
        target_client.post(
            "/api/v1/auth/login",
            json=_login_body(username, temp_password),
        ).status_code
        == 200
    )
    assert target_client.get("/api/v1/users").status_code == 428
