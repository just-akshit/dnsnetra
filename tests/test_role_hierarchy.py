"""
tests/test_role_hierarchy.py
============================
Tests for the SUPER_ADMIN role, the role hierarchy policy, and the
actor-vs-target matrix on every user-management route.
"""

from __future__ import annotations

import pytest

from api.rbac import UserRole, get_role_permissions
from tests.test_auth_security_audit import _db


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
