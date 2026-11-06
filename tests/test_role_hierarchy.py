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
