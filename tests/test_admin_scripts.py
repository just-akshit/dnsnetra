"""
tests/test_admin_scripts.py
===========================
Tests for the break-glass admin scripts:
- scripts/create_super_admin.py bootstraps the first SUPER_ADMIN
- scripts/rotate_admin_password.py rotates an ADMIN or SUPER_ADMIN password
"""

from __future__ import annotations

import uuid

from scripts.create_super_admin import create_super_admin
from scripts.rotate_admin_password import rotate_admin
from tests.test_auth_security_audit import _db, mk_user


def test_create_super_admin_dry_run_does_not_write():
    name = f"test_superdry_{uuid.uuid4().hex[:8]}"
    status, password = create_super_admin(name, execute=False)

    assert status == "dry-run"
    assert password is None
    assert _db("SELECT id FROM dashboard_users WHERE username = %s", (name,)) == []


def test_create_super_admin_execute_writes_role_and_audit():
    name = f"test_supersec_{uuid.uuid4().hex[:8]}"
    try:
        status, password = create_super_admin(name, execute=True)
        assert status == "created"
        assert password and len(password) >= 16

        row = _db(
            "SELECT role, must_change_password FROM dashboard_users WHERE username = %s",
            (name,),
        )[0]
        assert row == ("SUPER_ADMIN", True)

        audit = _db(
            "SELECT metadata::text FROM audit_logs WHERE target_user_id = "
            "(SELECT id FROM dashboard_users WHERE username = %s)",
            (name,),
        )
        assert any("system/cli" in (m or "") for (m,) in audit)
    finally:
        _db(
            "DELETE FROM audit_logs WHERE target_user_id IN "
            "(SELECT id FROM dashboard_users WHERE username = %s)",
            (name,),
        )
        _db("DELETE FROM dashboard_users WHERE username = %s", (name,))


def test_create_super_admin_refuses_existing_username(mk_user):
    username, _ = mk_user("superexists", role="ANALYST")
    status, password = create_super_admin(username, execute=False)

    assert status == "exists"
    assert password is None


def test_rotate_admin_accepts_super_admin_and_audits(mk_user):
    username, user_id = mk_user("rotatesuper", role="SUPER_ADMIN")

    ok, password = rotate_admin(username, execute=True)
    assert ok is True
    assert password and len(password) >= 16

    row = _db(
        "SELECT must_change_password FROM dashboard_users WHERE id = %s",
        (user_id,),
    )[0]
    assert row[0] is True

    audit = _db(
        "SELECT metadata::text FROM audit_logs WHERE target_user_id = %s",
        (user_id,),
    )
    assert any("system/cli" in (m or "") for (m,) in audit)


def test_rotate_admin_refuses_staff(mk_user):
    username, _ = mk_user("rotatestaff", role="ANALYST")

    ok, password = rotate_admin(username, execute=False)
    assert ok is False
    assert password is None
