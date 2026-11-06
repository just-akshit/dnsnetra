# SUPER_ADMIN Role and Admin Password Reset Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `SUPER_ADMIN` role with a backend-enforced role hierarchy and a server-generated temporary-password reset flow, without changing the opaque-session, Argon2id, CSRF, CAPTCHA, or audit model.

**Architecture:** Roles stay in code (`api/rbac.py`); PostgreSQL gets one check-constraint migration. A single policy module (`api/user_admin_policy.py`) answers "may this actor manage this target / assign this role?" every user-management route calls it before doing work. The existing admin-chosen `/users/{id}/reset-password` becomes a no-body endpoint that generates the password server-side and returns it once with `Cache-Control: no-store`.

**Tech Stack:** FastAPI, PostgreSQL (psycopg2), Pydantic v2, pytest, Next.js 16 App Router, React 19, Vitest + Testing Library, pnpm.

**Spec:** The requirement text supplied on 2026-11-06 (SUPER_ADMIN role, hierarchy, reset endpoint, UI, scripts, tests).

## Global Constraints

- Code-only. Do not run purge scripts, delete live rows, or run destructive DB commands.
- No JWT, no Redis, no new auth mechanism, no new dependencies.
- Roles: `SUPER_ADMIN > ADMIN > ANALYST = SUPPORT`.
- Deny by default. Hierarchy is enforced in the backend; UI hiding is cosmetic only.
- Never log, audit, or persist a temporary password in plaintext.
- Every state-changing admin route must keep CSRF/origin protection (already supplied by `get_current_user` for cookie auth).
- `scripts/rotate_admin_password.py` remains the break-glass path and must keep working.
- Work on branch `auth/super-admin`; one small commit per task.
- Existing known test baseline: the same 29 dataset-drift failures, no new failures.

---

## Decisions Required Before Execution

These change the design. Recommended answers are in bold.

| # | Question | Recommendation |
|---|---|---|
| D1 | May an `ADMIN` **read** (`GET /users`, `GET /users/{id}`) `ADMIN`/`SUPER_ADMIN` rows? | **Yes, read-only.** Write operations are hierarchy-gated. Hiding rows breaks the admin table and makes "show the button only when allowed" impossible. |
| D2 | Replace the existing admin-chosen `POST /users/{id}/reset-password` body with a server-generated password? | **Yes.** Keep the one-time `/reset-code` flow as the alternative where the user chooses their own password. |
| D3 | Add an "Issue reset code" button to `/users`? Task 13 currently has no admin UI trigger, so only curl can use it. | **Yes, add it.** Otherwise the reset-code flow is dead UI. |
| D4 | Last-admin protection with two role tiers | **Always protect the last active `SUPER_ADMIN`; protect the last active `ADMIN` only when no active `SUPER_ADMIN` exists.** |
| D5 | May an admin revoke their own sessions? | **Yes** (it is effectively logout). Reset/deactivate/role-change on self stays denied. |
| D6 | How is the first `SUPER_ADMIN` created? | **Run `scripts/create_super_admin.py --execute` immediately after the migration.** There is deliberately no auto-promotion and no API path to create the first one. |
| D7 | Runtime artifacts were committed and pushed (`parsing logs/logs/query.log.bak`, `logs/*.log`, `labeler/intel/trusted_domains.db`). | **Stop tracking them in a separate commit and add ignores.** If the repo is shared publicly, also rewrite history with `git filter-repo`; the branch is already on `origin`. This is separate from the feature. |
| D8 | The spec asks for a role dropdown in "create/edit user", but the current `/users` page has no edit-role control (only create + approve). | **Add a small "Change role" dialog** using `usersApi.update(id, {role})`, filtered by `assignableRoles`. Otherwise the edit half of the requirement is unimplemented. |

### Behavior changes that invalidate existing tests

These assertions encode the pre-SUPER_ADMIN behavior and must be rewritten, not just left failing:

- `tests/test_auth_complete.py::test_admin_creates_admin_and_role_change` — asserts an `ADMIN` can create and modify an `ADMIN`.
- `tests/test_auth_hardening.py::test_two_admins_can_manage_each_other_safely` — asserts an `ADMIN` can disable another `ADMIN`.
- `tests/test_users_admin.py::test_admin_reset_user_password` — posts `new_password` and expects 200; the new endpoint takes no body.
- `frontend/tests/users-api.test.ts` — asserts `resetPassword` sends `new_password`.
- `frontend/tests/users-page.test.tsx` — mocks the old reset dialog.

---

## File Map

**Create**

- `database/migrations/010_super_admin_role.sql` — widen the role check constraint.
- `api/user_admin_policy.py` — the single `can_manage` / `can_assign_role` authority.
- `scripts/create_super_admin.py` — dry-run-by-default bootstrap.
- `tests/test_role_hierarchy.py` — policy unit tests + route matrix.
- `tests/test_admin_scripts.py` — script dry-run/execute tests.
- `frontend/lib/admin/permissions.ts` — mirrors the backend hierarchy for UI affordances.
- `frontend/tests/permissions.test.ts` — helper tests.

**Modify**

- `api/rbac.py` — `UserRole.SUPER_ADMIN`, inherited permission set.
- `api/audit.py` — new audit action constants.
- `api/auth.py` — shared `generate_temporary_password`.
- `api/routes/users.py` — hierarchy checks on every lifecycle route; new reset contract.
- `scripts/rotate_admin_password.py` — accept `SUPER_ADMIN`, write audit row.
- `frontend/lib/admin/users-api.ts` — add `SUPER_ADMIN`, change reset contract, add `resetCode`.
- `frontend/app/(dashboard)/users/page.tsx` — role-aware actions, confirm dialog, one-time password modal.
- `frontend/components/app-sidebar.tsx` — show Users for `ADMIN` and `SUPER_ADMIN`.
- `frontend/tests/users-api.test.ts`, `frontend/tests/users-page.test.tsx`, `frontend/tests/app-sidebar.test.tsx`.
- `tests/test_auth_complete.py`, `tests/test_auth_hardening.py`, `tests/test_users_admin.py`.
- `deploy/README.md` — migration/bootstrap order and backup table list.

---

## Task 1: Migration and role plumbing

**Files:**
- Create: `database/migrations/010_super_admin_role.sql`
- Modify: `api/rbac.py:16-84`
- Test: `tests/test_role_hierarchy.py`

**Interfaces:**
- Produces: `UserRole.SUPER_ADMIN`; `get_role_permissions("SUPER_ADMIN")` is a superset of `get_role_permissions("ADMIN")`; DB accepts `SUPER_ADMIN`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_role_hierarchy.py
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

```

> The third test is a placeholder for the constraint only; delete it if it adds no value. The first two are the real gates.

- [ ] **Step 2: Run red**

Run: `.venv/bin/python -m pytest tests/test_role_hierarchy.py -q`
Expected: FAIL — `UserRole` has no `SUPER_ADMIN`, constraint lacks it.

- [ ] **Step 3: Write the migration**

`database/migrations/010_super_admin_role.sql`:

```sql
ALTER TABLE dashboard_users
    DROP CONSTRAINT IF EXISTS chk_dashboard_users_role;

ALTER TABLE dashboard_users
    ADD CONSTRAINT chk_dashboard_users_role
    CHECK (role IN ('SUPER_ADMIN', 'ADMIN', 'ANALYST', 'SUPPORT'));
```

Apply with the project runner, not `-m database.migrate`:

```bash
.venv/bin/python database/migrate.py
```

- [ ] **Step 4: Add the role and permissions**

`api/rbac.py`:

```python
class UserRole(str, Enum):
    SUPER_ADMIN = "SUPER_ADMIN"
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    SUPPORT = "SUPPORT"
```

At the end of the `ROLE_PERMISSIONS` definition, add:

```python
# SUPER_ADMIN is a strict superset of ADMIN. Extra authority is expressed by
# the hierarchy policy (api/user_admin_policy.py), not by a wider permission set.
ROLE_PERMISSIONS[UserRole.SUPER_ADMIN.value] = set(
    ROLE_PERMISSIONS[UserRole.ADMIN.value]
)
```

Update the module docstring to list all four roles.

- [ ] **Step 5: Run green**

Run: `.venv/bin/python -m pytest tests/test_role_hierarchy.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add database/migrations/010_super_admin_role.sql api/rbac.py tests/test_role_hierarchy.py
git commit -m "feat(rbac): add SUPER_ADMIN role and widen role constraint"
```

---

## Task 2: The single hierarchy helper

**Files:**
- Create: `api/user_admin_policy.py`
- Modify: `api/audit.py:19-31`
- Test: `tests/test_role_hierarchy.py`

**Interfaces:**
- Produces:
  - `can_manage(actor: Mapping, target: Mapping, new_role=None) -> tuple[bool, str]`
  - `can_assign_role(actor_role, new_role) -> tuple[bool, str]`
  - `ensure_can_manage(actor, target, *, request, attempted_action, new_role=None) -> None` (raises 403 and audit-logs denials)
  - `ensure_can_assign_role(actor, new_role, *, request, attempted_action) -> None`

- [ ] **Step 1: Write the failing unit tests**

Append to `tests/test_role_hierarchy.py`:

```python
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
```

- [ ] **Step 2: Run red**

Run: `.venv/bin/python -m pytest tests/test_role_hierarchy.py -q`
Expected: FAIL — `api.user_admin_policy` does not exist.

- [ ] **Step 3: Implement the policy module**

`api/user_admin_policy.py`:

```python
"""Actor-vs-target authorization for user management.

This is the single source of truth for the role hierarchy. Every
user-management route calls it; deny by default.
"""

from __future__ import annotations

from typing import Any, Mapping, Optional

from fastapi import HTTPException, Request, status

from .audit import AuditAction, log_audit_event
from .trusted_proxy import get_client_ip

# Higher rank may manage lower rank. ANALYST and SUPPORT are peers.
ROLE_RANK: dict[str, int] = {
    "SUPER_ADMIN": 3,
    "ADMIN": 2,
    "ANALYST": 1,
    "SUPPORT": 1,
}

# Roles each actor may manage (target role) and assign (new role).
MANAGEABLE_ROLES: dict[str, set[str]] = {
    "SUPER_ADMIN": {"SUPER_ADMIN", "ADMIN", "ANALYST", "SUPPORT"},
    "ADMIN": {"ANALYST", "SUPPORT"},
}


def _role(value: Any) -> str:
    if value is None:
        return ""
    return str(getattr(value, "value", value)).strip().upper()


def can_assign_role(actor_role: Any, new_role: Any) -> tuple[bool, str]:
    actor = _role(actor_role)
    target = _role(new_role)
    allowed = MANAGEABLE_ROLES.get(actor, set())
    if not allowed:
        return False, f"role '{actor}' cannot manage users"
    if target not in allowed:
        return False, f"role '{actor}' cannot assign role '{target}'"
    return True, "ok"


def can_manage(
    actor: Mapping[str, Any],
    target: Mapping[str, Any],
    new_role: Any = None,
) -> tuple[bool, str]:
    actor_role = _role(actor.get("role"))
    target_role = _role(target.get("role"))

    if actor_role not in MANAGEABLE_ROLES:
        return False, f"role '{actor_role}' cannot manage users"
    if actor.get("id") is not None and actor.get("id") == target.get("id"):
        return False, "cannot manage your own account"
    if target_role not in MANAGEABLE_ROLES[actor_role]:
        return False, f"role '{actor_role}' cannot manage role '{target_role}'"
    if new_role is not None:
        return can_assign_role(actor_role, new_role)
    return True, "ok"


def _deny(actor: Mapping[str, Any], target: Mapping[str, Any] | None, request: Request, attempted_action: str, reason: str) -> None:
    log_audit_event(
        action=AuditAction.AUTHORIZATION_DENIED,
        user_id=actor.get("id"),
        target_user_id=target.get("id") if target else None,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        metadata={
            "attempted_action": attempted_action,
            "actor_role": _role(actor.get("role")),
            "target_role": _role(target.get("role")) if target else None,
            "reason": reason,
            "outcome": "denied",
        },
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You are not allowed to manage this account",
    )


def ensure_can_manage(
    actor: Mapping[str, Any],
    target: Mapping[str, Any],
    *,
    request: Request,
    attempted_action: str,
    new_role: Any = None,
) -> None:
    ok, reason = can_manage(actor, target, new_role)
    if not ok:
        _deny(actor, target, request, attempted_action, reason)


def ensure_can_assign_role(
    actor: Mapping[str, Any],
    new_role: Any,
    *,
    request: Request,
    attempted_action: str,
) -> None:
    ok, reason = can_assign_role(actor.get("role"), new_role)
    if not ok:
        _deny(actor, None, request, attempted_action, reason)
```

Add to `api/audit.py` inside `AuditAction`:

```python
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    PASSWORD_RESET_CODE_ISSUED = "PASSWORD_RESET_CODE_ISSUED"
    PASSWORD_RESET_COMPLETED = "PASSWORD_RESET_COMPLETED"
```

- [ ] **Step 4: Run green**

Run: `.venv/bin/python -m pytest tests/test_role_hierarchy.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/user_admin_policy.py api/audit.py tests/test_role_hierarchy.py
git commit -m "feat(rbac): add a single role-hierarchy policy helper"
```

---

## Task 3: Enforce the hierarchy on every user-management route

**Files:**
- Modify: `api/routes/users.py`
- Test: `tests/test_role_hierarchy.py`

**Interfaces:**
- Consumes: `ensure_can_manage`, `ensure_can_assign_role` from Task 2.
- Produces: every lifecycle route returns 403 for an out-of-hierarchy actor and writes an `AUTHORIZATION_DENIED` audit row.

- [ ] **Step 1: Write the failing route matrix**

Append to `tests/test_role_hierarchy.py`:

```python
from tests.auth_testkit import auth_headers_for
from tests.test_auth_security_audit import _client, mk_user

ROLES = ("SUPER_ADMIN", "ADMIN", "ANALYST", "SUPPORT")


def _allowed(actor_role: str, target_role: str) -> bool:
    return target_role in MANAGEABLE_ROLES.get(actor_role, set())


@pytest.mark.parametrize("actor_role", ROLES)
@pytest.mark.parametrize("target_role", ROLES)
@pytest.mark.parametrize("action", ["update", "deactivate", "reset"])
def test_management_matrix(mk_user, actor_role, target_role, action):
    _, actor_id = mk_user(f"actor_{actor_role}", role=actor_role)
    _, target_id = mk_user(f"target_{target_role}", role=target_role)
    headers = auth_headers_for(actor_id)
    client = _client()

    if action == "update":
        res = client.patch(f"/api/v1/users/{target_id}", json={"role": "ANALYST"}, headers=headers)
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
    username = f"test_created_{actor_role}_{new_role}".lower()
    res = _client().post(
        "/api/v1/users",
        headers=headers,
        json={"username": username, "password": "CreatedPass123!", "role": new_role, "status": "ACTIVE"},
    )
    expected = 201 if _allowed(actor_role, new_role) else 403
    assert res.status_code == expected, res.text
```

Use `from api.user_admin_policy import MANAGEABLE_ROLES` at the top of the test file.

- [ ] **Step 2: Run red**

Run: `.venv/bin/python -m pytest tests/test_role_hierarchy.py -q`
Expected: FAIL — `ADMIN` can currently create/manage `ADMIN`, so several matrix rows return 200/201 instead of 403.

- [ ] **Step 3: Add shared test helpers**

In `tests/auth_testkit.py`, add:

```python
def auth_headers_for(user_id: int) -> dict[str, str]:
    """Create a real bearer session for a test user."""
    raw, _ = create_session(user_id=user_id, user_agent="pytest")
    return {
        "Authorization": f"Bearer {raw}",
        "Origin": "http://localhost:3000",
    }
```

Replace the local `_headers_for` helper in `tests/test_role_hierarchy.py` with `auth_headers_for`.

In `tests/conftest.py`, add a reusable SUPER_ADMIN fixture (it must clean up its own audit rows because `pytest_%` is excluded from the ephemeral sweep):

```python
import uuid

@pytest.fixture
def super_headers():
    username = f"pytest_super_{uuid.uuid4().hex[:8]}"
    rows = db(
        """
        INSERT INTO dashboard_users
            (username, email, password_hash, hashed_password, role, status,
             is_active, must_change_password, created_at, updated_at)
        VALUES (%s, %s, %s, NULL, 'SUPER_ADMIN', 'ACTIVE', true, false, NOW(), NOW())
        RETURNING id
        """,
        (username, f"{username}@dnsnetra.local", hash_password(TEST_PASSWORD)),
    )
    uid = rows[0][0]
    raw_token, _ = create_session(user_id=uid, user_agent="pytest")
    yield {"Authorization": f"Bearer {raw_token}", "Origin": "http://localhost:3000"}
    revoke_session(raw_token)
    db("DELETE FROM audit_logs WHERE user_id = %s OR target_user_id = %s", (uid, uid))
    db("DELETE FROM dashboard_users WHERE id = %s", (uid,))
```

- [ ] **Step 4: Wire the routes**

In `api/routes/users.py`, add the import:

```python
from ..user_admin_policy import ensure_can_assign_role, ensure_can_manage
```

Apply the checks in this exact order:

```python
# create_user, after username/password validation and before the INSERT
ensure_can_assign_role(
    admin,
    payload.role.value,
    request=request,
    attempted_action="create_user",
)
```

```python
# update_user, immediately after get_user_by_id(...)
ensure_can_manage(
    admin,
    target_user,
    new_role=payload.role.value if payload.role else None,
    request=request,
    attempted_action="update_user",
)
```

Keep a self-demotion / self-disable block **before** the helper so the current 400 response text stays stable, but make it role-aware so a `SUPER_ADMIN` cannot demote themselves to `ADMIN`:

```python
if user_id == admin["id"]:
    if payload.role is not None and payload.role.value != target_user["role"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot demote their own account",
        )
    if (payload.status is not None and payload.status != UserStatus.ACTIVE) or payload.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot disable their own account",
        )
```

The helper is still the defense-in-depth check for every cross-account path.

```python
# approve_user, immediately after get_user_by_id(...)
ensure_can_manage(
    admin,
    target_user,
    new_role=payload.role.value,
    request=request,
    attempted_action="approve_user",
)
```

```python
# disable_user: replace the inline self-check with the existing 400 text kept,
# then add:
ensure_can_manage(admin, target_user, request=request, attempted_action="disable_user")
```

```python
# enable_user: after get_user_by_id(...)
ensure_can_manage(admin, target_user, request=request, attempted_action="enable_user")
```

```python
# revoke_sessions: allow self (D5), gate everyone else
if user_id != admin["id"]:
    ensure_can_manage(admin, target_user, request=request, attempted_action="revoke_sessions")
```

```python
# issue_reset_code: after get_user_by_id(...)
ensure_can_manage(admin, target, request=request, attempted_action="issue_reset_code")
```

Also update the route summary/docstrings from "Admin only" to "ADMIN / SUPER_ADMIN" where relevant.

- [ ] **Step 5: Run green and the existing auth suite**

Run:

```bash
.venv/bin/python -m pytest tests/test_role_hierarchy.py -q
.venv/bin/python -m pytest tests/test_auth_security_audit.py tests/test_auth_complete.py tests/test_auth_hardening.py tests/test_users_admin.py tests/test_password_reset.py -q
```

Expected: the new matrix passes. Two legacy tests now fail **by design** (see "Behavior changes"): `test_admin_creates_admin_and_role_change` and `test_two_admins_can_manage_each_other_safely`. Rewrite them in Step 6.

- [ ] **Step 6: Rewrite the two legacy tests**

`tests/test_auth_complete.py::test_admin_creates_admin_and_role_change` becomes two tests:

```python
def test_admin_cannot_create_admin(admin_headers):
    res = client.post(
        "/api/v1/users",
        json={"username": "test_new_admin", "password": "NewAdminPass123!", "role": "ADMIN"},
        headers=admin_headers,
    )
    assert res.status_code == 403


def test_super_admin_creates_admin_and_changes_role(mk_user):
    _, super_id = mk_user("supercreator", role="SUPER_ADMIN")
    headers = auth_headers_for(super_id)

    res = client.post(
        "/api/v1/users",
        json={
            "username": "test_new_admin",
            "password": "NewAdminPass123!",
            "role": "ADMIN",
            "status": "ACTIVE",
        },
        headers=headers,
    )
    assert res.status_code == 201
    new_admin_id = res.json()["id"]

    patch_res = client.patch(
        f"/api/v1/users/{new_admin_id}",
        json={"role": "ANALYST"},
        headers=headers,
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["role"] == "ANALYST"
```

Import `auth_headers_for` from `tests.auth_testkit` in `test_auth_complete.py`.

`tests/test_auth_hardening.py::test_two_admins_can_manage_each_other_safely` becomes:

```python
def test_admin_cannot_manage_another_admin(mk_user):
    _, actor_id = mk_user("adminactor", role="ADMIN")
    _, target_id = mk_user("admintarget", role="ADMIN")
    headers = auth_headers_for(actor_id)
    assert client.post(f"/api/v1/users/{target_id}/disable", headers=headers).status_code == 403
    assert client.patch(f"/api/v1/users/{target_id}", json={"role": "ANALYST"}, headers=headers).status_code == 403
```

Positive counterpart:

```python
def test_super_admin_can_manage_another_admin(mk_user):
    _, actor_id = mk_user("superactor2", role="SUPER_ADMIN")
    _, target_id = mk_user("admintarget2", role="ADMIN")
    headers = auth_headers_for(actor_id)
    assert client.post(f"/api/v1/users/{target_id}/disable", headers=headers).status_code == 200
```

Import `auth_headers_for` from `tests.auth_testkit` in `test_auth_hardening.py`.

- [ ] **Step 7: Run green**

```bash
.venv/bin/python -m pytest tests/test_role_hierarchy.py tests/test_auth_security_audit.py tests/test_auth_complete.py tests/test_auth_hardening.py tests/test_users_admin.py tests/test_password_reset.py -q
```

Expected: all pass. If `test_users_admin.py` still fails it is because Task 4 has not changed the reset contract yet; defer that single test to Task 4.

- [ ] **Step 8: Commit**

```bash
git add api/routes/users.py tests/auth_testkit.py tests/conftest.py tests/test_role_hierarchy.py tests/test_auth_complete.py tests/test_auth_hardening.py
git commit -m "feat(users): enforce the role hierarchy on every management route"
```

---

## Task 4: Server-generated temporary-password reset

**Files:**
- Modify: `api/auth.py` (add `generate_temporary_password`)
- Modify: `api/routes/users.py:90-92, 666-722`
- Modify: `tests/test_users_admin.py`
- Test: `tests/test_role_hierarchy.py`

**Interfaces:**
- `POST /api/v1/users/{id}/reset-password` takes **no body** and returns:

```json
{
  "username": "analyst1",
  "temporary_password": "…20 chars…",
  "must_change_password": true
}
```

- Response headers include `Cache-Control: no-store, max-age=0` and `Pragma: no-cache`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_role_hierarchy.py`:

```python
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
    login = _client().post(
        "/api/v1/auth/login",
        json=_login_body(username, password),
    )
    assert login.status_code == 200

    # Audit never contains the password.
    audit = _db(
        "SELECT metadata::text FROM audit_logs WHERE target_user_id = %s",
        (target_id,),
    )
    assert all(password not in (m or "") for (m,) in audit)


def test_reset_rejects_self_and_writes_a_denial_audit(mk_user):
    _, super_id = mk_user("selfreset", role="SUPER_ADMIN")
    res = _client().post(f"/api/v1/users/{super_id}/reset-password", headers=auth_headers_for(super_id))
    assert res.status_code == 403
    rows = _db(
        "SELECT action FROM audit_logs WHERE user_id = %s AND target_user_id = %s",
        (super_id, super_id),
    )
    assert ("AUTHORIZATION_DENIED",) in rows


def test_denied_reset_writes_audit_for_admin_targeting_super_admin(mk_user):
    _, admin_id = mk_user("adminactor2", role="ADMIN")
    _, super_id = mk_user("supertarget2", role="SUPER_ADMIN")
    res = _client().post(f"/api/v1/users/{super_id}/reset-password", headers=auth_headers_for(admin_id))
    assert res.status_code == 403
    action = _db(
        "SELECT action FROM audit_logs WHERE user_id = %s AND target_user_id = %s",
        (admin_id, super_id),
    )
    assert ("AUTHORIZATION_DENIED",) in action
```

Add `from tests.auth_testkit import auth_headers_for` and `_login_body` to the imports from `tests.test_auth_security_audit`. Reuse the existing `_login_body` helper.

- [ ] **Step 2: Run red**

Run: `.venv/bin/python -m pytest tests/test_role_hierarchy.py -k reset -q`
Expected: FAIL — endpoint still expects a body / returns `message`.

- [ ] **Step 3: Add the generator**

In `api/auth.py`, add `import string` and:

```python
_TEMP_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"


def generate_temporary_password(length: int = 20) -> str:
    """Return a random password that satisfies validate_password_strength()."""
    for _ in range(100):
        candidate = "".join(
            secrets.choice(_TEMP_PASSWORD_ALPHABET) for _ in range(length)
        )
        if validate_password_strength(candidate)[0]:
            return candidate
    raise RuntimeError("could not generate a policy-compliant temporary password")
```

- [ ] **Step 4: Replace the reset endpoint**

In `api/routes/users.py`:

```python
class ResetPasswordResponse(BaseModel):
    username: str
    temporary_password: str
    must_change_password: bool = True
```

Delete the old `ResetPasswordRequest` class and its import usage. Replace the handler:

```python
@router.post(
    "/{user_id}/reset-password",
    response_model=ResetPasswordResponse,
    summary="Reset a user's password (ADMIN / SUPER_ADMIN only)",
    description=(
        "Generates a one-time temporary password server-side, forces a password "
        "change at next login, and revokes every active session for the target. "
        "The password is returned once and never stored or logged in plaintext."
    ),
)
def reset_password(
    user_id: int,
    request: Request,
    response: Response,
    admin: dict[str, Any] = Depends(require_permission("users:update")),
) -> ResetPasswordResponse:
    client_ip, user_agent = _extract_client_meta(request)

    target_user = get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    ensure_can_manage(
        admin,
        target_user,
        request=request,
        attempted_action="reset_password",
    )

    temporary_password = generate_temporary_password(20)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE dashboard_users
                SET password_hash = %s,
                    hashed_password = NULL,
                    must_change_password = true,
                    updated_at = NOW()
                WHERE id = %s;
                """,
                (hash_password(temporary_password), user_id),
            )
            conn.commit()

    revoke_all_user_sessions(user_id)

    log_audit_event(
        action=AuditAction.PASSWORD_RESET,
        user_id=admin["id"],
        target_user_id=user_id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={
            "outcome": "success",
            "target_username": target_user["username"],
            "sessions_revoked": True,
        },
    )

    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"

    return ResetPasswordResponse(
        username=target_user["username"],
        temporary_password=temporary_password,
    )
```

Add `generate_temporary_password` to the `..auth` import block, and add `Response` to the `fastapi` import (`from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status`).

- [ ] **Step 5: Add no-store to the reset-code response too**

`issue_reset_code` also returns a secret. Add a `response: Response` parameter and the same two headers before returning.

- [ ] **Step 6: Update the legacy test**

`tests/test_users_admin.py::test_admin_reset_user_password` becomes a SUPER_ADMIN-actor test:

```python
def test_super_admin_resets_user_password(mk_user, super_headers):
    username, uid = mk_user("pwdreset", role="ANALYST", status="ACTIVE")
    res = _client().post(f"/api/v1/users/{uid}/reset-password", headers=super_headers)
    assert res.status_code == 200
    assert res.json()["temporary_password"]
    detail = _client().get(f"/api/v1/users/{uid}", headers=super_headers).json()
    assert detail["must_change_password"] is True
```

The `super_headers` fixture was added to `tests/conftest.py` in Task 3; use it here so its audit rows are cleaned up on teardown.

- [ ] **Step 7: Run green**

```bash
.venv/bin/python -m pytest tests/test_role_hierarchy.py tests/test_users_admin.py tests/test_auth_complete.py tests/test_auth_hardening.py tests/test_password_reset.py -q
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add api/auth.py api/routes/users.py tests/test_role_hierarchy.py tests/test_users_admin.py tests/auth_testkit.py
git commit -m "feat(users): generate one-time temporary passwords on reset"
```

---

## Task 5: Last-principal protection

**Files:**
- Modify: `api/routes/users.py:115-133, 415-435, 576-591`
- Test: `tests/test_role_hierarchy.py`

**Interfaces:**
- Produces: `_lock_active_principals(cur) -> list[tuple[int, str]]` and `_ensure_principal_remains(cur, target_role, target_id)`.
- Rule: never remove the last active `SUPER_ADMIN`; never remove the last active `ADMIN` when no active `SUPER_ADMIN` exists.

- [ ] **Step 1: Write the failing unit test**

The HTTP path cannot reach the guard (the only actor who could demote the last SUPER_ADMIN is that same SUPER_ADMIN, and self-management is denied). Test the helper with a fake cursor:

```python
class _FakeCursor:
    def __init__(self, rows):
        self.rows = rows
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append(sql)

    def fetchall(self):
        return self.rows


def test_last_super_admin_is_protected():
    from api.routes.users import _ensure_principal_remains

    cur = _FakeCursor([(10, "SUPER_ADMIN")])
    with pytest.raises(Exception) as exc:
        _ensure_principal_remains(cur, "SUPER_ADMIN", 10)
    assert "last" in str(exc.value).lower()


def test_last_admin_is_protected_only_without_a_super_admin():
    from api.routes.users import _ensure_principal_remains

    cur = _FakeCursor([(10, "ADMIN")])
    with pytest.raises(Exception):
        _ensure_principal_remains(cur, "ADMIN", 10)

    cur = _FakeCursor([(10, "ADMIN"), (11, "SUPER_ADMIN")])
    _ensure_principal_remains(cur, "ADMIN", 10)  # allowed


def test_one_of_two_super_admins_may_be_removed():
    from api.routes.users import _ensure_principal_remains

    cur = _FakeCursor([(10, "SUPER_ADMIN"), (11, "SUPER_ADMIN")])
    _ensure_principal_remains(cur, "SUPER_ADMIN", 10)
```

- [ ] **Step 2: Run red**

Run: `.venv/bin/python -m pytest tests/test_role_hierarchy.py -k "last_" -q`
Expected: FAIL — helper does not exist / only counts `ADMIN`.

- [ ] **Step 3: Replace the guard**

In `api/routes/users.py`:

```python
def _lock_active_principals(cur) -> list[tuple[int, str]]:
    cur.execute(
        """
        SELECT id, role FROM dashboard_users
        WHERE role IN ('SUPER_ADMIN', 'ADMIN')
          AND status = 'ACTIVE'
          AND is_active = true
        ORDER BY id
        FOR UPDATE;
        """
    )
    return [(row[0], row[1]) for row in cur.fetchall()]


def _ensure_principal_remains(cur, target_role: str, target_id: int) -> None:
    rows = _lock_active_principals(cur)
    supers = [uid for uid, role in rows if role == "SUPER_ADMIN"]
    admins = [uid for uid, role in rows if role == "ADMIN"]

    if target_role == "SUPER_ADMIN" and target_id in supers and len(supers) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation rejected: cannot remove the last active super administrator.",
        )

    if target_role == "ADMIN" and target_id in admins and not supers and len(admins) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation rejected: cannot remove the last active administrator.",
        )
```

Call it from `update_user` when `role_changed` or `will_deactivate`, and from `disable_user`:

```python
if role_changed or will_deactivate:
    _ensure_principal_remains(cur, target_role, user_id)
```

Inside `disable_user`:

```python
_ensure_principal_remains(cur, target_user["role"], user_id)
```

Remove `_ensure_not_last_active_admin`. `will_demote` must compare ranks, not `!= ADMIN`:

```python
will_demote = role_changed and ROLE_RANK[new_role.value] < ROLE_RANK[target_role]
```

Import `ROLE_RANK` from `..user_admin_policy`.

- [ ] **Step 4: Run green**

```bash
.venv/bin/python -m pytest tests/test_role_hierarchy.py -q
.venv/bin/python -m pytest tests/test_auth_hardening.py tests/test_auth_complete.py -q
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/routes/users.py tests/test_role_hierarchy.py
git commit -m "fix(users): protect the last active SUPER_ADMIN and ADMIN"
```

---

## Task 6: Scripts

**Files:**
- Modify: `scripts/rotate_admin_password.py`
- Create: `scripts/create_super_admin.py`
- Test: `tests/test_admin_scripts.py`

**Interfaces:**
- `rotate_admin_password.py` accepts `ADMIN` or `SUPER_ADMIN` and writes an audit row with `metadata={"actor": "system/cli"}`.
- `create_super_admin.py --username NAME [--execute]` returns exit 0 on dry run and on success; exit 1 if the username exists or is invalid.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_admin_scripts.py
from __future__ import annotations

import uuid

from scripts.create_super_admin import create_super_admin
from tests.test_auth_security_audit import _db


def test_create_super_admin_dry_run_does_not_write():
    name = f"superdry_{uuid.uuid4().hex[:8]}"
    status, password = create_super_admin(name, execute=False)
    assert status == "dry-run"
    assert password is None
    assert _db("SELECT id FROM dashboard_users WHERE username = %s", (name,)) == []


def test_create_super_admin_execute_writes_role_and_audit():
    name = f"supersec_{uuid.uuid4().hex[:8]}"
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
```

- [ ] **Step 2: Run red**

Run: `.venv/bin/python -m pytest tests/test_admin_scripts.py -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `create_super_admin.py`**

```python
"""Bootstrap the first SUPER_ADMIN.

    python scripts/create_super_admin.py --username superadmin            # dry run
    python scripts/create_super_admin.py --username superadmin --execute  # create
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.audit import AuditAction, log_audit_event
from api.auth import (
    generate_temporary_password,
    hash_password,
    normalize_username,
    validate_username,
)
from labeler.intel.reputation.connection import get_connection


def create_super_admin(username: str, execute: bool) -> tuple[str, str | None]:
    clean = normalize_username(username)
    ok, _reason = validate_username(clean, is_signup=False)
    if not ok:
        return "invalid", None

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM dashboard_users WHERE lower(username) = lower(%s);",
                (clean,),
            )
            if cur.fetchone():
                conn.rollback()
                return "exists", None

            if not execute:
                conn.rollback()
                return "dry-run", None

            password = generate_temporary_password(20)
            cur.execute(
                """
                INSERT INTO dashboard_users
                    (username, email, password_hash, hashed_password, role, status,
                     is_active, must_change_password, created_at, updated_at)
                VALUES (%s, %s, %s, NULL, 'SUPER_ADMIN', 'ACTIVE', true, true, NOW(), NOW())
                RETURNING id;
                """,
                (clean, f"{clean}@dnsnetra.local", hash_password(password)),
            )
            user_id = cur.fetchone()[0]
            conn.commit()

    log_audit_event(
        action=AuditAction.USER_CREATED,
        user_id=None,
        target_user_id=user_id,
        metadata={"actor": "system/cli", "role": "SUPER_ADMIN", "username": clean},
    )
    return "created", password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    status, password = create_super_admin(args.username, args.execute)
    if status == "invalid":
        print(f"Invalid username: {args.username}", file=sys.stderr)
        return 1
    if status == "exists":
        print(f"Refusing: '{args.username}' already exists.", file=sys.stderr)
        return 1
    if status == "dry-run":
        print(f"Dry run: would create SUPER_ADMIN '{args.username}'. Re-run with --execute.")
        return 0

    print(f"Created SUPER_ADMIN '{args.username}'. One-time password (shown once):")
    print(password)
    print("The account must change this password at first login.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Update the rotation script**

In `scripts/rotate_admin_password.py`:

```python
from api.audit import AuditAction, log_audit_event
from api.auth import generate_temporary_password, hash_password, validate_password_strength
```

Replace the local `generate_temporary_password` with the imported one, allow both privileged roles, and audit after commit:

```python
            if role not in ("ADMIN", "SUPER_ADMIN"):
                return False, None
```

```python
    revoke_all_user_sessions(user_id)
    log_audit_event(
        action=AuditAction.PASSWORD_RESET,
        user_id=None,
        target_user_id=user_id,
        metadata={"actor": "system/cli", "outcome": "success"},
    )
    return True, password
```

Update the error text to say "not an ADMIN or SUPER_ADMIN".

- [ ] **Step 5: Run green**

```bash
.venv/bin/python -m pytest tests/test_admin_scripts.py -q
.venv/bin/python scripts/create_super_admin.py --username superadmin
```

Expected: tests pass; dry run prints `would create` and exits 0.

- [ ] **Step 6: Commit**

```bash
git add scripts/create_super_admin.py scripts/rotate_admin_password.py tests/test_admin_scripts.py
git commit -m "feat(scripts): add SUPER_ADMIN bootstrap and audit CLI rotations"
```

---

## Task 7: Frontend permission mirror and API client

**Files:**
- Create: `frontend/lib/admin/permissions.ts`
- Create: `frontend/tests/permissions.test.ts`
- Modify: `frontend/lib/admin/users-api.ts`
- Modify: `frontend/tests/users-api.test.ts`

**Interfaces:**
- `canManage(actorRole: string, target: {id:number; role:string}, selfId?: number|null): boolean`
- `assignableRoles(actorRole: string): UserRole[]`
- `usersApi.resetPassword(id)` → `POST` with **no body**, returns `{username, temporary_password, must_change_password}`.
- `usersApi.resetCode(id)` → `{code, expires_at}`.

- [ ] **Step 1: Write the failing tests**

`frontend/tests/permissions.test.ts`:

```ts
import { describe, expect, it } from "vitest"
import { assignableRoles, canManage } from "@/lib/admin/permissions"

describe("role hierarchy mirror", () => {
  it("lets ADMIN manage staff only", () => {
    expect(canManage("ADMIN", { id: 2, role: "ANALYST" })).toBe(true)
    expect(canManage("ADMIN", { id: 2, role: "SUPPORT" })).toBe(true)
    expect(canManage("ADMIN", { id: 2, role: "ADMIN" })).toBe(false)
    expect(canManage("ADMIN", { id: 2, role: "SUPER_ADMIN" })).toBe(false)
  })

  it("lets SUPER_ADMIN manage everyone else but not self", () => {
    expect(canManage("SUPER_ADMIN", { id: 2, role: "ADMIN" }, 1)).toBe(true)
    expect(canManage("SUPER_ADMIN", { id: 1, role: "SUPER_ADMIN" }, 1)).toBe(false)
  })

  it("offers only assignable roles", () => {
    expect(assignableRoles("ADMIN")).toEqual(["ANALYST", "SUPPORT"])
    expect(assignableRoles("SUPER_ADMIN")).toEqual(["SUPER_ADMIN", "ADMIN", "ANALYST", "SUPPORT"])
    expect(assignableRoles("ANALYST")).toEqual([])
  })
})
```

Update `frontend/tests/users-api.test.ts`:

```ts
it("resetPassword sends no body and returns the one-time password", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(
      JSON.stringify({ username: "u", temporary_password: "Tmp123!", must_change_password: true }),
      { status: 200, headers: { "Content-Type": "application/json" } }
    )
  )
  const result = await usersApi.resetPassword(9)
  expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/users/9/reset-password")
  expect(fetchMock.mock.calls[0][1]?.body).toBeUndefined()
  expect(result.temporary_password).toBe("Tmp123!")
})
```

- [ ] **Step 2: Run red**

Run: `cd frontend && pnpm vitest run tests/permissions.test.ts tests/users-api.test.ts`
Expected: FAIL — module missing / old signature.

- [ ] **Step 3: Implement the mirror**

`frontend/lib/admin/permissions.ts`:

```ts
import type { UserRole } from "./users-api"

const MANAGEABLE: Record<string, UserRole[]> = {
  SUPER_ADMIN: ["SUPER_ADMIN", "ADMIN", "ANALYST", "SUPPORT"],
  ADMIN: ["ANALYST", "SUPPORT"],
}

export function canManage(
  actorRole: string | undefined | null,
  target: { id: number; role: string },
  selfId?: number | string | null
): boolean {
  if (!actorRole) return false
  if (selfId != null && Number(selfId) === target.id) return false
  return MANAGEABLE[actorRole]?.includes(target.role as UserRole) ?? false
}

export function assignableRoles(actorRole: string | undefined | null): UserRole[] {
  return MANAGEABLE[actorRole ?? ""] ?? []
}
```

Update `users-api.ts`:

```ts
export type UserRole = "SUPER_ADMIN" | "ADMIN" | "ANALYST" | "SUPPORT"

export interface ResetPasswordResponse {
  username: string
  temporary_password: string
  must_change_password: boolean
}

  resetPassword: (id: number) =>
    request<ResetPasswordResponse>(`/api/v1/users/${id}/reset-password`, { method: "POST" }),

  resetCode: (id: number) =>
    request<{ code: string; expires_at: string }>(`/api/v1/users/${id}/reset-code`, {
      method: "POST",
    }),
```

- [ ] **Step 4: Run green**

Run: `cd frontend && pnpm vitest run tests/permissions.test.ts tests/users-api.test.ts`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/lib/admin/permissions.ts frontend/tests/permissions.test.ts frontend/lib/admin/users-api.ts frontend/tests/users-api.test.ts
git commit -m "feat(admin): mirror the role hierarchy in the users API client"
```

---

## Task 8: Users page UI

**Files:**
- Modify: `frontend/app/(dashboard)/users/page.tsx`
- Modify: `frontend/tests/users-page.test.tsx`

**Interfaces:**
- Consumes: `canManage`, `assignableRoles`, `usersApi.resetPassword`, `usersApi.resetCode`.
- Produces: role-aware action buttons; a reset dialog that shows the generated password exactly once.

- [ ] **Step 1: Write the failing tests**

Update the mock in `frontend/tests/users-page.test.tsx` to include `resetPassword` and `resetCode`, and add:

```tsx
it("hides reset for an ADMIN target when the actor is ADMIN", async () => {
  mockUser.current = { id: 1, username: "admin", role: "ADMIN" }
  mockList.mockResolvedValue(listOf(activeUser({ id: 3, username: "admin2", role: "ADMIN" })))
  render(<UsersPage />)
  await screen.findByText("admin2")
  expect(screen.queryByRole("button", { name: /reset password/i })).not.toBeInTheDocument()
})

it("shows the temporary password once and clears it on close", async () => {
  mockUser.current = { id: 1, username: "root", role: "SUPER_ADMIN" }
  mockList.mockResolvedValue(listOf(activeUser()))
  mockResetPassword.mockResolvedValue({
    username: "alice",
    temporary_password: "TmpPass123!",
    must_change_password: true,
  })
  render(<UsersPage />)
  fireEvent.click(await screen.findByRole("button", { name: /reset password/i }))
  fireEvent.click(screen.getByRole("button", { name: /confirm/i }))
  expect(await screen.findByText("TmpPass123!")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: /close/i }))
  expect(screen.queryByText("TmpPass123!")).not.toBeInTheDocument()
})

it("offers only assignable roles in the create dialog", async () => {
  mockUser.current = { id: 1, username: "admin", role: "ADMIN" }
  render(<UsersPage />)
  fireEvent.click(screen.getByRole("button", { name: /create user/i }))
  const dialog = screen.getByRole("dialog")
  expect(within(dialog).queryByText("ADMIN")).not.toBeInTheDocument()
  expect(within(dialog).getByText("ANALYST")).toBeInTheDocument()
})
```

Update the test-file import to `import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"`.

- [ ] **Step 2: Run red**

Run: `cd frontend && pnpm vitest run tests/users-page.test.tsx`
Expected: FAIL — old UI renders an admin-chosen password form.

- [ ] **Step 3: Update the page**

Key changes:

```tsx
import { assignableRoles, canManage } from "@/lib/admin/permissions"
import type { ResetPasswordResponse } from "@/lib/admin/users-api"

const role = me?.role
const isAdmin = role === "ADMIN" || role === "SUPER_ADMIN"

React.useEffect(() => {
  if (isAdmin) void load()
}, [load, isAdmin])
```

Action cell:

```tsx
{canManage(me?.role, u, me?.id) && (
  <ResetPasswordDialog user={u} disabled={busy} onDone={load} />
)}
{u.status === "ACTIVE" && canManage(me?.role, u, me?.id) && (
  <Button size="sm" variant="destructive" disabled={busy}
    onClick={() => run(() => usersApi.disable(u.id))}>
    Disable
  </Button>
)}
```

Gate `revokeSessions` and `enable` with `canManage(...)` too. `revokeSessions` may include the actor themselves (D5): use `u.id === me?.id || canManage(me?.role, u, me?.id)`.

Pass the actor's assignable roles into `CreateUserDialog`:

```tsx
<CreateUserDialog disabled={busy} onCreated={load} roles={assignableRoles(me?.role)} />
```

Reset dialog (confirmation then one-time password):

```tsx
function ResetPasswordDialog({ user, disabled, onDone }: {
  user: AdminUser
  disabled: boolean
  onDone: () => void
}) {
  const [open, setOpen] = React.useState(false)
  const [result, setResult] = React.useState<ResetPasswordResponse | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  function close(next: boolean) {
    setOpen(next)
    if (!next) setResult(null) // never keep the password in state after close
    setError(null)
  }

  async function confirm() {
    try {
      const res = await usersApi.resetPassword(user.id)
      setResult(res)
      onDone()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not reset password.")
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogTrigger render={<Button size="sm" variant="outline" disabled={disabled} />}>
        Reset password
      </DialogTrigger>
      <DialogContent>
        {result ? (
          <>
            <DialogHeader>
              <DialogTitle>Temporary password for {result.username}</DialogTitle>
              <DialogDescription>
                Shown once. Give it to the user in person or over a secure channel.
                They must change it at first login.
              </DialogDescription>
            </DialogHeader>
            <code data-testid="temporary-password" className="rounded bg-muted p-3 text-sm">
              {result.temporary_password}
            </code>
            <DialogFooter>
              <Button
                onClick={() => navigator.clipboard?.writeText(result.temporary_password)}
              >
                Copy
              </Button>
              <Button variant="outline" onClick={() => close(false)}>Close</Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Reset {user.username}&apos;s password?</DialogTitle>
              <DialogDescription>
                This signs them out everywhere and forces a password change at next login.
              </DialogDescription>
            </DialogHeader>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <DialogFooter>
              <Button variant="outline" onClick={() => close(false)}>Cancel</Button>
              <Button variant="destructive" onClick={confirm}>Confirm reset</Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
```

Also add an "Issue reset code" action (D3) next to it, reusing a small dialog that calls `usersApi.resetCode(user.id)` and displays `code` + expiry with the same once-only warning.

Update `CreateUserDialog` to accept `roles: UserRole[]` and map them into `SelectItem`s; default to `roles[0] ?? "ANALYST"`.

Add a `ChangeRoleDialog` for D8, rendered only when `canManage(...)` is true and `assignableRoles(me?.role).length > 1`:

```tsx
function ChangeRoleDialog({ user, roles, disabled, onDone }: {
  user: AdminUser
  roles: UserRole[]
  disabled: boolean
  onDone: () => void
}) {
  const [open, setOpen] = React.useState(false)
  const [role, setRole] = React.useState<UserRole>(user.role as UserRole)
  const [error, setError] = React.useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    try {
      await usersApi.update(user.id, { role })
      setOpen(false)
      onDone()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not change role.")
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm" variant="outline" disabled={disabled} />}>
        Change role
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Change {user.username}&apos;s role</DialogTitle>
          <DialogDescription>Only roles you may assign are listed.</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <Select value={role} onValueChange={(v) => { if (v) setRole(v as UserRole) }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {roles.map((r) => <SelectItem key={r} value={r}>{r}</SelectItem>)}
            </SelectContent>
          </Select>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <DialogFooter><Button type="submit">Save role</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
```

The list must exclude the target's current role from the "changed" path only if the backend rejects a no-op; it does not (no-op returns 200), so leaving it is fine.

- [ ] **Step 4: Run green**

Run: `cd frontend && pnpm vitest run tests/users-page.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add "frontend/app/(dashboard)/users/page.tsx" frontend/tests/users-page.test.tsx
git commit -m "feat(admin): show hierarchy-aware reset actions on the users page"
```

---

## Task 9: Sidebar gating

**Files:**
- Modify: `frontend/components/app-sidebar.tsx:173`
- Modify: `frontend/tests/app-sidebar.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
it("shows Users to SUPER_ADMIN", () => {
  state.user = { username: "root", role: "SUPER_ADMIN" }
  renderSidebar()
  expect(screen.getByText("Users")).toBeInTheDocument()
})
```

- [ ] **Step 2: Run red**

Run: `cd frontend && pnpm vitest run tests/app-sidebar.test.tsx`
Expected: FAIL — only `ADMIN` is gated.

- [ ] **Step 3: Update the gate**

```tsx
{(user?.role === "ADMIN" || user?.role === "SUPER_ADMIN") && navAdmin.map((item) => (
```

- [ ] **Step 4: Run green**

Run: `cd frontend && pnpm vitest run tests/app-sidebar.test.tsx`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add frontend/components/app-sidebar.tsx frontend/tests/app-sidebar.test.tsx
git commit -m "feat(admin): show the users nav entry to SUPER_ADMIN"
```

---

## Task 10: Deployment order, docs, and full verification

**Files:**
- Modify: `deploy/README.md`
- Modify: `docs/superpowers/plans/2026-11-03-auth-authz-phase2.md` (mark the new reset contract)

- [ ] **Step 1: Document the migration/bootstrap order**

Add to `deploy/README.md`:

```markdown
## SUPER_ADMIN bootstrap (run once, in this order)

1. Back up the database.
2. Stop the API.
3. `.venv/bin/python database/migrate.py`  # applies 010_super_admin_role.sql
4. `.venv/bin/python scripts/create_super_admin.py --username <name> --execute`
   - prints a one-time password to stdout; move it to the password manager
   - the account must change it at first login
5. Start the API.
6. Log in as the new SUPER_ADMIN and confirm `/users` is visible.

There is intentionally no automatic promotion of the existing `admin` account.
Until step 4 runs, no account can manage an ADMIN.
```

Also add `password_reset_tokens` to the Task 16 backup table list.

- [ ] **Step 2: Run the full backend suite**

```bash
.venv/bin/python -m pytest tests/ -q
```

Expected: the same 29 dataset-drift failures and **no new failures**. Compare against the recorded baseline; any new failure is a regression.

- [ ] **Step 3: Run the frontend suite and build**

```bash
cd frontend
pnpm test -- --run
pnpm build
```

Expected: all tests pass; build succeeds.

- [ ] **Step 4: Manual browser matrix**

Log in as each actor and record the result:

| Actor | Target | Reset password | Change role | Disable | Create |
|---|---|---|---|---|---|
| SUPER_ADMIN | ADMIN | allowed, shows temp password once | allowed | allowed | ADMIN allowed |
| SUPER_ADMIN | SUPER_ADMIN (other) | allowed | allowed | allowed | SUPER_ADMIN allowed |
| SUPER_ADMIN | self | 403, no button | 403, no button | 403, no button | n/a |
| ADMIN | ANALYST / SUPPORT | allowed | allowed | allowed | ANALYST/SUPPORT only |
| ADMIN | ADMIN | 403, no button | 403 | 403 | ADMIN option absent |
| ADMIN | SUPER_ADMIN | 403, no button | 403 | 403 | SUPER_ADMIN option absent |
| ANALYST / SUPPORT | anyone | 403 | 403 | 403 | 403 |

For each allowed reset: confirm the target is signed out, the temp password works, and any other route returns HTTP 428 until `/change-password` completes. Close the modal and confirm the password is gone from the DOM.

- [ ] **Step 5: Commit**

```bash
git add deploy/README.md docs/superpowers/plans/2026-11-03-auth-authz-phase2.md
git commit -m "docs(ops): document SUPER_ADMIN migration and bootstrap order"
```

---

## Self-Review Notes

- **Spec coverage:** role + DB constraint (Task 1); one helper (Task 2); every route (Task 3); reset endpoint (Task 4); last-principal guard (Task 5); scripts (Task 6); UI client (Task 7); UI page (Task 8); sidebar (Task 9); docs/verification (Task 10).
- **Known unreachable guard:** the HTTP API cannot demote the *last* SUPER_ADMIN because self-management is denied and only another SUPER_ADMIN can manage one. Task 5 tests the guard directly; the route-level matrix still exercises the two-SUPER_ADMIN case.
- **No placeholders:** every code step has concrete code; every command is runnable from the repo root unless `cd frontend` is shown.
- **Type consistency:** `temporary_password` is used identically in backend schema, API client, page state, and tests; `canManage`/`assignableRoles` names match between Tasks 7 and 8.
