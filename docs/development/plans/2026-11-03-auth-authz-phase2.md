# Authentication & Authorization Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the five deferred authentication findings, add a usable admin user-lifecycle surface and a self-service reset flow, then verify the nginx/systemd/ufw deployment on the real host.

**Architecture:** Keep the existing server-side opaque-session model. Phase 1 makes one isolated security change per task, each guarded by a failing test. Phase 2 adds an admin-only users API client, a `/users` page, and a one-time-code reset flow backed by a new `password_reset_tokens` table. Phase 3 is an on-host runbook with explicit acceptance checks. No JWT, no OIDC, no external identity provider.

**Tech Stack:** Python 3.13, FastAPI, psycopg2, PostgreSQL, pytest; Next.js 16 / React 19 / TypeScript, pnpm, base-ui + shadcn-style components; nginx, systemd, ufw on Ubuntu 24.04.

**Spec:** `docs/AUTH_SECURITY_AUDIT.md`, `docs/AUTH_HARDENING_WEEK1_CHANGES.md`, `docs/superpowers/plans/2026-10-28-auth-hardening-week1.md`

---

## Global Constraints

- Repository root: `/Users/akshit/Developer/dnsnetra`.
- Python interpreter for all commands:

  ```bash
  export PY=/Users/akshit/Developer/dnsnetra/.venv/bin/python
  ```

- Every task is TDD: write the failing test, run it red, implement, run it green, commit.
- One commit per task. Conventional messages exactly as written in each task.
- Never print, commit, or paste secrets, session tokens, CAPTCHA answers, or passwords. Phase 0 passwords go straight into the password manager.
- Destructive database actions are confined to Phase 0 and require explicit user approval immediately before execution.
- Do not touch the user's uncommitted frontend redesign (`frontend/app/globals.css`, `layout.tsx`, `components/auth/*`, `lib/auth/api.ts`, `lib/data-table/api-client.ts`). Phase 2 frontend work must stage only new/changed files it owns.
- Preserve the week-1 API contract except where a task explicitly changes it (Task 6 removes raw tokens from JSON).
- Known-good baseline after week 1: **29 failed, 387 passed, 7 xfailed**. The 29 failures are dataset drift in `test_reporting_service.py`, `test_aggregator.py`, `test_client_profiling.py`, `test_phase0_remediation.py`, `test_reporting_repository.py`, `test_data_reconciliation.py`, `test_investigation_service.py`. Any *new* failure is a regression.
- Frontend gates: `pnpm test` (46/46 baseline) and `pnpm build`. `pnpm lint` has 4 pre-existing errors in untouched files; do not fix them in this plan.
- nginx only. Do not introduce Caddy or another reverse proxy.
- No new runtime dependency without a note in the task. Phase 2 reset flow uses only the standard library plus what is already installed.

---

## Phase map

| Task | Original ID | Deliverable | Effort | Approval gate |
|---|---|---|---|---|
| 1 | T00 | Clean branch, committed docs, baseline snapshot | 10 min | — |
| 2 | T01 | Purged users/sessions/audit residue + backup | 15 min | **yes** |
| 3 | T02 | Rotated `admin`, forced-change flow proven | 20 min | **yes** |
| 4 | T03 | `Cache-Control: no-store` on auth responses | 1–2 h | — |
| 5 | T04 | Constant-ish login timing for unknown users | 2–3 h | — |
| 6 | T05 | No raw session token in login/change-password JSON | 4–6 h | — |
| 7 | T06 | Canonical password/username policy | 2–3 h | — |
| 8 | T07 | User-update invariants, no-op safe | 3–5 h | — |
| 9 | T08 | Per-account lockout + change-password limit | 4–6 h | — |
| 10 | T09a | Admin users API client | 3–4 h | — |
| 11 | T09b | `/users` admin page | 1 d | — |
| 12 | T09c | Role-gated navigation + page guard | 2–3 h | — |
| 13 | T10 | One-time-code password reset | 1–2 d | **decision** |
| 14 | T12 | Live nginx + TLS verification | 3–4 h | host access |
| 15 | T13 | systemd, loopback, ufw verification | 2–3 h | host access |
| 16 | T14 | Auth backups + audit retention | 2–3 h | host access |
| 17 | T15 | Auth monitoring and alerting | 2–4 h | host access |

Phase 4 (shared CAPTCHA store, session UI, CSP, access review) is **not** part of this plan; see Appendix B.

---

## File structure

**Backend**

| File | Responsibility |
|---|---|
| `api/main.py` | App wiring, security headers, auth cache-control middleware |
| `api/auth.py` | Password hashing, authentication, session dependency, token models |
| `api/login_throttle.py` | **new** — per-account failure counter and lockout |
| `api/routes/auth.py` | Login, token, change-password, logout, me, reset-password |
| `api/routes/users.py` | Admin user lifecycle, reset-code issuance |
| `api/sessions.py` | Session creation/lookup/revocation |
| `api/rbac.py` | Role matrix and `require_permission` |
| `database/migrations/009_password_reset_tokens.sql` | **new** — one-time reset codes |

**Frontend**

| File | Responsibility |
|---|---|
| `frontend/lib/auth/api.ts` | Existing auth client; remove token-from-body type |
| `frontend/lib/admin/users-api.ts` | **new** — admin users API client |
| `frontend/app/(dashboard)/users/page.tsx` | **new** — admin user lifecycle |
| `frontend/components/app-sidebar.tsx` | Role-gated “Users” entry |
| `frontend/app/(auth)/reset-password/page.tsx` | **new** — code + new password |
| `frontend/app/(auth)/login/page.tsx` | Link to reset page (auth-only hunk) |

**Tests**

| File | Responsibility |
|---|---|
| `tests/test_auth_security_audit.py` | Finding reproducers; all xfails must be removed by Task 9 |
| `tests/test_auth_complete.py` | End-to-end auth flows |
| `tests/test_auth_hardening.py` | Regression guards |
| `tests/conftest.py` | Shared fixtures, throttle reset |
| `tests/auth_testkit.py` | Login/CAPTCHA/session helpers |
| `tests/test_users_admin.py` | **new** — admin API client contract at route level |
| `tests/test_password_reset.py` | **new** — reset-code lifecycle |

**Deployment**

| File | Responsibility |
|---|---|
| `deploy/nginx/*`, `deploy/systemd/*`, `deploy/*.sh` | Already written in week 1; verified in Tasks 14–15 |
| `deploy/README.md` | Runbook; update with verification results |

---

## Phase 0 — Stabilize the live system

### Task 1 (T00): Housekeeping and baseline snapshot

**Files:**
- Modify: `docs/AUTH_HARDENING_WEEK1_CHANGES.md` (commit only)
- Add: `docs/superpowers/plans/2026-11-03-auth-authz-phase2.md` (this file)
- No application code.

**Interfaces:**
- Consumes: week-1 head `39056a5`.
- Produces: branch `auth/phase-2`, recorded baseline counts for Tasks 2–3.

- [ ] **Step 1: Confirm the working tree and head**

```bash
cd /Users/akshit/Developer/dnsnetra
git log --oneline -1
git status --short
```

Expected: head is `39056a5`; only the known frontend WIP, test artifacts, and the two untracked docs appear.

- [ ] **Step 2: Commit the documentation**

```bash
git add docs/AUTH_HARDENING_WEEK1_CHANGES.md docs/superpowers/plans/2026-10-28-auth-hardening-week1.md docs/superpowers/plans/2026-11-03-auth-authz-phase2.md
git commit -m "docs(auth): add week-1 change record and phase-2 plan"
```

Do **not** add `frontend/`, `labeler/intel/trusted_domains.db`, or `logs/`.

- [ ] **Step 3: Create the working branch**

```bash
git switch -c auth/phase-2
```

- [ ] **Step 4: Record the baseline**

```bash
PGPASSWORD=$(grep -E '^UDR_DB_PASSWORD=' .env | cut -d= -f2- | tr -d '\r') \
psql -h localhost -U postgres -d dns_threat_detection -c "
SELECT id, username, role, status, must_change_password FROM dashboard_users ORDER BY id;
SELECT count(*) AS sessions FROM sessions;
SELECT count(*) AS audit_rows FROM audit_logs;"
```

Paste the output into the Phase 0 notes in `docs/AUTH_HARDENING_WEEK1_CHANGES.md` (counts only, no secrets).

- [ ] **Step 5: Confirm the backend baseline**

```bash
$PY -m pytest tests/test_auth_security_audit.py tests/test_auth_complete.py \
  tests/test_auth_hardening.py tests/test_rbac_routes.py -q
```

Expected: all pass except the 7 known `xfail`s.

---

### Task 2 (T01): Back up and purge test data — **approval required**

**Files:**
- No code changes.
- Produces: `~/dnsnetra-auth-backup-<timestamp>.sql`.

**Interfaces:**
- Consumes: `scripts/purge_test_users.py`, dry-run output.
- Produces: one `admin` row; `audit_logs` retained; sessions belonging to the deleted users removed by `ON DELETE CASCADE`. Admin's sessions are cleared by Task 3.

- [ ] **Step 1: Ask for explicit approval**

State exactly what will be deleted: `admin_sec`, `CASE_TEST_CE775C`, `analyst_user_1`, and their sessions. Audit logs are **kept** (they contain real login history). Do not proceed on silence.

- [ ] **Step 2: Dry run**

```bash
$PY scripts/purge_test_users.py --keep admin
```

Expected: lists the three accounts and says “3 user(s) would be deleted”.

- [ ] **Step 3: Back up**

```bash
STAMP=$(date +%Y%m%d-%H%M%S)
PGPASSWORD=$(grep -E '^UDR_DB_PASSWORD=' .env | cut -d= -f2- | tr -d '\r') \
pg_dump -h localhost -U postgres -d dns_threat_detection \
  -t dashboard_users -t sessions -t audit_logs \
  > "$HOME/dnsnetra-auth-backup-$STAMP.sql"
ls -lh "$HOME/dnsnetra-auth-backup-$STAMP.sql"
```

Expected: a non-empty SQL file.

- [ ] **Step 4: Execute**

```bash
$PY scripts/purge_test_users.py --keep admin --execute
```

Expected: `Deleted 3 user(s). Kept: admin`.

- [ ] **Step 5: Verify**

```bash
PGPASSWORD=$(grep -E '^UDR_DB_PASSWORD=' .env | cut -d= -f2- | tr -d '\r') \
psql -h localhost -U postgres -d dns_threat_detection -c "
SELECT username, role, status, must_change_password FROM dashboard_users;
SELECT count(*) AS sessions FROM sessions;
SELECT count(*) AS audit_rows FROM audit_logs;"
```

Expected: one row (`admin`); `audit_rows` retained (real history is not destroyed); `sessions` still counts historical rows but **zero active** sessions after Task 3. Check with:

```sql
SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > NOW();
```

---

### Task 3 (T02): Rotate the admin password — **approval required**

**Files:**
- No code changes.

**Interfaces:**
- Consumes: `scripts/rotate_admin_password.py`.
- Produces: `admin.must_change_password=true`, zero sessions for `admin`.

- [ ] **Step 1: Dry run**

```bash
$PY scripts/rotate_admin_password.py --username admin
```

Expected: `Dry run: would rotate 'admin'.`

- [ ] **Step 2: Execute without echoing the password into chat**

```bash
umask 077
$PY scripts/rotate_admin_password.py --username admin --execute \
  > "$HOME/dnsnetra-admin-once.txt"
chmod 600 "$HOME/dnsnetra-admin-once.txt"
```

Read the one-time password from `~/dnsnetra-admin-once.txt` and put it in your
password manager. Do not paste it into this conversation or a ticket. Delete the
file after you have set the new password in Step 4:

```bash
rm -f "$HOME/dnsnetra-admin-once.txt"
```

- [ ] **Step 3: Verify the database flag**

```bash
PGPASSWORD=$(grep -E '^UDR_DB_PASSWORD=' .env | cut -d= -f2- | tr -d '\r') \
psql -h localhost -U postgres -d dns_threat_detection -c \
"SELECT username, must_change_password FROM dashboard_users;"
```

Expected: `admin | t`.

- [ ] **Step 4: Prove the browser flow**

1. Open `http://localhost:3000/login`.
2. Log in as `admin` with the one-time password + CAPTCHA.
3. Confirm redirect to `/change-password`, not `/dashboard`.
4. Try `GET /dashboard` directly: expect a redirect back to `/change-password`.
5. Set a new password; confirm `/dashboard` loads.
6. Log out; confirm the one-time password no longer works.

- [ ] **Step 5: Verify final state**

```bash
PGPASSWORD=$(grep -E '^UDR_DB_PASSWORD=' .env | cut -d= -f2- | tr -d '\r') \
psql -h localhost -U postgres -d dns_threat_detection -c \
"SELECT username, must_change_password FROM dashboard_users;"
```

Expected: `admin | f`.

---

## Phase 1 — Close deferred findings

### Task 4 (T03): `Cache-Control: no-store` on auth responses

**Files:**
- Modify: `api/main.py` (inside `add_security_headers`)
- Test: `tests/test_auth_security_audit.py`

**Interfaces:**
- Consumes: existing `add_security_headers` middleware.
- Produces: every response under `/api/v1/auth/` carries `Cache-Control: no-store, max-age=0` and `Pragma: no-cache`.

- [ ] **Step 1: Remove the xfail and add a `/me` assertion**

Replace the marker above `test_login_response_is_not_cacheable` and extend it:

```python
def test_login_response_is_not_cacheable(mk_user):
    username, _ = mk_user("cache")
    client = _client()
    res = client.post("/api/v1/auth/login", json=_login_body(username))
    assert "no-store" in (res.headers.get("cache-control") or "").lower()
    me = client.get("/api/v1/auth/me")
    assert "no-store" in (me.headers.get("cache-control") or "").lower()
```

- [ ] **Step 2: Run it red**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k cacheable -q
```

Expected: FAIL — `Cache-Control` header is absent.

- [ ] **Step 3: Add the header in `api/main.py`**

Inside `add_security_headers`, immediately after `response = await call_next(request)`:

```python
    if request.url.path.startswith("/api/v1/auth/"):
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
```

- [ ] **Step 4: Run it green**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k cacheable -q
$PY -m pytest tests/test_auth_security_audit.py tests/test_auth_complete.py tests/test_auth_hardening.py -q
```

Expected: pass; only the remaining known `xfail`s reported.

- [ ] **Step 5: Commit**

```bash
git add api/main.py tests/test_auth_security_audit.py
git commit -m "fix(auth): forbid caching of authentication responses"
```

---

### Task 5 (T04): Equalize unknown-user login timing

**Files:**
- Modify: `api/auth.py` (imports, module constant, `authenticate_user`)
- Test: `tests/test_auth_security_audit.py`

**Interfaces:**
- Consumes: `verify_password(plain: str, hashed: str) -> bool`.
- Produces: `_DUMMY_PASSWORD_HASH: str`; `authenticate_user` performs exactly one password verification for existing and unknown identifiers.

- [ ] **Step 1: Replace the xfail with a call-count test**

```python
def test_unknown_user_still_performs_a_dummy_hash(mk_user, monkeypatch):
    calls: list[str] = []
    real_verify = auth.verify_password

    def counting_verify(plain: str, hashed: str) -> bool:
        calls.append(hashed)
        return real_verify(plain, hashed)

    monkeypatch.setattr(auth, "verify_password", counting_verify)
    res = _client().post("/api/v1/auth/login", json=_login_body("definitely_missing_user"))
    assert res.status_code == 401
    assert len(calls) == 1
    assert calls[0] == auth._DUMMY_PASSWORD_HASH
```

- [ ] **Step 2: Run it red**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k dummy_hash -q
```

Expected: FAIL — `api.auth` has no `_DUMMY_PASSWORD_HASH`, and `calls` is empty.

- [ ] **Step 3: Implement**

Add `import secrets` to `api/auth.py`, then after the `_hasher` definition:

```python
# A fixed hash used to spend the same Argon2id work for unknown usernames.
_DUMMY_PASSWORD_HASH = _hasher.hash(secrets.token_urlsafe(32))
```

Change the start of `authenticate_user`:

```python
    user = get_user_by_username(identifier)
    if not user:
        verify_password(plain_password, _DUMMY_PASSWORD_HASH)
        return None

    if not user.get("is_active") or user.get("status") != "ACTIVE":
        verify_password(plain_password, user.get("password_hash") or _DUMMY_PASSWORD_HASH)
        return None
```

- [ ] **Step 4: Run it green**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k dummy_hash -q
$PY -m pytest tests/test_auth_security_audit.py tests/test_auth_complete.py tests/test_auth_hardening.py -q
```

- [ ] **Step 5: Commit**

```bash
git add api/auth.py tests/test_auth_security_audit.py
git commit -m "fix(auth): spend equal hashing work for unknown usernames"
```

---

### Task 6 (T05): Remove raw session tokens from JSON responses

**Files:**
- Modify: `api/auth.py` (`TokenResponse`)
- Modify: `api/routes/auth.py` (`ChangePasswordResponse`, `login`, `token`, `change_password`)
- Modify: `tests/auth_testkit.py` (cookie extraction helper)
- Modify: `tests/test_auth_security_audit.py`, `tests/test_auth_complete.py`, `tests/test_auth_hardening.py`
- Modify: `frontend/lib/auth/api.ts` (return type only)

**Interfaces:**
- Consumes: `Set-Cookie: dnsnetra_session=<opaque>`.
- Produces:
  - `TokenResponse`: `{token_type: str, expires_in: int, user: dict}`
  - `ChangePasswordResponse`: `{message: str}`
  - `session_token_from_client(client: TestClient) -> str` in the test kit.

> **Breaking change.** Confirm no external client reads `session_token`/`access_token` from the JSON body before starting. Scripts in this repo create sessions server-side and are unaffected.

- [ ] **Step 1: Add the test-kit helper**

In `tests/auth_testkit.py`:

```python
def session_token_from_client(client: TestClient) -> str:
    """Read the opaque token from the client's cookie jar, never from JSON."""
    token = client.cookies.get("dnsnetra_session")
    if not token:
        raise AssertionError("login did not set the dnsnetra_session cookie")
    return token
```

- [ ] **Step 2: Update the AUTH-14 test and run it red**

```python
def test_login_does_not_return_raw_session_token_in_body(mk_user):
    username, _ = mk_user("nobodytoken")
    client = _client()
    res = client.post("/api/v1/auth/login", json=_login_body(username))
    assert res.status_code == 200
    body = res.json()
    assert "session_token" not in body
    assert "access_token" not in body
    assert client.cookies.get("dnsnetra_session")
```

```bash
$PY -m pytest tests/test_auth_security_audit.py -k raw_session_token -q
```

Expected: FAIL — both keys are present.

- [ ] **Step 3: Change the response models**

`api/auth.py`:

```python
class TokenResponse(BaseModel):
    token_type: str = "bearer"
    expires_in: int
    user: dict[str, Any]
```

`api/routes/auth.py`:

```python
class ChangePasswordResponse(BaseModel):
    message: str
```

Remove `session_token=` and `access_token=` from both `TokenResponse(...)` returns and from `ChangePasswordResponse(...)`.

- [ ] **Step 4: Update test call sites**

Replace body extraction with the cookie helper:

| File | Old | New |
|---|---|---|
| `test_auth_security_audit.py` | `token = login_res.json()["session_token"]` | `token = session_token_from_client(client)` |
| `test_auth_security_audit.py` | `token = client.post(...).json()["session_token"]` (2 sites) | `client.post(...); token = session_token_from_client(client)` |
| `test_auth_security_audit.py` | `t1 = first.post(...).json()["session_token"]` | `first.post(...); t1 = session_token_from_client(first)` |
| `test_auth_security_audit.py` | `t2 = second.post(...).json()["session_token"]` | `second.post(...); t2 = session_token_from_client(second)` |
| `test_auth_security_audit.py` | `Bearer {res.json()['session_token']}` after change-password | `Bearer {session_token_from_client(first)}` |
| `test_auth_complete.py` | `assert "session_token" in data` | `assert "session_token" not in data` + `assert login_res.cookies.get("dnsnetra_session")` |
| `test_auth_complete.py` | `assert "access_token" in data` | delete the assertion |
| `test_auth_complete.py` | `token = login_res.json()["session_token"]` | `token = session_token_from_client(client)` |
| `test_auth_hardening.py` | every `*.json()["access_token"]` (10 sites) and `*.json()["session_token"]` (1 site) | `session_token_from_client(<client that just logged in>)` |

Import the helper in each file:

```python
from tests.auth_testkit import session_token_from_client
```

Where a test uses `_client()` inline, assign it to a local variable first. Also update the docstring/response description of `/login` and `/token` in `api/routes/auth.py` so Swagger no longer advertises a token in the body.

- [ ] **Step 5: Update the frontend type**

`frontend/lib/auth/api.ts`:

```ts
  login: (b: {
    username: string
    password: string
    captcha_id: string
    captcha_answer: string
  }) => post<{ user: AuthUser }>("/login", b),

  changePassword: (b: {
    current_password: string
    new_password: string
    confirm_password: string
  }) => post<{ message: string }>("/change-password", b),
```

- [ ] **Step 6: Run the suites**

```bash
$PY -m pytest tests/test_auth_security_audit.py tests/test_auth_complete.py tests/test_auth_hardening.py tests/test_auth_config.py -q
cd frontend && pnpm test && pnpm build
```

Expected: backend pass except known `xfail`s; frontend 46/46 and build pass.

- [ ] **Step 7: Commit**

```bash
git add api/auth.py api/routes/auth.py tests/auth_testkit.py \
  tests/test_auth_security_audit.py tests/test_auth_complete.py tests/test_auth_hardening.py \
  frontend/lib/auth/api.ts
git commit -m "fix(auth): keep session tokens out of JSON responses"
```

---

### Task 7 (T06): Canonical password and username policy

**Files:**
- Modify: `api/auth.py` (`validate_password_strength`, `validate_username`)
- Test: `tests/test_auth_security_audit.py`

**Interfaces:**
- Produces: one special-character rule (`[^A-Za-z]`); reserved-name comparison ignores leading/trailing `.`, `_`, `-`.

- [ ] **Step 1: Replace both xfails with the real tests**

```python
def test_underscore_counts_as_special_character():
    ok, reason = auth.validate_password_strength("Password_")
    assert ok, reason


@pytest.mark.parametrize("candidate", [".admin.", "admin.", "_admin_", "Admin.", ".ROOT."])
def test_dotted_reserved_username_is_rejected(candidate):
    ok, reason = auth.validate_username(candidate, is_signup=True)
    assert not ok, reason


def test_normal_username_with_dot_is_still_allowed():
    ok, reason = auth.validate_username("john.doe", is_signup=True)
    assert ok, reason
```

- [ ] **Step 2: Run red**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k "underscore or reserved" -q
```

Expected: FAIL — `_` rejected; `.admin.` accepted.

- [ ] **Step 3: Implement**

In `validate_password_strength`, replace the digit/special regex:

```python
    if not re.search(r"[^A-Za-z]", password):
        return False, "Password must contain at least one digit or special character"
```

Add a helper above `validate_username`:

```python
def _reserved_key(value: str) -> str:
    return value.strip().strip("._-").lower()
```

Replace the reserved check:

```python
    if is_signup and _reserved_key(clean) in RESERVED_USERNAMES:
        return False, f"Username '{clean}' is reserved by the system"
```

- [ ] **Step 4: Run green**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k "underscore or reserved or username" -q
$PY -m pytest tests/test_auth_security_audit.py tests/test_auth_hardening.py -q
```

- [ ] **Step 5: Commit**

```bash
git add api/auth.py tests/test_auth_security_audit.py
git commit -m "fix(auth): make password and reserved-name policy consistent"
```

---

### Task 8 (T07): User-update invariants and no-op safety

**Files:**
- Modify: `api/routes/users.py` (`update_user`)
- Test: `tests/test_auth_security_audit.py`

**Interfaces:**
- Consumes: `UpdateUserRequest {role?, status?, is_active?}`, `get_user_by_id`, `_ensure_not_last_active_admin`.
- Produces: `400` on contradictory fields; no revocation when nothing changes; real changes still revoke.

- [ ] **Step 1: Remove both xfails and add contradiction variants**

```python
def test_contradictory_status_update_returns_4xx(mk_user, admin_headers):
    _, uid = mk_user("contradict")
    client = _client()
    assert client.patch(
        f"/api/v1/users/{uid}",
        json={"status": "ACTIVE", "is_active": False},
        headers=admin_headers,
    ).status_code == 400
    assert client.patch(
        f"/api/v1/users/{uid}",
        json={"status": "DISABLED", "is_active": True},
        headers=admin_headers,
    ).status_code == 400


def test_noop_update_does_not_revoke_sessions(mk_user, admin_headers):
    username, uid = mk_user("noop", role="ANALYST")
    client = _client()
    token = login(client, username)
    raw = session_token_from_client(client)
    assert client.patch(
        f"/api/v1/users/{uid}", json={"role": "ANALYST"}, headers=admin_headers
    ).status_code == 200
    res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {raw}"})
    assert res.status_code == 200
```

Update the test-module imports (Task 6 adds the helper to the kit):

```python
from tests.auth_testkit import issue_captcha, login, session_token_from_client
```

- [ ] **Step 2: Run red**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k "contradictory or noop" -q
```

Expected: FAIL — 500 on the contradiction; 401 after the no-op because sessions were revoked.

- [ ] **Step 3: Rewrite the decision block in `update_user`**

Replace the block from `# Check if role demotion or deactivation` through the `revoke_all_user_sessions` call with:

```python
    target_role = target_user["role"]
    target_status = target_user["status"]
    target_active = target_user["is_active"]

    new_role = payload.role
    new_status = payload.status
    new_active = payload.is_active

    if new_status is not None and new_active is not None:
        if new_active != (new_status == UserStatus.ACTIVE):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="status and is_active must agree",
            )

    if new_status is None and new_active is not None:
        new_status = UserStatus.ACTIVE if new_active else UserStatus.DISABLED
    if new_active is None and new_status is not None:
        new_active = new_status == UserStatus.ACTIVE

    role_changed = new_role is not None and new_role.value != target_role
    status_changed = (
        new_status is not None
        and (new_status.value != target_status or new_active != target_active)
    )

    if not role_changed and not status_changed:
        return UserDetail(**target_user)

    will_demote = role_changed and new_role != UserRole.ADMIN
    will_deactivate = status_changed and new_status != UserStatus.ACTIVE

    updates = []
    params = []
    if role_changed:
        updates.append("role = %s")
        params.append(new_role.value)
    if status_changed:
        updates.append("status = %s")
        updates.append("is_active = %s")
        params.extend([new_status.value, new_active])
```

Keep the rest (`updated_at`, guard, UPDATE … RETURNING, revoke if `will_deactivate or will_demote`) unchanged.

- [ ] **Step 4: Run green**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k "contradictory or noop" -q
$PY -m pytest tests/test_auth_security_audit.py tests/test_auth_complete.py tests/test_rbac_routes.py -q
```

Also confirm a real change still revokes:

```bash
$PY -m pytest tests/test_auth_hardening.py -k "revoke or re_enabling" -q
```

- [ ] **Step 5: Commit**

```bash
git add api/routes/users.py tests/test_auth_security_audit.py
git commit -m "fix(users): validate status invariants and skip no-op revocation"
```

---

### Task 9 (T08): Per-account lockout and change-password limit

**Files:**
- Create: `api/login_throttle.py`
- Modify: `api/routes/auth.py` (`login`, `change_password`)
- Modify: `tests/conftest.py` (autouse reset)
- Test: `tests/test_auth_security_audit.py`

**Interfaces:**
- Produces:
  - `is_locked(username: str) -> tuple[bool, int]`
  - `record_failure(username: str) -> int`
  - `reset(username: str) -> None`
  - `reset_all() -> None`
- Lockout schedule: 5 failures → 60 s, 10 → 300 s, 15+ → 900 s.

> This is in-process state. It is correct for the current `--workers 1` deployment. AUTH-16 (shared store) is still deferred; document the limitation in the module docstring.

- [ ] **Step 1: Write the failing tests**

```python
def test_five_failed_logins_lock_the_account(mk_user):
    username, _ = mk_user("lockme")
    client = _client()
    for _ in range(5):
        res = client.post("/api/v1/auth/login", json=_login_body(username, "WrongPass123!"))
        assert res.status_code == 401
    blocked = client.post("/api/v1/auth/login", json=_login_body(username))
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


def test_successful_login_resets_the_failure_counter(mk_user):
    username, _ = mk_user("resetme")
    client = _client()
    for _ in range(4):
        assert client.post(
            "/api/v1/auth/login", json=_login_body(username, "WrongPass123!")
        ).status_code == 401
    assert login(client, username).status_code == 200
    for _ in range(4):
        assert client.post(
            "/api/v1/auth/login", json=_login_body(username, "WrongPass123!")
        ).status_code == 401


def test_change_password_is_rate_limited(analyst_headers):
    codes = [
        _client().post(
            "/api/v1/auth/change-password",
            json={
                "current_password": "wrong",
                "new_password": "NewPass123!",
                "confirm_password": "NewPass123!",
            },
            headers=analyst_headers,
        ).status_code
        for _ in range(12)
    ]
    assert 429 in codes
```

- [ ] **Step 2: Run red**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k "lock or resets_the_failure or change_password_is_rate" -q
```

Expected: no 429 from either path.

- [ ] **Step 3: Create `api/login_throttle.py`**

```python
"""Per-account login failure throttling.

In-process state, matching the existing rate limiter. Correct for the current
single-worker deployment; AUTH-16 tracks moving this to a shared store.
"""

from __future__ import annotations

import threading
import time

_LOCK = threading.Lock()
_FAILURES: dict[str, tuple[int, float]] = {}
_MAX_KEYS = 10000


def _key(username: str) -> str:
    return username.strip().lower()


def _lock_seconds(count: int) -> int:
    if count < 5:
        return 0
    if count < 10:
        return 60
    if count < 15:
        return 300
    return 900


def is_locked(username: str) -> tuple[bool, int]:
    now = time.time()
    with _LOCK:
        count, locked_until = _FAILURES.get(_key(username), (0, 0.0))
        if locked_until > now:
            return True, max(1, int(locked_until - now))
        return False, 0


def record_failure(username: str) -> int:
    now = time.time()
    key = _key(username)
    with _LOCK:
        if len(_FAILURES) > _MAX_KEYS:
            for stale in [k for k, (_, until) in _FAILURES.items() if until < now][:1000]:
                _FAILURES.pop(stale, None)
        count = _FAILURES.get(key, (0, 0.0))[0] + 1
        until = now + _lock_seconds(count) if _lock_seconds(count) else 0.0
        _FAILURES[key] = (count, until)
        return count


def reset(username: str) -> None:
    with _LOCK:
        _FAILURES.pop(_key(username), None)


def reset_all() -> None:
    with _LOCK:
        _FAILURES.clear()
```

- [ ] **Step 4: Wire it into login (both entry points)**

At the top of `login`, after `identifier` is validated:

```python
    locked, retry_after = is_locked(identifier)
    if locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please retry later.",
            headers={"Retry-After": str(retry_after)},
        )
```

In the failure branch, before raising 401:

```python
        record_failure(identifier)
```

After `user = authenticate_user(...)` succeeds:

```python
    reset(identifier)
```

Apply the same three changes to `login_for_access_token` (`/token`) using
`form_data.username`, otherwise the lockout is trivially bypassed by calling the
OAuth2 form alias.

- [ ] **Step 5: Add the change-password limit**

Add to the route decorator:

```python
    dependencies=[Depends(rate_limiter(action="change_password", max_requests=10, window_seconds=60))],
```

Inside the handler, after resolving `current_user`:

```python
    allowed, retry_after = check_rate_limit(
        key=current_user["username"],
        action="change_password_user",
        max_requests=5,
        window_seconds=60,
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many password change attempts.",
            headers={"Retry-After": str(retry_after)},
        )
```

Import `check_rate_limit` from `..rate_limiter` and the throttle helpers.

- [ ] **Step 6: Reset state between tests**

In `tests/conftest.py`, add `from api.login_throttle import reset_all` to the imports and extend `_reset_rate_limits`:

```python
@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_rate_limits()
    reset_all()
    yield
    reset_rate_limits()
    reset_all()
```

- [ ] **Step 7: Run green**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k "lock or resets_the_failure or change_password_is_rate" -q
$PY -m pytest tests/test_auth_security_audit.py tests/test_auth_complete.py tests/test_auth_hardening.py -q
```

- [ ] **Step 8: Confirm zero xfails**

```bash
grep -c "xfail" tests/test_auth_security_audit.py
```

Expected: `0` (the module docstring no longer mentions xfail either; update it).

- [ ] **Step 9: Commit**

```bash
git add api/login_throttle.py api/routes/auth.py tests/conftest.py tests/test_auth_security_audit.py
git commit -m "feat(auth): add per-account lockout and change-password limits"
```

---

## Phase 2 — Product gaps

### Task 10 (T09a): Admin users API client

**Files:**
- Create: `frontend/lib/admin/users-api.ts`
- Test: `frontend/lib/admin/users-api.test.ts` (vitest, mocked `fetch`)

**Interfaces:**
- Consumes: `/api/v1/users*` (all admin-only).
- Produces:

```ts
export type UserRole = "ADMIN" | "ANALYST" | "SUPPORT"
export type UserStatus = "PENDING" | "ACTIVE" | "DISABLED"

export interface AdminUser {
  id: number
  username: string
  email?: string | null
  role: UserRole
  status: UserStatus
  is_active: boolean
  created_at?: string
  updated_at?: string
  last_login_at?: string | null
  must_change_password?: boolean
}

export interface UserListResponse {
  total: number
  limit: number
  offset: number
  items: AdminUser[]
}

export class AdminApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

export const usersApi = {
  list: (params?: { status?: UserStatus; limit?: number; offset?: number }) => Promise<UserListResponse>,
  get: (id: number) => Promise<AdminUser>,
  create: (body: { username: string; password: string; role: UserRole; status: UserStatus }) => Promise<AdminUser>,
  update: (id: number, body: { role?: UserRole; status?: UserStatus; is_active?: boolean }) => Promise<AdminUser>,
  approve: (id: number, role: "ANALYST" | "SUPPORT") => Promise<{ message: string }>,
  disable: (id: number) => Promise<{ message: string }>,
  enable: (id: number) => Promise<{ message: string }>,
  resetPassword: (id: number, newPassword: string) => Promise<{ message: string }>,
  revokeSessions: (id: number) => Promise<{ message: string; revoked_count: number }>,
}
```

- [x] **Step 1: Write the failing test**

```ts
import { afterEach, describe, expect, it, vi } from "vitest"
import { usersApi } from "./users-api"

describe("usersApi", () => {
  afterEach(() => vi.restoreAllMocks())

  it("lists users with query parameters", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ total: 0, limit: 50, offset: 0, items: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      })
    )
    await usersApi.list({ status: "PENDING", limit: 25 })
    const url = String(fetchMock.mock.calls[0][0])
    expect(url).toContain("/api/v1/users?")
    expect(url).toContain("status=PENDING")
    expect(url).toContain("limit=25")
  })

  it("raises AdminApiError on 403", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: "Forbidden" }), { status: 403 })
    )
    await expect(usersApi.list()).rejects.toMatchObject({ status: 403 })
  })
})
```

- [x] **Step 2: Run red**

```bash
cd frontend && pnpm vitest run lib/admin/users-api.test.ts
```

Expected: FAIL — module not found.

- [x] **Step 3: Implement the client**

```ts
import { getActiveApiBase } from "@/lib/auth/api"

export type UserRole = "ADMIN" | "ANALYST" | "SUPPORT"
export type UserStatus = "PENDING" | "ACTIVE" | "DISABLED"

export interface AdminUser {
  id: number
  username: string
  email?: string | null
  role: UserRole
  status: UserStatus
  is_active: boolean
  created_at?: string
  updated_at?: string
  last_login_at?: string | null
  must_change_password?: boolean
}

export interface UserListResponse {
  total: number
  limit: number
  offset: number
  items: AdminUser[]
}

export class AdminApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = "AdminApiError"
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${getActiveApiBase()}${path}`, {
    ...init,
    credentials: "include",
    cache: "no-store",
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new AdminApiError(res.status, body?.detail ?? `Request failed (${res.status})`)
  }
  return body as T
}

function query(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") search.set(k, String(v))
  }
  const s = search.toString()
  return s ? `?${s}` : ""
}

export const usersApi = {
  list: (params: { status?: UserStatus; limit?: number; offset?: number } = {}) =>
    request<UserListResponse>(`/api/v1/users${query(params)}`),
  get: (id: number) => request<AdminUser>(`/api/v1/users/${id}`),
  create: (body: { username: string; password: string; role: UserRole; status: UserStatus }) =>
    request<AdminUser>("/api/v1/users", { method: "POST", body: JSON.stringify(body) }),
  update: (id: number, body: { role?: UserRole; status?: UserStatus; is_active?: boolean }) =>
    request<AdminUser>(`/api/v1/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  approve: (id: number, role: "ANALYST" | "SUPPORT") =>
    request<{ message: string }>(`/api/v1/users/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ role }),
    }),
  disable: (id: number) =>
    request<{ message: string }>(`/api/v1/users/${id}/disable`, { method: "POST" }),
  enable: (id: number) =>
    request<{ message: string }>(`/api/v1/users/${id}/enable`, { method: "POST" }),
  resetPassword: (id: number, newPassword: string) =>
    request<{ message: string }>(`/api/v1/users/${id}/reset-password`, {
      method: "POST",
      body: JSON.stringify({ new_password: newPassword }),
    }),
  revokeSessions: (id: number) =>
    request<{ message: string; revoked_count: number }>(`/api/v1/users/${id}/revoke-sessions`, {
      method: "POST",
    }),
}
```

- [x] **Step 4: Run green**

```bash
cd frontend && pnpm vitest run lib/admin/users-api.test.ts
```

- [x] **Step 5: Commit**

```bash
git add frontend/lib/admin/users-api.ts frontend/lib/admin/users-api.test.ts
git commit -m "feat(admin): add typed users API client"
```

---

### Task 11 (T09b): `/users` admin page

**Files:**
- Create: `frontend/app/(dashboard)/users/page.tsx`
- Test: `frontend/app/(dashboard)/users/page.test.tsx` (smoke: renders pending users)

**Interfaces:**
- Consumes: `usersApi`.
- Produces: pending-approval table, active/disabled table, create form, reset dialog, disable/enable/revoke actions.

- [x] **Step 1: Write the failing smoke test**

```tsx
import { render, screen, waitFor } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"
import UsersPage from "./page"

vi.mock("@/lib/admin/users-api", () => ({
  // The page uses `instanceof AdminApiError` in its error handler.
  AdminApiError: class AdminApiError extends Error {
    status: number
    constructor(status: number, message: string) {
      super(message)
      this.status = status
    }
  },
  usersApi: {
    list: vi.fn().mockResolvedValue({
      total: 1, limit: 200, offset: 0,
      items: [{
        id: 7, username: "new.analyst", role: "ANALYST", status: "PENDING", is_active: false,
      }],
    }),
    approve: vi.fn().mockResolvedValue({ message: "ok" }),
  },
}))

// The page reads the signed-in user from the dashboard AuthGuard.
vi.mock("@/components/auth/AuthGuard", () => ({
  useAuthUser: () => ({ username: "admin", role: "ADMIN" }),
}))

describe("UsersPage", () => {
  it("shows pending accounts", async () => {
    render(<UsersPage />)
    await waitFor(() => expect(screen.getByText("new.analyst")).toBeInTheDocument())
  })
})
```

- [x] **Step 2: Run red**

```bash
cd frontend && pnpm vitest run "app/(dashboard)/users/page.test.tsx"
```

Expected: FAIL — module not found.

- [x] **Step 3: Implement the page**

Use `Table`, `Badge`, `Button`, `Input`, `Label`, `Dialog`, `Select` from `@/components/ui/*`. Keep the page client-side.

```tsx
"use client"

import * as React from "react"
import { useAuthUser } from "@/components/auth/AuthGuard"
import { usersApi, AdminApiError, type AdminUser, type UserRole } from "@/lib/admin/users-api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"

const STATUS_STYLE: Record<string, string> = {
  ACTIVE: "bg-emerald-500/10 text-emerald-700",
  PENDING: "bg-amber-500/10 text-amber-700",
  DISABLED: "bg-muted text-muted-foreground",
}

export default function UsersPage() {
  const me = useAuthUser()
  const [users, setUsers] = React.useState<AdminUser[]>([])
  const [error, setError] = React.useState<string | null>(null)
  const [busy, setBusy] = React.useState(false)

  const load = React.useCallback(async () => {
    try {
      const res = await usersApi.list({ limit: 200 })
      setUsers(res.items)
      setError(null)
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not load users.")
    }
  }, [])

  React.useEffect(() => { void load() }, [load])

  async function run(action: () => Promise<unknown>) {
    setBusy(true)
    try {
      await action()
      await load()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Action failed.")
    } finally {
      setBusy(false)
    }
  }

  if (me?.role !== "ADMIN") {
    return <p className="p-6 text-sm text-muted-foreground">Administrator access required.</p>
  }

  const pending = users.filter((u) => u.status === "PENDING")
  const others = users.filter((u) => u.status !== "PENDING")

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <header className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Users</h1>
          <p className="text-sm text-muted-foreground">
            Approve new accounts and manage existing ones.
          </p>
        </div>
        <CreateUserDialog disabled={busy} onCreated={load} />
      </header>

      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium">Pending approval ({pending.length})</h2>
        <UserTable
          users={pending}
          busy={busy}
          actions={(u) => (
            <>
              {(["ANALYST", "SUPPORT"] as const).map((role) => (
                <Button key={role} size="sm" disabled={busy}
                  onClick={() => run(() => usersApi.approve(u.id, role))}>
                  Approve as {role}
                </Button>
              ))}
            </>
          )}
        />
      </section>

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium">All accounts</h2>
        <UserTable
          users={others}
          busy={busy}
          actions={(u) => (
            <>
              <Button size="sm" variant="outline" disabled={busy}
                onClick={() => run(() => usersApi.revokeSessions(u.id))}>
                Revoke sessions
              </Button>
              {u.status === "ACTIVE" ? (
                <Button size="sm" variant="destructive" disabled={busy}
                  onClick={() => run(() => usersApi.disable(u.id))}>
                  Disable
                </Button>
              ) : (
                <Button size="sm" variant="outline" disabled={busy}
                  onClick={() => run(() => usersApi.enable(u.id))}>
                  Enable
                </Button>
              )}
              <ResetPasswordDialog user={u} disabled={busy} onDone={load} />
            </>
          )}
        />
      </section>
    </div>
  )
}

function UserTable({
  users, busy, actions,
}: {
  users: AdminUser[]
  busy: boolean
  actions: (u: AdminUser) => React.ReactNode
}) {
  if (!users.length) return <p className="text-sm text-muted-foreground">None.</p>
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Username</TableHead>
          <TableHead>Role</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Last login</TableHead>
          <TableHead className="text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {users.map((u) => (
          <TableRow key={u.id}>
            <TableCell className="font-medium">{u.username}</TableCell>
            <TableCell>{u.role}</TableCell>
            <TableCell>
              <Badge className={STATUS_STYLE[u.status]}>{u.status}</Badge>
            </TableCell>
            <TableCell className="text-muted-foreground">
              {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "Never"}
            </TableCell>
            <TableCell className="flex justify-end gap-2">{actions(u)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function CreateUserDialog({ disabled, onCreated }: { disabled: boolean; onCreated: () => void }) {
  const [open, setOpen] = React.useState(false)
  const [username, setUsername] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [role, setRole] = React.useState<UserRole>("ANALYST")
  const [error, setError] = React.useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    try {
      await usersApi.create({ username, password, role, status: "ACTIVE" })
      setOpen(false); setUsername(""); setPassword(""); setRole("ANALYST"); onCreated()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not create user.")
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button disabled={disabled} />}>Create user</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create user</DialogTitle>
          <DialogDescription>
            The user must change this password at first login.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="new-username">Username</Label>
            <Input id="new-username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="new-password">Temporary password</Label>
            <Input id="new-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>Role</Label>
            <Select value={role} onValueChange={(v) => { if (v) setRole(v as UserRole) }}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="ANALYST">ANALYST</SelectItem>
                <SelectItem value="SUPPORT">SUPPORT</SelectItem>
                <SelectItem value="ADMIN">ADMIN</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="submit">Create</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ResetPasswordDialog({
  user, disabled, onDone,
}: { user: AdminUser; disabled: boolean; onDone: () => void }) {
  const [open, setOpen] = React.useState(false)
  const [password, setPassword] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    try {
      await usersApi.resetPassword(user.id, password)
      setOpen(false); setPassword(""); onDone()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not reset password.")
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm" variant="outline" disabled={disabled} />}>
        Reset password
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset {user.username}&apos;s password</DialogTitle>
          <DialogDescription>
            All sessions are revoked. The user must change this password at next login.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          {error && <p className="text-sm text-destructive">{error}</p>}
          <DialogFooter><Button type="submit">Reset</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
```

- [x] **Step 4: Run the test and the build**

```bash
cd frontend && pnpm vitest run "app/(dashboard)/users/page.test.tsx" && pnpm build
```

- [x] **Step 5: Commit**

```bash
git add "frontend/app/(dashboard)/users/page.tsx" "frontend/app/(dashboard)/users/page.test.tsx"
git commit -m "feat(admin): add user lifecycle page"
```

---

### Task 12 (T09c): Role-gated navigation

**Files:**
- Modify: `frontend/components/app-sidebar.tsx`
- Test: `frontend/components/app-sidebar.test.tsx` (new, or extend existing)

**Interfaces:**
- Consumes: `useAuthUser()` → `{ role }`.
- Produces: “Users” link visible only to `ADMIN`.

- [x] **Step 1: Write the failing test**

```tsx
import * as React from "react"
import { render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { AppSidebar } from "./app-sidebar"
import { SidebarProvider } from "@/components/ui/sidebar"

// vi.mock factories are hoisted above module imports, so shared mutable state
// must be created with vi.hoisted.
const state = vi.hoisted(() => ({
  user: { username: "a", role: "ANALYST" as string },
}))

vi.mock("@/components/auth/AuthGuard", () => ({
  useAuthUser: () => state.user,
}))
vi.mock("@/hooks/use-mobile", () => ({ useIsMobile: () => false }))
vi.mock("next/navigation", () => ({
  usePathname: () => "/dashboard",
  useRouter: () => ({ replace: vi.fn() }),
}))
vi.mock("next/link", () => ({
  default: ({ href, children, ...props }: React.ComponentProps<"a">) =>
    React.createElement("a", { href, ...props }, children),
}))

function renderSidebar() {
  return render(
    <SidebarProvider>
      <AppSidebar />
    </SidebarProvider>
  )
}

describe("AppSidebar", () => {
  beforeEach(() => {
    state.user = { username: "a", role: "ANALYST" }
  })

  it("hides Users from non-admins", () => {
    renderSidebar()
    expect(screen.queryByText("Users")).not.toBeInTheDocument()
  })

  it("shows Users to admins", () => {
    state.user = { username: "a", role: "ADMIN" }
    renderSidebar()
    expect(screen.getByText("Users")).toBeInTheDocument()
  })
})
```

- [x] **Step 2: Run red**

```bash
cd frontend && pnpm vitest run components/app-sidebar.test.tsx
```

Expected: FAIL on “shows Users to admins” — the entry does not exist yet. The
non-admin case passes vacuously until the link is added; Step 4 re-runs both.

- [x] **Step 3: Implement**

Add to `navSystem`:

```tsx
const navSystem = [
  { title: "Settings", url: "/settings", icon: <SettingsIcon /> },
  { title: "Users", url: "/users", icon: <UsersIcon />, adminOnly: true },
]
```

Filter the System group before mapping (`user` already exists in the component):

```tsx
{navSystem
  .filter((item) => !("adminOnly" in item) || user?.role === "ADMIN")
  .map((item) => (
    <SidebarMenuItem key={item.title}>
      <SidebarMenuButton
        isActive={pathname === item.url}
        tooltip={item.title}
        render={<Link href={item.url} />}
      >
        {item.icon}
        <span>{item.title}</span>
      </SidebarMenuButton>
    </SidebarMenuItem>
  ))}
```

- [x] **Step 4: Run green + build**

```bash
cd frontend && pnpm vitest run components/app-sidebar.test.tsx && pnpm test && pnpm build
```

- [x] **Step 5: Commit**

```bash
git add frontend/components/app-sidebar.tsx frontend/components/app-sidebar.test.tsx
git commit -m "feat(admin): gate user management navigation by role"
```

---

### Task 13 (T10): One-time-code password reset — **decision gate**

> **Update (2026-11-06):** the admin-chosen `POST /users/{id}/reset-password`
> body was replaced by a server-generated temporary password (returned once,
> `Cache-Control: no-store`). The one-time-code flow below remains the
> user-chosen alternative and now has an admin UI trigger. See
> `docs/superpowers/plans/2026-11-06-super-admin-role.md`.

**Decision required before starting:** approve Option A (admin-issued code, no email). If you prefer emailed links, stop and write a separate plan; this task assumes Option A.

**Files:**
- Create: `database/migrations/009_password_reset_tokens.sql`
- Modify: `api/routes/users.py` (issue code)
- Modify: `api/routes/auth.py` (redeem code)
- Create: `frontend/app/(auth)/reset-password/page.tsx`
- Modify: `frontend/app/(auth)/login/page.tsx` (link only)
- Modify: `frontend/lib/auth/api.ts` (`resetPassword`)
- Test: `tests/test_password_reset.py`

**Interfaces:**
- `POST /api/v1/users/{user_id}/reset-code` → `{code: str, expires_at: datetime}` (admin, `users:update`)
- `POST /api/v1/auth/reset-password` → `{message: str}` (public, CAPTCHA, rate-limited)
- Table `password_reset_tokens(id, user_id, token_hash, expires_at, used_at, created_by, created_at)`
- Code: `secrets.token_urlsafe(9)` (12 chars), stored as `hash_session_token(code)`, TTL 15 min, single use.

- [x] **Step 1: Write the failing test**

`tests/test_password_reset.py` reuses the disposable-user fixture and admin session fixture from the audit module (pytest collects imported fixtures):

```python
from tests.test_auth_security_audit import (  # noqa: F401 — reused fixtures
    _client,
    admin_headers,
    mk_user,
)
from tests.auth_testkit import issue_captcha


def test_reset_code_changes_password_once(mk_user, admin_headers):
    username, uid = mk_user("resetflow")
    client = _client()

    issued = client.post(f"/api/v1/users/{uid}/reset-code", headers=admin_headers)
    assert issued.status_code == 200
    code = issued.json()["code"]

    captcha_id, answer = issue_captcha()
    first = client.post("/api/v1/auth/reset-password", json={
        "username": username,
        "code": code,
        "new_password": "BrandNewPass123!",
        "confirm_password": "BrandNewPass123!",
        "captcha_id": captcha_id,
        "captcha_answer": answer,
    })
    assert first.status_code == 200

    captcha_id, answer = issue_captcha()
    replay = client.post("/api/v1/auth/reset-password", json={
        "username": username,
        "code": code,
        "new_password": "AnotherPass123!",
        "confirm_password": "AnotherPass123!",
        "captcha_id": captcha_id,
        "captcha_answer": answer,
    })
    assert replay.status_code == 400
```

- [x] **Step 2: Run red**

```bash
$PY -m pytest tests/test_password_reset.py -q
```

Expected: 404 — route absent.

- [x] **Step 3: Add the migration**

`database/migrations/009_password_reset_tokens.sql`:

```sql
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_by INTEGER REFERENCES dashboard_users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_user_id
    ON password_reset_tokens (user_id);
CREATE INDEX IF NOT EXISTS idx_password_reset_expires_at
    ON password_reset_tokens (expires_at);
```

Apply:

```bash
$PY database/migrate.py
```

- [x] **Step 4: Issue codes (admin route)**

Add to `api/routes/users.py`:

```python
class ResetCodeResponse(BaseModel):
    code: str
    expires_at: datetime


@router.post(
    "/{user_id}/reset-code",
    response_model=ResetCodeResponse,
    summary="Issue a one-time password reset code (Admin only)",
)
def issue_reset_code(
    user_id: int,
    request: Request,
    admin: dict[str, Any] = Depends(require_permission("users:update")),
) -> ResetCodeResponse:
    target = get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail=f"User with ID {user_id} not found")

    code = secrets.token_urlsafe(9)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=15)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE password_reset_tokens SET used_at = NOW() "
                "WHERE user_id = %s AND used_at IS NULL;",
                (user_id,),
            )
            cur.execute(
                "INSERT INTO password_reset_tokens "
                "(user_id, token_hash, expires_at, created_by) "
                "VALUES (%s, %s, %s, %s);",
                (user_id, hash_session_token(code), expires_at, admin["id"]),
            )
            conn.commit()

    log_audit_event(
        action="PASSWORD_RESET_CODE_ISSUED",
        user_id=admin["id"],
        target_user_id=user_id,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        metadata={},
    )
    return ResetCodeResponse(code=code, expires_at=expires_at)
```

Imports in `api/routes/users.py`: add `import secrets`, extend `from datetime import datetime` to `from datetime import datetime, timedelta, timezone`, and import `hash_session_token` from `..sessions` (alongside the existing `revoke_all_user_sessions`).

- [x] **Step 5: Redeem codes (public route)**

In `api/routes/auth.py`, extend the sessions import first:

```python
from ..sessions import (
    create_session,
    hash_session_token,
    revoke_all_user_sessions,
    revoke_session,
)
```

Then add the route below the existing `/logout` handler:

```python
class ResetPasswordRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=100)
    code: str = Field(..., min_length=4, max_length=64)
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)
    captcha_id: str = Field(..., min_length=10, max_length=64)
    captcha_answer: str = Field(..., min_length=1, max_length=20)


@router.post(
    "/reset-password",
    summary="Redeem a one-time password reset code",
    dependencies=[Depends(rate_limiter(action="reset_password", max_requests=10, window_seconds=60))],
)
def reset_password(payload: ResetPasswordRequest, request: Request) -> dict[str, str]:
    captcha_valid, captcha_err = verify_and_consume_captcha(
        captcha_id=payload.captcha_id, user_answer=payload.captcha_answer
    )
    if not captcha_valid:
        raise HTTPException(status_code=400, detail=f"CAPTCHA verification failed: {captcha_err}")

    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    user = get_user_by_username(payload.username)
    generic = HTTPException(status_code=400, detail="Invalid or expired reset code")
    if not user:
        raise generic

    ok, reason = validate_password_strength(payload.new_password, user["username"])
    if not ok:
        raise HTTPException(status_code=400, detail=reason)

    token_hash = hash_session_token(payload.code)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id FROM password_reset_tokens
                WHERE user_id = %s AND token_hash = %s
                  AND used_at IS NULL AND expires_at > NOW()
                FOR UPDATE;
                """,
                (user["id"], token_hash),
            )
            row = cur.fetchone()
            if not row:
                conn.rollback()
                raise generic
            cur.execute(
                "UPDATE dashboard_users SET password_hash = %s, hashed_password = NULL, "
                "must_change_password = false, updated_at = NOW() WHERE id = %s;",
                (hash_password(payload.new_password), user["id"]),
            )
            cur.execute(
                "UPDATE password_reset_tokens SET used_at = NOW() WHERE id = %s;",
                (row[0],),
            )
            conn.commit()

    revoke_all_user_sessions(user["id"])
    log_audit_event(
        action="PASSWORD_RESET_COMPLETED",
        user_id=user["id"],
        target_user_id=user["id"],
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        metadata={"username": user["username"]},
    )
    return {"message": "Password updated. Sign in with your new password."}
```

- [x] **Step 6: Frontend reset page**

Create `frontend/app/(auth)/reset-password/page.tsx`:

```tsx
"use client"

import * as React from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { AuthApiError, authApi } from "@/lib/auth/api"
import { useCaptcha } from "@/lib/auth/use-captcha"
import { AuthLayout } from "@/components/auth/AuthLayout"
import { AuthForm } from "@/components/auth/AuthForm"
import { UsernameField } from "@/components/auth/UsernameField"
import { PasswordField } from "@/components/auth/PasswordField"
import { CaptchaField } from "@/components/auth/CaptchaField"
import { AuthButton } from "@/components/auth/AuthButton"
import { AuthError } from "@/components/auth/AuthError"
import { Field, authInput } from "@/components/auth/Field"
import { Input } from "@/components/ui/input"

export default function ResetPasswordPage() {
  const router = useRouter()
  const captcha = useCaptcha()
  const [username, setUsername] = React.useState("")
  const [code, setCode] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [confirm, setConfirm] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [notice, setNotice] = React.useState<string | null>(null)
  const [pending, setPending] = React.useState(false)
  const busy = React.useRef(false)

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (busy.current) return
    if (!username.trim() || !code.trim()) return setError("Enter your username and reset code.")
    if (password !== confirm) return setError("Passwords do not match.")
    if (!captcha.challenge) return setError("Verification code could not be loaded. Please click refresh.")
    if (!captcha.answer.trim()) return setError("Enter the verification characters.")

    busy.current = true
    setPending(true)
    setError(null)
    try {
      const result = await authApi.resetPassword({
        username: username.trim(),
        code: code.trim(),
        new_password: password,
        confirm_password: confirm,
        captcha_id: captcha.challenge.captcha_id,
        captcha_answer: captcha.answer.trim(),
      })
      setNotice(result.message)
      window.setTimeout(() => router.replace("/login"), 1200)
    } catch (err) {
      const authError = err instanceof AuthApiError ? err : null
      setError(authError?.message ?? "Something went wrong. Please try again.")
      if (!authError || authError.needsNewCaptcha) captcha.refresh()
      busy.current = false
      setPending(false)
    }
  }

  const isCaptchaError = Boolean(
    error && (error.toLowerCase().includes("captcha") || error.toLowerCase().includes("verification"))
  )

  return (
    <AuthLayout>
      <AuthForm
        title="Set a new password"
        subtitle="Enter the one-time code from your administrator"
        onSubmit={onSubmit}
      >
        <UsernameField value={username} onChange={setUsername} disabled={pending} />
        <Field id="reset-code" label="Reset code" hint="Expires 15 minutes after it was issued.">
          <Input
            id="reset-code"
            name="reset-code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Paste your reset code"
            autoComplete="one-time-code"
            autoCapitalize="none"
            spellCheck={false}
            disabled={pending}
            className={authInput}
          />
        </Field>
        <PasswordField
          id="new-password"
          label="New password"
          value={password}
          onChange={setPassword}
          autoComplete="new-password"
          placeholder="Choose a new password"
          disabled={pending}
        />
        <PasswordField
          id="confirm-password"
          label="Confirm new password"
          value={confirm}
          onChange={setConfirm}
          autoComplete="new-password"
          placeholder="Repeat the new password"
          disabled={pending}
        />
        <CaptchaField
          captcha={captcha}
          error={isCaptchaError ? error : undefined}
          disabled={pending}
        />
        <AuthError message={error} />
        {notice && (
          <p
            role="status"
            className="rounded-[var(--auth-radius)] border border-[var(--auth-line)] px-3.5 py-2.5 text-sm text-[var(--auth-muted)]"
          >
            {notice}
          </p>
        )}
        <AuthButton pending={pending} idle="Set new password" busy="Saving..." />
      </AuthForm>
      <p className="text-center text-sm text-[var(--auth-muted)]">
        Remembered it?{" "}
        <Link
          href="/login"
          className="font-medium text-[var(--auth-ink)] underline-offset-4 hover:underline"
        >
          Back to sign in
        </Link>
      </p>
    </AuthLayout>
  )
}
```

Replace the footer text on the login page (`frontend/app/(auth)/login/page.tsx`) and add `import Link from "next/link"`:

```tsx
      <p className="text-center text-sm text-[var(--auth-muted)]">
        Have a reset code?{" "}
        <Link
          href="/reset-password"
          className="font-medium text-[var(--auth-ink)] underline-offset-4 hover:underline"
        >
          Set a new password
        </Link>
      </p>
```

Add to `frontend/lib/auth/api.ts`:

```ts
  resetPassword: (b: {
    username: string
    code: string
    new_password: string
    confirm_password: string
    captcha_id: string
    captcha_answer: string
  }) => post<{ message: string }>("/reset-password", b),
```

- [x] **Step 7: Run tests**

```bash
$PY -m pytest tests/test_password_reset.py -q
$PY -m pytest tests/test_auth_security_audit.py tests/test_auth_complete.py -q
cd frontend && pnpm test && pnpm build
```

- [x] **Step 8: Commit**

```bash
git add database/migrations/009_password_reset_tokens.sql api/routes/users.py api/routes/auth.py \
  tests/test_password_reset.py "frontend/app/(auth)/reset-password/page.tsx" \
  "frontend/app/(auth)/login/page.tsx" frontend/lib/auth/api.ts
git commit -m "feat(auth): add one-time-code password reset"
```

> If the frontend auth files contain your uncommitted redesign, stage only the reset-related hunks with `git update-index --cacheinfo`, as done in week 1.

---

## Phase 3 — Deployment and operations

> These tasks need the Ubuntu host. Run them over SSH, in a second session while changing firewall rules.

### Task 14 (T12): Live nginx and TLS verification

**Files:**
- Modify: `deploy/README.md` (record the result)
- No application code.

- [ ] **Step 1: Install and stage**

```bash
sudo apt update && sudo apt install -y nginx
sudo cp deploy/nginx/dnsnetra-proxy.conf /etc/nginx/snippets/dnsnetra-proxy.conf
sudo cp deploy/nginx/dnsnetra.conf /etc/nginx/sites-available/dnsnetra.conf
sudo ln -sf /etc/nginx/sites-available/dnsnetra.conf /etc/nginx/sites-enabled/dnsnetra.conf
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
```

Expected: `syntax is ok` / `test is successful`.

- [ ] **Step 2: Certificate**

```bash
sudo ./deploy/gen-internal-cert.sh dnsnetra.corp.local
```

Expected: cert and key under `/etc/ssl/dnsnetra/`, key mode 600.

- [ ] **Step 3: Reload and probe**

```bash
sudo systemctl reload nginx
curl -k -I https://dnsnetra.corp.local/login
curl -k https://dnsnetra.corp.local/api/v1/auth/captcha
```

Expected: `200 OK` on `/login`; JSON CAPTCHA on the API; `Strict-Transport-Security` present.

- [ ] **Step 4: Redirect check**

```bash
curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n" http://dnsnetra.corp.local/login
```

Expected: `301 https://dnsnetra.corp.local/login`.

- [ ] **Step 5: Signup redirect**

```bash
curl -k -s -o /dev/null -w "%{http_code} %{redirect_url}\n" https://dnsnetra.corp.local/signup
```

Expected: `307` to `/login`.

---

### Task 15 (T13): systemd, loopback, ufw

- [ ] **Step 1: Install units**

```bash
sudo cp deploy/systemd/dnsnetra-api.service deploy/systemd/dnsnetra-web.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now dnsnetra-api dnsnetra-web
sudo systemctl status dnsnetra-api dnsnetra-web --no-pager
```

- [ ] **Step 2: Prove loopback-only binds**

```bash
ss -ltnp | grep -E ':3000|:8000'
```

Expected: only `127.0.0.1:3000` and `127.0.0.1:8000`. Any `0.0.0.0` is a failure.

- [ ] **Step 3: Apply ufw (keep SSH open)**

```bash
sudo ADMIN_CIDR=10.0.0.0/8 USER_CIDR=10.0.0.0/8 ./deploy/ufw-dnsnetra.sh
sudo ufw status verbose
```

Expected: default deny incoming; 22 from admin CIDR; 443 from user CIDR; no 3000/8000.

- [ ] **Step 4: External probe**

From another host in the user CIDR:

```bash
curl -k https://dnsnetra.corp.local/api/v1/auth/captcha
```

From the same host, confirm direct access fails:

```bash
curl --max-time 3 http://127.0.0.1:8000/api/v1/auth/captcha
```

Expected: works through nginx; direct port only works on loopback, not remotely.

---

### Task 16 (T14): Auth backups and audit retention

- [ ] **Step 1: Nightly backup script**

Create `/usr/local/sbin/dnsnetra-auth-backup`:

```bash
#!/usr/bin/env bash
set -euo pipefail
STAMP=$(date +%Y-%m-%d)
DEST=/var/backups/dnsnetra
install -d -m 0700 "$DEST"
PGPASSWORD="$(grep -E '^UDR_DB_PASSWORD=' /etc/dnsnetra/api.env | cut -d= -f2-)" \
pg_dump -h 127.0.0.1 -U dnsnetra_app -d dns_threat_detection \
  -t dashboard_users -t sessions -t audit_logs \
  > "$DEST/auth-$STAMP.sql"
chmod 0600 "$DEST/auth-$STAMP.sql"
find "$DEST" -name 'auth-*.sql' -mtime +30 -delete
```

```bash
sudo chmod 0750 /usr/local/sbin/dnsnetra-auth-backup
sudo crontab -e
```

Add:

```cron
15 2 * * * /usr/local/sbin/dnsnetra-auth-backup
```

- [ ] **Step 2: Restore drill**

```bash
createdb -h 127.0.0.1 -U postgres dnsnetra_restore_test
psql -h 127.0.0.1 -U postgres -d dnsnetra_restore_test -f /var/backups/dnsnetra/auth-$(date +%F).sql
psql -h 127.0.0.1 -U postgres -d dnsnetra_restore_test -c "SELECT count(*) FROM dashboard_users;"
dropdb -h 127.0.0.1 -U postgres dnsnetra_restore_test
```

Expected: the backup restores and reports the expected user count.

- [ ] **Step 3: Retention policy**

Document in `deploy/README.md`: auth backups 30 days; audit rows 12 months, then archive to cold storage. If you need 12-month deletion, add a monthly job:

```sql
DELETE FROM audit_logs WHERE timestamp < NOW() - INTERVAL '12 months';
```

Do not schedule that until the retention policy is approved.

---

### Task 17 (T15): Auth monitoring

- [ ] **Step 1: Failed-login query**

```sql
SELECT date_trunc('hour', timestamp) AS hour, count(*)
FROM audit_logs
WHERE action = 'LOGIN_FAILURE'
GROUP BY 1
ORDER BY 1 DESC
LIMIT 24;
```

- [ ] **Step 2: Alert threshold**

Add a cron/health check that alerts when either is true in the last 15 minutes:

- `LOGIN_FAILURE` count > 20;
- any `429` rate on `/api/v1/auth/login` sustained for 10 minutes (nginx access log).

- [ ] **Step 3: Service health**

```bash
systemctl is-active nginx dnsnetra-api dnsnetra-web
curl -k -s -o /dev/null -w "%{http_code}\n" https://dnsnetra.corp.local/api/v1/auth/captcha
```

Expected: `active` ×3 and `200`.

- [ ] **Step 4: Certificate expiry**

```bash
openssl x509 -enddate -noout -in /etc/ssl/dnsnetra/dnsnetra.crt
```

Add a reminder 30 days before expiry.

---

## Appendix A — Verification matrix

| Task | Command | Expected |
|---|---|---|
| 1 | `$PY -m pytest tests/test_auth_security_audit.py -q` | pass + 7 xfail |
| 2 | purge then `SELECT count(*)` | 1 user; audit rows retained; no active test-user sessions |
| 3 | browser login | forced `/change-password` |
| 4 | `pytest -k cacheable` | pass |
| 5 | `pytest -k dummy_hash` | pass |
| 6 | `pytest` auth trio | pass; no token in JSON |
| 7 | `pytest -k "underscore or reserved"` | pass |
| 8 | `pytest -k "contradictory or noop"` | pass |
| 9 | `grep -c xfail tests/test_auth_security_audit.py` | `0` |
| 10 | `pnpm vitest run lib/admin/users-api.test.ts` | pass |
| 11 | `pnpm vitest run "app/(dashboard)/users/page.test.tsx"` | pass |
| 12 | `pnpm vitest run components/app-sidebar.test.tsx` | pass |
| 13 | `pytest tests/test_password_reset.py` | pass |
| 14 | `nginx -t` + `curl -kI` | 200 / HSTS |
| 15 | `ss -ltnp` | loopback only |
| 16 | restore drill | user count matches |
| 17 | health check | active ×3, 200 |

Phase 1 exit gate:

```bash
$PY -m pytest tests/ -q
```

Expected: the same 29 dataset-drift failures, **no new failures**, and **zero `xfail`s** in `tests/test_auth_security_audit.py`.

---

## Appendix B — Not scheduled (Phase 4)

These are real improvements but are deliberately outside this plan:

1. **Shared CAPTCHA/rate-limit store (AUTH-16).** Required before `--workers > 1`. Move `InMemoryCaptchaStore`, `_BUCKETS`, and `_FAILURES` to Redis or PostgreSQL.
2. **TOTP MFA (T11).** `pyotp` + QR provisioning, encrypted secret, backup codes; require for `ADMIN`. Needs a product decision and a migration (`010_totp.sql`).
3. **Session-management UI.** List active sessions per user; revoke one/all.
4. **CSP and app-level security headers.** nginx already sets HSTS, nosniff, frame-deny, referrer policy; add a report-only CSP and tighten it.
5. **Quarterly access review.** Export the user/role table, have an owner sign off, disable unused accounts.

---

## Appendix C — Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Purge deletes the wrong account | Low | High | Dry run first; `--keep admin`; `pg_dump` before execute |
| Admin password lost during rotation | Low | High | Password printed once; move immediately to password manager; backup exists |
| Task 6 breaks an external API client | Medium | Medium | Confirm no client reads the token body; keep cookie/bearer session support |
| Frontend WIP conflicts with Tasks 10–13 | Medium | Medium | New files only; stage auth hunks selectively; never `git add -A` |
| Lockout used to deny service | Medium | Medium | Per-account only; 60 s base; document admin unlock path (`reset_all` on restart / DB-free) |
| Reset codes leak via logs | Low | High | Never log the code; store only the hash; 15-minute TTL; single use |
| nginx/ufw locks out SSH | Low | High | Keep a second SSH session open; confirm admin CIDR before enabling ufw |
| In-memory state lost on restart | High | Low | Accept for single worker; AUTH-16 tracks the shared store |

---

## Appendix D — Commit sequence

```text
docs(auth): add week-1 change record and phase-2 plan
fix(auth): forbid caching of authentication responses
fix(auth): spend equal hashing work for unknown usernames
fix(auth): keep session tokens out of JSON responses
fix(auth): make password and reserved-name policy consistent
fix(users): validate status invariants and skip no-op revocation
feat(auth): add per-account lockout and change-password limits
feat(admin): add typed users API client
feat(admin): add user lifecycle page
feat(admin): gate user management navigation by role
feat(auth): add one-time-code password reset
```
