# DNSNetra — Authentication & Authorization Security Audit

**Date:** 2026-10-23
**Scope:** `api/auth.py`, `api/sessions.py`, `api/csrf.py`, `api/rbac.py`, `api/rate_limiter.py`,
`api/trusted_proxy.py`, `api/captcha.py`, `api/audit.py`, `api/routes/auth.py`,
`api/routes/users.py`, `frontend/lib/auth/*`, `frontend/components/auth/*`,
migrations `007`/`008`, and the auth test suites.
**Method:** static review + live reproduction against the running PostgreSQL instance
(`dns_threat_detection`) via `TestClient`. All probe artifacts were deleted afterwards.

**Test evidence**

| Suite | Result |
|---|---|
| `tests/test_auth_complete.py` | 31 passed |
| `tests/test_auth_hardening.py` | 23 passed |
| `tests/test_api_v1.py` | 37 passed |
| **`tests/test_auth_security_audit.py` (new)** | **7 passed, 22 xfailed (defects reproduced)** |

The new suite encodes correct behaviour. The 22 `xfail` markers are confirmed defects;
each turns green when the corresponding AUTH-xx is fixed (remove the marker).

---

## Severity summary

| ID | Severity | Finding |
|---|---|---|
| AUTH-01 | **CRITICAL** | Published default JWT secret + JWT fallback = full admin auth bypass |
| AUTH-02 | **CRITICAL** | Production `admin` account password is literally `admin` |
| AUTH-03 | **HIGH** | CAPTCHA is optional on `/login` and absent on `/token` |
| AUTH-04 | **HIGH** | `must_change_password` is stored but never enforced |
| AUTH-05 | **HIGH** | JWT fallback trusts `role` claim and cannot be revoked |
| AUTH-06 | **HIGH** | `X-Forwarded-For` spoofing → rate-limit bypass, audit IP forgery |
| AUTH-07 | **HIGH** | `/users/{id}/approve` bypasses lifecycle and last-admin protection |
| AUTH-08 | **MEDIUM** | `PATCH /users/{id}` returns 500 on contradictory input; no-op updates kill sessions |
| AUTH-09 | **MEDIUM** | Incomplete secret/TTL configuration validation |
| AUTH-10 | **MEDIUM** | CAPTCHA single-use is not atomic; `consume()` result ignored |
| AUTH-11 | **MEDIUM** | RBAC permission matrix is dead code; contradicts route guards |
| AUTH-12 | **MEDIUM** | Username enumeration via response timing |
| AUTH-13 | **MEDIUM** | No per-account lockout; audit write amplification |
| AUTH-14 | **MEDIUM** | Unlimited sessions, no cleanup job, token exposed in JSON |
| AUTH-15 | **LOW** | Auth responses are cacheable |
| AUTH-16 | **MEDIUM** | In-memory CAPTCHA/rate-limit state breaks with >1 worker |
| AUTH-17 | **LOW** | Password/username policy inconsistencies |
| AUTH-18 | **LOW** | `localhost` origins always allowed, even in production |
| AUTH-19 | **PROCESS** | Existing tests depend on the AUTH-01 vulnerability |

---

## AUTH-01 — Full authentication bypass (CRITICAL)

**Files:** `api/auth.py:42-49`, `api/auth.py:102`, `api/auth.py:442-456`

`get_jwt_secret_key()` returns the hard-coded, source-published
`DEV_INSECURE_TEST_SECRET` whenever `AUTH_SESSION_SECRET` is unset and
`DNSNETRA_ENV` is not `production`. Neither variable exists in `.env` or
`.env.example`, and the guard is skipped whenever `DNSNETRA_ENV` is missing —
which is the default for every deployment in this repo.

`get_current_user()` then falls back to accepting **any HS256 JWT** signed with
that secret and looks the user up by `sub`. Because `sub` is just a username,
the public `admin` account is enough.

Reproduced:

```
AUTH_SESSION_SECRET set: False
DNSNETRA_ENV: None
get_jwt_secret_key() == published DEV constant: True
forged ADMIN token -> /auth/me  = 200 role=ADMIN
forged ADMIN token -> /users    = 200     # admin-only endpoint
forged token in Cookie header   = 200     # cookie path works too
```

A token **without `exp`** is also accepted (`jwt.decode` doesn't require it):

```
no-exp token -> 200
```

**Fix:** delete the JWT fallback from `get_current_user` (sessions are the only
credential), or gate it behind an explicit, default-off `AUTH_ALLOW_LEGACY_JWT`
flag that is rejected in production and requires `exp`, `iss`, `aud`.
Never derive identity from a signing secret that ships in source. Add all
`.env.example` placeholders to `INSECURE_SECRETS`.

---

## AUTH-02 — Seed admin password is `admin` (CRITICAL, environment)

User `admin` (id 2) has a valid Argon2id hash whose plaintext is `admin`:

```
admin | hash: $argon2id$ | password==username: True
```

That password violates the module's own policy (min 8 chars, must differ from
username), so it was written outside the policy path. `tests/test_auth_complete.py:346`
even asserts this login succeeds. Rotate it and remove the assertion.

---

## AUTH-03 — CAPTCHA is decorative (HIGH)

**File:** `api/routes/auth.py:260-269`, `api/routes/auth.py:341`

```python
if payload.captcha_id or payload.captcha_answer:
    verify_and_consume_captcha(...)
```

Both fields are `Optional`; omitting them skips verification entirely.
`/auth/token` never checks a CAPTCHA at all.

Reproduced:

```
login with no captcha fields      = 200
/auth/token form login, no captcha = 200
```

Combined with AUTH-06 this gives unmetered credential stuffing. Make the fields
required (or remove the control and stop claiming it in docs/UI).

---

## AUTH-04 — `must_change_password` never enforced (HIGH)

`must_change_password` is written by admin reset (`api/routes/users.py:654`),
returned by `/me`, and cleared by `change-password` — but no dependency or
middleware ever checks it.

Reproduced: a user with the flag set logs in and immediately reaches
`GET /api/v1/users` (admin-only) → `200`. The advertised "forced rotation after
admin reset" does not exist. Add a dependency returning `428 Precondition Required`
for every route except `/auth/change-password`, `/auth/logout`, `/auth/me`.

---

## AUTH-05 — JWT fallback trusts `role` and ignores revocation (HIGH)

**File:** `api/auth.py:448-454`

```python
if payload.get("role"):
    user["role"] = payload["role"]
```

Any valid JWT can promote the DB user to `ADMIN`; privilege changes and
`revoke_all_user_sessions()` have no effect on JWT-authenticated requests.

Reproduced:

```
ANALYST + JWT(role=ADMIN) -> /users = 200
after revoke_all_user_sessions, JWT still valid = 200
```

Fix: never copy authorization data from the token; resolve role from
`dashboard_users` only (sessions already do this).

---

## AUTH-06 — `X-Forwarded-For` spoofing (HIGH)

**File:** `api/trusted_proxy.py:59-65`

```python
hops = [h.strip() for h in forwarded.split(",") if h.strip()]
for hop in hops:
    if is_valid_ip(hop):
        return hop          # returns the left-most, client-supplied hop
```

The left-most entry is fully attacker-controlled. Because loopback is a default
trusted proxy, any deployment behind a local reverse proxy (the normal layout)
honours it.

Reproduced:

```
peer 127.0.0.1, XFF "6.6.6.6, 10.0.0.9" -> get_client_ip() = 6.6.6.6
35 captcha calls (limit 30/min) rotating XFF -> 429 count = 0
```

Impact: rate limits bypassed (login brute force), audit `ip_address` forged,
session `ip_address` forged. Fix: walk XFF from the right, skipping trusted
proxies, and stop at the first untrusted hop; don't trust loopback by default in
production.

---

## AUTH-07 — `/approve` bypasses lifecycle and last-admin guard (HIGH)

**File:** `api/routes/users.py:448-496`

`approve_user` unconditionally sets `status='ACTIVE', is_active=true` for any
target and accepts `UserRole.ADMIN` (the docstring promises ANALYST/SUPPORT). It
does not call `_ensure_not_last_active_admin`, unlike disable/update.

Reproduced:

```
approve DISABLED user with role=ADMIN -> 200; row now ('ACTIVE', True, 'ADMIN')
```

Consequences: a disabled account is silently re-enabled, self-service users can
be granted ADMIN, and the **last active admin can be demoted** through this
endpoint, locking everyone out. Fix: require current status `PENDING`, restrict
roles, and run the same `FOR UPDATE` guard.

---

## AUTH-08 — User update invariants (MEDIUM)

**File:** `api/routes/users.py:352-417`

1. `{"status": "ACTIVE", "is_active": false}` writes both columns, violating
   `chk_dashboard_users_status_active` (migration 008) and surfacing as
   **HTTP 500** instead of 400/422.
2. `will_demote` / `will_deactivate` are computed from the *payload*, not the
   current row. Sending the role the user already has (`role=ANALYST` on an
   analyst) revokes every session.

Reproduced:

```
PATCH status=ACTIVE,is_active=false -> 500
PATCH role=ANALYST (unchanged) -> 200; session afterwards -> 401
```

Fix: derive transitions from `target_user`, reject contradictory pairs with
400, and map integrity errors.

---

## AUTH-09 — Configuration validation gaps (MEDIUM)

- `get_captcha_secret()` (`api/captcha.py:35-38`) has a published default and
  **no** production check. Verified: in `DNSNETRA_ENV=production` with no
  `AUTH_CAPTCHA_SECRET`, the dev constant is still returned.
- `.env.example:26` ships `change-this-in-production-session-secret-key-min-32-chars`;
  that placeholder is **not** in `INSECURE_SECRETS`, so it is accepted in
  production (verified).
- `AUTH_CAPTCHA_EXPIRE_SECONDS` is documented in `.env.example` but never read
  (hard-coded `300`).
- `AUTH_SESSION_EXPIRE_MINUTES` is honoured by `create_session`, but the cookie
  `max_age` and `expires_in` are hard-coded `86400`.
  Verified with TTL=5min: `expires_in=86400`, DB TTL `299s`, `Max-Age=86400`.
- `_is_cookie_secure()` (`api/routes/auth.py:52-57`) returns `False` unless
  `DNSNETRA_ENV` is exactly `production`; since that variable is not configured
  anywhere, production cookies are not `Secure`.

---

## AUTH-10 — CAPTCHA replay window (MEDIUM)

**File:** `api/captcha.py:305-330`

`is_consumed()` → `get()` → `consume()` is not atomic, and the return value of
`consume()` is ignored:

```python
store.consume(captcha_id, expiry)
return True, "OK"
```

Two concurrent requests with the same correct answer can both verify. Verified
with a store whose `consume()` returns `False`: verification still returns
`True`. Also: a *wrong* answer does not consume the challenge (unlimited guesses
per challenge) and the answer is drawn from `random`, not `secrets`.

Fix: a single atomic `consume_if_valid()` returning success; consume on failure
too (or count attempts); use `secrets.choice`.

---

## AUTH-11 — RBAC matrix is dead code (MEDIUM)

`require_permission`, `require_role`, `has_permission` and `get_role_permissions`
are **never used** by any route. Every route is either public,
`get_current_user`, or `require_admin`.

Consequences:

- `ROLE_PERMISSIONS[ANALYST]` grants `daily_review:update`, but
  `POST /daily-review/{domain}/verdict` requires ADMIN (`api/routes/daily_review.py:228`)
  → analysts are blocked despite the documented permission.
- `ROLE_PERMISSIONS[SUPPORT]` omits `reports:export`, but every report/export
  route only requires `get_current_user` → SUPPORT can export.
- ADMIN-only permissions such as `settings:*` have no routes at all.

Either enforce the matrix on routes or delete it; keeping a contradictory
policy document is worse than none.

---

## AUTH-12 — Username enumeration via timing (MEDIUM)

`authenticate_user` returns immediately when the user is absent, skipping the
~50 ms Argon2 verification that runs for an existing account.

Verified by instrumenting `verify_password`:

```
missing user  -> 0 hash verifications
existing user -> 1 hash verification
```

Fix: verify against a fixed dummy hash when the user is missing, and keep the
generic 401. (Signup `409 "already taken"` is standard, but note it is also an
enumeration oracle.)

---

## AUTH-13 — Brute-force resistance (MEDIUM)

- No per-account lockout or exponential backoff; the only limit is per-IP and
  spoofable (AUTH-06).
- `/auth/change-password` has **no** rate limit (authenticated offline guessing
  of the current password).
- Every failed login performs a synchronous `audit_logs` INSERT (a separate pool
  connection) → DB write amplification / pool pressure under attack.
- `/auth/token` and `/auth/login` share one 15/min bucket, so neither benefits
  from an independent budget.

---

## AUTH-14 — Session hygiene (MEDIUM)

- Three logins produce three concurrently valid sessions (verified). There is no
  per-user cap and no re-login invalidation.
- `cleanup_expired_sessions()` exists (`api/sessions.py:192`) but is never
  scheduled or called. Live DB: **296 session rows, 253 expired and never
  revoked**.
- `/auth/login` and `/auth/change-password` return the raw session token in the
  JSON body in addition to the `HttpOnly` cookie. This defeats the point of
  `HttpOnly` for any consumer that stores it, and exposes it to response logging
  and caches.
- `logout` for a JWT-authenticated caller returns 200 but revokes nothing
  (`request.state.session_token` is `None`).

---

## AUTH-15 — Auth responses are cacheable (LOW)

`/auth/login`, `/auth/me` and `/auth/change-password` return no
`Cache-Control: no-store` (verified). The login body contains the session token.
Add `Cache-Control: no-store` + `Pragma: no-cache` for the auth router.

---

## AUTH-16 — Per-process state (MEDIUM, deployment)

`InMemoryCaptchaStore` and `_BUCKETS` live in process memory. With
`uvicorn --workers N` (or gunicorn), a CAPTCHA issued by worker A fails
verification on worker B (random login failures) and each worker gets its own
rate-limit budget. Use Redis/PostgreSQL (the store abstraction already exists)
or pin to one worker.

---

## AUTH-17 — Policy inconsistencies (LOW)

- `validate_password_strength` special-character class is
  `[0-9!@#$%^&*(),.?":{}|<>]`. It rejects `_`, `-`, `+`, `=`, `/`, `~`, and all
  non-ASCII symbols. Verified: `Password_` (9 chars, letter + symbol) is rejected.
- The frontend validator (`frontend/lib/auth/api.ts:166-173`) accepts any
  non-letter, so it approves passwords the backend rejects (e.g. `Password😀`).
- Reserved-name check happens after `strip()` but before normalisation, so
  `.admin.` passes (`validate_username(".admin.") -> (True, 'OK')`) and creates a
  visually confusable account.
- `validate_username` allows leading/trailing dots and consecutive dots.

---

## AUTH-18 — Origin allow-list cannot be tightened (LOW)

`get_allowed_origins()` always merges `DEFAULT_ALLOWED_ORIGINS` (all localhost
ports) even when `CORS_ALLOWED_ORIGINS` is configured. In production, any
page/app on `localhost:3000` or `localhost:8000` is a trusted CSRF origin and a
credentialed CORS origin. Only merge defaults when no explicit config exists.

---

## AUTH-19 — The existing test suite validates the vulnerability (PROCESS)

`tests/test_api_v1.py:40-49` mints admin/analyst JWTs with the default secret and
`tests/test_api_v1.py:668-672` monkeypatches `api.auth.get_user_by_email` to
fabricate users. That is why 74 existing auth/API tests are green while AUTH-01
is exploitable. Fixing AUTH-01 requires reworking those fixtures to use
`create_session()`; otherwise CI will keep enforcing the bypass.

---

## Working correctly (keep it that way)

Verified by the 7 passing tests in the new suite:

- Sessions are random 288-bit tokens; only SHA-256 hashes are stored.
- Session cookies are `HttpOnly`, `SameSite=Lax`, `Path=/`.
- Disabling an account invalidates its live session immediately (DB join check).
- CSRF blocks cookie-authenticated cross-site POSTs and allows same-origin.
- Password change rotates the session and revokes all other sessions.
- Unknown/garbage bearer tokens produce `401` with `WWW-Authenticate: Bearer`.
- Password resets and disables revoke sessions; last-admin demotion via
  `PATCH`/`disable` is transactionally guarded.
- Audit metadata sanitisation drops password/token/secret keys.

---

## Operational issues found while running the audit

1. `.venv/`, `venv/`, and `myenv/` are unusable on this machine — all three were
   created on Linux (`pyvenv.cfg` → `/usr/bin/python3.14`) and contain no
   interpreter. The audit ran in a throwaway Python 3.13 venv.
2. `.env` uses CRLF line endings; POSIX `source .env` breaks (`command not found: ^M`).
3. No `DNSNETRA_ENV` / `AUTH_SESSION_SECRET` / `AUTH_CAPTCHA_SECRET` is set
   anywhere, which is exactly the state that triggers AUTH-01.
4. Test data leakage: the auth suites only clean up usernames matching
   `test_%`, while they create `case_test_*`, `admin2_*`, `pending_*`, `legacy_*`,
   `user_*`, `revtest_*`. The live DB holds **72 users** and **805 audit rows**
   from test runs.

---

## Suggested fix order

1. AUTH-02 (rotate password) and AUTH-01 (remove fallback / require secret) — same day.
2. AUTH-03, AUTH-04, AUTH-05, AUTH-07.
3. AUTH-06, AUTH-08, AUTH-09, AUTH-10, AUTH-11.
4. AUTH-12–AUTH-18 plus the test-fixture rework in AUTH-19.

---

## Remediation status — 2026-10-28 (week 1)

| Finding | Status | Evidence |
|---|---|---|
| AUTH-01 | Fixed | JWT fallback deleted; forged tokens covered by `tests/test_auth_security_audit.py` |
| AUTH-02 | Fixed | `scripts/rotate_admin_password.py`; admin forced to change at next login |
| AUTH-03 | Fixed | CAPTCHA required on `/login` and `/token` |
| AUTH-04 | Fixed | 428 enforcement in `get_current_user`; `/change-password` UI |
| AUTH-05 | Fixed | role always resolved from `dashboard_users` |
| AUTH-06 | Fixed | XFF walks right-to-left; nginx overwrites the header |
| AUTH-07 | Fixed | approval restricted to PENDING → ANALYST/SUPPORT |
| AUTH-09 | Fixed | `api/auth_config.py`; TTLs wired to cookie and response |
| AUTH-10 | Fixed | atomic consume; wrong answers burn the challenge |
| AUTH-11 | Fixed | `require_permission` on every protected route |
| AUTH-18 | Fixed | configured origins no longer merge localhost |
| AUTH-08/12/14/15/17 | Deferred | still reproduced as `xfail` in `tests/test_auth_security_audit.py` |
