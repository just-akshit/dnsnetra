# DNSNetra Authentication & Authorization — Week 1 Change Record

> **Historical record.** Paths reflect the pre-monorepo layout. `frontend/` now lives
> under `apps/web/`; API/security paths now live under `apps/api/` and
> `backend/src/dnsnetra/core/security/`. See `docs/README.md` for the mapping.

**Date:** 2026-10-28
**Branch:** `main`
**Base commit:** `8dd0b46d1bb5ee77b7afdd2e02a31d72cc6534bc`
**Head commit:** `39056a5` (`chore(auth): add admin rotation and test-data purge scripts`)
**Scope:** 10 commits, 54 files, +2,413 / −592 lines

---

## 1. Read this first

This document records everything that was built, changed, fixed, deliberately
deferred, and **still requires an operator action**.

Three things are true right now and need to be understood before anything else:

1. **The code is hardened and committed.** All ten week-1 tasks are on `main`.
2. **The database has not been cleaned or rotated.** The live `admin` account
   still has its old password (`admin`), a second admin account (`admin_sec`)
   still exists, and 506 sessions plus 1,902 audit rows are still present.
   Purging and rotation are the only remaining steps; they were paused for
   your approval.
3. **The frontend has unrelated work-in-progress.** Your visual redesign is
   still uncommitted in the working tree. The commits contain only the
   auth-related hunks, so none of your redesign was lost or overwritten.

---

## 2. Executive summary

The audit found 19 issues (`AUTH-01` … `AUTH-19`), including a full
authentication bypass, a decorative CAPTCHA, an unenforced password-rotation
flag, an approval endpoint that could mint admins, and a dead RBAC matrix.

Week 1 closed **11 findings fully**, **1 operationally mitigated**, and
**1 partially mitigated**:

| Category | Findings |
|---|---|
| Fully fixed | AUTH-01, 02 (code), 03, 04, 05, 06, 07, 09, 10, 11, 18, 19 |
| Operationally mitigated (not code-fixed) | AUTH-16 (single-worker pin) |
| Partially mitigated | AUTH-13 (per-IP limits improved; no per-account lockout yet) |
| Deferred, still reproduced as `xfail` | AUTH-08, 12, 14, 15, 17 |
| Pending data action | AUTH-02 rotation + test-data purge |

Net effect:

- There is now **one** way to authenticate: an opaque, server-side session
  token. The JWT fallback is gone.
- Login and token issuance **cannot** succeed without solving a single-use
  CAPTCHA.
- Privileged routes **cannot** be reached while `must_change_password` is set.
- Every protected route is permission-checked against one role matrix.
- Public signup is closed by default.
- Approval can only promote `PENDING` accounts to `ANALYST` or `SUPPORT`.
- The production front door is nginx + TLS, both apps on loopback, firewall
  baseline included.

Test evidence: **387 passed**, 29 pre-existing dataset-drift failures
(unchanged from baseline), 7 intentional `xfail`s. Frontend: **46/46**,
production build passes.

---

## 3. Findings status

### 3.1 Fixed in this cycle

| ID | Severity | Original problem | What changed |
|---|---|---|---|
| AUTH-01 | Critical | `Authorization: Bearer <JWT>` bypassed sessions; a forged JWT with `role: ADMIN` was accepted | JWT creation, decoding and fallback deleted. `get_current_user` uses `HTTPBearer` only as a carrier for an **opaque** session token looked up in `sessions` |
| AUTH-02 | Critical | Seeded `admin` password was `admin` | `scripts/rotate_admin_password.py` generates a policy-compliant 20-char secret, sets `must_change_password=true`, revokes sessions. **Execution still pending** |
| AUTH-03 | High | CAPTCHA was optional on `/login` and `/token` | `captcha_id` / `captcha_answer` are now required fields; verification happens before credentials are checked |
| AUTH-04 | High | `must_change_password` was stored but never enforced | Session lookup returns the flag; `get_current_user` raises `428` for every path outside a 3-route allowlist |
| AUTH-05 | High | JWT fallback trusted client-supplied `role` and ignored revocation | Role/status always come from `dashboard_users` joined to a live, non-revoked session |
| AUTH-06 | High | Left-most `X-Forwarded-For` hop was trusted, so rate limits were spoofable | `TRUSTED_PROXIES` is explicit (empty by default); XFF walks right-to-left and stops at the first untrusted hop; nginx **overwrites** the header |
| AUTH-07 | High | `/approve` reactivated `DISABLED` users and could grant `ADMIN` | Approval requires `PENDING`, accepts only `ANALYST`/`SUPPORT`, uses `SELECT … FOR UPDATE`, returns `409` on a race |
| AUTH-09 | Medium | Missing/weak secrets and hard-coded TTLs | `api/auth_config.py` fails closed in production; session/CAPTCHA TTLs come from one place and drive cookies, responses and DB expiry |
| AUTH-10 | Medium | CAPTCHA answer was not burned on a wrong guess | `consume()` is atomic; any verification attempt (right or wrong) removes the challenge |
| AUTH-11 | Medium | `ROLE_PERMISSIONS` existed but routes used `get_current_user`/`require_admin` | 36 dependencies across 9 route modules now use `require_permission(...)`; matrix extended with `dashboard:read`, `status:read`, `analytics:read` |
| AUTH-18 | Low | Configured CORS origins were merged with localhost, so production could not be tightened | When `CORS_ALLOWED_ORIGINS` is set, it is used verbatim; localhost defaults apply only when nothing is configured |
| AUTH-19 | Process | Existing tests authenticated with forged JWTs, hiding AUTH-01 | Test kit rewritten around real sessions; no test authenticates as `admin`; the audit suite is executable and CI-visible |

### 3.2 Mitigated but not fixed in code

| ID | Status | Detail |
|---|---|---|
| AUTH-16 | Mitigated | CAPTCHA and rate-limit state are still in-process. The systemd unit pins `uvicorn --workers 1`, so this is correct for the current single-server deployment. Redis/Postgres backing is the fix if you scale out |
| AUTH-13 | Partial | nginx adds per-IP limits on login/token (10 r/m) and CAPTCHA (30 r/m), and XFF is no longer spoofable. Still missing: per-account lockout/backoff and a rate limit on `/auth/change-password` |

### 3.3 Deferred (reproduced as `xfail`)

These are real, still-open defects. They are intentionally left visible in
`tests/test_auth_security_audit.py` rather than hidden.

| ID | Risk | Remaining problem |
|---|---|---|
| AUTH-08 | Medium | `PATCH /users/{id}` can set contradictory `status`/`is_active`, leaking a DB constraint as HTTP 500; a no-op role update revokes all sessions |
| AUTH-12 | Medium | Unknown usernames skip password hashing, creating a timing oracle for username enumeration |
| AUTH-14 | Medium | `/auth/login` still returns `session_token` in the JSON body alongside the HttpOnly cookie |
| AUTH-15 | Low | Auth responses have no `Cache-Control: no-store` |
| AUTH-17 | Low | `_` counts as special in one place but is rejected in another; `.admin.` bypasses the reserved-name check because of the trailing dot |

---

## 4. Commit-by-commit changelog

### Task 1 — Test foundation (`485ba7a`)

**Why:** the old suite authenticated with forged JWTs and leaked rows into the
shared database, so it could not detect AUTH-01 and made every later test
unreliable.

- **Added `tests/auth_testkit.py`** — `TEST_PASSWORD` (overridable via
  `TEST_AUTH_PASSWORD`, default `PytestPass123!`), `issue_captcha()`,
  `login()`, `bearer_for_user()`, `bearer_for_username()`.
- **Added seeded fixtures in `tests/conftest.py`** — session-scoped
  `pytest_admin` / `pytest_analyst` / `pytest_support`, `admin_headers` /
  `analyst_headers` / `support_headers`, an autouse rate-limit reset, and
  prefix-scoped cleanup that only deletes rows created by this test run.
- **Added `tests/test_auth_fixtures.py`** — proves the fixtures are real and
  the cleanup is scoped.
- **Removed leaky cleanup** from `tests/test_auth_complete.py`.
- First run deleted **62 leaked test accounts** (66 → 4 rows) and cascaded
  **19 sessions**.

### Task 2 — Secrets and configuration (`037bcfc`)

- **New `api/auth_config.py`** — `is_production()`, `require_secret()`,
  `get_session_pepper()`, `get_captcha_secret()`, `get_session_ttl_minutes()`,
  `get_session_ttl_seconds()`, `get_captcha_ttl_seconds()`, `cookie_secure()`,
  `signup_enabled()`, `validate_auth_config()`.
- Production startup now **fails** if either secret is empty, a known default,
  or shorter than 32 characters.
- Session tokens are hashed with **HMAC-SHA256 keyed by
  `AUTH_SESSION_SECRET`**, not a bare SHA-256. A separate
  `AUTH_CAPTCHA_SECRET` keys CAPTCHA signatures.
- Session TTL (default 1,440 min; `.env.example` ships 480) now drives the DB
  expiry, the `Set-Cookie` `max-age`, and the response `expires_in` from one
  value instead of three hard-coded `86400`s.
- CORS no longer merges localhost into a configured allow-list.
- `.env.example` rewritten; local `.env` normalised to LF with development
  secrets.

### Task 3 — Remove the JWT fallback (`7a84ecd`)

- Deleted `create_access_token`, `get_jwt_secret_key`, and the JWT decode
  branch in `api/auth.py`.
- `HTTPBearer(auto_error=False)` is now only a transport for the opaque
  session token; bearer and cookie values go through the same lookup.
- **Added `scripts/_session_auth.py`** — server-side scripts create a real
  session instead of minting a token.
- Migrated `scripts/measure_performance.py`, `reconciliation_check.py`,
  `verify_api_complete.py`, `verify_http_live.py`.
- Migrated tests to real sessions.

### Task 4 — CAPTCHA enforcement (`a666eaa`)

- `captcha_id` and `captcha_answer` are required on both `/login` and
  `/token`; the old `if payload.captcha_id or payload.captcha_answer:` branch
  is gone.
- CAPTCHA is verified and consumed **before** the username/password check.
- `api/captcha.py` uses `secrets.choice` for the answer string (pixel noise
  still uses `random`, which is fine and was deliberately not changed).
- `consume()` removes the challenge atomically on first attempt.
- Rate-limit test now requests a fresh CAPTCHA per attempt.
- All hard-coded `admin`/`admin` logins removed from tests.
- **Closes AUTH-03 and AUTH-10.**

### Task 5 — Force password rotation (`9605c3c`)

- `api/sessions.py` selects `must_change_password` and returns it in the
  session user dict.
- `api/auth.py` defines `PASSWORD_CHANGE_ALLOWLIST` (`/me`, `/logout`,
  `/change-password`) and raises **HTTP 428** with
  `X-Password-Change-Required: true` for everything else.
- Admin-created accounts now set `must_change_password=true` (API response and
  DB insert).
- **New page `frontend/app/(auth)/change-password/page.tsx`** — current/new/
  confirm fields, client-side policy check, then redirect to `/dashboard`.
- `frontend/lib/auth/api.ts` — added `changePassword()`, a
  `password_change_required` error kind, and 428 classification.
- Login page and `AuthGuard` redirect flagged users to `/change-password`.
- **Closes AUTH-04.**

### Task 6 — Approval lifecycle (`7741fee`)

- `/users/{id}/approve` now:
  - rejects any role other than `ANALYST`/`SUPPORT` with `400`;
  - rejects non-`PENDING` targets with `400`;
  - takes `SELECT … FOR UPDATE` and re-checks state;
  - returns `409` if another request won the race;
  - updates with `WHERE id = %s AND status = 'PENDING'`.
- **Closes AUTH-07.**

### Task 7 — Close public signup (`225df80`)

- `auth_config.signup_enabled()` gates `POST /auth/signup`; default is
  **403** with a message to contact an administrator.
- Added a `signup_enabled` pytest fixture so the legacy signup coverage can
  still exercise the route when explicitly opted in.
- Deleted `frontend/app/(auth)/signup/page.tsx`
  (backup: `/private/var/folders/…/opencode/task7-backup-signup-page.tsx`).
- `/signup` now redirects to `/login` (307, temporary) via `next.config.ts`.
- Removed the `signup` client method and the “Create account” footer; the
  login page now says to ask an administrator for a reset.

### Task 8 — Enforce RBAC (`09855df`)

- Matrix extended so all three roles can read the dashboard, system status
  and domain analytics.
- **36 route dependencies** across `dashboard`, `reports`, `domains`,
  `clients`, `investigation`, `status`, `analytics`, `daily_review`, `users`
  now use `require_permission(...)`.
- Deliberate policy outcomes:
  - `SUPPORT` is read-only and **loses CSV export** (`reports:export`).
  - `ANALYST` **gains** `daily_review:update` and `domains:investigate`
    (previously admin-only).
  - `users:*` and `audit_logs:read` remain admin-only.
- Added `tests/test_rbac_routes.py` (5 tests) and updated the matrix
  assertions in `tests/test_auth_complete.py` and the analyst expectations in
  `tests/test_api_v1.py`.
- **Closes AUTH-11.**

### Task 9 — Trusted proxy and deployment (`0a51ef6`)

- **`api/trusted_proxy.py` rewritten** — no default trusted proxies; a peer
  must be listed in `TRUSTED_PROXIES`. XFF is walked right-to-left, skipping
  trusted hops; `X-Real-IP` is a fallback. Untrusted peers always resolve to
  their own socket address.
- **New `deploy/` tree:**
  - `nginx/dnsnetra.conf` — 80→443 redirect, TLS 1.2/1.3, HSTS, nosniff,
    `X-Frame-Options: DENY`, Referrer-Policy, `/api/` → `127.0.0.1:8000`,
    `/` → `127.0.0.1:3000`, per-IP limits on login/token/CAPTCHA.
  - `nginx/dnsnetra-proxy.conf` — shared proxy headers, with
    `X-Forwarded-For $remote_addr` (overwrite, never append).
  - `systemd/dnsnetra-api.service` — loopback bind, `--workers 1`,
    `--proxy-headers --forwarded-allow-ips=127.0.0.1`, systemd hardening.
  - `systemd/dnsnetra-web.service` — Next.js on `127.0.0.1:3000`.
  - `api.env.example` — production environment template.
  - `gen-internal-cert.sh` — self-signed internal cert with SANs.
  - `ufw-dnsnetra.sh` — default-deny inbound, 22 from admin CIDR, 443 from
    user CIDR.
  - `README.md` — end-to-end Ubuntu 24.04 runbook.
- **Closes AUTH-06.**

### Task 10 — Operator scripts (`39056a5`)

- **`scripts/rotate_admin_password.py`** — dry-run by default; `--execute`
  generates a 20-char policy-compliant password, writes the Argon2id hash,
  clears the legacy `hashed_password`, sets `must_change_password=true`,
  activates the account, and revokes all its sessions.
- **`scripts/purge_test_users.py`** — dry-run by default; `--keep` is
  required; refuses an empty keep-list or a keep-list with no admin;
  `--execute` deletes everything else; `--purge-audit-logs` also clears
  `audit_logs` (sessions cascade with users).
- **`tests/test_admin_scripts.py`** — 3 tests (password policy, empty
  keep-list, keep-list must contain an admin).
- `start_all.sh` no longer prints `admin / admin`.
- Remediation status table appended to `docs/AUTH_SECURITY_AUDIT.md`.

---

## 5. Behaviour and API contract changes

These are the changes that can break an existing client, script or habit.

| Area | Before | Now |
|---|---|---|
| Authentication | JWT **or** session token accepted | **Only** opaque server-side session tokens. A JWT is rejected as an unknown session |
| `POST /auth/login` | CAPTCHA optional | `captcha_id` + `captcha_answer` **required** (422 if absent). Wrong/expired/reused → 400 before credentials are checked |
| `POST /auth/token` | Form login without CAPTCHA | Form login **requires** `captcha_id` + `captcha_answer` |
| `POST /auth/signup` | Open, created `PENDING` users | **403** unless `AUTH_ALLOW_SIGNUP=true` (off by default) |
| Protected routes | Reachable with a valid session | **428** `Password change required` while `must_change_password` is set. Only `/auth/me`, `/auth/logout`, `/auth/change-password` are allowed |
| Admin-created users | `must_change_password=false` | `true`; first login forces `/change-password` |
| `POST /users/{id}/approve` | Any target, any role, reactivated disabled users | `PENDING` only; `ANALYST`/`SUPPORT` only; 400 otherwise; 409 on race |
| RBAC | Matrix existed but was unused | Every protected route checks a permission. `SUPPORT` cannot export CSV; `ANALYST` can set daily-review verdicts and trigger investigations |
| `GET /auth/me` | No rotation flag | Includes `must_change_password` |
| `TRUSTED_PROXIES` | Loopback trusted implicitly | **Empty by default.** Behind nginx you must set `TRUSTED_PROXIES=127.0.0.1,::1` or every client looks like `127.0.0.1` |
| CORS / CSRF origins | Configured list + localhost | Configured list **verbatim**; when set, localhost is not implicitly allowed |
| Secrets | Weak defaults accepted | Production refuses to start without 32+ char `AUTH_SESSION_SECRET` and `AUTH_CAPTCHA_SECRET` |
| Session lifetime | Hard-coded 24 h | `AUTH_SESSION_EXPIRE_MINUTES` (default 1,440; example file 480) drives DB, cookie and response |
| CAPTCHA lifetime | Hard-coded 300 s | `AUTH_CAPTCHA_EXPIRE_SECONDS` |
| Error detail for missing permission | “administrator privileges required” | Contains “lacks permission” (tests assert this) |

### Role matrix as shipped

| Permission | ADMIN | ANALYST | SUPPORT |
|---|:---:|:---:|:---:|
| `dashboard:read`, `status:read`, `analytics:read` | ✅ | ✅ | ✅ |
| `domains:read`, `clients:read`, `queries:read` | ✅ | ✅ | ✅ |
| `reports:read` | ✅ | ✅ | ✅ |
| `reports:export` | ✅ | ✅ | ❌ |
| `domains:investigate`, `clients:investigate`, `queries:investigate` | ✅ | ✅ | ❌ |
| `daily_review:read`, `daily_review:update` | ✅ | ✅ | ❌ |
| `users:read`, `users:create`, `users:update` | ✅ | ❌ | ❌ |
| `audit_logs:read` | ✅ | ❌ | ❌ |
| `settings:read`, `settings:update` | ✅ | ❌ | ❌ |

---

## 6. Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `DNSNETRA_ENV` | `development` | `production`/`prod` turns on fail-closed secret checks and secure cookies |
| `AUTH_SESSION_SECRET` | dev pepper (non-prod) | 32+ char HMAC pepper for session-token hashes. Generate with `openssl rand -hex 32` |
| `AUTH_CAPTCHA_SECRET` | dev secret (non-prod) | 32+ char HMAC key for CAPTCHA signatures |
| `AUTH_SESSION_EXPIRE_MINUTES` | `1440` | Session lifetime, minutes |
| `AUTH_CAPTCHA_EXPIRE_SECONDS` | `300` | CAPTCHA lifetime, seconds |
| `AUTH_COOKIE_SECURE` | `false` (true in prod) | `Secure` flag on the session cookie |
| `AUTH_ALLOW_SIGNUP` | `false` | Must be explicitly `true` to re-open public signup |
| `CORS_ALLOWED_ORIGINS` | localhost defaults | Comma-separated origins; replaces the defaults entirely when set |
| `TRUSTED_PROXIES` | empty | Comma-separated proxy IPs allowed to supply XFF. Set to `127.0.0.1,::1` behind nginx |

Production values live in `/etc/dnsnetra/api.env` (mode 600, `root:dnsnetra`),
not in the repo.

---

## 7. Deployment artifacts (nginx, not Caddy)

```
deploy/
├── README.md                     # Ubuntu 24.04 runbook, 9 steps
├── api.env.example               # production env template
├── gen-internal-cert.sh          # self-signed cert with SANs, 825 days
├── ufw-dnsnetra.sh               # deny inbound; 22 admin CIDR; 443 user CIDR
├── nginx/
│   ├── dnsnetra.conf             # TLS server, routes, rate limits, headers
│   └── dnsnetra-proxy.conf       # shared proxy_set_header block
└── systemd/
    ├── dnsnetra-api.service      # uvicorn on 127.0.0.1:8000, 1 worker
    └── dnsnetra-web.service      # Next.js on 127.0.0.1:3000
```

Traffic path:

```
browser ──443──> nginx ──/api/*──> 127.0.0.1:8000 (FastAPI)
                    └────/──────> 127.0.0.1:3000 (Next.js)
```

Same origin, so the session cookie needs no cross-site relaxation. nginx
overwrites `X-Forwarded-For` with the real peer address; the API trusts it
only because `127.0.0.1` is in `TRUSTED_PROXIES`.

**Caveat:** nginx is not installed on this machine, so Task 9 was verified
statically (shell syntax, unit-file structure, config review). `nginx -t` and a
live TLS handshake must be run on the Ubuntu host.

---

## 8. Operator scripts

Both are **dry-run by default** and refuse to do anything surprising.

```bash
# Inspect what would be deleted
python scripts/purge_test_users.py --keep admin

# Delete everything except admin, and clear audit history
python scripts/purge_test_users.py --keep admin --execute --purge-audit-logs

# Inspect rotation eligibility
python scripts/rotate_admin_password.py --username admin

# Rotate and print the one-time password exactly once
python scripts/rotate_admin_password.py --username admin --execute
```

`purge_test_users.py` refuses to run if the keep-list is empty or contains no
`ADMIN`. `rotate_admin_password.py` refuses a missing or non-admin user, and
revokes every session for the rotated account.

---

## 9. Verification evidence

### Backend

| Run | Result |
|---|---|
| Baseline before week 1 | 29 failed, 346 passed |
| After Task 8 | 29 failed, 382 passed, 8 xfailed |
| After Task 10 (final) | **29 failed, 387 passed, 7 xfailed** |

- The 29 failures are **identical to baseline** and are unrelated dataset
  drift: the dev database holds ~64,000 queries while
  `tests/test_reporting_service.py` and friends expect the 30,181-row fixture
  dataset.
- Failure distribution: `test_reporting_service.py` 12, `test_aggregator.py` 4,
  `test_client_profiling.py` 4, `test_phase0_remediation.py` 4,
  `test_reporting_repository.py` 3, `test_data_reconciliation.py` 1,
  `test_investigation_service.py` 1.
- 41 more tests pass than at baseline.
- Auth/RBAC/admin suites collect **104 tests**; zero failures; the only
  non-passes are the 7 intentional `xfail`s listed in §3.3.
- The earlier `admin`/`admin` logins are gone from the test suite; tests use
  the seeded `pytest_admin`/`pytest_analyst`/`pytest_support` accounts.

### Frontend

| Check | Result |
|---|---|
| `pnpm test` | 7 files, **46/46 passed** |
| `pnpm build` | **passes**; `/change-password` present, `/signup` absent |
| `pnpm lint` | 4 **pre-existing** errors, 6 warnings |

The 4 lint errors are `react-hooks/set-state-in-effect` in files this work did
not touch: `clients/[client_ip]/page.tsx`, `domains/[domain]/page.tsx`,
`components/data-table/data-table.tsx`, `components/theme-provider.tsx`.

### What was not verified live

- nginx config load and TLS handshake (nginx not installed locally).
- ufw rules (not applied to this machine).
- systemd units (not installed on this machine).
- A full browser pass through nginx → Next.js → FastAPI.

---

## 10. Frontend state and caveats

Committed auth work:

- `frontend/app/(auth)/change-password/page.tsx` (new)
- `frontend/app/(auth)/login/page.tsx` (rotation redirect, CAPTCHA message,
  footer copy)
- `frontend/components/auth/AuthGuard.tsx` (rotation redirect)
- `frontend/lib/auth/api.ts` (`changePassword`, 428 kind)
- `frontend/next.config.ts` (`/signup` redirect)
- `frontend/app/(auth)/signup/page.tsx` (deleted)

Still uncommitted **by design** (your redesign work-in-progress):

```
frontend/app/(auth)/login/page.tsx
frontend/app/globals.css
frontend/app/layout.tsx
frontend/components/auth/AuthBrand.tsx
frontend/components/auth/AuthButton.tsx
frontend/components/auth/AuthForm.tsx
frontend/components/auth/AuthLayout.tsx
frontend/components/auth/AuthVisual.tsx
frontend/components/auth/CaptchaField.tsx
frontend/lib/auth/api.ts
frontend/lib/data-table/api-client.ts
```

Task 5 and Task 7 staged only the auth hunks (via blob-level
`git update-index --cacheinfo`) so your redesign stayed in the working tree.
The one non-auth fix left unstaged is
`frontend/lib/data-table/api-client.ts`, where two `API_BASE` references
became `currentApiBase`; without it the production build fails.

Also still untracked: `docs/superpowers/` (the 2,962-line plan) and
`frontend/public/assets/`.

---

## 11. Deliberately not done

| Decision | Reason |
|---|---|
| No Keycloak / OIDC / SAML | 5–10 admin-provisioned users, one internal app. An IdP would add an operational dependency with no security gain here. Revisit above ~25–50 users or when a second app needs SSO |
| No Better Auth | It is a TypeScript library; the authoritative backend is Python/FastAPI |
| No JWT | Server-side sessions revoke instantly and are simpler to reason about. A JWT would weaken revocation |
| No Google reCAPTCHA | Requires outbound egress and conflicts with the WAF/isolated-network posture. The self-hosted CAPTCHA was fixed instead. Turnstile is the fallback only if a hosted challenge is ever mandated |
| No public signup | Matches the admin-provisioned model; gated behind `AUTH_ALLOW_SIGNUP` if policy changes |
| No self-service password reset | There is no mail infrastructure in the private network. Reset is currently **admin-initiated** (`POST /users/{id}/reset-password`) and the login page points users to an administrator. See §13 |
| No admin user-management UI | User lifecycle is API-only today (`/api/v1/users…`, Swagger/`/docs`). This is a product gap, not a security gap |

---

## 12. Known gaps to schedule next

1. **Admin UI for user lifecycle** — create, approve, disable, reset, revoke
   sessions. Today these are API calls only, which is workable for 5–10 users
   but error-prone.
2. **Self-service “reset password” button** — the original request. Needs a
   decision: admin-issued one-time code (no mail), or a reset link if internal
   SMTP exists.
3. **AUTH-13 remainder** — per-account lockout/backoff and a limit on
   `/auth/change-password`.
4. **AUTH-14/15** — stop returning the token in the JSON body and add
   `Cache-Control: no-store` to auth responses.
5. **AUTH-12** — dummy hash verification for unknown usernames.
6. **AUTH-08** — validate `status`/`is_active` together; avoid session revocation
   on no-op updates.
7. **AUTH-17** — one canonical special-character definition and reserved-name
   matching that ignores leading/trailing dots.
8. **Redis/Postgres CAPTCHA + rate-limit store** before running more than one
   API worker.
9. **Live deployment verification** — nginx `-t`, TLS, ufw, systemd, and a
   browser login through the real front door.

---

## 13. Required operator action (pending your approval)

The database is currently:

```
users=4   sessions=506   audit_logs=1902
```

```
id=1    admin_sec          ADMIN    ACTIVE   must_change=false
id=2    admin              ADMIN    ACTIVE   must_change=false
id=87   CASE_TEST_CE775C   ANALYST  PENDING
id=171  analyst_user_1     ANALYST  PENDING
```

The dry run confirms the purge would remove the three non-`admin` accounts and
keep `admin`. Until rotation runs, **the `admin` password is still `admin`** —
this is the largest remaining live risk.

Recommended sequence:

```bash
# 1. Back up the auth tables first
pg_dump -h localhost -U postgres -d dns_threat_detection \
  -t dashboard_users -t sessions -t audit_logs \
  > backup_auth_$(date +%F).sql

# 2. Purge test accounts and audit history
python scripts/purge_test_users.py --keep admin --execute --purge-audit-logs

# 3. Rotate the admin password (prints the one-time password once)
python scripts/rotate_admin_password.py --username admin --execute

# 4. Verify
psql -h localhost -U postgres -d dns_threat_detection -c \
  "SELECT username, role, status, must_change_password FROM dashboard_users;"
```

Expected after step 2–3: one `admin` row with `must_change_password=t`, zero
sessions, zero audit rows.

Do **not** paste the generated password into chat or a ticket. Move it
directly into the password manager; the first login will force a change.

---

## 14. Rollback

- Code: `git revert 39056a5 0a51ef6 09855df 225df80 7741fee 9605c3c a666eaa
  7a84ecd 037bcfc 485ba7a`, or reset to `8dd0b46` on a scratch branch.
- The deploy artifacts are additive; removing `deploy/` and the two units
  restores the previous process model.
- The test kit and conftest are additive; reverting the task commits restores
  the old fixtures (and their JWT bypass).
- After purge/rotation, rollback requires the `pg_dump` from step 1. **There is
  no undo for deleted audit rows.**

---

## 15. File index

**Backend**
- `api/auth_config.py` (new)
- `api/auth.py` (JWT removed, 428 enforcement)
- `api/sessions.py` (HMAC pepper, TTLs, `must_change_password`)
- `api/captcha.py` (CSPRNG, atomic consume, TTL)
- `api/csrf.py` (origin list no longer merged)
- `api/trusted_proxy.py` (explicit proxies, right-to-left XFF)
- `api/rbac.py` (matrix + `require_permission`)
- `api/main.py` (startup validation)
- `api/routes/auth.py`, `users.py`, `daily_review.py`, `dashboard.py`,
  `reports.py`, `domains.py`, `clients.py`, `investigation.py`, `status.py`,
  `analytics.py`

**Scripts**
- `scripts/_session_auth.py` (new)
- `scripts/rotate_admin_password.py` (new)
- `scripts/purge_test_users.py` (new)
- `scripts/measure_performance.py`, `reconciliation_check.py`,
  `verify_api_complete.py`, `verify_http_live.py` (session-based auth)

**Tests**
- `tests/auth_testkit.py`, `tests/conftest.py`, `tests/test_auth_fixtures.py`
- `tests/test_auth_security_audit.py` (29 tests, 7 `xfail`)
- `tests/test_rbac_routes.py`, `tests/test_admin_scripts.py`,
  `tests/test_auth_config.py`
- Updated: `test_auth_complete.py`, `test_auth_hardening.py`, `test_api_v1.py`,
  `test_detection_pipeline.py`

**Frontend**
- `app/(auth)/change-password/page.tsx` (new)
- `app/(auth)/login/page.tsx`, `app/(auth)/signup/page.tsx` (deleted)
- `components/auth/AuthGuard.tsx`, `lib/auth/api.ts`, `next.config.ts`

**Deployment / docs**
- `deploy/**` (8 files)
- `docs/AUTH_SECURITY_AUDIT.md` (findings + remediation table)
- `docs/superpowers/plans/2026-10-28-auth-hardening-week1.md` (executed plan,
  untracked)
- `docs/AUTH_HARDENING_WEEK1_CHANGES.md` (this document)

---

## Phase 2 baseline (2026-11-03)

Recorded on branch `auth/phase-2` at the start of Phase 2, before any
destructive action.

| Object | Count / value |
|---|---|
| `dashboard_users` | 4 rows |
| `sessions` | 530 rows |
| `audit_logs` | 2,048 rows |
| Accounts | `admin_sec` (ADMIN, ACTIVE), `admin` (ADMIN, ACTIVE, `must_change_password=false`), `CASE_TEST_CE775C` (ANALYST, PENDING), `analyst_user_1` (ANALYST, PENDING) |

Auth suite baseline: `82 passed, 7 xfailed` across
`test_auth_security_audit.py`, `test_auth_complete.py`,
`test_auth_hardening.py`, `test_rbac_routes.py`.

Phase 0 result (2026-11-03): purged `admin_sec`, `CASE_TEST_CE775C`,
`analyst_user_1`; kept all `audit_logs` (real history preserved); rotated
`admin` and set `must_change_password=true`. Pre-change backup:
`~/dnsnetra-auth-backup-20261103-154007.sql` (mode 0600).
