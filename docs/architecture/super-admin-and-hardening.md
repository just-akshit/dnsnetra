# Auth Phase Guide — SUPER_ADMIN, Admin Reset, and Domain-Intelligence Hardening

> **Layout note.** This guide was written before the monorepo migration. Paths such as
> `api/`, `frontend/`, `database/`, and `deploy/` refer to the current `apps/api`,
> `apps/web`, `backend/src/dnsnetra/persistence`, and `infrastructure/deployment`
> locations respectively. See `docs/README.md` for the full mapping.

> **What this document is:** a plain-English companion to the work, not a replacement
> for the executable plans. It explains *what* was built, *why* it was built that way,
> *how* the pieces talk to each other, and *what is still left*. Each section points at
> the exact files so you can go read the code with context instead of guessing.
>
> **Audience:** a developer or operator who knows the project loosely and needs to
> understand this phase without reading 7,000 lines of plan documents first.

**Date:** 2026-11-10
**Repo:** `/Users/akshit/Developer/dnsnetra`
**Branch state:** SUPER_ADMIN phase is merged to `main` (PR #2). The Domain-Intelligence
P0/P1 hardening described in Parts B and D1 is also merged to `main` (PRs #5, #4, #3;
merge commit `4c7d61b`). The only open items are the backlog in Part D.

---

## Status at a glance

| Stream | State | Where it lives |
|---|---|---|
| SUPER_ADMIN role + hierarchy | ✅ Merged | `api/rbac.py`, `api/user_admin_policy.py`, `database/migrations/010_super_admin_role.sql` |
| Server-generated temporary passwords | ✅ Merged | `api/auth.py`, `api/routes/users.py` |
| Last-principal protection | ✅ Merged | `api/routes/users.py` |
| SUPER_ADMIN bootstrap / rotation scripts | ✅ Merged | `scripts/create_super_admin.py`, `scripts/rotate_admin_password.py` |
| Role-aware users UI + sidebar | ✅ Merged | `frontend/lib/admin/*`, `frontend/app/(dashboard)/users/page.tsx` |
| Domain-Intelligence live dossier + 4-state verdict | ✅ Merged | `investigation/live/*`, `frontend/components/intelligence/live-verdict.tsx` |
| Domain-Intelligence P0 fixes | ✅ Merged | See Part B |
| Domain-Intelligence P1 (indexes, partial failures, min length, refresh, single-flight) | ✅ Merged | See Part D1 |
| Domain-Intelligence P1 (browser E2E) + P2 | ⏳ Open | See Part D |
| Auth Phase 4 (MFA, session UI, shared store, CSP) | ⏳ Open | See Part D3 |

**One-sentence summary:** this phase gave the system a protected top-level
administrator, replaced "type the new password for the user" with a server-generated
one-time password, and made the new domain/IP search safe enough to be exposed to real
traffic.

## If you are deploying this, do these in order

1. **Back up** `dashboard_users`, `password_reset_tokens`, and the audit table.
2. **Stop the API.**
3. Run `.venv/bin/python database/migrate.py` — applies `010_super_admin_role.sql`
   and `011_search_trgm_indexes.sql`.
4. Run `.venv/bin/python scripts/create_super_admin.py --username <name> --execute`
   — move the printed one-time password to the password manager.
5. Set `VT_API_KEYS`, `OTX_API_KEYS`, and `LIVE_INTEL_ENABLED` in the systemd
   environment file.
6. **Start the API** and log in as the new super admin; confirm `/users` is visible.
7. Keep `--workers 1` until the shared CAPTCHA/rate-limit store lands (see D4).
8. Run the verification commands in Part C before calling it done.

---

## 0. The one-paragraph version

Before this phase, `ADMIN` was the highest role in the system. Any admin could
disable, demote, or reset the password of any other admin. That meant one compromised
admin account could take over the entire installation, and two admins could
accidentally lock each other out. Password resets also required the admin to invent
the new password and send it to the user — so the admin knew the user's password, and
the password travelled through chat or email.

This phase introduced `SUPER_ADMIN`, a role above `ADMIN`, with one small policy
module that answers "may this actor manage this target?" on every management route.
It also changed reset-password to generate a random temporary password on the server,
show it exactly once, revoke all of the target's sessions, and force a password change
at next login. The system now refuses to remove the last active `SUPER_ADMIN`
(and the last active `ADMIN` when no super admin exists).

In parallel, the Domain-Intelligence search bar got its production blockers fixed:
stale responses can no longer overwrite fresh ones, search input can no longer inject
SQL wildcards or trigger unbounded table scans, the live-intelligence cache is
bounded, external providers cannot hang the page, deployment keys are documented,
and users are told when their query leaves the network.

---

# Part A — The SUPER_ADMIN role

## A1. Why a new role was needed

Think of the old setup as a building with one master key. Every `ADMIN` held the same
master key, so:

- **No separation of power.** If an admin account was phished, the attacker could
  create another admin, disable the real admins, and keep the keys.
- **No safe recovery.** If the only admin was disabled, there was no in-product way
  back in. You needed the break-glass CLI script.
- **Mutual lockout.** Two admins could disable each other, leaving nobody with
  management access.
- **Password co-ownership.** An admin who reset a password knew the new password.
  That is an audit and privacy problem.

`SUPER_ADMIN` fixes this by adding one rank above `ADMIN` and by making the
hierarchy explicit in one place instead of scattering `if role == ...` checks
across the routes.

## A2. The role ladder

The hierarchy is deliberately tiny:

| Rank | Role | Can manage | Notes |
|---|---|---|---|
| 3 | `SUPER_ADMIN` | `SUPER_ADMIN`, `ADMIN`, `ANALYST`, `SUPPORT` | The protected top tier |
| 2 | `ADMIN` | `ANALYST`, `SUPPORT` | Operational administrator |
| 1 | `ANALYST` | nobody | Investigation / review work |
| 1 | `SUPPORT` | nobody | Read-only operational views |

`ANALYST` and `SUPPORT` are peers. They have different permissions, but neither can
manage users.

### Permissions vs. hierarchy

These are two different things, and mixing them up is the usual source of confusion:

- **Permissions** answer "can this role open this page / call this endpoint?"
  (`users:read`, `domains:investigate`, …). They live in `api/rbac.py`.
- **Hierarchy** answers "can this actor act on *this specific person*?"
  It lives in `api/user_admin_policy.py`.

`SUPER_ADMIN` uses the **same permission set as `ADMIN`**. The extra authority is not
a bigger permission list; it is the ability to manage administrators. This keeps the
permission matrix small and makes the hierarchy the only thing you have to reason
about for user management.

Code: `api/rbac.py` (`UserRole`, `ROLE_PERMISSIONS`, `require_permission`).

## A3. One policy module decides every management question

File: `api/user_admin_policy.py`

This module is the single source of truth. Every user-management route calls it
*before* doing any work. If a new route is added later, it must call this too; that
is the review rule.

It exposes two functions:

```python
can_assign_role(actor_role, new_role) -> (bool, reason)
can_manage(actor, target, new_role=None) -> (bool, reason)
```

`can_manage` checks, in order:

1. **Is the actor allowed to manage users at all?**
   Only `SUPER_ADMIN` and `ADMIN` are in `MANAGEABLE_ROLES`.
2. **Is the actor trying to manage themselves?**
   If `actor.id == target.id`, deny. Self-service is intentionally not a management
   operation (except revoking your own sessions, which is effectively logout).
3. **Is the target's current role inside the actor's allowed set?**
   `ADMIN` may only touch `ANALYST` / `SUPPORT`; `SUPER_ADMIN` may touch anyone.
4. **If a new role is being assigned, is it assignable?**
   This stops privilege escalation such as an `ADMIN` promoting someone to `ADMIN`
   or `SUPER_ADMIN`.

Anything not explicitly allowed is denied. Denials are written to the audit log as
`AUTHORIZATION_DENIED` with the actor role, target role, attempted action, and reason
(`ensure_can_manage` / `_deny`).

### Why this shape

- **One place to change.** Adding a role or changing a rule is a one-file change.
- **Deny by default.** The route does not have to enumerate every bad case.
- **Auditable.** A denial is evidence, not a silent 403.
- **UI can mirror it.** The frontend copies the *same* table so it can hide controls,
  but the backend is still the authority.

## A4. Every route is guarded

File: `api/routes/users.py`

| Route | Permission | Hierarchy check | Extra guard |
|---|---|---|---|
| `GET /api/v1/users` | `users:read` | none (read-only) | — |
| `GET /api/v1/users/{id}` | `users:read` | none (read-only) | — |
| `POST /api/v1/users` | `users:create` | `ensure_can_assign_role` | username/password validation, duplicate check |
| `PATCH /api/v1/users/{id}` | `users:update` | `ensure_can_manage` | self-demote / self-disable returns 400 |
| `POST /api/v1/users/{id}/approve` | `users:update` | `ensure_can_manage` | only `PENDING` → `ANALYST`/`SUPPORT` |
| `POST /api/v1/users/{id}/disable` | `users:update` | `ensure_can_manage` | self-disable 400 + last-principal guard |
| `POST /api/v1/users/{id}/enable` | `users:update` | `ensure_can_manage` | — |
| `POST /api/v1/users/{id}/reset-password` | `users:update` | `ensure_can_manage` | server-generated temp password |
| `POST /api/v1/users/{id}/reset-code` | `users:update` | `ensure_can_manage` | one-time code, 15-minute expiry |
| `POST /api/v1/users/{id}/revoke-sessions` | `users:update` | `ensure_can_manage` unless self | self-revoke allowed |

Two deliberate design choices:

- **Reads are broad.** An `ADMIN` can list and open `ADMIN` / `SUPER_ADMIN` rows.
  This is read-only and is what makes the users table workable. Hiding rows would
  break pagination and make the "show the button only when allowed" logic impossible.
- **Writes are narrow.** Every write goes through the hierarchy.

## A5. Self-management rules and status codes

These are stable contracts; tests and the UI depend on them.

| Attempt | Result | Why |
|---|---|---|
| Reset your own password via admin reset | **403** | The policy denies self-management; use the normal change-password flow |
| Change your own role | **400** | Stable pre-existing self-guard message |
| Disable your own account | **400** | Stable pre-existing self-guard message |
| Revoke your own sessions | **200** | Effectively logout; explicitly allowed |
| Manage an `ADMIN` while you are `ADMIN` | **403** | Hierarchy denial |
| Manage a `SUPER_ADMIN` while you are `ADMIN` | **403** | Hierarchy denial |
| Assign `ADMIN` / `SUPER_ADMIN` while you are `ADMIN` | **403** | `can_assign_role` denial |
| Target does not exist | **404** | Route-level lookup |
| Duplicate username | **409** | Uniqueness check |
| Session valid but password change pending | **428** | `must_change_password` enforcement in `api/auth.py` |
| Search or auth throttled | **429** | Rate limiter, with `Retry-After` |

Why the split between 400 and 403? The 400s are the older self-service guards that
already existed and are covered by tests. The 403s are the hierarchy policy. Keeping
both stable avoids breaking clients while still putting the real authorization
decision in one place.

## A6. Server-generated temporary passwords

File: `api/routes/users.py` (`reset_password`), `api/auth.py`
(`generate_temporary_password`)

### The flow, step by step

1. An `ADMIN` or `SUPER_ADMIN` clicks **Reset password** on the users page.
2. The frontend sends `POST /api/v1/users/{id}/reset-password` **with no body**.
   The old API accepted `new_password`; that contract is gone.
3. The backend loads the target and runs `ensure_can_manage`.
4. It generates a 20-character password from letters, digits, and symbols using
   `secrets.choice`, and retries until the result satisfies
   `validate_password_strength`.
5. It stores only the Argon2id hash, sets `must_change_password = true`, and clears
   the legacy `hashed_password` column.
6. It revokes **every** active session for the target. A stolen session cannot
   survive a reset.
7. It writes a `PASSWORD_RESET` audit row with metadata, **never the password**.
8. It returns the plaintext password once, with:
   - `Cache-Control: no-store, max-age=0`
   - `Pragma: no-cache`

### What the user sees

The users page opens a modal showing the temporary password with a copy button. The
password exists only in that response and in React state. Closing the modal discards
it. There is no "show again" endpoint, because storing it would defeat the design.

At next login, the target authenticates with the temporary password and is
immediately stopped by `428 Password change required` on every route except the
small allowlist: `/api/v1/auth/me`, `/api/v1/auth/logout`, and
`/api/v1/auth/change-password`. After the change, normal access resumes.

### Why this is better

| Before | After |
|---|---|
| Admin invents the password | Server generates it; nobody chooses it |
| Admin knows the user's password | Admin sees it once and cannot retrieve it later |
| Password may be reused | Random, policy-compliant, one-time |
| Old sessions survive a reset | All sessions are revoked |
| Password could leak via browser/proxy cache | `no-store` on the response |

**Invariant:** the temporary password is never logged, audited, persisted in
plaintext, or written to the database. Only its hash exists after the response.

### The alternative: one-time reset code

`POST /api/v1/users/{id}/reset-code` is for the case where you want the user to
choose their own password. The backend generates a short-lived code (15 minutes),
stores only its hash in `password_reset_tokens`, invalidates any previous unused
code for that user, and returns the code once with `no-store`. The user redeems it
through the reset-password flow. This is separate from the temporary-password reset
above; both are hierarchy-gated.

## A7. Last-principal protection

File: `api/routes/users.py` (`_lock_active_principals`, `_ensure_principal_remains`)

The rule:

- The **last active `SUPER_ADMIN` is always protected.**
- The **last active `ADMIN` is protected only when no active `SUPER_ADMIN` exists**
  to take over.

Why the second clause? If a super admin exists, that account can always restore an
admin. Blocking the last admin removal in that case would be unnecessarily
restrictive. If no super admin exists, the last admin is the only privileged
principal and must not disappear.

The check runs **inside the same transaction** that disables or demotes the account.
It locks every active privileged row with `FOR UPDATE` first, so two concurrent
requests cannot both observe "there are two admins" and both remove one.

A subtle point: through the HTTP API, the last `SUPER_ADMIN` cannot normally be
demoted anyway, because self-management is denied and only another `SUPER_ADMIN`
can manage a `SUPER_ADMIN`. The guard is defense in depth for scripts, direct DB
work, and future route changes.

## A8. The database change

File: `database/migrations/010_super_admin_role.sql`

```sql
ALTER TABLE dashboard_users
    DROP CONSTRAINT IF EXISTS chk_dashboard_users_role;

ALTER TABLE dashboard_users
    ADD CONSTRAINT chk_dashboard_users_role
    CHECK (role IN ('SUPER_ADMIN', 'ADMIN', 'ANALYST', 'SUPPORT'));
```

It only widens the `CHECK` constraint. There is no data rewrite and no automatic
promotion of the existing `admin` account. That is deliberate: the first super admin
is created by an operator, not by the application.

**Order matters:** back up the database → stop the API → apply the migration →
bootstrap the first `SUPER_ADMIN` → start the API. The runbook is in
`deploy/README.md`.

## A9. Bootstrap and break-glass scripts

### First SUPER_ADMIN — `scripts/create_super_admin.py`

```bash
# Dry run: validates the username and reports what would happen.
.venv/bin/python scripts/create_super_admin.py --username superadmin

# Actually create the account.
.venv/bin/python scripts/create_super_admin.py --username superadmin --execute
```

- Dry-run is the default. `--execute` is required to write.
- The account is created `ACTIVE` with `must_change_password = true`.
- A one-time password is printed to stdout. Move it straight to the password
  manager.
- An audit row `USER_CREATED` records `actor = system/cli`.
- There is no API path to create the first `SUPER_ADMIN`, and no auto-promotion.

### Break-glass rotation — `scripts/rotate_admin_password.py`

This remains the emergency path if the only privileged account is locked out. It
now accepts `ADMIN` or `SUPER_ADMIN`, writes an audit row, and forces a password
change at next login.

## A10. Frontend: mirror, not authority

Files:

- `frontend/lib/admin/permissions.ts` — client-side copy of the hierarchy
- `frontend/lib/admin/users-api.ts` — typed client, `SUPER_ADMIN` added, new reset
  contract, `resetCode`
- `frontend/app/(dashboard)/users/page.tsx` — role-aware actions and the
  one-time-password modal
- `frontend/components/app-sidebar.tsx` — Users nav entry shown to `ADMIN` and
  `SUPER_ADMIN`

The mirror exposes `canManage(actorRole, target, selfId)` and
`assignableRoles(actorRole)`. It decides **which controls to render**. It is not a
security boundary. The backend will reject anything the UI accidentally allows.
This is stated at the top of `permissions.ts`, and it is worth repeating: hiding a
button is not authorization.

The users page uses the mirror to:

- filter which actions appear on each row,
- restrict the roles in the create/change-role dialog,
- hide reset/disable/role controls on your own row,
- show the "reset password" confirmation and then the one-time password modal.

## A11. Tests that protect this phase

| Test file | What it locks down |
|---|---|
| `tests/test_role_hierarchy.py` | Policy unit tests + route matrix across actors and targets |
| `tests/test_admin_scripts.py` | `create_super_admin` dry-run/execute, audit behavior |
| `tests/test_users_admin.py` | New no-body reset contract, validation errors |
| `tests/test_auth_complete.py` | Updated legacy assertions for the new hierarchy |
| `tests/test_auth_hardening.py` | Updated two-admin behavior |
| `frontend/tests/permissions.test.ts` | Client mirror matches the backend table |
| `frontend/tests/users-api.test.ts` | Typed client sends the right shape |
| `frontend/tests/users-page.test.tsx` | Role-aware actions and reset modal |
| `frontend/tests/app-sidebar.test.tsx` | Nav gating for `ADMIN`/`SUPER_ADMIN` |

---

# Part B — Domain-Intelligence P0 hardening

> Context: this is the second workstream from the Domain-Intelligence search-bar
> session. It is unrelated to the auth hierarchy, but it shares the same production
> concern: **do not let a nice feature become an outage or a data leak.**

## B1. What the feature does

The header search accepts any domain or IP address. It normalizes real-world input
(`https://Evil.Example/login` → `evil.example`, `192.168.1.10:53` →
`192.168.1.10`, `[2001:db8::1]` → `2001:db8::1`), offers existing telemetry matches
below the input, and on **Enter** opens the entity's dossier page.

The dossier is assembled from two places:

- **Local telemetry** — what this network has actually observed.
- **Live external intelligence** — DNS, RDAP, VirusTotal, and AlienVault OTX.

A domain that has never been seen locally is no longer a 404. It returns a real
dossier with `observed_in_network: false` plus a full `live_intel` block. Malformed
input is still a 400.

## B2. The four-state verdict (the important idea)

The old engine had a dangerous habit: if no provider voted malicious, it called the
domain **clean**. A brand-new malware domain that nobody had scanned yet would be
presented as clean. That is exactly backwards.

The live layer now uses four states:

| State | Meaning | Rough rule |
|---|---|---|
| `malicious` | Real evidence of harm | VirusTotal has ≥ 20 engines and ≥ 10% detections |
| `suspicious` | Some evidence, not enough to convict | ≥ 2 VT detections, or ≥ 2% ratio, or ≥ 3 suspicious engines |
| `clean` | Real evidence of safety | 0 detections across ≥ 10 engines; 1 detection in a broad scan is treated as an outlier |
| `unknown` | No usable data | No provider returned data, or a very new domain lacks scan history |

Additional rules:

- **Only providers with real data vote.** `found = false` and `unavailable = true`
  are not clean votes.
- **OTX alone never convicts.** OTX pulse counts are noisy; many legitimate domains
  appear in unrelated pulses. OTX can add suspicion, not a malicious verdict.
- **A strong VT clean outranks noisy OTX.** A broad clean scan (≥ 50 engines)
  beats a pile of unrelated pulses.
- **New domains are never called clean on thin evidence.** Younger than 14 days
  with fewer than 20 engines → `unknown`, with a reason.
- **Confidence is separate from state.** You can have "malicious, high confidence"
  or "unknown, very little data". The UI shows both.

Code: `investigation/live/verdict.py`, `investigation/live/models.py`.

## B3. The P0 fixes, one by one

### P0-1 — Stale-response race

**Problem:** the search is debounced. If you type fast, request A (for `goo`) can
land after request B (for `google.com`) and overwrite the newer results. You could
press Enter and land on the wrong entity.

**Fix:** a monotonically increasing request id (`requestSeqRef`) in
`frontend/components/global-intelligence-search.tsx`. Every request captures its
sequence number; when the response arrives, it is applied only if it is still the
latest. Clearing, closing, or starting a new search bumps the counter. There is no
network-level abort; the sequence guard is what protects correctness — late
responses are ignored, and the debounce timer is cleared when the query changes.

**Evidence:** a new test fails when the guard is removed and passes when restored.
That is the point of the test — it proves the guard matters.

### P0-2 — SQL wildcard injection and unbounded search

**Problem:** `search=%` was interpolated into `ILIKE '%%%'`, which matches every row
and forces a full table scan — three times per keystroke, because the bar fans out to
domains, clients, and queries. There was no length cap and no search-specific rate
limit (the limiter was auth-only).

**Fix (three layers):**

1. **Escape and cap** — `reporting/repository.py::_like_pattern` escapes `\`, `%`,
   and `_`, and truncates to 253 characters (the DNS name limit). The pattern is
   still parameterized; escaping prevents user input from changing the pattern's
   meaning.
2. **Throttle** — `api/rate_limiter.py::enforce_search_rate_limit`, 60 requests per
   minute per client IP, applied only when a non-empty search term is present.
   Routes: `GET /api/v1/domains`, `GET /api/v1/clients`,
   `GET /api/v1/reports/queries`.
3. **Route hygiene** — the routes strip whitespace and pass the clean term; an empty
   or whitespace-only term is treated as "no filter", not as a wildcard.

**Why 60/min?** One keystroke triggers three requests. A human typing a domain is
well under 60. A script is not. It is a cheap abuse ceiling, not a precise quota.

### P0-3 — Unbounded live-intel cache

**Problem:** `_CACHE` never evicted. Every unique domain ever searched stayed in
memory forever. That is a slow memory leak and an easy denial-of-service vector.

**Fix:** `investigation/live/service.py` now uses an `OrderedDict` LRU:

- maximum 2,000 entries,
- 15-minute TTL per entry,
- expired entries removed on access,
- least-recently-used entries evicted when full.

**Trade-off:** a burst of unique searches can evict a useful entry early. That is
acceptable; correctness and bounded memory matter more than a perfect hit rate.

### P0-4 — Providers could hang the page

**Problem:** VirusTotal and OTX retried with 1s + 2s + 4s backoff inside the request
path. One flaky provider could stall the dossier for 15–20 seconds.

**Fix:**

- providers run concurrently,
- hard per-provider deadline of 5 seconds,
- hard wall-clock deadline of 6 seconds for the whole live lookup,
- a timed-out provider degrades to `unknown` with a reason instead of raising,
- `LIVE_INTEL_ENABLED=false` is a kill switch that skips external providers
  entirely and returns `unknown` with an explanation.

**Why degrade instead of fail?** A partial answer is more useful than a 500. The UI
shows "live external intelligence is temporarily unavailable" and still renders local
telemetry when it exists.

### P0-5 — Production deploy had no provider keys

**Problem:** `deploy/api.env.example` had no `VT_API_KEYS` or `OTX_API_KEYS`. An
operator following the deploy README would get silent `unknown` verdicts everywhere
and assume the feature was broken.

**Fix:** `deploy/api.env.example` now documents:

```dotenv
VT_API_KEYS=
OTX_API_KEYS=
LIVE_INTEL_ENABLED=true
```

and `deploy/README.md` explains quota, key rotation, and the systemd
`EnvironmentFile`. The root `api.env.example` still has placeholder examples.

### P0-6 — Attribution and privacy

**Problem:** searching an indicator sends it to VirusTotal and AlienVault OTX. That
is a data-egress event. Users were not told, and VT's terms expect attribution.

**Fix:**

- the search bar's idle state says:
  *"Domain and IP lookups query VirusTotal and AlienVault OTX for live reputation."*
- the verdict footer lists the sources that answered and states that external
  lookups are sent to those providers,
- the UI distinguishes "not observed in this network" from "no external data".

**Why it matters:** an analyst may search an internal or sensitive hostname. They
should know it leaves the network before they press Enter.

## B4. The request flow

```text
┌──────────────────────────────────────────────────────────────────┐
│ Header search (global-intelligence-search.tsx)                   │
│                                                                  │
│  keystroke ──► normalize + validate ──► debounce                 │
│                    │                                             │
│                    ├─ invalid ──► inline validation, no request  │
│                    │                                             │
│                    └─ valid ──► Promise.allSettled([             │
│                                   /domains?search=...            │
│                                   /clients?search=...            │
│                                   /reports/queries?search=...    │
│                                 ])                               │
│                                 │                                │
│                                 ▼                                │
│                    requestSeqRef check (drop stale)              │
│                                 │                                │
│                                 ▼                                │
│                    suggestions + "Domain/IP lookup" row          │
│                                                                  │
│  Enter ──► /domains/<domain> or /clients/<ip>                    │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ Investigation route (api/routes/investigation.py)                │
│                                                                  │
│  validate ──► local dossier (optional)                           │
│           └─► live intel (concurrent, 6s wall)                   │
│                 ├─ DNS records                                   │
│                 ├─ RDAP registrar / age                          │
│                 ├─ VirusTotal (domain or IP)                     │
│                 └─ AlienVault OTX (domain or IP)                 │
│                                                                  │
│  merge ──► 200 dossier {                                        │
│               profile?: ...,                                     │
│               observed_in_network: bool,                         │
│               live_intel: { verdict, evidence, infra, ... }      │
│            }                                                     │
└──────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│ Domain / Client page                                             │
│  - live verdict hero: state + confidence + reasons               │
│  - provider evidence: VT ratio, categories, OTX pulses           │
│  - activity: DNS, RDAP, ASN/owner/country                        │
│  - local telemetry only when observed_in_network                 │
└──────────────────────────────────────────────────────────────────┘
```

## B5. Tests that protect this work

| Test file | What it covers |
|---|---|
| `tests/test_domain_intelligence_search.py` | HTTP seam for `search=` on domains, clients, queries; case-insensitivity; empty results; limits |
| `tests/test_live_verdict.py` | Four-state thresholds, outlier handling, OTX noise, new-domain rule |
| `tests/test_live_intel_service.py` | Cache bounds/TTL, deadlines, kill switch |
| `tests/test_investigation_live.py` | Unseen entity returns 200 with live intel; malformed input 400 |
| `tests/test_investigation_service.py` | Dossier merge behavior |
| `frontend/tests/global-search.test.tsx` | Search normalization, direct lookup, stale-response guard |
| `frontend/tests/live-verdict.test.tsx` | Verdict rendering and provider evidence |
| `frontend/tests/search-entity.test.ts` | URL/IP/domain normalization |

## B6. What P0 did **not** fix — and what landed afterwards

P0 closed the release blockers. A follow-up pass then landed most of the P1 list on
`main` (merged via PRs #5, #4, #3):

| Follow-up item | State | Where |
|---|---|---|
| Trigram indexes for `%term%` search | ✅ Merged | `database/migrations/011_search_trgm_indexes.sql` |
| Partial-failure reporting | ✅ Merged | `searchIntelligence` returns `unavailable`, bar shows a banner |
| Minimum query length (2 chars) | ✅ Merged | `MIN_SEARCH_LENGTH = 2` in the search component |
| `?refresh=1` cache bypass | ✅ Merged | investigation route → `LiveIntelService` → page "Refresh Profile" |

Still open: distributed cache, browser E2E infrastructure, accessibility semantics,
IDN parity, JSX cleanup, and provider metrics. See Part D.

The most important remaining constraint is not a bug at all: the live cache, the
rate limiter, the CAPTCHA store, and the login lockout are all in-process. They are
correct for a single `uvicorn` worker and wrong for two.

---

# Part C — Verification

## C1. Commands

Run from the repo root.

**Auth phase**

```bash
.venv/bin/python -m pytest \
  tests/test_role_hierarchy.py \
  tests/test_admin_scripts.py \
  tests/test_users_admin.py \
  tests/test_auth_complete.py \
  tests/test_auth_hardening.py \
  tests/test_password_reset.py -q
```

**Domain-Intelligence backend**

```bash
.venv/bin/python -m pytest \
  tests/test_live_verdict.py \
  tests/test_live_intel_service.py \
  tests/test_investigation_live.py \
  tests/test_investigation_service.py \
  tests/test_domain_intelligence_search.py -q
```

**Frontend**

```bash
cd frontend
pnpm test -- --run
pnpm exec tsc --noEmit
pnpm build
```

## C2. Manual browser matrix (auth)

Log in as each actor and confirm the row.

| Actor | Target | Reset | Change role | Disable | Create |
|---|---|---|---|---|---|
| `SUPER_ADMIN` | `ADMIN` | allowed; temp password shown once | allowed | allowed | `ADMIN` allowed |
| `SUPER_ADMIN` | other `SUPER_ADMIN` | allowed | allowed | allowed | `SUPER_ADMIN` allowed |
| `SUPER_ADMIN` | self | 403; no button | 400; no button | 400; no button | n/a |
| `ADMIN` | `ANALYST` / `SUPPORT` | allowed | allowed | allowed | `ANALYST`/`SUPPORT` only |
| `ADMIN` | `ADMIN` | 403; no button | 403 | 403 | `ADMIN` option absent |
| `ADMIN` | `SUPER_ADMIN` | 403; no button | 403 | 403 | `SUPER_ADMIN` option absent |
| `ANALYST` / `SUPPORT` | anyone | 403 | 403 | 403 | 403 |

For every allowed reset, also confirm:

- the target is signed out immediately,
- the temporary password works once,
- every route outside the allowlist (`me`, `logout`, `change-password`) returns
  **428** until the password change completes,
- closing the modal removes the password from the DOM,
- the audit log contains the reset (and never the password).

## C3. Known baseline noise

The suite has **pre-existing dataset-drift failures** that assert exact seeded
counts against a local database that has since changed. They are not caused by this
phase and should not be counted as regressions:

- `test_reporting_repository.py` / `test_reporting_service.py` — hardcoded
  `total_queries`, `unique_clients`, `unique_domains` values.
- Small drift in aggregator/client-profiling suites noted in the phase-2 baseline.

The rule from the plan still applies: **any *new* failure is a regression.**

---

# Part D — What is still left

## D1. P1 — scale and correctness (Domain Intelligence)

### Already landed on `main`

| Item | Where | What changed |
|---|---|---|
| `pg_trgm` GIN indexes | `database/migrations/011_search_trgm_indexes.sql` | `domain` and `client_ip` on `domain_query_history` use `gin_trgm_ops`; the migration explains why the small profile tables are left alone |
| Partial-failure reporting | `frontend/lib/data-table/api-client.ts`, search component | `searchIntelligence` returns an `unavailable` list; the bar shows "Partial results — … unavailable" instead of pretending zero |
| Minimum query length | `frontend/components/global-intelligence-search.tsx` | `MIN_SEARCH_LENGTH = 2`; one character no longer fires three scans |
| `?refresh=1` | `api/routes/investigation.py`, `investigation/live/service.py`, both dossier pages | "Refresh Profile" bypasses the 15-minute cache once |
| Single-flight per indicator | `investigation/live/service.py` | Concurrent lookups of one domain/IP share one upstream call; the leader builds, followers wait. Cache + in-flight table stay process-local; the Redis/Postgres path is documented in the module and in D4 |
| Search limiter no longer self-trips | `api/rate_limiter.py` | Budget is keyed per endpoint, so a keystroke's three requests no longer exhaust one shared bucket and fake a "partial results" outage |
| Race + happy-path tests | `tests/test_live_intel_service.py`, `tests/test_domain_intelligence_search.py`, `frontend/tests/global-search.test.tsx` | Concurrent lookup collapses to one provider call; a 25-keystroke search stays under the limiter; search miss → unseen dossier returns 200; stale-response guard and close-mid-search spinner tests stay green |

> **Deployment note:** migration `011` is not applied automatically just because the
> file exists. Run `.venv/bin/python database/migrate.py` as part of the deploy.

### Still open

| # | Task | Why it matters | Where | Definition of done |
|---|---|---|---|---|
| 1 | Distributed cache + single-flight | Single-flight is per process; two workers still double VT usage | `investigation/live/service.py` | Redis `SET NX` on the indicator key (or a Postgres advisory lock) replaces `_INFLIGHT`, and the TTL cache reads/writes the same shared store |
| 2 | Browser E2E | The happy path is pinned at the HTTP seam only; no Playwright/Cypress exists | new `e2e/` | Type an unseen domain in the bar, land on the dossier, see the verdict hero |

## D2. P2 — polish (Domain Intelligence)

| # | Task | Why |
|---|---|---|
| 3 | Combobox/listbox accessibility | The palette works with mouse and arrow keys, but screen readers get no `role=combobox`, `aria-activedescendant`, `role=option`, or result-count live region |
| 4 | IDN parity | The frontend regex rejects `münchen.de`; the backend accepts it via IDNA. Normalize before validating |
| 5 | Collapse duplicated JSX | The domains group is rendered twice (IP vs non-IP ordering); one ordered list is easier to maintain |
| 6 | Provider observability | Emit latency/error/quota metrics and alert on repeated 429s; today there are only warning logs |

## D3. Auth Phase 4 backlog

These were deliberately not part of the SUPER_ADMIN plan. They are real
improvements, not defects in what shipped.

| # | Item | Why / dependency |
|---|---|---|
| 1 | **Shared CAPTCHA + rate-limit store (AUTH-16)** | Required before `--workers > 1`. Move `InMemoryCaptchaStore`, `_BUCKETS`, `_FAILURES`, and the live-intel cache to Redis or PostgreSQL |
| 2 | **TOTP MFA** | `pyotp` + QR provisioning, encrypted secret, backup codes; require for `ADMIN` and `SUPER_ADMIN`. Needs a product decision and a migration |
| 3 | **Session-management UI** | List active sessions per user; revoke one or all. The backend already has revoke endpoints |
| 4 | **CSP and app-level security headers** | nginx sets HSTS, nosniff, frame-deny, and referrer policy. Add a report-only CSP and tighten it |
| 5 | **Quarterly access review** | Export the user/role table, have an owner sign off, disable unused accounts |

## D4. The single-worker constraint (read before scaling)

Today the deployment runs **one** `uvicorn` worker. Several security and performance
mechanisms rely on process-local memory:

- login failure counters / per-account lockout,
- the CAPTCHA store,
- the sliding-window rate limiter (`_BUCKETS`),
- the live-intel LRU cache.

With two workers, each process has its own counters and cache. Consequences:

- a user can get twice the login attempts,
- a CAPTCHA solved in worker A is unknown to worker B,
- rate limits are effectively multiplied,
- VT/OTX quota usage multiplies,
- a cache hit in one worker is a miss in the other.

**Decision:** keep `--workers 1` until the shared store lands. If you must scale out
first, move at least the auth state (CAPTCHA, lockout, rate limit) to a shared store
*before* adding workers. Document the worker count in the deploy runbook so this is
not discovered during an incident.

---

# Part E — Glossary

| Term | Plain meaning |
|---|---|
| **RBAC** | Role-based access control: permissions attached to roles, not individuals |
| **Hierarchy** | Which role may act on which other role |
| **Principal** | An account that holds privileges; here, `ADMIN` and `SUPER_ADMIN` |
| **Opaque session** | A random server-side token; the client cannot read or forge its meaning |
| **CSRF** | Cross-site request forgery; the backend verifies the request origin for cookie auth |
| **CAPTCHA** | A challenge that must be solved before login/token issuance |
| **Argon2id** | The password hashing algorithm; slow by design |
| **`must_change_password`** | A flag that forces `/change-password` before any work outside the `me`/`logout` allowlist |
| **HTTP 428** | "Precondition required"; used here for "change your password first" |
| **Last-principal guard** | Refuses to remove the only remaining privileged account |
| **Audit event** | An append-only record of a security-relevant action |
| **ILIKE** | Case-insensitive SQL pattern matching |
| **Trigram index** | An index that makes `%substring%` searches fast |
| **TTL** | Time to live; how long a cache entry stays valid |
| **LRU** | Least recently used; the eviction policy when a cache is full |
| **Single-flight** | Collapse concurrent identical requests into one upstream call |
| **VT** | VirusTotal, an external multi-engine malware scanning service |
| **OTX** | AlienVault Open Threat Exchange, an external threat-intelligence feed |
| **RDAP** | The modern WHOIS: registration dates, registrar, status |
| **Dossier** | The combined profile of a domain or IP: local telemetry + live intelligence |
| **Four-state verdict** | `malicious` / `suspicious` / `clean` / `unknown`; absence of data is `unknown`, never `clean` |
| **Confidence** | How much usable evidence backed the verdict, separate from the verdict itself |
| **Telemetry** | What this network actually observed (DNS queries, clients, labels) |

---

# Part F — File map

## Auth

| File | Responsibility |
|---|---|
| `api/rbac.py` | Roles, permission matrix, `require_permission` |
| `api/user_admin_policy.py` | The single hierarchy authority (`can_manage`, `can_assign_role`) |
| `api/routes/users.py` | User lifecycle routes, hierarchy checks, temp-password reset, last-principal guard |
| `api/auth.py` | Password hashing/validation, temp-password generator, session dependency, 428 enforcement |
| `api/audit.py` | Audit action constants, including `AUTHORIZATION_DENIED` |
| `database/migrations/010_super_admin_role.sql` | Widens the role `CHECK` constraint |
| `scripts/create_super_admin.py` | Dry-run-by-default bootstrap of the first super admin |
| `scripts/rotate_admin_password.py` | Break-glass rotation, accepts `ADMIN`/`SUPER_ADMIN` |
| `frontend/lib/admin/permissions.ts` | Client mirror of the hierarchy (cosmetic only) |
| `frontend/lib/admin/users-api.ts` | Typed users client, new reset contract |
| `frontend/app/(dashboard)/users/page.tsx` | Role-aware users page, temp-password modal |
| `frontend/components/app-sidebar.tsx` | Users nav entry gating |

## Domain Intelligence

| File | Responsibility |
|---|---|
| `frontend/components/global-intelligence-search.tsx` | Header palette, normalization, stale-response guard, privacy copy |
| `frontend/lib/search/entity.ts` | Domain/IP/URL normalization |
| `frontend/lib/data-table/api-client.ts` | `searchIntelligence`, `ApiError`, typed dossier calls |
| `frontend/components/intelligence/live-verdict.tsx` | Verdict hero, provider evidence, activity sections |
| `frontend/app/(dashboard)/domains/[domain]/page.tsx` | Domain dossier page, not-observed state |
| `frontend/app/(dashboard)/clients/[client_ip]/page.tsx` | Client dossier page, not-observed state |
| `investigation/live/service.py` | Concurrent live lookup, LRU cache, deadlines, kill switch |
| `investigation/live/verdict.py` | Four-state verdict composition |
| `investigation/live/models.py` | `LiveIntelReport`, `ProviderEvidence`, `IndicatorVerdict`, `IPContext` |
| `investigation/schemas.py` | `DomainDossier` / `ClientDossier` with optional profile and live intel |
| `investigation/service.py` | Merge local dossier + live intel; unseen entities are 200 |
| `api/routes/investigation.py` | Dossier endpoints, error mapping |
| `api/rate_limiter.py` | Auth throttle + search throttle |
| `reporting/repository.py` | `_like_pattern` escaping and length cap |
| `database/migrations/011_search_trgm_indexes.sql` | Trigram GIN indexes for `ILIKE '%term%'` search |
| `labeler/intel/providers/virustotal.py` | VT domain + IP lookup |
| `labeler/intel/providers/alienvault.py` | OTX domain + IP lookup |
| `deploy/api.env.example` | `VT_API_KEYS`, `OTX_API_KEYS`, `LIVE_INTEL_ENABLED` |
| `deploy/README.md` | Migration/bootstrap order, provider keys, quota notes |

---

# Part G — Commit trail (for archaeology)

```text
# Auth phase 2 (merged in 2ea2713)
37e9cdc feat(admin): add typed users API client
5358252 feat(admin): add user lifecycle page
1f2871d feat(admin): gate Users nav entry to ADMIN role
aa86212 feat(auth): add one-time-code password reset flow
af366b7 docs(plan): mark Phase 2 tasks 10-13 complete

# SUPER_ADMIN phase (merged in 537fe74; PR #2 b56f622)
fcbada1 docs(auth): add SUPER_ADMIN role implementation plan
c470be3 feat(rbac): add SUPER_ADMIN role and widen role constraint
54bac3b feat(rbac): add a single role-hierarchy policy helper
5128cb4 feat(users): enforce the role hierarchy on every management route
5069fd5 feat(users): generate one-time temporary passwords on reset
9e177e3 fix(users): protect the last active SUPER_ADMIN and ADMIN
d45e01a feat(scripts): add SUPER_ADMIN bootstrap and audit CLI rotations
8b6d010 feat(admin): mirror the role hierarchy in the users API client
8cbf0a6 feat(admin): show hierarchy-aware reset actions on the users page
dbc2d8b feat(admin): show the users nav entry to SUPER_ADMIN
5293f33 docs(ops): document SUPER_ADMIN migration and bootstrap order
4c422aa fix(admin): surface validation errors when creating users
176d404 test(admin): cover the create-user form submission
809a46d docs(auth): record self-management denial codes and close matrix

# Domain-Intelligence P0/P1 (merged via PR #5 579a7dd, PR #4 5e70ef2, PR #3 4c7d61b)
4e5cdc5 feat: live domain/IP intelligence search with production hardening
50d51da docs: add PRODUCT.md and impeccable build-path config
6097de1 docs: add DESIGN.md and impeccable design sidecar
a960041 fix(live-intel): collapse concurrent lookups with single-flight
46935a3 fix(search): budget searches per endpoint and clear the dialog spinner
```

---

## Final takeaway

The auth story is now: **one top principal, one policy module, one-time passwords,
and a guard against deleting the only keyholder.** The search story is now: **a
bounded, throttled, deadline-aware feature that tells users when data leaves the
network.** Neither is finished forever — Part D is the honest backlog — but the
dangerous failure modes are closed and covered by tests.
