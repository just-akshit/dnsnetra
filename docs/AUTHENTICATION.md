# DNSNetra — Hardened Backend Authentication & Authorization Architecture

## 1. Authentication Architecture

DNSNetra is a private organizational DNS threat detection and incident response platform. The backend authentication and authorization system is entirely internal, self-contained, and defensively hardened:

- **Username-only credentials**: No third-party OAuth, OIDC, SAML, SSO, or email dependencies. Usernames are case-insensitive and strictly canonicalized.
- **Argon2id password hashing**: Passwords are never stored in plaintext or reversible forms. Argon2id (RFC 9106) is enforced with automatic transparent legacy bcrypt hash migration.
- **Self-hosted Visual CAPTCHA**: Text/image challenge generated in-process via Pillow without external network dependencies. Challenges are cryptographically signed with HMAC-SHA256 (`hmac.compare_digest`), bounded in memory, rate limited, and single-use protected against replay attacks via a pluggable `BaseCaptchaStore`.
- **Stateful Server-Side Sessions**: Opaque 256-bit URL-safe tokens stored only as SHA-256 hashes in PostgreSQL. Supports instant revocation, logout invalidation, and multi-session revocation on password resets.
- **Browser Cookie Security & CSRF Defense**: Browser clients use a canonical `HttpOnly`, `SameSite=lax`, `Secure` (in production) cookie (`dnsnetra_session`). State-changing requests authenticated via cookie require strict `Origin` / `Referer` validation matching allowed origins.
- **Trusted Proxy Resolution**: Client IP addresses are resolved safely; `X-Forwarded-For` and `X-Real-IP` headers are only trusted if the direct connection originates from a configured trusted reverse proxy (`TRUSTED_PROXIES`).
- **Last Active Admin Protection**: Administrative state changes (disable, role demotion) acquire transaction-safe row-level locks (`SELECT ... FOR UPDATE`) to guarantee that the system can never reach zero active administrators.
- **Centralized Role-Based Access Control (RBAC)**: Central authorization dependencies and permission maps governing administrative and operational API surfaces.

```
                               ┌──────────────────────────────────────────┐
                               │       Client / Browser / Consumer        │
                               └────────────────────┬─────────────────────┘
                                                    │
                                      1. GET /api/v1/auth/captcha
                                         (Rate limited to 30/min)
                                                    │
                                                    ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ FastAPI Backend                                                                        │
│                                                                                        │
│   ┌────────────────────────┐         ┌────────────────────────┐                        │
│   │   api/captcha.py       │         │    api/auth.py         │                        │
│   │  - Pillow Distortion   │         │  - Argon2id Hasher     │                        │
│   │  - HMAC compare_digest │         │  - Credentials Check   │                        │
│   │  - BaseCaptchaStore    │         │  - get_current_user    │                        │
│   └───────────┬────────────┘         └───────────┬────────────┘                        │
│               │                                  │                                     │
│               │ 2. POST /auth/login              │                                     │
│               │    (user + pass + captcha)       │                                     │
│               ▼                                  ▼                                     │
│   ┌────────────────────────┐         ┌────────────────────────┐                        │
│   │   api/rate_limiter.py  │         │   api/sessions.py      │                        │
│   │  - Sliding Window      │         │  - 256-bit Token       │                        │
│   │  - Trusted Proxy IP    │         │  - SHA-256 Hash        │                        │
│   └────────────────────────┘         └───────────┬────────────┘                        │
│                                                  │                                     │
│   ┌────────────────────────┐         ┌───────────┴────────────┐                        │
│   │   api/csrf.py          │         │   api/trusted_proxy.py │                        │
│   │  - Origin Validation   │         │  - Peer IP validation  │                        │
│   │  - Cookie State-change │         │  - Forwarded-For scrub │                        │
│   └───────────┬────────────┘         └───────────┬────────────┘                        │
│               │                                  │                                     │
│   ┌───────────┴────────────┐                     │                                     │
│   │   api/audit.py         │◄────────────────────┘                                     │
│   │  - Append-only Logs    │                                                           │
│   │  - Sensitive Redaction │                                                           │
│   └───────────┬────────────┘                                                           │
└───────────────┼──────────────────────────────────┼─────────────────────────────────────┘
                │                                  │
                ▼                                  ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ PostgreSQL Database (dns_threat_detection)                                             │
│                                                                                        │
│   ┌────────────────────────┐ ┌────────────────────────┐ ┌────────────────────────────┐ │
│   │ dashboard_users        │ │ sessions               │ │ audit_logs                 │ │
│   │  - id, username        │ │  - id, user_id         │ │  - id, user_id, action    │ │
│   │  - LOWER(username) uq  │ │  - session_token_hash  │ │  - target_user_id, ip      │ │
│   │  - password_hash       │ │  - expires_at          │ │  - timestamp, metadata     │ │
│   │  - must_change_password│ │  - revoked_at          │ │                            │ │
│   │  - role, status        │ │  - created_at          │ │                            │ │
│   │  - is_active           │ │                        │ │                            │ │
│   │  - DB CHECK constraints│ │                        │ │                            │ │
│   └────────────────────────┘ └────────────────────────┘ └────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. User Database Model & Schema Constraints

The system extends PostgreSQL `dashboard_users` with defensive constraints and indices:

| Column | Type | Constraints | Description |
|---|---|---|---|
| `id` | `SERIAL` | `PRIMARY KEY` | Unique numeric identifier |
| `username` | `VARCHAR(100)` | `NOT NULL` | Username identifier (canonical lowercase) |
| `email` | `VARCHAR` | `NULL` | Legacy identifier / compatibility field |
| `password_hash` | `VARCHAR(255)` | `NULL` | Argon2id password hash |
| `hashed_password` | `VARCHAR(255)` | `NULL` | Legacy bcrypt field (cleared to NULL upon successful migration) |
| `role` | `VARCHAR(20)` | `NOT NULL DEFAULT 'ANALYST'` | Role: `ADMIN`, `ANALYST`, or `SUPPORT` |
| `status` | `VARCHAR(20)` | `NOT NULL DEFAULT 'PENDING'` | Status: `PENDING`, `ACTIVE`, `DISABLED` |
| `is_active` | `BOOLEAN` | `NOT NULL DEFAULT FALSE` | Boolean active flag required for authentication |
| `must_change_password` | `BOOLEAN` | `NOT NULL DEFAULT FALSE` | Forces password change on initial login after reset |
| `created_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` | Account creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | `NOT NULL DEFAULT NOW()` | Last update timestamp |
| `last_login_at` | `TIMESTAMPTZ` | `NULL` | Timestamp of last successful session creation |

### Hardened Database Constraints (Migration 008)
- **Functional Unique Index**: `CREATE UNIQUE INDEX IF NOT EXISTS uq_dashboard_users_lower_username ON dashboard_users (LOWER(username));`
- **Role Domain Constraint**: `CONSTRAINT chk_dashboard_users_role CHECK (role IN ('ADMIN', 'ANALYST', 'SUPPORT'))`
- **Status Domain Constraint**: `CONSTRAINT chk_dashboard_users_status CHECK (status IN ('PENDING', 'ACTIVE', 'DISABLED'))`
- **Status/Active Coherence**: `CONSTRAINT chk_dashboard_users_status_active CHECK ((status = 'ACTIVE' AND is_active = true) OR (status IN ('PENDING', 'DISABLED') AND is_active = false))`

---

## 3. Roles & Account Lifecycle

Three authoritative system roles are defined in `api/rbac.py`:

1. **`ADMIN`**: Full system control. Can approve, create, disable, and enable users; assign and update roles; reset passwords; revoke sessions; inspect security audit logs; and manage all threat intelligence review queues and operational reports.
2. **`ANALYST`**: Operational security investigation role. Allowed to inspect domain and client dossiers, search queries, trigger enrichment pipelines, and submit verdicts in the daily review queue. Forbidden from accessing user management, system settings, or audit logs.
3. **`SUPPORT`**: Read-only operational monitoring role. Allowed to view summary reports, query event logs, and view client and domain profiles. Forbidden from performing mutations, review queue updates, or administrative actions.

### Lifecycle State Machine
```
[ Signup ] ──► PENDING (is_active=false, no effective permissions, login blocked)
                  │
                  ▼ (Admin Approval: POST /api/v1/users/{id}/approve)
               ACTIVE (is_active=true, valid sessions allowed)
                  │
                  ▼ (Admin Disablement: POST /api/v1/users/{id}/disable)
               DISABLED (is_active=false, all sessions revoked immediately)
                  │
                  ▼ (Admin Enablement: POST /api/v1/users/{id}/enable)
               ACTIVE (previous sessions remain dead; fresh login required)
```

> **Lifecycle over Delete**: DNSNetra deliberately omits hard user deletion (`users:delete` removed from RBAC). Account removal is represented by transitioning accounts to `DISABLED`. This immediately revokes all active sessions while preserving complete forensic audit trails.

---

## 4. Permissions Matrix

Centralized in `api/rbac.py`:

| Permission | ADMIN | ANALYST | SUPPORT | Description |
|---|:---:|:---:|:---:|---|
| `users:read` | ✅ | ❌ | ❌ | List users and view user profiles |
| `users:create` | ✅ | ❌ | ❌ | Directly create accounts with roles |
| `users:update` | ✅ | ❌ | ❌ | Approve, disable, enable, or patch accounts |
| `audit_logs:read` | ✅ | ❌ | ❌ | Read security audit logs |
| `settings:read` | ✅ | ❌ | ❌ | View administrative configuration |
| `settings:update` | ✅ | ❌ | ❌ | Update administrative configuration |
| `daily_review:read` | ✅ | ✅ | ❌ | View daily review queue domains |
| `daily_review:update` | ✅ | ✅ | ❌ | Submit verdicts and trigger enrichment |
| `domains:read` | ✅ | ✅ | ✅ | View domain catalog and telemetry |
| `domains:investigate`| ✅ | ✅ | ❌ | Deep dossier analysis and threat intel |
| `clients:read` | ✅ | ✅ | ✅ | View client catalog and query stats |
| `clients:investigate`| ✅ | ✅ | ❌ | Deep client behavioral dossiers |
| `queries:read` | ✅ | ✅ | ✅ | Search query event log |
| `queries:investigate`| ✅ | ✅ | ❌ | Filter and analyze query telemetry |
| `reports:read` | ✅ | ✅ | ✅ | View aggregation reports and KPI charts |
| `reports:export` | ✅ | ✅ | ❌ | Export reports to CSV/JSON |

---

## 5. CAPTCHA Architecture

Implemented in `api/captcha.py`:
- **Image Generation**: Rendered in-process via Pillow with individual character rotations (-25° to +25°), 350+ background noise points, multiple noise lines, and continuous sinusoidal distortion. Excludes confusing glyphs (0/O, 1/I/l).
- **HMAC Challenge Binding**:
  `HMAC-SHA256(AUTH_CAPTCHA_SECRET, f"{captcha_id}:{normalized_answer}:{exp}")`
- **Constant-Time Verification**: Uses `hmac.compare_digest` to prevent timing attacks.
- **Answer Normalization**: Generation and verification use identical `normalize_captcha_answer(raw)` (whitespace trimmed, uppercased).
- **Pluggable Storage Abstraction**: `BaseCaptchaStore` interface (`issue`, `get`, `consume`, `is_consumed`, `cleanup_expired`). Default implementation is `InMemoryCaptchaStore` bounded to `max_capacity=10,000` with automatic TTL pruning.
- **Replay Protection**: Successfully verified challenges are consumed atomically. Replay attempts immediately fail.
- **Rate Limiting**: Protected by sliding-window rate limiter set to 30 requests/minute per client IP.

---

## 6. Sessions, Cookies & CSRF Protection

Implemented in `api/sessions.py`, `api/auth.py`, and `api/csrf.py`:
- **Token Format**: 256-bit URL-safe opaque random string (`secrets.token_urlsafe(36)`).
- **Persisted Hash**: Only SHA-256 hash (`session_token_hash`) is persisted in PostgreSQL.
- **Browser Cookies**: Login sets canonical `dnsnetra_session` cookie:
  `HttpOnly=True`, `SameSite=lax`, `Secure` (enabled in production or via `AUTH_COOKIE_SECURE=true`), `Path=/`, `Max-Age=86400`.
- **CSRF Defense**: State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) relying on cookie authentication strictly enforce that the request `Origin` or `Referer` matches configured allowed origins (`CORS_ALLOWED_ORIGINS`). Cross-origin browser attacks are rejected with HTTP 403 Forbidden.
- **Bearer Token Clients**: Programmatic API consumers using `Authorization: Bearer <token>` bypass CSRF origin checks since custom headers cannot be forged across origins by browsers without CORS preflight permission.
- **Session Revocation**:
  - Logout revokes the caller's active session.
  - Admin disable revokes all active sessions for that user.
  - Admin password reset revokes all active sessions for that user.
  - Re-enabling an account does NOT resurrect old sessions.

---

## 7. Last Active Admin Protection

Implemented in `api/routes/users.py`:
To prevent administrative lockout:
1. **Self-Disablement & Self-Demotion Guards**: Administrators cannot disable or demote their own account.
2. **Concurrency-Safe Active Admin Lock**: Operations that disable or demote an administrator execute inside a transaction with row-level locks:
   ```sql
   SELECT id FROM dashboard_users
   WHERE role = 'ADMIN' AND status = 'ACTIVE' AND is_active = true
   FOR UPDATE;
   ```
   If the target user is an active administrator and `len(active_admins) <= 1`, the operation is aborted with HTTP 400 Bad Request, guaranteeing zero-admin states cannot occur even under concurrent requests.

---

## 8. Password Security & Legacy Hash Migration

Implemented in `api/auth.py`:
- **Argon2id (RFC 9106)**: Canonical hashing algorithm (time_cost=2, memory_cost=64MB, parallelism=1, hash_len=32).
- **Password Policy**:
  - Length: 8 to 128 characters.
  - Must contain at least one letter.
  - Must contain at least one digit or special character.
  - Must NOT equal the username.
  - Reject whitespace-only passwords.
  - Confirmation password match checked at signup, reset, and change endpoints.
- **Legacy Bcrypt Migration**: Users created prior to Argon2id adoption authenticate transparently. Upon successful verification of the legacy bcrypt hash, the backend re-hashes the password using Argon2id, writes `password_hash`, and clears `hashed_password = NULL` atomically.
- **Password Reset Lifecycle**: Admin password reset sets `must_change_password = true` and invalidates all existing sessions. The user authenticates with temporary credentials and updates their password at `POST /api/v1/auth/change-password`, which clears the `must_change_password` flag and generates a fresh session.

---

## 9. Trusted Proxy & Client IP Handling

Implemented in `api/trusted_proxy.py`:
- Direct peer IP is obtained from `request.client.host`.
- If peer IP is listed in `TRUSTED_PROXIES` (default: `127.0.0.1`, `::1`, `localhost`), the real client IP is extracted from `X-Forwarded-For` (rightmost untrusted entry) or `X-Real-IP`.
- If the request originates from an untrusted peer, forwarded headers are ignored, preventing IP spoofing attacks against audit logging and rate limiting.

---

## 10. Rate Limiting

Implemented in `api/rate_limiter.py`:
- Thread-safe sliding window rate limiting.
- Stale IP buckets are pruned periodically to prevent memory exhaustion.
- Protected Endpoints:
  - `GET /api/v1/auth/captcha`: 30 requests / 60 seconds
  - `POST /api/v1/auth/signup`: 10 requests / 60 seconds
  - `POST /api/v1/auth/login`: 15 requests / 60 seconds
  - `POST /api/v1/auth/token`: 15 requests / 60 seconds
  - `POST /api/v1/users/{id}/reset-password`: 10 requests / 60 seconds
- Exceeding thresholds returns HTTP 429 Too Many Requests with standard `Retry-After` header.

---

## 11. Security Audit Trail

Implemented in `api/audit.py`:
- Append-only audit records stored in `audit_logs` table.
- Records: `user_id`, `actor_username`, `action`, `target_user_id`, `target_username`, `ip_address`, `user_agent`, `timestamp`, `metadata`.
- **Sensitive Value Scrubbing**: Automatically purges passwords, password hashes, secrets, session tokens, and CAPTCHA answers before persistence.

---

## 12. Security Headers

FastAPI application middleware (`api/main.py`) applies defensive security headers to all responses:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains` (enforced when `DNSNETRA_ENV=production`)

---

## 13. Known Single-Instance Limitations

1. **CAPTCHA Challenge Store**: The default store is `InMemoryCaptchaStore`. If DNSNetra API is scaled horizontally across multiple distinct worker processes without sticky sessions, challenges must be validated on the same instance or the store must be swapped to a distributed backend (e.g. shared PostgreSQL/Redis via `BaseCaptchaStore`).
2. **Rate Limiter**: The sliding window rate limiter stores hit counters in process memory. Each worker maintains its own bucket counters.
