# Auth Hardening — Week 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the critical and high-severity authentication defects, make opaque Postgres sessions the only credential, enforce CAPTCHA / forced password rotation / RBAC, close public signup, and put the app behind nginx TLS on loopback.

**Architecture:** FastAPI stays the single authorization authority. Browsers authenticate with an `HttpOnly` session cookie; bearer headers carry the same opaque session token for scripts and tests. Every protected route resolves a permission from `ROLE_PERMISSIONS`, never from a token claim. nginx terminates TLS on `443`, serves the Next.js UI and the API from one origin, and forwards to services bound to `127.0.0.1` only. The API runs as one uvicorn worker because CAPTCHA and rate-limit state are in-process (AUTH-16).

**Tech Stack:** Python 3.13, FastAPI, psycopg, PostgreSQL, Argon2id, Next.js 16.3.5 / React 19, nginx, systemd, Ubuntu 24.04 LTS.

**Spec:** `docs/AUTH_SECURITY_AUDIT.md` (findings AUTH-01…AUTH-19 and their required behaviour). This plan implements the subset listed under “Global Constraints” and leaves the rest as `xfail` reproducers.

## Global Constraints

- Roles are exactly `ADMIN`, `ANALYST`, `SUPPORT`. No new roles in this phase.
- No public signup. Accounts are created by an administrator through `POST /api/v1/users`.
- No OIDC, SAML, Keycloak, Better Auth, social login, or Google reCAPTCHA. The CAPTCHA is the existing self-hosted image challenge.
- Sessions are the only credential. The JWT fallback and `create_access_token` are deleted, not gated.
- One uvicorn worker (`--workers 1`). Do not add `--workers N` until CAPTCHA and rate-limit state move to Redis/Postgres.
- Reverse proxy is **nginx**, never Caddy. Both services bind to `127.0.0.1`.
- External hostname for this plan: `dnsnetra.corp.local`. If the real hostname differs, change it in `deploy/nginx/dnsnetra.conf`, `deploy/api.env.example`, and the frontend build environment — nowhere else.
- Tests must never authenticate as the seeded `admin` account and must never contain the literal password `admin`.
- This phase fixes AUTH-01, 02, 03, 04, 05, 06, 07, 09, 10, 11 and 18. AUTH-08, 12, 14, 15, 17 stay `xfail`; do not delete those tests.
- All commands run from the repository root `/Users/akshit/Developer/dnsnetra` unless the step says otherwise.
- Use the working audit virtualenv for Python commands:
  `/private/var/folders/98/mngfqhbx1rd0nwgb97wt9_300000gn/T/opencode/dnsnetra-audit-venv/bin/python`.
  Set `PY=/private/var/folders/98/mngfqhbx1rd0nwgb97wt9_300000gn/T/opencode/dnsnetra-audit-venv/bin/python` once per shell.

## File Structure

**New backend files**

| File | Responsibility |
|---|---|
| `api/auth_config.py` | Environment parsing, dev fallbacks, production fail-closed validation, TTLs, pepper, signup flag |
| `tests/auth_testkit.py` | Shared test helpers: DB access, CAPTCHA issuance, login, bearer headers |
| `tests/conftest.py` | Seeded `pytest_admin` / `pytest_analyst` / `pytest_support`, session fixtures, ephemeral-user cleanup |
| `tests/test_auth_fixtures.py` | Proves the fixtures authenticate with the right roles |
| `tests/test_auth_config.py` | Production validation and TTL tests |
| `tests/test_rbac_routes.py` | Route-level permission enforcement |
| `tests/test_admin_scripts.py` | Password generator and purge-plan safety |
| `scripts/_session_auth.py` | Bearer token from a database user (replaces JWT minting in scripts) |
| `scripts/rotate_admin_password.py` | Rotate one admin, force change at next login, revoke sessions |
| `scripts/purge_test_users.py` | Keep-list purge with dry-run default |

**New deployment files**

`deploy/nginx/dnsnetra.conf`, `deploy/nginx/dnsnetra-proxy.conf`, `deploy/systemd/dnsnetra-api.service`, `deploy/systemd/dnsnetra-web.service`, `deploy/api.env.example`, `deploy/gen-internal-cert.sh`, `deploy/ufw-dnsnetra.sh`, `deploy/README.md`.

**Modified backend files**

`api/auth.py` (JWT removal, HTTPBearer, forced password change), `api/sessions.py` (HMAC pepper, TTL, `must_change_password`), `api/captcha.py` (secret validation, `secrets`, atomic consume), `api/rbac.py` (permission additions), `api/csrf.py` (origin tightening), `api/main.py` (config validation), `api/routes/auth.py` (required CAPTCHA, TTL, signup gate, cookie helper), `api/routes/users.py` (`/approve`), all read-only route modules (permission dependencies), `tests/test_api_v1.py`, `tests/test_auth_complete.py`, `tests/test_auth_hardening.py`, `tests/test_auth_security_audit.py`, `tests/test_detection_pipeline.py`, `scripts/measure_performance.py`, `scripts/reconciliation_check.py`, `scripts/verify_api_complete.py`, `scripts/verify_http_live.py`, `.env.example`, `start_all.sh`.

**Modified frontend files**

`frontend/lib/auth/api.ts` (change-password call, 428 classification), `frontend/app/(auth)/login/page.tsx` (forced-change redirect, footer), `frontend/components/auth/AuthGuard.tsx` (forced-change redirect), `frontend/app/(auth)/change-password/page.tsx` (new), `frontend/app/(auth)/signup/page.tsx` (deleted), `frontend/next.config.ts` (`/signup` redirect).

---

### Task 1: Test identities, helpers, and cleanup

**Files:**
- Create: `tests/auth_testkit.py`
- Create: `tests/conftest.py`
- Create: `tests/test_auth_fixtures.py`
- Modify: `tests/test_auth_complete.py:66-75` (cleanup prefix list)

**Interfaces:**
- Produces: `TEST_PASSWORD: str`, `CAPTCHA_ANSWER: str`, `db(sql, params)`, `issue_captcha(answer=...)`, `login(client, username, password=TEST_PASSWORD, *, expect=200)`, `bearer_for_user(user_id)`, `bearer_for_username(username)`
- Produces fixtures: `seeded_users` (session-scoped dict of `{"admin": id, "analyst": id, "support": id}`), `admin_user`, `analyst_user`, `support_user`, `admin_headers`, `analyst_headers`, `support_headers`
- Consumes: `api.auth.hash_password`, `api.sessions.create_session`, `api.captcha.compute_challenge_signature`

- [ ] **Step 1: Write the failing fixture test**

Create `tests/test_auth_fixtures.py`:

```python
"""Proves the shared auth fixtures exist, authenticate, and carry distinct roles."""

from fastapi.testclient import TestClient

from api.main import app


def _me(headers: dict[str, str]) -> dict:
    res = TestClient(app).get("/api/v1/auth/me", headers=headers)
    assert res.status_code == 200, res.text
    return res.json()


def test_admin_fixture_authenticates_as_admin(admin_headers):
    body = _me(admin_headers)
    assert body["username"] == "pytest_admin"
    assert body["role"] == "ADMIN"
    assert body["status"] == "ACTIVE"


def test_role_fixtures_are_distinct(admin_headers, analyst_headers, support_headers):
    roles = {_me(admin_headers)["role"], _me(analyst_headers)["role"], _me(support_headers)["role"]}
    assert roles == {"ADMIN", "ANALYST", "SUPPORT"}
```

- [ ] **Step 2: Run it and confirm the fixtures are missing**

```bash
$PY -m pytest tests/test_auth_fixtures.py -v
```

Expected: FAIL/ERROR with `fixture 'admin_headers' not found`.

- [ ] **Step 3: Create the shared test kit**

Create `tests/auth_testkit.py`:

```python
"""Shared helpers for authentication tests.

This module is imported by tests, never by production code.
"""

from __future__ import annotations

import os
import time
import uuid
from typing import Any, Optional

from fastapi.testclient import TestClient

from api.captcha import (
    compute_challenge_signature,
    get_captcha_store,
    normalize_captcha_answer,
)
from api.sessions import create_session
from labeler.intel.reputation.connection import get_connection

TEST_PASSWORD = os.getenv("TEST_AUTH_PASSWORD", "PytestPass123!")
CAPTCHA_ANSWER = "TEST99"


def db(sql: str, params: tuple = ()) -> Any:
    """Run one statement and return rows (or None). Commits on success."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall() if cur.description else None
            conn.commit()
            return rows


def issue_captcha(answer: str = CAPTCHA_ANSWER) -> tuple[str, str]:
    """Register a challenge with a known answer in the active CAPTCHA store."""
    captcha_id = str(uuid.uuid4())
    expiry = time.time() + 300
    signature = compute_challenge_signature(
        captcha_id, normalize_captcha_answer(answer), int(expiry)
    )
    get_captcha_store().issue(captcha_id, signature, expiry)
    return captcha_id, answer


def login(
    client: TestClient,
    username: str,
    password: str = TEST_PASSWORD,
    *,
    expect: Optional[int] = 200,
):
    """POST /api/v1/auth/login with a freshly issued single-use CAPTCHA."""
    captcha_id, answer = issue_captcha()
    res = client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": password,
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    if expect is not None:
        assert res.status_code == expect, res.text
    return res


def bearer_for_user(user_id: int) -> dict[str, str]:
    """Create a real server-side session and return a bearer header."""
    raw_token, _ = create_session(user_id=user_id, user_agent="pytest")
    return {"Authorization": f"Bearer {raw_token}"}


def bearer_for_username(username: str) -> dict[str, str]:
    """Create a session for an existing username (used by integration scripts/tests)."""
    rows = db("SELECT id FROM dashboard_users WHERE lower(username) = lower(%s)", (username,))
    if not rows:
        raise RuntimeError(f"user '{username}' does not exist")
    return bearer_for_user(rows[0][0])
```

- [ ] **Step 4: Create the conftest with seeded users and cleanup**

Create `tests/conftest.py`:

```python
"""Shared fixtures for the DNSNetra test suite.

Test identities are created once per pytest session and deleted afterwards.
No test authenticates as the seeded production `admin` account.
"""

from __future__ import annotations

import pytest

from api.auth import hash_password
from api.rate_limiter import reset_rate_limits
from api.sessions import create_session, revoke_session
from tests.auth_testkit import TEST_PASSWORD, db

SEEDED_ROLES = {"admin": "ADMIN", "analyst": "ANALYST", "support": "SUPPORT"}

# Users created by tests that must never survive a test run. `pytest_%` is
# excluded because the session-scoped fixtures own those rows.
EPHEMERAL_PREFIXES = [
    "test\\_%",
    "case\\_test\\_%",
    "admin2\\_%",
    "pending\\_%",
    "legacy\\_%",
    "user\\_%",
    "revtest\\_%",
    "audit\\_%",
]


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_rate_limits()
    yield
    reset_rate_limits()


@pytest.fixture(autouse=True)
def _cleanup_ephemeral_users():
    """Delete throw-away accounts after every test, including leaked prefixes."""
    yield
    db(
        "DELETE FROM dashboard_users WHERE username LIKE ANY(%s)",
        (EPHEMERAL_PREFIXES,),
    )


@pytest.fixture(scope="session", autouse=True)
def seeded_users() -> dict[str, int]:
    """Create the three role identities once per session and remove them at the end."""
    ids: dict[str, int] = {}
    for key, role in SEEDED_ROLES.items():
        username = f"pytest_{key}"
        db("DELETE FROM dashboard_users WHERE username = %s", (username,))
        rows = db(
            """
            INSERT INTO dashboard_users
                (username, email, password_hash, hashed_password, role, status,
                 is_active, must_change_password, created_at, updated_at)
            VALUES (%s, %s, %s, NULL, %s, 'ACTIVE', true, false, NOW(), NOW())
            RETURNING id
            """,
            (
                username,
                f"{username}@dnsnetra.local",
                hash_password(TEST_PASSWORD),
                role,
            ),
        )
        ids[key] = rows[0][0]
    yield ids
    db("DELETE FROM dashboard_users WHERE id = ANY(%s)", (list(ids.values()),))


@pytest.fixture
def admin_user(seeded_users) -> dict:
    return {"id": seeded_users["admin"], "username": "pytest_admin", "password": TEST_PASSWORD}


@pytest.fixture
def analyst_user(seeded_users) -> dict:
    return {"id": seeded_users["analyst"], "username": "pytest_analyst", "password": TEST_PASSWORD}


@pytest.fixture
def support_user(seeded_users) -> dict:
    return {"id": seeded_users["support"], "username": "pytest_support", "password": TEST_PASSWORD}


def _headers_for(user_id: int):
    raw_token, _ = create_session(user_id=user_id, user_agent="pytest")
    yield {"Authorization": f"Bearer {raw_token}"}
    revoke_session(raw_token)


@pytest.fixture
def admin_headers(seeded_users):
    yield from _headers_for(seeded_users["admin"])


@pytest.fixture
def analyst_headers(seeded_users):
    yield from _headers_for(seeded_users["analyst"])


@pytest.fixture
def support_headers(seeded_users):
    yield from _headers_for(seeded_users["support"])
```

- [ ] **Step 5: Run the fixture test**

```bash
$PY -m pytest tests/test_auth_fixtures.py -v
```

Expected: 2 passed.

- [ ] **Step 6: Fix the leaky cleanup in `test_auth_complete.py`**

Replace lines 66-75 with:

```python
@pytest.fixture(autouse=True)
def clean_rate_limits_and_test_users():
    """Reset rate limits; conftest deletes every known test-user prefix."""
    reset_rate_limits()
    yield
    reset_rate_limits()
```

- [ ] **Step 7: Prove the existing suites still start clean**

```bash
$PY -m pytest tests/test_auth_complete.py tests/test_auth_hardening.py -q
```

Expected: same pass counts as the audit baseline (31 and 23) with no new failures.

- [ ] **Step 8: Commit**

```bash
git add tests/auth_testkit.py tests/conftest.py tests/test_auth_fixtures.py tests/test_auth_complete.py
git commit -m "test: add seeded role fixtures and shared auth test helpers"
```

---

### Task 2: Secrets, configuration, TTLs, and origin tightening

**Files:**
- Create: `api/auth_config.py`
- Create: `tests/test_auth_config.py`
- Modify: `api/sessions.py:9-27`, `api/sessions.py:30-44`
- Modify: `api/captcha.py:27-38`
- Modify: `api/csrf.py:29-37`
- Modify: `api/routes/auth.py:52-57`, `api/routes/auth.py:295-303`, `api/routes/auth.py:314-327`, `api/routes/auth.py:370-378`, `api/routes/auth.py:388-401`, `api/routes/auth.py:460-468`
- Modify: `api/main.py:32`, `api/main.py:58-64`
- Modify: `.env.example:26-31`

**Interfaces:**
- Produces: `is_production() -> bool`, `require_secret(name, *, dev_default, aliases=(), min_length=32) -> str`, `get_session_pepper() -> str`, `get_captcha_secret() -> str`, `get_session_ttl_minutes() -> int`, `get_captcha_ttl_seconds() -> int`, `cookie_secure() -> bool`, `signup_enabled() -> bool`, `validate_auth_config() -> None`, constants `DEV_SESSION_PEPPER`, `DEV_CAPTCHA_SECRET`, `INSECURE_SECRETS`
- Consumes: environment only

- [ ] **Step 1: Write the failing configuration tests**

Create `tests/test_auth_config.py`:

```python
import pytest

from api import auth_config
from api.csrf import get_allowed_origins
from api.sessions import hash_session_token


def _prod(monkeypatch):
    monkeypatch.setattr(auth_config, "is_production", lambda: True)


def test_dev_mode_falls_back_to_dev_pepper(monkeypatch):
    monkeypatch.setattr(auth_config, "is_production", lambda: False)
    monkeypatch.delenv("AUTH_SESSION_SECRET", raising=False)
    assert auth_config.get_session_pepper() == auth_config.DEV_SESSION_PEPPER


def test_production_requires_session_secret(monkeypatch):
    _prod(monkeypatch)
    monkeypatch.delenv("AUTH_SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        auth_config.get_session_pepper()


def test_production_rejects_example_placeholder(monkeypatch):
    _prod(monkeypatch)
    monkeypatch.setenv(
        "AUTH_SESSION_SECRET",
        "change-this-in-production-session-secret-key-min-32-chars",
    )
    with pytest.raises(RuntimeError):
        auth_config.get_session_pepper()


def test_production_accepts_a_strong_secret(monkeypatch):
    _prod(monkeypatch)
    monkeypatch.setenv("AUTH_SESSION_SECRET", "a" * 64)
    assert auth_config.get_session_pepper() == "a" * 64


def test_production_requires_captcha_secret(monkeypatch):
    _prod(monkeypatch)
    monkeypatch.delenv("AUTH_CAPTCHA_SECRET", raising=False)
    monkeypatch.delenv("CAPTCHA_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        auth_config.validate_auth_config()


def test_session_ttl_comes_from_environment(monkeypatch):
    monkeypatch.setenv("AUTH_SESSION_EXPIRE_MINUTES", "5")
    assert auth_config.get_session_ttl_minutes() == 5


def test_invalid_ttl_is_rejected(monkeypatch):
    monkeypatch.setenv("AUTH_SESSION_EXPIRE_MINUTES", "soon")
    with pytest.raises(RuntimeError):
        auth_config.get_session_ttl_minutes()


def test_session_hash_changes_with_the_pepper(monkeypatch):
    monkeypatch.setenv("AUTH_SESSION_SECRET", "a" * 64)
    first = hash_session_token("same-token")
    monkeypatch.setenv("AUTH_SESSION_SECRET", "b" * 64)
    second = hash_session_token("same-token")
    assert first != second
    assert len(first) == 64


def test_configured_origins_are_not_merged_with_localhost(monkeypatch):
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "https://dnsnetra.corp.local")
    assert get_allowed_origins() == {"https://dnsnetra.corp.local"}


def test_signup_is_off_by_default(monkeypatch):
    monkeypatch.delenv("AUTH_ALLOW_SIGNUP", raising=False)
    assert auth_config.signup_enabled() is False
```

- [ ] **Step 2: Run the tests and confirm they fail**

```bash
$PY -m pytest tests/test_auth_config.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'api.auth_config'`.

- [ ] **Step 3: Implement `api/auth_config.py`**

```python
"""Central authentication configuration with production fail-closed validation.

The session secret is an HMAC pepper for session-token hashing, not a JWT key.
"""

from __future__ import annotations

import os

DEV_SESSION_PEPPER = "dnsnetra-dev-session-pepper-not-for-production"
DEV_CAPTCHA_SECRET = "dnsnetra-dev-captcha-secret-not-for-production"

INSECURE_SECRETS = frozenset(
    {
        "",
        "change-this-in-production-session-secret-key-min-32-chars",
        "change-this-in-production-captcha-secret-key-min-32-chars",
        "dnsnetra-secure-default-change-in-prod",
        "dnsnetra-dev-test-jwt-secret-do-not-use-in-production",
        DEV_SESSION_PEPPER,
        DEV_CAPTCHA_SECRET,
        "secret",
        "changeme",
        "default",
    }
)


def is_production() -> bool:
    env = (
        os.getenv("DNSNETRA_ENV")
        or os.getenv("APP_ENV")
        or os.getenv("ENVIRONMENT")
        or "development"
    )
    return env.strip().lower() in ("production", "prod")


def _env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value is not None:
            return value.strip()
    return ""


def require_secret(
    name: str,
    *,
    dev_default: str,
    aliases: tuple[str, ...] = (),
    min_length: int = 32,
) -> str:
    value = _env(name, *aliases)
    if is_production():
        if value in INSECURE_SECRETS or len(value) < min_length:
            raise RuntimeError(
                f"CRITICAL SECURITY CONFIGURATION ERROR: {name} must be set to a "
                f"non-default secret of at least {min_length} characters in production."
            )
        return value
    return value or dev_default


def get_session_pepper() -> str:
    return require_secret(
        "AUTH_SESSION_SECRET",
        dev_default=DEV_SESSION_PEPPER,
        aliases=("AUTH_SECRET_KEY", "JWT_SECRET"),
    )


def get_captcha_secret() -> str:
    return require_secret(
        "AUTH_CAPTCHA_SECRET",
        dev_default=DEV_CAPTCHA_SECRET,
        aliases=("CAPTCHA_SECRET",),
    )


def _positive_int(name: str, default: int) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer, got {raw!r}") from exc
    if value < 1:
        raise RuntimeError(f"{name} must be greater than zero, got {value}")
    return value


def get_session_ttl_minutes() -> int:
    return _positive_int("AUTH_SESSION_EXPIRE_MINUTES", 1440)


def get_session_ttl_seconds() -> int:
    return get_session_ttl_minutes() * 60


def get_captcha_ttl_seconds() -> int:
    return _positive_int("AUTH_CAPTCHA_EXPIRE_SECONDS", 300)


def cookie_secure() -> bool:
    return is_production() or _env("AUTH_COOKIE_SECURE").lower() in ("1", "true", "yes")


def signup_enabled() -> bool:
    return _env("AUTH_ALLOW_SIGNUP").lower() in ("1", "true", "yes")


def validate_auth_config() -> None:
    """Fail at import/startup when production secrets are missing or unsafe."""
    get_session_pepper()
    get_captcha_secret()
    get_session_ttl_minutes()
    get_captcha_ttl_seconds()
```

- [ ] **Step 4: Run the configuration tests**

```bash
$PY -m pytest tests/test_auth_config.py -v
```

Expected: 10 passed.

- [ ] **Step 5: Use the pepper and TTL in `api/sessions.py`**

Replace the imports and `hash_session_token` / `create_session` header:

```python
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone

from .auth_config import get_session_pepper, get_session_ttl_minutes

logger = logging.getLogger("api_sessions")


def hash_session_token(token: str) -> str:
    """HMAC-SHA256 of the token keyed by the server pepper."""
    return hmac.new(
        get_session_pepper().encode("utf-8"),
        token.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def create_session(
    user_id: int,
    ip_address: str | None = None,
    user_agent: str | None = None,
    expire_minutes: int | None = None,
) -> tuple[str, datetime]:
    raw_token = secrets.token_urlsafe(36)
    token_hash = hash_session_token(raw_token)

    mins = expire_minutes if expire_minutes is not None else get_session_ttl_minutes()
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=mins)
    # ... keep the existing IP validation and INSERT unchanged ...
```

- [ ] **Step 6: Validate the CAPTCHA secret and TTL in `api/captcha.py`**

Replace lines 27-38 with:

```python
from . import auth_config

CAPTCHA_LENGTH = 6


def get_captcha_secret() -> bytes:
    """Retrieve the CAPTCHA signing secret; raises in production when unset."""
    return auth_config.get_captcha_secret().encode("utf-8")
```

`CAPTCHA_EXPIRY_SECONDS_DEFAULT` stays for callers; the HTTP endpoint switches to `auth_config.get_captcha_ttl_seconds()` in Task 4.

- [ ] **Step 7: Stop merging localhost into an explicitly configured origin list**

Replace `get_allowed_origins` in `api/csrf.py` with:

```python
def get_allowed_origins() -> Set[str]:
    """Return the configured origins; localhost defaults only when nothing is configured."""
    raw = os.getenv("CORS_ALLOWED_ORIGINS") or os.getenv("ALLOWED_ORIGINS") or ""
    if raw.strip():
        return {o.strip() for o in raw.split(",") if o.strip()}
    return set(DEFAULT_ALLOWED_ORIGINS)
```

- [ ] **Step 8: Use config for cookies and TTL in `api/routes/auth.py`**

Replace `_is_cookie_secure` with:

```python
def _is_cookie_secure() -> bool:
    return cookie_secure()
```

Add to the imports:

```python
from ..auth_config import (
    cookie_secure,
    get_captcha_ttl_seconds,
    get_session_ttl_seconds,
    signup_enabled,
)
```

In both `login` and `login_for_access_token`, replace the hard-coded cookie and response values:

```python
    ttl_seconds = get_session_ttl_seconds()
    raw_session_token, expires_at = create_session(
        user_id=user["id"],
        ip_address=client_ip,
        user_agent=user_agent,
        expire_minutes=ttl_seconds // 60,
    )
    response.set_cookie(
        key=CANONICAL_COOKIE_NAME,
        value=raw_session_token,
        httponly=True,
        secure=_is_cookie_secure(),
        samesite="lax",
        max_age=ttl_seconds,
        path="/",
    )
```

and in the returned `TokenResponse`:

```python
        expires_in=ttl_seconds,
```

Apply the same `ttl_seconds` change to the cookie in `user_change_password`.

In `get_captcha`, replace `create_captcha(expires_in=300)` with:

```python
    challenge = create_captcha(expires_in=get_captcha_ttl_seconds())
```

- [ ] **Step 9: Validate at startup in `api/main.py`**

Replace the `get_jwt_secret_key` import with:

```python
from api.auth_config import validate_auth_config
```

Add immediately after the imports (before `app = FastAPI(...)`):

```python
validate_auth_config()
```

and replace the lifespan body call:

```python
    validate_auth_config()
```

- [ ] **Step 10: Update `.env.example`**

Replace the `# Authentication & Sessions` block with:

```dotenv
# Authentication & Sessions
# Generate secrets with: openssl rand -hex 32
DNSNETRA_ENV=development
AUTH_SESSION_SECRET=
AUTH_CAPTCHA_SECRET=
AUTH_SESSION_EXPIRE_MINUTES=480
AUTH_CAPTCHA_EXPIRE_SECONDS=300
AUTH_COOKIE_SECURE=false
AUTH_ALLOW_SIGNUP=false
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
TRUSTED_PROXIES=
```

- [ ] **Step 11: Add local development secrets without touching `.env.example`**

`.env` currently has CRLF line endings. Normalise and append only if the keys are absent:

```bash
$PY - <<'PY'
import os
from pathlib import Path

path = Path(".env")
text = path.read_text().replace("\r\n", "\n")
if "AUTH_SESSION_SECRET=" not in text:
    text += (
        "\n# Authentication & Sessions (local development)\n"
        "DNSNETRA_ENV=development\n"
        f"AUTH_SESSION_SECRET={os.urandom(32).hex()}\n"
        f"AUTH_CAPTCHA_SECRET={os.urandom(32).hex()}\n"
        "AUTH_SESSION_EXPIRE_MINUTES=480\n"
        "AUTH_CAPTCHA_EXPIRE_SECONDS=300\n"
        "AUTH_COOKIE_SECURE=false\n"
        "AUTH_ALLOW_SIGNUP=false\n"
        "CORS_ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000\n"
        "TRUSTED_PROXIES=127.0.0.1,::1\n"
    )
path.write_text(text)
PY
```

Run this verification:

```bash
$PY - <<'PY'
from api.auth_config import get_session_pepper, get_captcha_secret
print("pepper length:", len(get_session_pepper()))
print("captcha length:", len(get_captcha_secret()))
PY
```

Expected: both lengths are 64.

- [ ] **Step 12: Run the affected suites**

```bash
$PY -m pytest tests/test_auth_config.py tests/test_auth_fixtures.py tests/test_auth_complete.py -q
```

Expected: all pass. `test_auth_security_audit.py` still has two AUTH-09 xfails until Step 13.

- [ ] **Step 13: Remove the AUTH-09 xfail markers and update the tests**

In `tests/test_auth_security_audit.py`:

Replace `test_captcha_secret_must_not_use_dev_default_in_production` with:

```python
def test_captcha_secret_must_not_use_dev_default_in_production(monkeypatch):
    monkeypatch.setenv("DNSNETRA_ENV", "production")
    monkeypatch.delenv("AUTH_CAPTCHA_SECRET", raising=False)
    monkeypatch.delenv("CAPTCHA_SECRET", raising=False)
    from api.captcha import get_captcha_secret
    import pytest
    with pytest.raises(RuntimeError):
        get_captcha_secret()
```

Replace `test_env_example_placeholder_is_rejected_in_production` with:

```python
def test_env_example_placeholder_is_rejected_in_production(monkeypatch):
    from api import auth_config
    monkeypatch.setattr(auth_config, "is_production", lambda: True)
    monkeypatch.setenv(
        "AUTH_SESSION_SECRET",
        "change-this-in-production-session-secret-key-min-32-chars",
    )
    with pytest.raises(RuntimeError):
        auth_config.get_session_pepper()
```

Replace `test_expires_in_matches_configured_session_ttl` with:

```python
def test_expires_in_matches_configured_session_ttl(mk_user, monkeypatch):
    username, _ = mk_user("ttl")
    monkeypatch.setenv("AUTH_SESSION_EXPIRE_MINUTES", "5")
    res = _client().post("/api/v1/auth/login", json=_login_body(username))
    assert res.status_code == 200
    assert res.json()["expires_in"] <= 300
    assert "Max-Age=86400" not in res.headers.get("set-cookie", "")
```

Remove the three `@pytest.mark.xfail(reason="AUTH-09...")` decorators.

- [ ] **Step 14: Re-run the audit suite**

```bash
$PY -m pytest tests/test_auth_security_audit.py -rxX -q
```

Expected: the three AUTH-09 tests pass; all other xfails unchanged.

- [ ] **Step 15: Commit**

```bash
git add api/auth_config.py api/sessions.py api/captcha.py api/csrf.py api/routes/auth.py api/main.py .env.example tests/test_auth_config.py tests/test_auth_security_audit.py
git commit -m "feat(auth): fail closed on secrets and centralize session TTLs"
```

---

### Task 3: Delete the JWT fallback

**Files:**
- Modify: `api/auth.py:15-29`, `api/auth.py:42-109`, `api/auth.py:374-383`, `api/auth.py:386-462`
- Modify: `api/main.py:32` (already changed in Task 2)
- Create: `scripts/_session_auth.py`
- Create: `scripts/__init__.py`
- Modify: `scripts/measure_performance.py:26-30`, `scripts/reconciliation_check.py:34-44`, `scripts/verify_api_complete.py:35-91`, `scripts/verify_http_live.py:35-51`
- Modify: `tests/test_api_v1.py:22-49`, `tests/test_api_v1.py:101-175`, `tests/test_api_v1.py:635-717`
- Modify: `tests/test_auth_security_audit.py:129-175`
- Modify: `tests/test_auth_hardening.py:38-41`
- Modify: `tests/test_detection_pipeline.py:650-655`, `tests/test_detection_pipeline.py:860-865`, `tests/test_detection_pipeline.py:915-920`, `tests/test_detection_pipeline.py:970-995`

**Interfaces:**
- Produces: `get_current_user` accepts bearer tokens that resolve to a row in `sessions` only; `scripts._session_auth.bearer_for_username(username="admin") -> str`
- Removes: `get_jwt_secret_key`, `DEV_INSECURE_TEST_SECRET`, `INSECURE_SECRETS`, `SECRET_KEY`, `ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES`, `create_access_token`, `oauth2_scheme`

- [ ] **Step 1: Rewrite the AUTH-01 / AUTH-05 reproducers to expect rejection**

In `tests/test_auth_security_audit.py`, replace the block from `# AUTH-01` through the end of AUTH-05 tests with:

```python
LEGACY_PUBLISHED_SECRET = "dnsnetra-dev-test-jwt-secret-do-not-use-in-production"


def _legacy_token(claims: dict) -> str:
    return pyjwt.encode(claims, LEGACY_PUBLISHED_SECRET, algorithm="HS256")


def test_legacy_jwt_signed_with_published_secret_is_rejected():
    forged = _legacy_token(
        {
            "sub": "admin",
            "role": "ADMIN",
            "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        }
    )
    res = _client().get("/api/v1/users?limit=1", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401


def test_token_without_expiry_is_rejected():
    forged = _legacy_token({"sub": "admin", "role": "ADMIN"})
    res = _client().get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401


def test_jwt_role_claim_cannot_escalate_privileges(mk_user):
    username, _ = mk_user("escalate", role="ANALYST")
    forged = _legacy_token({"sub": username, "role": "ADMIN"})
    res = _client().get("/api/v1/users?limit=1", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401


def test_jwt_is_revoked_when_sessions_are_revoked(mk_user):
    username, uid = mk_user("revoke", role="ANALYST")
    forged = _legacy_token({"sub": username, "role": "ANALYST"})
    sessions_mod.revoke_all_user_sessions(uid)
    res = _client().get("/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"})
    assert res.status_code == 401
```

- [ ] **Step 2: Run them and confirm they fail**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k "jwt or expiry or role_claim" -q
```

Expected: FAIL — forged tokens are still accepted.

- [ ] **Step 3: Remove the JWT code from `api/auth.py`**

Delete the `jwt` import, `timedelta` from the datetime import, and `from fastapi.security import OAuth2PasswordBearer`. Add the HTTP bearer scheme import at the top:

```python
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
```

Replace the block from `DEV_INSECURE_TEST_SECRET = ...` through `oauth2_scheme = ...` with:

```python
bearer_scheme = HTTPBearer(auto_error=False)
```

Delete `create_access_token` entirely.

Replace `get_current_user` with:

```python
async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    canonical_cookie: Optional[str] = Cookie(None, alias="dnsnetra_session"),
    legacy_cookie: Optional[str] = Cookie(None, alias="session_token"),
) -> dict[str, Any]:
    """
    Resolve the caller from a server-side session only.
    A bearer token and a session cookie carry the same opaque token.
    """
    token = credentials.credentials if credentials else None
    auth_method = "bearer"

    if not token:
        token = canonical_cookie or legacy_cookie
        if token:
            auth_method = "cookie"

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.auth_method = auth_method

    if auth_method == "cookie":
        verify_csrf_protection(request)

    session_user = get_session_and_user(token)
    if not session_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked authentication session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.session_token = token
    request.state.current_user = session_user
    return session_user
```

Leave `require_authenticated_user` and `require_admin` unchanged.

- [ ] **Step 4: Add the script session helper**

Create `scripts/__init__.py` (empty) and `scripts/_session_auth.py`:

```python
"""Create a real server-side session for local verification scripts.

Scripts run on the server and cannot solve an image CAPTCHA, so they use the
same trusted database access the application already has.
"""

from __future__ import annotations

from api.auth import get_user_by_username
from api.sessions import create_session


def bearer_for_username(username: str = "admin") -> str:
    user = get_user_by_username(username)
    if not user:
        raise SystemExit(f"user '{username}' does not exist")
    raw_token, _ = create_session(user_id=user["id"], user_agent="verification-script")
    return raw_token
```

- [ ] **Step 5: Update the scripts**

`scripts/measure_performance.py` — replace `from api.auth import create_access_token` with:

```python
from scripts._session_auth import bearer_for_username
```

and replace `token = create_access_token(...)` with:

```python
token = bearer_for_username("admin")
```

`scripts/reconciliation_check.py` — same two replacements.

`scripts/verify_api_complete.py`:

- Replace `from api.auth import create_access_token` with `from scripts._session_auth import bearer_for_username`.
- Replace the `/auth/token` login block at lines 72-91 with:

```python
admin_token = bearer_for_username("admin")
analyst_token = bearer_for_username("pytest_analyst") if _user_exists("pytest_analyst") else admin_token
```

Add this helper near the top:

```python
def _user_exists(username: str) -> bool:
    from api.auth import get_user_by_username
    return get_user_by_username(username) is not None
```

- Remove `/api/v1/auth/token` and `/api/v1/auth/login` from the happy-path route matrix. Add a negative check instead:

```python
def check_login_requires_captcha(client):
    res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "not-a-real-password"})
    return res.status_code in (400, 422), res.status_code
```

- Replace every `auth=False` login entry with no entry; the matrix must not expect a 200 from login.

`scripts/verify_http_live.py`:

- Replace the `/auth/token` and `/auth/login` checks with:

```python
token = bearer_for_username("admin")
headers = {"Authorization": f"Bearer {token}"}
res = client.get("/api/v1/auth/me", headers=headers)
check("GET /api/v1/auth/me (session)", res.status_code, res.status_code == 200 and res.json().get("username") == "admin", "")
```

- Add `from scripts._session_auth import bearer_for_username`.

- [ ] **Step 6: Rework `tests/test_api_v1.py` fixtures**

Replace lines 22-49 with:

```python
from tests.auth_testkit import TEST_PASSWORD, issue_captcha, login
```

Delete the local `auth_headers` and `non_admin_headers` fixtures; the conftest now supplies `admin_headers` and `analyst_headers`.

Rename every `non_admin_headers` parameter/usage to `analyst_headers`.

Replace `test_auth_token_success` with:

```python
def test_auth_token_success():
    """OAuth2 form login succeeds with valid credentials and a CAPTCHA."""
    captcha_id, answer = issue_captcha()
    res = client.post(
        "/api/v1/auth/token",
        data={
            "username": "pytest_admin",
            "password": TEST_PASSWORD,
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    assert res.status_code == 200
    assert res.json()["token_type"] == "bearer"
    assert res.json()["expires_in"] > 0
```

Replace `test_auth_token_invalid_password` with:

```python
def test_auth_token_invalid_password():
    captcha_id, answer = issue_captcha()
    res = client.post(
        "/api/v1/auth/token",
        data={
            "username": "pytest_admin",
            "password": "wrongpassword",
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    assert res.status_code == 401
    assert "Incorrect username or password" in res.json()["detail"]
```

Replace `test_auth_login_json_success` and `test_auth_me_success` with:

```python
def test_auth_login_json_success():
    res = login(client, "pytest_admin")
    assert res.status_code == 200
    assert res.json()["user"]["username"] == "pytest_admin"
    client.cookies.clear()


def test_auth_login_json_missing_credentials():
    client.cookies.clear()
    captcha_id, answer = issue_captcha()
    res = client.post(
        "/api/v1/auth/login",
        json={
            "password": TEST_PASSWORD,
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    assert res.status_code == 400
```

`test_auth_me_success` stays header-based and must assert:

```python
    assert data["email"] == "pytest_admin@dnsnetra.local"
    assert data["role"] == "ADMIN"
    assert data["is_active"] is True
```

In `test_daily_review_endpoints_and_mutations`, delete the `monkeypatch.setattr("api.auth.get_user_by_email", ...)` block. Change the analyst verdict expectation from 403 to 200:

```python
    res_analyst = client.post(
        "/api/v1/daily-review/test-safe-domain.example.com/verdict",
        json={"verdict": "clean", "reason": "Analyst review"},
        headers=analyst_headers,
    )
    assert res_analyst.status_code == 200
```

Change the analyst trigger expectation from 403 to 200 as well (the matrix grants `domains:investigate`).

- [ ] **Step 7: Update `tests/test_auth_hardening.py`**

Delete `create_access_token` from the `api.auth` import list. No test uses it.

- [ ] **Step 8: Update `tests/test_detection_pipeline.py`**

Replace the three `/api/v1/auth/token` login blocks with:

```python
from tests.auth_testkit import bearer_for_username
headers = bearer_for_username("admin")
```

and use `headers` where the old `token`/`auth_headers` variable was used. Keep the surrounding assertions; only the credential acquisition changes.

Replace the JWT secret test block (lines 970-995) with:

```python
def test_auth_config_is_fail_closed_in_production(monkeypatch):
    from api import auth_config
    monkeypatch.setattr(auth_config, "is_production", lambda: True)
    monkeypatch.delenv("AUTH_SESSION_SECRET", raising=False)
    with pytest.raises(RuntimeError):
        auth_config.get_session_pepper()
```

- [ ] **Step 9: Run the suites**

```bash
$PY -m pytest tests/test_auth_security_audit.py tests/test_api_v1.py tests/test_auth_hardening.py -q
```

Expected: `test_api_v1.py` 37 passed (or the same count modulo removed login expectations), `test_auth_hardening.py` 23 passed, audit: the four JWT tests now pass.

- [ ] **Step 10: Prove no JWT minting remains**

```bash
grep -rn "create_access_token\|get_jwt_secret_key\|OAuth2PasswordBearer" api scripts tests --include="*.py"
```

Expected: no output. (`pyjwt` may remain as a test import only; that is fine.)

- [ ] **Step 11: Commit**

```bash
git add api/auth.py api/main.py scripts tests/test_api_v1.py tests/test_auth_security_audit.py tests/test_auth_hardening.py tests/test_detection_pipeline.py
git commit -m "feat(auth): remove JWT fallback and use server-side sessions only"
```

---

### Task 4: Require CAPTCHA on both login endpoints and make consumption atomic

**Files:**
- Modify: `api/routes/auth.py:84-90`, `api/routes/auth.py:237-401`
- Modify: `api/captcha.py:118-137`, `api/captcha.py:250-277`, `api/captcha.py:303-332`
- Modify: `tests/test_auth_security_audit.py:177-193`, `tests/test_auth_security_audit.py:298-324`
- Modify: `tests/test_auth_hardening.py` (all direct login calls)
- Modify: `tests/test_auth_complete.py:79-98`

**Interfaces:**
- Consumes: `auth_config.get_captcha_ttl_seconds`, `auth_config.get_captcha_secret`
- Produces: `LoginRequest.captcha_id` / `.captcha_answer` are required; `/auth/token` takes `captcha_id` and `captcha_answer` form fields

- [ ] **Step 1: Make the reproducers expect 400/422**

Replace `test_login_requires_a_captcha` with:

```python
def test_login_requires_a_captcha(mk_user):
    username, _ = mk_user("nocaptcha")
    res = _client().post(
        "/api/v1/auth/login",
        json={"username": username, "password": PASSWORD},
    )
    assert res.status_code in (400, 422)
```

Replace `test_oauth2_form_login_requires_a_captcha` with:

```python
def test_oauth2_form_login_requires_a_captcha(mk_user):
    username, _ = mk_user("tokennocaptcha")
    res = _client().post("/api/v1/auth/token", data={"username": username, "password": PASSWORD})
    assert res.status_code in (400, 422)
```

Replace the `_login_body` helper at `tests/test_auth_security_audit.py:121-122` with:

```python
def _login_body(username: str, password: str = PASSWORD) -> dict:
    captcha_id, answer = issue_captcha()
    return {
        "username": username,
        "password": password,
        "captcha_id": captcha_id,
        "captcha_answer": answer,
    }
```

Remove both AUTH-03 `xfail` decorators. Remove the AUTH-10 `xfail` decorator from `test_captcha_rejects_when_consume_fails`.

- [ ] **Step 2: Run them and confirm they fail**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k "captcha" -q
```

Expected: FAIL — missing CAPTCHA still logs in; `consume()` failure still verifies.

- [ ] **Step 3: Require CAPTCHA in the request model and verify it first**

In `api/routes/auth.py`, replace the `LoginRequest` CAPTCHA fields with:

```python
    captcha_id: str = Field(..., min_length=10, max_length=64)
    captcha_answer: str = Field(..., min_length=1, max_length=20)
```

In `login`, replace the conditional CAPTCHA block with an unconditional one placed before `authenticate_user`:

```python
    captcha_valid, captcha_err = verify_and_consume_captcha(
        captcha_id=payload.captcha_id,
        user_answer=payload.captcha_answer,
    )
    if not captcha_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"CAPTCHA verification failed: {captcha_err}",
        )
```

In `login_for_access_token`, add form fields and the same check:

```python
from fastapi import Form

def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    captcha_id: str = Form(..., min_length=10, max_length=64),
    captcha_answer: str = Form(..., min_length=1, max_length=20),
) -> TokenResponse:
    captcha_valid, captcha_err = verify_and_consume_captcha(
        captcha_id=captcha_id,
        user_answer=captcha_answer,
    )
    if not captcha_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"CAPTCHA verification failed: {captcha_err}",
        )
```

- [ ] **Step 4: Use `secrets` and make consumption atomic**

In `api/captcha.py`, import `secrets` and replace the answer generation:

```python
answer = "".join(secrets.choice(CAPTCHA_CHARACTERS) for _ in range(CAPTCHA_LENGTH))
```

Replace `InMemoryCaptchaStore.consume` with:

```python
    def consume(self, challenge_id: str, expiry: float) -> bool:
        with self._lock:
            if challenge_id in self._consumed or challenge_id not in self._issued:
                return False
            self._issued.pop(challenge_id, None)
            self._consumed[challenge_id] = expiry
            return True
```

Replace the tail of `verify_and_consume_captcha` with:

```python
    if not hmac.compare_digest(expected_sig, computed_sig):
        store.consume(captcha_id, expiry)
        return False, "Incorrect CAPTCHA answer"

    if not store.consume(captcha_id, expiry):
        return False, "CAPTCHA challenge has already been used"

    return True, "OK"
```

- [ ] **Step 5: Update the test helper in `test_auth_complete.py`**

Replace `get_captcha_with_known_answer` with:

```python
def get_captcha_with_known_answer() -> tuple[str, str]:
    """Issue a challenge with a known answer in the active store."""
    from tests.auth_testkit import issue_captcha
    return issue_captcha()
```

- [ ] **Step 6: Add CAPTCHA to every login in `test_auth_hardening.py`**

Add near the top:

```python
from tests.auth_testkit import TEST_PASSWORD, issue_captcha


def _login(username: str, password: str = TEST_PASSWORD):
    captcha_id, answer = issue_captcha()
    return client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": password,
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
```

Replace each direct login:

| Test | Old call | New call |
|---|---|---|
| `test_login_returns_httponly_samesite_cookie` | `{"username": "admin", "password": "admin"}` | `_login("pytest_admin")` |
| `test_admin_cannot_demote_final_admin` | admin/admin | `_login("pytest_admin")` |
| `test_admin_cannot_disable_final_admin` | admin/admin | `_login("pytest_admin")` |
| `test_two_admins_can_manage_each_other_safely` | admin/admin | `_login("pytest_admin")` |
| `test_pending_user_has_no_effective_permissions` | direct login | `_login(base_user, "Password123!")` and assert 401 |
| `test_password_reset_and_must_change_password_flow` | admin/admin + analyst logins | `_login("pytest_admin")`, `_login(analyst_name, "InitialPass123!")`, `_login(analyst_name, "TempPassword999!")` |
| `test_re_enabling_account_does_not_resurrect_sessions` | admin/admin + user logins | `_login("pytest_admin")`, `_login(uname, "Password123!")` |

For 401 expectations, do not assert inside `_login`; add a separate `expect` parameter:

```python
def _login(username: str, password: str = TEST_PASSWORD, *, expect: int | None = 200):
    captcha_id, answer = issue_captcha()
    res = client.post(...)
    if expect is not None:
        assert res.status_code == expect, res.text
    return res
```

- [ ] **Step 7: Replace the remaining `admin/admin` logins in `test_auth_complete.py`**

Add `from tests.auth_testkit import TEST_PASSWORD, login` to the imports.

In `test_login_valid_with_admin`, replace the request body with:

```python
    cid, ans = get_captcha_with_known_answer()
    res = client.post(
        "/api/v1/auth/login",
        json={
            "username": "pytest_admin",
            "password": TEST_PASSWORD,
            "captcha_id": cid,
            "captcha_answer": ans,
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert "session_token" in data
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["username"] == "pytest_admin"
    assert data["user"]["role"] == "ADMIN"
    assert data["user"]["status"] == "ACTIVE"
```

In `test_login_invalid_password_and_username`, change the existing-user attempt to `pytest_admin` with `"WrongPassword999!"`; keep the missing-user attempt unchanged.

In `test_session_lifecycle_and_logout`, replace the login with:

```python
    login_res = login(client, "pytest_admin")
    assert login_res.status_code == 200
    token = login_res.json()["session_token"]
```

and change the two `"admin"` username assertions to `"pytest_admin"`.

Run:

```bash
grep -rn '"password": "admin"\|"username": "admin"' tests/test_auth_complete.py tests/test_auth_hardening.py tests/test_api_v1.py
```

Expected: no output. If anything remains, replace it before continuing.

- [ ] **Step 8: Update the rate-limit test**

In `test_login_rate_limiting`, issue a fresh CAPTCHA for each of the 20 attempts:

```python
    responses = []
    for _ in range(20):
        responses.append(_login("rate_limited_user", "WrongPassword123!", expect=None))
    statuses = [r.status_code for r in responses]
    assert 200 not in statuses
    assert 429 in statuses
```

- [ ] **Step 9: Run the auth suites**

```bash
$PY -m pytest tests/test_auth_complete.py tests/test_auth_hardening.py tests/test_auth_security_audit.py -rxX -q
```

Expected: AUTH-03 and AUTH-10 xfails are gone and pass. Any remaining login test without a CAPTCHA must be fixed before committing.

- [ ] **Step 10: Commit**

```bash
git add api/routes/auth.py api/captcha.py tests/test_auth_complete.py tests/test_auth_hardening.py tests/test_auth_security_audit.py
git commit -m "feat(auth): require and atomically consume CAPTCHA on login"
```

---

### Task 5: Enforce `must_change_password` (backend and frontend)

**Files:**
- Modify: `api/sessions.py:82-150`
- Modify: `api/auth.py` (`get_current_user`)
- Create: `frontend/app/(auth)/change-password/page.tsx`
- Modify: `frontend/lib/auth/api.ts:19-105`, `frontend/app/(auth)/login/page.tsx`, `frontend/components/auth/AuthGuard.tsx`
- Modify: `tests/test_auth_security_audit.py:195-208`

**Interfaces:**
- Consumes: `session_user["must_change_password"]`
- Produces: HTTP `428` with `{"detail": "Password change required"}` for every route except `/api/v1/auth/me`, `/api/v1/auth/logout`, `/api/v1/auth/change-password`

- [ ] **Step 1: Write the failing backend test**

Replace the AUTH-04 test in `tests/test_auth_security_audit.py` with:

```python
def test_must_change_password_blocks_privileged_access(mk_user):
    username, _ = mk_user("mustchange", role="ADMIN", must_change=True)
    client = _client()
    captcha_id, answer = issue_captcha()
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "username": username,
            "password": PASSWORD,
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    assert login_res.status_code == 200
    token = login_res.json()["session_token"]
    res = client.get("/api/v1/users?limit=1", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == 428
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["must_change_password"] is True
```

Add `from tests.auth_testkit import issue_captcha` to the imports and remove the AUTH-04 `xfail` decorator.

- [ ] **Step 2: Run it and confirm it fails**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k must_change -q
```

Expected: FAIL — `/api/v1/users` returns 200.

- [ ] **Step 3: Return the flag from session lookup**

In `api/sessions.py`, add `u.must_change_password` to the SELECT list after `u.last_login_at`, unpack it, and include it in the returned dict:

```python
                u.last_login_at,
                u.must_change_password
```

```python
                last_login_at,
                must_change_password,
            ) = row
```

```python
                "last_login_at": last_login_at,
                "must_change_password": bool(must_change_password),
            }
```

- [ ] **Step 4: Enforce the flag in `get_current_user`**

Add above `get_current_user`:

```python
PASSWORD_CHANGE_ALLOWLIST = {
    "/api/v1/auth/me",
    "/api/v1/auth/logout",
    "/api/v1/auth/change-password",
}


def _requires_password_change(user: dict[str, Any], path: str) -> bool:
    return bool(user.get("must_change_password")) and path.rstrip("/") not in PASSWORD_CHANGE_ALLOWLIST
```

After the session lookup and before returning:

```python
    if _requires_password_change(session_user, request.url.path):
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="Password change required",
            headers={"X-Password-Change-Required": "true"},
        )
```

Also make administrator-created accounts rotate their first password. In `api/routes/users.py::create_user`, change the INSERT value `false` for `must_change_password` to `true`, and change the returned `must_change_password=False` to `True`:

```python
                ) VALUES (%s, %s, %s, NULL, %s, %s, %s, true, NOW(), NOW())
```

```python
        must_change_password=True,
```

This makes the temporary password an administrator hands over single-use in practice: the first login can only reach `/me`, `/logout`, and `/change-password`.

- [ ] **Step 5: Run the backend test**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k must_change -q
```

Expected: PASS.

- [ ] **Step 6: Add the frontend API support**

In `frontend/lib/auth/api.ts`:

Add `"password_change_required"` to `AuthErrorKind`.

In `classify`, before the 401/403 branch:

```ts
  if (status === 428)
    return new AuthApiError("password_change_required", "You must change your password before continuing.")
```

Add to `authApi`:

```ts
  changePassword: (b: {
    current_password: string
    new_password: string
    confirm_password: string
  }) => post<{ message: string; session_token: string }>("/change-password", b),
```

- [ ] **Step 7: Redirect to the change-password screen**

In `frontend/app/(auth)/login/page.tsx`, replace the post-login redirect:

```tsx
      const result = await authApi.login({
        username: username.trim(),
        password,
        captcha_id: captcha.challenge.captcha_id,
        captcha_answer: captcha.answer.trim(),
      })
      router.replace(result.user.must_change_password ? "/change-password" : "/dashboard")
```

In `frontend/components/auth/AuthGuard.tsx`, replace the `me()` handler:

```tsx
      .then((u) => {
        if (!u) return router.replace("/login")
        if (u.must_change_password) return router.replace("/change-password")
        setUser(u)
      })
```

- [ ] **Step 8: Create the change-password page**

Create `frontend/app/(auth)/change-password/page.tsx`:

```tsx
"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { AuthApiError, authApi, validatePassword, type AuthUser } from "@/lib/auth/api"
import { AuthLayout } from "@/components/auth/AuthLayout"
import { AuthForm } from "@/components/auth/AuthForm"
import { PasswordField } from "@/components/auth/PasswordField"
import { AuthButton } from "@/components/auth/AuthButton"
import { AuthError } from "@/components/auth/AuthError"

export default function ChangePasswordPage() {
  const router = useRouter()
  const [user, setUser] = React.useState<AuthUser | null>(null)
  const [current, setCurrent] = React.useState("")
  const [next, setNext] = React.useState("")
  const [confirm, setConfirm] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [pending, setPending] = React.useState(false)

  React.useEffect(() => {
    authApi.me().then((u) => (u ? setUser(u) : router.replace("/login"))).catch(() => router.replace("/login"))
  }, [router])

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    if (!user) return
    const policy = validatePassword(next, user.username)
    if (policy) return setError(policy)
    if (next !== confirm) return setError("The new passwords do not match.")
    if (current === next) return setError("Choose a password different from your current one.")

    setPending(true)
    setError(null)
    try {
      await authApi.changePassword({
        current_password: current,
        new_password: next,
        confirm_password: confirm,
      })
      router.replace("/dashboard")
    } catch (err) {
      const e2 = err instanceof AuthApiError ? err : null
      setError(e2?.message ?? "Could not update your password. Please try again.")
      setPending(false)
    }
  }

  return (
    <AuthLayout>
      <AuthForm
        title="Set a new password"
        subtitle="Your administrator issued a temporary password. Replace it to continue."
        onSubmit={onSubmit}
      >
        <PasswordField
          id="current-password"
          label="Current password"
          value={current}
          onChange={setCurrent}
          autoComplete="current-password"
          disabled={pending}
        />
        <PasswordField
          id="new-password"
          label="New password"
          value={next}
          onChange={setNext}
          autoComplete="new-password"
          disabled={pending}
        />
        <PasswordField
          id="confirm-password"
          label="Confirm new password"
          value={confirm}
          onChange={setConfirm}
          autoComplete="new-password"
          disabled={pending}
        />
        <AuthError message={error} />
        <AuthButton pending={pending} idle="Update password" busy="Updating..." />
      </AuthForm>
    </AuthLayout>
  )
}
```

- [ ] **Step 9: Verify the frontend builds**

```bash
cd frontend
pnpm lint
pnpm test
pnpm build
```

Expected: lint, tests and production build pass.

- [ ] **Step 10: Run the backend suites**

```bash
$PY -m pytest tests/test_auth_security_audit.py tests/test_auth_hardening.py -rxX -q
```

Expected: AUTH-04 test passes. `test_password_reset_and_must_change_password_flow` still passes because `/me` and `/change-password` are allowlisted.

- [ ] **Step 11: Commit**

```bash
git add api/sessions.py api/auth.py frontend/app/\(auth\)/change-password/page.tsx frontend/app/\(auth\)/login/page.tsx frontend/components/auth/AuthGuard.tsx frontend/lib/auth/api.ts tests/test_auth_security_audit.py
git commit -m "feat(auth): force password rotation before privileged access"
```

---

### Task 6: Fix the `/users/{id}/approve` lifecycle

**Files:**
- Modify: `api/routes/users.py:448-496`
- Modify: `tests/test_auth_security_audit.py:210-227`
- Test: `tests/test_auth_complete.py:526-556` (existing happy path)

**Interfaces:**
- Consumes: `get_user_by_id`, `ApproveUserRequest.role`, `UserRole`
- Produces: approval only for `PENDING` targets and only `ANALYST` / `SUPPORT`

- [ ] **Step 1: Remove the AUTH-07 xfail markers**

Delete both `@pytest.mark.xfail(reason="AUTH-07...")` decorators. Keep the test bodies as they are.

- [ ] **Step 2: Run them and confirm they fail**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k approve -q
```

Expected: FAIL — disabled users are reactivated and ADMIN is granted.

- [ ] **Step 3: Enforce the lifecycle and allowed roles**

Replace `approve_user` with:

```python
def approve_user(
    user_id: int,
    payload: ApproveUserRequest,
    request: Request,
    admin: dict[str, Any] = Depends(require_admin),
) -> GenericMessageResponse:
    client_ip, user_agent = _extract_client_meta(request)

    if payload.role not in (UserRole.ANALYST, UserRole.SUPPORT):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Approval may only assign the ANALYST or SUPPORT role",
        )

    target_user = get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )
    if target_user["status"] != "PENDING":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only PENDING accounts can be approved",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT status FROM dashboard_users WHERE id = %s FOR UPDATE;",
                (user_id,),
            )
            row = cur.fetchone()
            if not row or row[0] != "PENDING":
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Account is no longer pending approval",
                )
            cur.execute(
                """
                UPDATE dashboard_users
                SET status = 'ACTIVE',
                    is_active = true,
                    role = %s,
                    updated_at = NOW()
                WHERE id = %s AND status = 'PENDING';
                """,
                (payload.role.value, user_id),
            )
            if cur.rowcount != 1:
                conn.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Account is no longer pending approval",
                )
            conn.commit()

    log_audit_event(
        action=AuditAction.ACCOUNT_APPROVED,
        user_id=admin["id"],
        target_user_id=user_id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"assigned_role": payload.role.value},
    )

    return GenericMessageResponse(
        message=f"User '{target_user['username']}' approved with role '{payload.role.value}'",
        user_id=user_id,
    )
```

- [ ] **Step 4: Run the approve tests and the happy path**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k approve tests/test_auth_complete.py::test_admin_approve_user -q
```

Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add api/routes/users.py tests/test_auth_security_audit.py
git commit -m "fix(users): restrict approval to pending non-admin accounts"
```

---

### Task 7: Disable public signup (API and UI)

**Files:**
- Modify: `api/routes/auth.py:137-234`
- Modify: `frontend/app/(auth)/login/page.tsx:68-72`
- Delete: `frontend/app/(auth)/signup/page.tsx`
- Modify: `frontend/lib/auth/api.ts:137-144`
- Modify: `frontend/next.config.ts`
- Modify: `tests/test_auth_complete.py` (all `test_signup_*`)
- Modify: `tests/test_auth_hardening.py:100-150`, `tests/test_auth_hardening.py:410-435`

**Interfaces:**
- Consumes: `auth_config.signup_enabled()`
- Produces: `POST /api/v1/auth/signup` returns `403` unless `AUTH_ALLOW_SIGNUP=true`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_auth_security_audit.py`:

```python
def test_public_signup_is_disabled_by_default(monkeypatch):
    monkeypatch.delenv("AUTH_ALLOW_SIGNUP", raising=False)
    captcha_id, answer = issue_captcha()
    res = _client().post(
        "/api/v1/auth/signup",
        json={
            "username": "audit_signup",
            "password": "Password123!",
            "confirm_password": "Password123!",
            "captcha_id": captcha_id,
            "captcha_answer": answer,
        },
    )
    assert res.status_code == 403
```

- [ ] **Step 2: Run it and confirm it fails**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k signup -q
```

Expected: FAIL — signup returns 201.

- [ ] **Step 3: Gate the endpoint**

At the top of `signup`, before parsing CAPTCHA:

```python
    if not signup_enabled():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Self-service registration is disabled. Ask an administrator to create your account.",
        )
```

- [ ] **Step 4: Add an explicit fixture for legacy signup tests**

Add to `tests/conftest.py`:

```python
@pytest.fixture
def signup_enabled(monkeypatch):
    monkeypatch.setenv("AUTH_ALLOW_SIGNUP", "true")
```

Add the `signup_enabled` parameter to these tests:

- `tests/test_auth_complete.py`: `test_signup_valid`, `test_signup_duplicate_username`, `test_signup_invalid_username`, `test_signup_weak_password_and_mismatch`, `test_signup_wrong_and_expired_captcha`, `test_signup_admin_role_injection_prevention`.
- `tests/test_auth_hardening.py`: `test_case_insensitive_username_signup_conflict`, `test_pending_user_has_no_effective_permissions`.

- [ ] **Step 5: Remove the signup UI**

Delete `frontend/app/(auth)/signup/page.tsx`.

Remove the `signup` method from `frontend/lib/auth/api.ts`.

Replace the `AuthFooter` line in `frontend/app/(auth)/login/page.tsx` with:

```tsx
      <p className="text-center text-sm text-[var(--auth-muted)]">
        Forgotten your password? Ask your administrator to reset it.
      </p>
```

Add to `frontend/next.config.ts`:

```ts
  async redirects() {
    return [{ source: "/signup", destination: "/login", permanent: false }]
  },
```

- [ ] **Step 6: Run backend and frontend checks**

```bash
$PY -m pytest tests/test_auth_complete.py tests/test_auth_hardening.py tests/test_auth_security_audit.py -k "signup or pending" -q
cd frontend && pnpm lint && pnpm build
```

Expected: all pass; the build no longer references `/signup`.

- [ ] **Step 7: Commit**

```bash
git add api/routes/auth.py tests/test_auth_complete.py tests/test_auth_hardening.py tests/test_auth_security_audit.py tests/conftest.py frontend/app/\(auth\)/login/page.tsx frontend/app/\(auth\)/signup/page.tsx frontend/lib/auth/api.ts frontend/next.config.ts
git commit -m "feat(auth): close public signup and point users to an administrator"
```

---

### Task 8: Enforce the RBAC matrix on every protected route

**Files:**
- Modify: `api/rbac.py:29-75`
- Modify: `api/routes/dashboard.py`, `reports.py`, `domains.py`, `clients.py`, `investigation.py`, `status.py`, `analytics.py`, `daily_review.py`, `users.py`
- Create: `tests/test_rbac_routes.py`
- Modify: `tests/test_auth_complete.py:467-485`, `tests/test_api_v1.py:635-717`

**Interfaces:**
- Consumes: `require_permission(permission)`
- Produces permissions: `dashboard:read`, `status:read`, `analytics:read` for all roles; `reports:export` only for ADMIN/ANALYST; `daily_review:update` for ADMIN/ANALYST

- [ ] **Step 1: Write the failing route-permission tests**

Create `tests/test_rbac_routes.py`:

```python
"""Route-level proof that the RBAC matrix is enforced by the API."""

from fastapi.testclient import TestClient

from api.main import app


def test_all_roles_can_read_dashboard(admin_headers, analyst_headers, support_headers):
    for headers in (admin_headers, analyst_headers, support_headers):
        assert TestClient(app).get("/api/v1/dashboard", headers=headers).status_code == 200


def test_support_can_read_reports_but_not_export(support_headers):
    client = TestClient(app)
    assert client.get("/api/v1/reports/summary", headers=support_headers).status_code == 200
    assert client.get("/api/v1/reports/export/csv", headers=support_headers).status_code == 403


def test_support_cannot_manage_users(support_headers):
    assert TestClient(app).get("/api/v1/users", headers=support_headers).status_code == 403


def test_analyst_can_update_daily_review_but_not_manage_users(analyst_headers, monkeypatch):
    monkeypatch.setattr("api.routes.daily_review.promote_to_clean", lambda *a, **k: None)
    client = TestClient(app)
    verdict = client.post(
        "/api/v1/daily-review/test-safe-domain.example.com/verdict",
        json={"verdict": "clean", "reason": "RBAC test"},
        headers=analyst_headers,
    )
    assert verdict.status_code == 200
    assert client.get("/api/v1/users", headers=analyst_headers).status_code == 403


def test_analyst_can_read_audit_only_as_admin(admin_headers, analyst_headers):
    client = TestClient(app)
    assert client.get("/api/v1/users/audit/logs", headers=admin_headers).status_code == 200
    assert client.get("/api/v1/users/audit/logs", headers=analyst_headers).status_code == 403
```

- [ ] **Step 2: Run and confirm failures**

```bash
$PY -m pytest tests/test_rbac_routes.py -q
```

Expected: support export and analyst verdict assertions fail (currently allowed / 403 respectively).

- [ ] **Step 3: Extend the permission matrix**

In `api/rbac.py`, add to `ADMIN`, `ANALYST`, and `SUPPORT`:

```python
        "dashboard:read",
        "status:read",
        "analytics:read",
```

Ensure `SUPPORT` does **not** contain `reports:export`, `daily_review:update`, `domains:investigate`, `clients:investigate`, or any `users:*`.

- [ ] **Step 4: Put a permission dependency on every route**

For each file, add `from ..rbac import require_permission` and replace the auth dependency as follows.

| File | Function / path | Permission |
|---|---|---|
| `dashboard.py` | `get_dashboard` (`GET ""`) | `dashboard:read` |
| `reports.py` | summary, root, timeseries, clients, domains, queries, malicious-domains, flagged, entity | `reports:read` |
| `reports.py` | `export_csv` (`GET /export/csv`) | `reports:export` |
| `domains.py` | list, detail | `domains:read` |
| `clients.py` | list, detail | `clients:read` |
| `investigation.py` | both domain dossier aliases | `domains:investigate` |
| `investigation.py` | both client dossier aliases | `clients:investigate` |
| `status.py` | `GET ""` | `status:read` |
| `analytics.py` | `GET /domains` | `analytics:read` |
| `daily_review.py` | list, stats, dossier | `daily_review:read` |
| `daily_review.py` | `set_manual_verdict` | `daily_review:update` |
| `daily_review.py` | `trigger_domain_review` | `domains:investigate` |
| `users.py` | list, get | `users:read` |
| `users.py` | create | `users:create` |
| `users.py` | update, approve, disable, enable, reset-password, revoke-sessions | `users:update` |
| `users.py` | audit logs | `audit_logs:read` |

Example for `domains.py`:

```python
from ..rbac import require_permission
...
    current_user: dict[str, Any] = Depends(require_permission("domains:read")),
```

Example for `daily_review.py`:

```python
from ..rbac import require_permission
...
def set_manual_verdict(
    domain: str,
    payload: VerdictOverrideRequest,
    current_user: dict[str, Any] = Depends(require_permission("daily_review:update")),
):
    ...
    admin_tag = f"admin_override:{current_user.get('email', 'admin')}"
```

Rename the two `admin` parameters to `current_user` and update their three uses (`admin_tag`, `override_by`, and the trigger's `admin.get`). Keep `require_admin` imported only if another route still uses it; otherwise delete the import.

- [ ] **Step 5: Update tests that encoded the old contradictions**

In `tests/test_auth_complete.py::test_rbac_permission_matrix`, add:

```python
    assert has_permission("SUPPORT", "dashboard:read") is True
    assert has_permission("SUPPORT", "reports:export") is False
    assert has_permission("ANALYST", "daily_review:update") is True
    assert has_permission("ANALYST", "users:read") is False
```

In `tests/test_api_v1.py`, the analyst verdict and trigger expectations must be `200` (already changed in Task 3).

- [ ] **Step 6: Run the full backend suite**

```bash
$PY -m pytest tests/ -q
```

Expected: no new failures. Fix any route test that assumed SUPPORT could export or ANALYST could not review.

- [ ] **Step 7: Commit**

```bash
git add api/rbac.py api/routes tests/test_rbac_routes.py tests/test_auth_complete.py tests/test_api_v1.py
git commit -m "feat(rbac): enforce permissions on every protected route"
```

---

### Task 9: nginx TLS, loopback binding, systemd, and firewall (server task)

**Files:**
- Create: `deploy/nginx/dnsnetra.conf`
- Create: `deploy/nginx/dnsnetra-proxy.conf`
- Create: `deploy/systemd/dnsnetra-api.service`
- Create: `deploy/systemd/dnsnetra-web.service`
- Create: `deploy/api.env.example`
- Create: `deploy/gen-internal-cert.sh`
- Create: `deploy/ufw-dnsnetra.sh`
- Create: `deploy/README.md`
- Modify: `api/trusted_proxy.py:16-69`
- Modify: `tests/test_auth_hardening.py:659-677`, `tests/test_auth_security_audit.py:252-265`

**Interfaces:**
- Consumes: `TRUSTED_PROXIES`, nginx `$remote_addr`
- Produces: `https://dnsnetra.corp.local/` → Next.js `127.0.0.1:3000`, `/api/*` → FastAPI `127.0.0.1:8000`; no direct remote access to ports 3000/8000

- [ ] **Step 1: Update the XFF reproducer so it does not depend on a trusted loopback**

Replace the AUTH-06 test body with:

```python
def test_rate_limit_cannot_be_bypassed_with_spoofed_xff(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXIES", "10.255.255.1")
    proxy_client = _client(client=("127.0.0.1", 4444))
    codes = [
        proxy_client.get(
            "/api/v1/auth/captcha", headers={"X-Forwarded-For": f"203.0.113.{i}"}
        ).status_code
        for i in range(35)
    ]
    assert 429 in codes
```

Remove the AUTH-06 `xfail` decorator.

Update `test_trusted_proxy_ignores_spoofed_headers_from_untrusted_peer` to set the env explicitly:

```python
def test_trusted_proxy_ignores_spoofed_headers_from_untrusted_peer(monkeypatch):
    class DummyRequest:
        def __init__(self, peer_ip: str, forwarded_for: str):
            self.client = type("Client", (), {"host": peer_ip})()
            self.headers = {"x-forwarded-for": forwarded_for}

    monkeypatch.delenv("TRUSTED_PROXIES", raising=False)
    req_untrusted = DummyRequest(peer_ip="203.0.113.5", forwarded_for="1.1.1.1, 10.0.0.1")
    assert get_client_ip(req_untrusted) == "203.0.113.5"

    monkeypatch.setenv("TRUSTED_PROXIES", "127.0.0.1")
    req_trusted = DummyRequest(peer_ip="127.0.0.1", forwarded_for="198.51.100.42, 127.0.0.1")
    assert get_client_ip(req_trusted) == "198.51.100.42"
```

Add a rightmost-hop test:

```python
def test_xff_walks_from_the_right(monkeypatch):
    class DummyRequest:
        def __init__(self):
            self.client = type("Client", (), {"host": "127.0.0.1"})()
            self.headers = {"x-forwarded-for": "6.6.6.6, 198.51.100.7, 127.0.0.1"}

    monkeypatch.setenv("TRUSTED_PROXIES", "127.0.0.1")
    assert get_client_ip(DummyRequest()) == "198.51.100.7"
```

- [ ] **Step 2: Run and confirm the XFF test fails**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k xff tests/test_auth_hardening.py -k trusted_proxy -q
```

Expected: FAIL — the left-most hop is still trusted.

- [ ] **Step 3: Trust only configured proxies and walk XFF from the right**

In `api/trusted_proxy.py`:

```python
DEFAULT_TRUSTED_PROXIES: Set[str] = set()


def get_trusted_proxies() -> Set[str]:
    raw = os.getenv("TRUSTED_PROXIES", "")
    return {p.strip() for p in raw.split(",") if p.strip()}
```

```python
def get_client_ip(request: Request) -> str:
    peer_ip = "127.0.0.1"
    if request.client and request.client.host:
        peer_ip = request.client.host.strip()

    trusted = get_trusted_proxies()
    if peer_ip not in trusted:
        return peer_ip

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        hops = [h.strip() for h in forwarded.split(",") if h.strip()]
        for hop in reversed(hops):
            if not is_valid_ip(hop):
                continue
            if hop in trusted:
                continue
            return hop

    real_ip = request.headers.get("x-real-ip")
    if real_ip and is_valid_ip(real_ip) and real_ip.strip() not in trusted:
        return real_ip.strip()

    return peer_ip
```

- [ ] **Step 4: Re-run the XFF tests**

```bash
$PY -m pytest tests/test_auth_security_audit.py -k xff tests/test_auth_hardening.py -k trusted_proxy -q
```

Expected: PASS.

- [ ] **Step 5: Add the nginx proxy snippet**

Create `deploy/nginx/dnsnetra-proxy.conf`:

```nginx
proxy_http_version 1.1;
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
# Overwrite, never append: the browser cannot inject a forged hop.
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host $host;
proxy_set_header Connection "";
proxy_connect_timeout 5s;
proxy_read_timeout 60s;
proxy_send_timeout 60s;
```

- [ ] **Step 6: Add the nginx site**

Create `deploy/nginx/dnsnetra.conf`:

```nginx
limit_req_zone $binary_remote_addr zone=auth_login:10m rate=10r/m;
limit_req_zone $binary_remote_addr zone=auth_captcha:10m rate=30r/m;

upstream dnsnetra_api {
    server 127.0.0.1:8000;
    keepalive 16;
}

upstream dnsnetra_web {
    server 127.0.0.1:3000;
    keepalive 16;
}

server {
    listen 80;
    server_name dnsnetra.corp.local;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name dnsnetra.corp.local;

    ssl_certificate     /etc/ssl/dnsnetra/dnsnetra.crt;
    ssl_certificate_key /etc/ssl/dnsnetra/dnsnetra.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    client_max_body_size 10m;

    location = /api/v1/auth/login {
        limit_req zone=auth_login burst=3 nodelay;
        proxy_pass http://dnsnetra_api;
        include /etc/nginx/snippets/dnsnetra-proxy.conf;
    }

    location = /api/v1/auth/token {
        limit_req zone=auth_login burst=3 nodelay;
        proxy_pass http://dnsnetra_api;
        include /etc/nginx/snippets/dnsnetra-proxy.conf;
    }

    location = /api/v1/auth/captcha {
        limit_req zone=auth_captcha burst=10 nodelay;
        proxy_pass http://dnsnetra_api;
        include /etc/nginx/snippets/dnsnetra-proxy.conf;
    }

    location /api/ {
        proxy_pass http://dnsnetra_api;
        include /etc/nginx/snippets/dnsnetra-proxy.conf;
    }

    location / {
        proxy_pass http://dnsnetra_web;
        include /etc/nginx/snippets/dnsnetra-proxy.conf;
    }
}
```

- [ ] **Step 7: Add the systemd units**

Create `deploy/systemd/dnsnetra-api.service`:

```ini
[Unit]
Description=DNSNetra API (FastAPI)
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=simple
User=dnsnetra
Group=dnsnetra
WorkingDirectory=/opt/dnsnetra
EnvironmentFile=/etc/dnsnetra/api.env
ExecStart=/opt/dnsnetra/.venv/bin/uvicorn api.main:app --host 127.0.0.1 --port 8000 --workers 1 --proxy-headers --forwarded-allow-ips=127.0.0.1
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/dnsnetra/logs
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true

[Install]
WantedBy=multi-user.target
```

Create `deploy/systemd/dnsnetra-web.service`:

```ini
[Unit]
Description=DNSNetra web (Next.js)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dnsnetra
Group=dnsnetra
WorkingDirectory=/opt/dnsnetra/frontend
Environment=NODE_ENV=production
Environment=PORT=3000
Environment=HOSTNAME=127.0.0.1
ExecStart=/usr/bin/node node_modules/next/dist/bin/next start -H 127.0.0.1 -p 3000
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/dnsnetra/frontend/.next/cache
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 8: Add the environment template**

Create `deploy/api.env.example`:

```dotenv
# Copy to /etc/dnsnetra/api.env, chmod 600, root:dnsnetra.
# Generate each secret with: openssl rand -hex 32
DNSNETRA_ENV=production
AUTH_SESSION_SECRET=
AUTH_CAPTCHA_SECRET=
AUTH_SESSION_EXPIRE_MINUTES=480
AUTH_CAPTCHA_EXPIRE_SECONDS=300
AUTH_COOKIE_SECURE=true
AUTH_ALLOW_SIGNUP=false
CORS_ALLOWED_ORIGINS=https://dnsnetra.corp.local
TRUSTED_PROXIES=127.0.0.1,::1

UDR_DB_HOST=127.0.0.1
UDR_DB_PORT=5432
UDR_DB_DATABASE=dns_threat_detection
UDR_DB_USERNAME=dnsnetra_app
UDR_DB_PASSWORD=
```

- [ ] **Step 9: Add the certificate and firewall scripts**

Create `deploy/gen-internal-cert.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

HOSTNAME="${1:-dnsnetra.corp.local}"
CERT_DIR=/etc/ssl/dnsnetra

install -d -m 0755 "$CERT_DIR"
openssl req -x509 -nodes -newkey rsa:4096 -sha256 -days 825 \
  -keyout "$CERT_DIR/dnsnetra.key" \
  -out "$CERT_DIR/dnsnetra.crt" \
  -subj "/CN=${HOSTNAME}" \
  -addext "subjectAltName=DNS:${HOSTNAME},DNS:localhost,IP:127.0.0.1" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

chmod 0600 "$CERT_DIR/dnsnetra.key"
chmod 0644 "$CERT_DIR/dnsnetra.crt"

echo "Installed certificate for ${HOSTNAME} in ${CERT_DIR}"
echo "Distribute ${CERT_DIR}/dnsnetra.crt to clients via GPO/MDM."
```

Create `deploy/ufw-dnsnetra.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

: "${ADMIN_CIDR:?set ADMIN_CIDR, e.g. 10.0.0.0/8}"
: "${USER_CIDR:?set USER_CIDR, e.g. 10.0.0.0/8}"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow from "$ADMIN_CIDR" to any port 22 proto tcp comment 'SSH admin subnet'
ufw allow from "$USER_CIDR" to any port 443 proto tcp comment 'DNSNetra HTTPS'
ufw --force enable
ufw status verbose
```

- [ ] **Step 10: Write the deployment runbook**

Create `deploy/README.md` with these exact sections and commands:

```markdown
# DNSNetra production deployment (Ubuntu 24.04)

## 1. Host and DNS
- Static IP, `dnsnetra.corp.local` resolving to it (internal DNS or `/etc/hosts` on clients).
- UEFI Secure Boot, BIOS password, LUKS on the data disk, UPS.

## 2. Service account and code
    sudo apt update && sudo apt install -y nginx postgresql python3.13 python3.13-venv nodejs
    sudo useradd --system --home /opt/dnsnetra --shell /usr/sbin/nologin dnsnetra
    sudo mkdir -p /opt/dnsnetra /etc/dnsnetra
    sudo cp -a . /opt/dnsnetra
    sudo chown -R dnsnetra:dnsnetra /opt/dnsnetra
    sudo -u dnsnetra python3.13 -m venv /opt/dnsnetra/.venv
    sudo -u dnsnetra /opt/dnsnetra/.venv/bin/pip install -r /opt/dnsnetra/requirements.txt

## 3. Frontend build (NEXT_PUBLIC_* is baked in at build time)
    cd /opt/dnsnetra/frontend
    sudo -u dnsnetra env NEXT_PUBLIC_API_URL=https://dnsnetra.corp.local pnpm install --frozen-lockfile
    sudo -u dnsnetra env NEXT_PUBLIC_API_URL=https://dnsnetra.corp.local pnpm build

## 4. Secrets
    sudo install -m 600 -o root -g dnsnetra deploy/api.env.example /etc/dnsnetra/api.env
    sudo sed -i "s|^AUTH_SESSION_SECRET=.*|AUTH_SESSION_SECRET=$(openssl rand -hex 32)|" /etc/dnsnetra/api.env
    sudo sed -i "s|^AUTH_CAPTCHA_SECRET=.*|AUTH_CAPTCHA_SECRET=$(openssl rand -hex 32)|" /etc/dnsnetra/api.env
    sudo editor /etc/dnsnetra/api.env   # set the database password only

## 5. TLS
    sudo ./deploy/gen-internal-cert.sh dnsnetra.corp.local

## 6. nginx
    sudo cp deploy/nginx/dnsnetra-proxy.conf /etc/nginx/snippets/dnsnetra-proxy.conf
    sudo cp deploy/nginx/dnsnetra.conf /etc/nginx/sites-available/dnsnetra.conf
    sudo ln -sf /etc/nginx/sites-available/dnsnetra.conf /etc/nginx/sites-enabled/dnsnetra.conf
    sudo rm -f /etc/nginx/sites-enabled/default
    sudo nginx -t
    sudo systemctl reload nginx

## 7. systemd
    sudo cp deploy/systemd/dnsnetra-api.service deploy/systemd/dnsnetra-web.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now dnsnetra-api dnsnetra-web

## 8. Firewall
    sudo ADMIN_CIDR=10.0.0.0/8 USER_CIDR=10.0.0.0/8 ./deploy/ufw-dnsnetra.sh

## 9. Verification
    ss -ltnp | grep -E ':3000|:8000'     # must show 127.0.0.1 only
    curl -k https://dnsnetra.corp.local/api/v1/auth/captcha
    curl -k -I https://dnsnetra.corp.local/login
    sudo systemctl status dnsnetra-api dnsnetra-web nginx
    sudo journalctl -u dnsnetra-api -n 50 --no-pager
```

- [ ] **Step 11: Run the static checks available on the development machine**

```bash
bash -n deploy/gen-internal-cert.sh
bash -n deploy/ufw-dnsnetra.sh
python3 - <<'PY'
from pathlib import Path
for p in Path("deploy/systemd").glob("*.service"):
    text = p.read_text()
    assert "[Service]" in text and "ExecStart=" in text
print("unit files look structurally valid")
PY
```

Expected: no output from `bash -n`, and the Python check prints the confirmation.

- [ ] **Step 12: Commit**

```bash
git add deploy api/trusted_proxy.py tests/test_auth_hardening.py tests/test_auth_security_audit.py
git commit -m "feat(deploy): add nginx TLS front door, systemd units, and ufw baseline"
```

---

### Task 10: Rotate the seeded admin, purge test data, and record remediation status

**Files:**
- Create: `scripts/rotate_admin_password.py`
- Create: `scripts/purge_test_users.py`
- Create: `tests/test_admin_scripts.py`
- Modify: `start_all.sh` (banner)
- Modify: `docs/AUTH_SECURITY_AUDIT.md` (append status table)

**Interfaces:**
- Produces: `generate_temporary_password(length=20) -> str`, `rotate_admin(username, execute) -> tuple[bool, str | None]`, `plan_purge(keep) -> list[tuple]`, `purge_users(keep, execute, purge_audit_logs) -> int`

- [ ] **Step 1: Write the failing script tests**

Create `tests/test_admin_scripts.py`:

```python
import pytest

from api.auth import validate_password_strength
from scripts.purge_test_users import plan_purge
from scripts.rotate_admin_password import generate_temporary_password


def test_temporary_password_satisfies_policy():
    for _ in range(20):
        password = generate_temporary_password()
        ok, reason = validate_password_strength(password)
        assert ok, reason


def test_purge_refuses_empty_keep_list():
    with pytest.raises(ValueError):
        plan_purge([])


def test_purge_keep_list_must_include_an_admin():
    with pytest.raises(ValueError):
        plan_purge(["definitely_not_a_user"])
```

- [ ] **Step 2: Run and confirm they fail**

```bash
$PY -m pytest tests/test_admin_scripts.py -q
```

Expected: FAIL with `ModuleNotFoundError: No module named 'scripts.purge_test_users'`.

- [ ] **Step 3: Implement the rotation script**

Create `scripts/rotate_admin_password.py`:

```python
"""Rotate a local admin password and force a change at the next login.

    python scripts/rotate_admin_password.py --username admin            # dry run
    python scripts/rotate_admin_password.py --username admin --execute  # rotate
"""

from __future__ import annotations

import argparse
import secrets
import string
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.auth import hash_password, validate_password_strength
from api.sessions import revoke_all_user_sessions
from labeler.intel.reputation.connection import get_connection

ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*"


def generate_temporary_password(length: int = 20) -> str:
    while True:
        candidate = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if validate_password_strength(candidate)[0]:
            return candidate


def rotate_admin(username: str, execute: bool) -> tuple[bool, str | None]:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, role FROM dashboard_users WHERE lower(username) = lower(%s);",
                (username,),
            )
            row = cur.fetchone()
            if not row:
                return False, None
            user_id, role = row
            if role != "ADMIN":
                return False, None

            password = generate_temporary_password()
            if not execute:
                conn.rollback()
                return True, None

            cur.execute(
                """
                UPDATE dashboard_users
                SET password_hash = %s,
                    hashed_password = NULL,
                    must_change_password = true,
                    status = 'ACTIVE',
                    is_active = true,
                    updated_at = NOW()
                WHERE id = %s;
                """,
                (hash_password(password), user_id),
            )
            conn.commit()

    revoke_all_user_sessions(user_id)
    return True, password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default="admin")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    ok, password = rotate_admin(args.username, args.execute)
    if not ok:
        print(f"Refusing: '{args.username}' is missing or is not an ADMIN.", file=sys.stderr)
        return 1
    if not args.execute:
        print(f"Dry run: would rotate '{args.username}'. Re-run with --execute.")
        return 0

    print(f"Rotated '{args.username}'. One-time password (shown once):")
    print(password)
    print("The account must change this password at next login.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Implement the purge script**

Create `scripts/purge_test_users.py`:

```python
"""Delete every dashboard user except an explicit keep-list.

    python scripts/purge_test_users.py --keep admin                 # dry run
    python scripts/purge_test_users.py --keep admin --execute --purge-audit-logs
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from labeler.intel.reputation.connection import get_connection


def plan_purge(keep: list[str]) -> list[tuple]:
    if not keep:
        raise ValueError("keep-list cannot be empty")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, role, status
                FROM dashboard_users
                WHERE lower(username) <> ALL(%s)
                ORDER BY id;
                """,
                ([name.lower() for name in keep],),
            )
            rows = cur.fetchall()
            cur.execute(
                "SELECT count(*) FROM dashboard_users WHERE role = 'ADMIN' AND lower(username) = ANY(%s);",
                ([name.lower() for name in keep],),
            )
            admins = cur.fetchone()[0]
            conn.rollback()
    if admins < 1:
        raise ValueError("keep-list must retain at least one ADMIN account")
    return rows


def purge_users(keep: list[str], execute: bool, purge_audit_logs: bool) -> int:
    doomed = plan_purge(keep)
    if not execute:
        return len(doomed)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM dashboard_users WHERE lower(username) <> ALL(%s);",
                ([name.lower() for name in keep],),
            )
            deleted = cur.rowcount
            if purge_audit_logs:
                cur.execute("DELETE FROM audit_logs;")
            conn.commit()
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="append", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--purge-audit-logs", action="store_true")
    args = parser.parse_args()

    try:
        doomed = plan_purge(args.keep)
    except ValueError as exc:
        print(f"Refusing: {exc}", file=sys.stderr)
        return 1

    for user_id, username, role, status in doomed:
        print(f"  would delete id={user_id} username={username} role={role} status={status}")

    if not args.execute:
        print(f"Dry run: {len(doomed)} user(s) would be deleted. Re-run with --execute.")
        return 0

    deleted = purge_users(args.keep, execute=True, purge_audit_logs=args.purge_audit_logs)
    print(f"Deleted {deleted} user(s). Kept: {', '.join(args.keep)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Run the script tests**

```bash
$PY -m pytest tests/test_admin_scripts.py -q
```

Expected: 3 passed.

- [ ] **Step 6: Dry-run the purge against the live database**

```bash
$PY scripts/purge_test_users.py --keep admin
```

Expected: a list of every user except `admin`, ending with `Dry run: N user(s) would be deleted.` Stop and inspect the list. The database is test-only, but the count must match the current `SELECT count(*) - 1`.

- [ ] **Step 7: Execute the purge**

```bash
$PY scripts/purge_test_users.py --keep admin --execute --purge-audit-logs
```

Expected: `Deleted N user(s). Kept: admin`.

- [ ] **Step 8: Rotate the admin password**

```bash
$PY scripts/rotate_admin_password.py --username admin --execute
```

Expected: prints a one-time password once and states that a change is required at next login. Record it in the team password manager, not in git or chat.

- [ ] **Step 9: Verify the database state**

```bash
PGPASSWORD="$(grep -E '^UDR_DB_PASSWORD=' .env | cut -d= -f2- | tr -d '\r')" \
psql -h localhost -U postgres -d dns_threat_detection -c \
"SELECT id, username, role, status, is_active, must_change_password FROM dashboard_users ORDER BY id;"
```

Expected: exactly one row — `admin`, `ADMIN`, `ACTIVE`, `t`, `t`. Also verify:

```bash
PGPASSWORD="$(grep -E '^UDR_DB_PASSWORD=' .env | cut -d= -f2- | tr -d '\r')" \
psql -h localhost -U postgres -d dns_threat_detection -c "SELECT count(*) FROM sessions; SELECT count(*) FROM audit_logs;"
```

Expected: `sessions` 0 (cascade) and `audit_logs` 0.

- [ ] **Step 10: Remove the weak-credentials banner**

In `start_all.sh`, replace the dashboard line with:

```bash
echo "  Dashboard  : http://localhost:3000  (credentials: managed by an administrator)"
```

- [ ] **Step 11: Append the remediation status to the audit**

Append to `docs/AUTH_SECURITY_AUDIT.md`:

```markdown
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
```

- [ ] **Step 12: Run the full suite one final time**

```bash
$PY -m pytest tests/ -q
cd frontend && pnpm lint && pnpm test && pnpm build
```

Expected: green, with only the five deferred findings still marked `xfail`.

- [ ] **Step 13: Commit**

```bash
git add scripts/rotate_admin_password.py scripts/purge_test_users.py tests/test_admin_scripts.py start_all.sh docs/AUTH_SECURITY_AUDIT.md
git commit -m "chore(auth): rotate seeded admin, purge test data, and record remediation"
```

---

## Self-Review

**1. Spec coverage**

| Requirement | Task |
|---|---|
| Remove JWT fallback / published secret (AUTH-01, 05) | 2, 3 |
| Rotate `admin` off `admin` (AUTH-02) | 10 |
| CAPTCHA required on every login (AUTH-03, 10) | 4 |
| Force password change (AUTH-04) | 5 |
| XFF spoofing (AUTH-06) | 9 |
| `/approve` lifecycle (AUTH-07) | 6 |
| Secret/TTL validation (AUTH-09) | 2 |
| RBAC on every route (AUTH-11) | 8 |
| Localhost origin merge (AUTH-18) | 2 |
| No public signup | 7 |
| Admin reset-password + forced change | 5, 6, 10 |
| nginx TLS / loopback / ufw | 9 |
| Test suite stops using `admin/admin` | 1, 3, 4 |
| Data purge | 10 |

**2. Placeholder scan:** No `TBD`, `TODO`, “implement later”, or “similar to Task N”. Every code step contains runnable code. The only operator-entered values are the real hostname, the DB password, and the CIDR ranges; each appears in exactly one file and the runbook names it.

**3. Type consistency:** `create_session` keeps its `(raw_token, expires_at)` return. `get_current_user` still returns `dict[str, Any]`. `require_permission` returns the same user dict as `get_current_user`, so handler bodies that used `current_user` are unchanged except in `daily_review.py`, where the rename is shown. `session_user["must_change_password"]` is added in Task 5 and consumed in the same task. `get_session_ttl_seconds()` is defined in Task 2 and used in Task 2's route edits.
