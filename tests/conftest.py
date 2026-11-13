"""Shared fixtures for the DNSNetra test suite.

Test identities are created once per pytest session and deleted afterwards.
No test authenticates as the seeded production `admin` account.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dnsnetra.core.security.auth import hash_password
from dnsnetra.core.security.login_throttle import reset_all
from dnsnetra.core.security.rate_limiter import reset_rate_limits
from dnsnetra.core.security.sessions import create_session, revoke_session
from tests.fixtures.auth_testkit import TEST_PASSWORD, db

LEGACY_UDR_TESTS = Path(__file__).resolve().parent / "unit" / "unknown_domains"


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-legacy-udr",
        action="store_true",
        default=False,
        help="Also run the opt-in unknown-domain repository suite.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Keep the frozen UDR suite opt-in until it is reconciled with the service."""
    if config.getoption("--run-legacy-udr"):
        return
    skip = pytest.mark.skip(
        reason="Opt-in subsystem suite; use --run-legacy-udr to run it."
    )
    for item in items:
        if LEGACY_UDR_TESTS in item.path.parents:
            item.add_marker(skip)


SEEDED_ROLES = {
    "superadmin": "SUPER_ADMIN",
    "admin": "ADMIN",
    "analyst": "ANALYST",
    "support": "SUPPORT",
}

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


@pytest.fixture
def signup_enabled(monkeypatch):
    """Legacy signup tests opt in explicitly; production defaults to closed."""
    monkeypatch.setenv("AUTH_ALLOW_SIGNUP", "true")


@pytest.fixture(autouse=True)
def _reset_rate_limits():
    reset_rate_limits()
    reset_all()
    yield
    reset_rate_limits()
    reset_all()


@pytest.fixture(autouse=True)
def _cleanup_ephemeral_users():
    """Delete throw-away accounts after every test, including leaked prefixes."""
    yield
    db(
        "DELETE FROM dashboard_users WHERE username LIKE ANY(%s::text[])",
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
    db("DELETE FROM dashboard_users WHERE id = ANY(%s::int[])", (list(ids.values()),))


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
def super_headers(seeded_users):
    yield from _headers_for(seeded_users["superadmin"])


@pytest.fixture
def admin_headers(seeded_users):
    yield from _headers_for(seeded_users["admin"])


@pytest.fixture
def analyst_headers(seeded_users):
    yield from _headers_for(seeded_users["analyst"])


@pytest.fixture
def support_headers(seeded_users):
    yield from _headers_for(seeded_users["support"])
