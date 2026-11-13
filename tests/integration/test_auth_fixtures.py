"""Proves the shared auth fixtures exist, authenticate, and carry distinct roles."""

from fastapi.testclient import TestClient

from apps.api.main import app


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
