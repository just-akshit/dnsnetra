"""
Unit Tests for Authentication API
=================================
Tests:
- Admin login with username 'admin' and passcode 'admin'
- Admin login with email 'admin@soc.local'
- Protected /me user profile endpoint with Bearer JWT
- Invalid password rejection (HTTP 401)
- User signup and session retrieval
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient

from api.main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


class TestAuthAPI:
    def test_admin_login_with_username(self, client):
        res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
        assert res.status_code == 200
        data = res.json()
        assert "token" in data
        assert data["user"]["username"] == "admin"
        assert data["user"]["role"] == "admin"

    def test_admin_login_with_email(self, client):
        res = client.post("/api/v1/auth/login", json={"email": "admin@soc.local", "password": "admin"})
        assert res.status_code == 200
        data = res.json()
        assert data["user"]["email"] == "admin@soc.local"
        assert data["user"]["role"] == "admin"

    def test_auth_me_with_bearer_token(self, client):
        login_res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "admin"})
        token = login_res.json()["token"]

        me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 200
        user = me_res.json()
        assert user["username"] == "admin"
        assert user["role"] == "admin"

    def test_invalid_password_rejected(self, client):
        res = client.post("/api/v1/auth/login", json={"username": "admin", "password": "incorrect_password_123"})
        assert res.status_code == 401
        assert "invalid" in res.json()["detail"].lower()

    def test_user_signup_and_login(self, client):
        import uuid
        uid = uuid.uuid4().hex[:8]
        username = f"analyst_{uid}"
        email = f"analyst_{uid}@soc.local"
        signup_res = client.post(
            "/api/v1/auth/signup",
            json={
                "username": username,
                "email": email,
                "password": "secure_pass_456",
                "name": "Test Analyst",
            },
        )
        assert signup_res.status_code == 200
        token = signup_res.json()["token"]

        me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert me_res.status_code == 200
        assert me_res.json()["username"] == username
        assert me_res.json()["name"] == "Test Analyst"

