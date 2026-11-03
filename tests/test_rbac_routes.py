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
