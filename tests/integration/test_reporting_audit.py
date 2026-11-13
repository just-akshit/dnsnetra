"""Audit rows for exports and verdict overrides."""

from fastapi.testclient import TestClient

from dnsnetra.core.security.audit import get_audit_logs
from apps.api.main import app

client = TestClient(app)


def test_csv_export_writes_an_audit_row(admin_headers):
    res = client.get(
        "/api/v1/reports/export/csv",
        headers=admin_headers,
        params={"limit": 1, "search": "a"},
    )
    assert res.status_code == 200

    rows, _ = get_audit_logs(action="REPORT_EXPORTED", limit=1)
    assert rows[0]["action"] == "REPORT_EXPORTED"
    assert rows[0]["target_type"] == "export"
    assert rows[0]["metadata"]["format"] == "csv"


def test_verdict_override_writes_an_audit_row(admin_headers):
    payload = {"verdict": "clean", "reason": "audit-test"}
    res = client.post(
        "/api/v1/daily-review/audit-override.example/verdict",
        headers=admin_headers,
        json=payload,
    )
    assert res.status_code == 200

    rows, _ = get_audit_logs(action="VERDICT_OVERRIDE", limit=1)
    assert rows[0]["target_type"] == "domain"
    assert rows[0]["target_id"] == "audit-override.example"
    assert rows[0]["metadata"]["verdict"] == "CLEAN"
