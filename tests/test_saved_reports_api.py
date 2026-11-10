"""Saved report API behavior and role gates."""

import pytest
from fastapi.testclient import TestClient

from api.audit import get_audit_logs
from api.main import app
from tests.auth_testkit import db

client = TestClient(app)


@pytest.fixture
def created_reports():
    """Track reports created by a test and delete them afterwards."""
    public_ids: list[str] = []
    yield public_ids
    if public_ids:
        db(
            "DELETE FROM reports WHERE public_id = ANY(%s::text[])",
            (public_ids,),
        )


def _create_report(headers, created_reports) -> str:
    res = client.post(
        "/api/v1/reports/saved",
        headers=headers,
        json={"kind": "query_set", "window": "24h", "filters": {"search": "a"}},
    )
    assert res.status_code == 201
    public_id = res.json()["public_id"]
    created_reports.append(public_id)
    return public_id


def test_analyst_can_create_and_review_a_report(analyst_headers, created_reports):
    public_id = _create_report(analyst_headers, created_reports)
    assert public_id.startswith("RPT-")

    rows, _ = get_audit_logs(action="REPORT_CREATED", limit=1)
    assert rows[0]["target_type"] == "report"
    assert rows[0]["target_id"] == public_id

    reviewed = client.patch(
        f"/api/v1/reports/saved/{public_id}/review",
        headers=analyst_headers,
        json={"status": "reviewed", "verdict": "Review Needed",
              "conclusion": "Needs follow-up."},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "reviewed"

    rows, _ = get_audit_logs(action="REPORT_REVIEWED", limit=1)
    assert rows[0]["target_type"] == "report"
    assert rows[0]["target_id"] == public_id


def test_review_requires_a_conclusion(analyst_headers, created_reports):
    public_id = _create_report(analyst_headers, created_reports)
    res = client.patch(
        f"/api/v1/reports/saved/{public_id}/review",
        headers=analyst_headers,
        json={"status": "reviewed", "verdict": "Unknown", "conclusion": ""},
    )
    assert res.status_code == 400


def test_archive_writes_audit_and_is_idempotent(analyst_headers, created_reports):
    public_id = _create_report(analyst_headers, created_reports)

    first = client.post(
        f"/api/v1/reports/saved/{public_id}/archive", headers=analyst_headers
    )
    assert first.status_code == 204
    second = client.post(
        f"/api/v1/reports/saved/{public_id}/archive", headers=analyst_headers
    )
    assert second.status_code == 204

    rows, _ = get_audit_logs(action="REPORT_ARCHIVED", limit=1)
    assert rows[0]["target_type"] == "report"
    assert rows[0]["target_id"] == public_id


def test_support_cannot_create_reports(support_headers):
    res = client.post(
        "/api/v1/reports/saved",
        headers=support_headers,
        json={"kind": "query_set", "window": "24h", "filters": {"search": "a"}},
    )
    assert res.status_code == 403
