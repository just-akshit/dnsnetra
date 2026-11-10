"""Saved report API behavior and role gates."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_analyst_can_create_and_review_a_report(analyst_headers):
    res = client.post(
        "/api/v1/reports/saved",
        headers=analyst_headers,
        json={"kind": "query_set", "window": "24h", "filters": {"search": "a"}},
    )
    assert res.status_code == 201
    public_id = res.json()["public_id"]
    assert public_id.startswith("RPT-")

    reviewed = client.patch(
        f"/api/v1/reports/saved/{public_id}/review",
        headers=analyst_headers,
        json={"status": "reviewed", "verdict": "Review Needed",
              "conclusion": "Needs follow-up."},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "reviewed"


def test_review_requires_a_conclusion(analyst_headers):
    created = client.post(
        "/api/v1/reports/saved",
        headers=analyst_headers,
        json={"kind": "query_set", "window": "24h", "filters": {"search": "a"}},
    )
    public_id = created.json()["public_id"]
    res = client.patch(
        f"/api/v1/reports/saved/{public_id}/review",
        headers=analyst_headers,
        json={"status": "reviewed", "verdict": "Unknown", "conclusion": ""},
    )
    assert res.status_code == 400


def test_support_cannot_create_reports(support_headers):
    res = client.post(
        "/api/v1/reports/saved",
        headers=support_headers,
        json={"kind": "query_set", "window": "24h", "filters": {"search": "a"}},
    )
    assert res.status_code == 403
