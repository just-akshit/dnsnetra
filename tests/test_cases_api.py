"""Case API workflow."""

from fastapi.testclient import TestClient

from api.audit import get_audit_logs
from api.main import app
from tests.auth_testkit import db

client = TestClient(app)


def _create(analyst_headers, **overrides):
    payload = {
        "title": "Investigate beacon.example",
        "priority": "high",
        "entity_type": "domain",
        "entity_value": "beacon.example",
    }
    payload.update(overrides)
    return client.post("/api/v1/cases", headers=analyst_headers, json=payload)


def test_analyst_creates_self_assigns_and_resolves(analyst_headers):
    created = _create(analyst_headers)
    assert created.status_code == 201
    public_id = created.json()["public_id"]
    assert public_id.startswith("CASE-")

    me = client.get("/api/v1/auth/me", headers=analyst_headers).json()
    assigned = client.patch(
        f"/api/v1/cases/{public_id}",
        headers=analyst_headers,
        json={"status": "triaged", "assigned_to": me["id"]},
    )
    assert assigned.status_code == 200
    assert assigned.json()["assigned_to"] == me["id"]

    investigating = client.patch(
        f"/api/v1/cases/{public_id}",
        headers=analyst_headers,
        json={"status": "investigating"},
    )
    assert investigating.status_code == 200

    done = client.patch(
        f"/api/v1/cases/{public_id}",
        headers=analyst_headers,
        json={"status": "resolved", "resolution": "true_positive"},
    )
    assert done.status_code == 200
    assert done.json()["resolution"] == "true_positive"


def test_analyst_cannot_close_or_reassign(support_headers, analyst_headers):
    created = _create(analyst_headers)
    public_id = created.json()["public_id"]
    client.patch(f"/api/v1/cases/{public_id}", headers=analyst_headers,
                 json={"status": "triaged"})
    client.patch(f"/api/v1/cases/{public_id}", headers=analyst_headers,
                 json={"status": "investigating"})
    client.patch(f"/api/v1/cases/{public_id}", headers=analyst_headers,
                 json={"status": "resolved", "resolution": "benign"})

    closed = client.patch(f"/api/v1/cases/{public_id}", headers=analyst_headers,
                          json={"status": "closed"})
    assert closed.status_code == 403


def test_support_can_read_but_not_patch(support_headers, analyst_headers):
    created = _create(analyst_headers)
    public_id = created.json()["public_id"]
    assert client.get(f"/api/v1/cases/{public_id}", headers=support_headers).status_code == 200
    assert client.patch(f"/api/v1/cases/{public_id}", headers=support_headers,
                        json={"status": "triaged"}).status_code == 403


def test_create_and_update_write_audit_rows(analyst_headers):
    created = _create(analyst_headers)
    public_id = created.json()["public_id"]

    rows, _ = get_audit_logs(action="CASE_CREATED", limit=1)
    assert rows[0]["target_type"] == "case"
    assert rows[0]["target_id"] == public_id

    assert client.patch(
        f"/api/v1/cases/{public_id}", headers=analyst_headers,
        json={"status": "triaged"},
    ).status_code == 200

    rows, _ = get_audit_logs(action="CASE_UPDATED", limit=1)
    assert rows[0]["target_type"] == "case"
    assert rows[0]["target_id"] == public_id


def _create_report(analyst_headers) -> str:
    res = client.post(
        "/api/v1/reports/saved",
        headers=analyst_headers,
        json={"kind": "query_set", "window": "24h", "filters": {"search": "a"}},
    )
    assert res.status_code == 201
    return res.json()["public_id"]


def test_reports_link_on_create_and_via_endpoint(analyst_headers):
    report_ids = []
    try:
        on_create = _create_report(analyst_headers)
        report_ids.append(on_create)
        created = _create(analyst_headers, report_id=on_create)
        assert created.status_code == 201
        assert created.json()["reports"] == [on_create]

        via_endpoint = _create_report(analyst_headers)
        report_ids.append(via_endpoint)
        case = _create(analyst_headers, title="Second case")
        case_id = case.json()["public_id"]
        linked = client.post(
            f"/api/v1/cases/{case_id}/reports",
            headers=analyst_headers,
            json={"report_public_id": via_endpoint},
        )
        assert linked.status_code == 200
        assert linked.json()["reports"] == [via_endpoint]

        other_case = _create(analyst_headers, title="Third case")
        other_id = other_case.json()["public_id"]
        conflict = client.post(
            f"/api/v1/cases/{other_id}/reports",
            headers=analyst_headers,
            json={"report_public_id": via_endpoint},
        )
        assert conflict.status_code == 409
        assert client.get(
            f"/api/v1/cases/{other_id}", headers=analyst_headers
        ).json()["reports"] == []

        missing = client.post(
            f"/api/v1/cases/{case_id}/reports",
            headers=analyst_headers,
            json={"report_public_id": "RPT-1999-999999"},
        )
        assert missing.status_code == 404
    finally:
        db(
            "DELETE FROM reports WHERE public_id = ANY(%s::text[])",
            (report_ids,),
        )


