"""Case API workflow."""

import pytest
from fastapi.testclient import TestClient

from api.audit import get_audit_logs
from api.main import app
from tests.auth_testkit import db

client = TestClient(app)


@pytest.fixture
def cases():
    """Track cases created by a test and delete them afterwards."""
    public_ids: list[str] = []
    yield public_ids
    if public_ids:
        db(
            "DELETE FROM cases WHERE public_id = ANY(%s::text[])",
            (public_ids,),
        )


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


@pytest.fixture
def other_analyst():
    """A second analyst, removed by the conftest `case_test_%` cleanup."""
    db("DELETE FROM dashboard_users WHERE username = %s", ("case_test_analyst",))
    rows = db(
        """
        INSERT INTO dashboard_users
            (username, email, password_hash, hashed_password, role, status,
             is_active, must_change_password, created_at, updated_at)
        VALUES ('case_test_analyst', 'case_test_analyst@dnsnetra.local', 'x',
                NULL, 'ANALYST', 'ACTIVE', true, false, NOW(), NOW())
        RETURNING id
        """
    )
    return rows[0][0]


def _create(headers, cases=None, **overrides):
    payload = {
        "title": "Investigate beacon.example",
        "priority": "high",
        "entity_type": "domain",
        "entity_value": "beacon.example",
    }
    payload.update(overrides)
    res = client.post("/api/v1/cases", headers=headers, json=payload)
    if cases is not None and res.status_code == 201:
        cases.append(res.json()["public_id"])
    return res


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


def test_analyst_creates_self_assigns_and_resolves(analyst_headers, cases):
    created = _create(analyst_headers, cases)
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


def test_analyst_cannot_close(analyst_headers, cases):
    created = _create(analyst_headers, cases)
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


def test_support_can_read_but_not_patch(support_headers, analyst_headers, cases):
    created = _create(analyst_headers, cases)
    public_id = created.json()["public_id"]
    assert client.get(f"/api/v1/cases/{public_id}", headers=support_headers).status_code == 200
    assert client.patch(f"/api/v1/cases/{public_id}", headers=support_headers,
                        json={"status": "triaged"}).status_code == 403


def test_create_and_update_write_audit_rows(analyst_headers, cases):
    created = _create(analyst_headers, cases)
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


def test_list_returns_paginated_response(analyst_headers, cases):
    _create(analyst_headers, cases)
    res = client.get("/api/v1/cases", headers=analyst_headers, params={"limit": 1})
    assert res.status_code == 200
    body = res.json()
    assert {"total", "limit", "offset", "has_more", "items"} <= set(body)
    assert body["has_more"] is (body["offset"] + len(body["items"]) < body["total"])
    assert body["items"]
    assert "id" not in body["items"][0]


def test_analyst_cannot_assign_a_case_to_someone_else(
    analyst_headers, other_analyst, cases
):
    res = _create(analyst_headers, cases, assigned_to=other_analyst)
    assert res.status_code == 403
    assert cases == []


def test_analyst_can_self_assign_on_create(analyst_headers, cases):
    me = client.get("/api/v1/auth/me", headers=analyst_headers).json()
    res = _create(analyst_headers, cases, assigned_to=me["id"])
    assert res.status_code == 201
    assert res.json()["assigned_to"] == me["id"]


def test_analyst_cannot_patch_case_assigned_to_another_analyst(
    admin_headers, analyst_headers, other_analyst, cases
):
    created = _create(admin_headers, cases, assigned_to=other_analyst)
    assert created.status_code == 201
    public_id = created.json()["public_id"]

    res = client.patch(
        f"/api/v1/cases/{public_id}",
        headers=analyst_headers,
        json={"status": "triaged"},
    )
    assert res.status_code == 403


def test_admin_can_reassign_case_to_another_user(
    admin_headers, analyst_headers, other_analyst, cases
):
    created = _create(analyst_headers, cases)
    public_id = created.json()["public_id"]

    res = client.patch(
        f"/api/v1/cases/{public_id}",
        headers=admin_headers,
        json={"assigned_to": other_analyst},
    )
    assert res.status_code == 200
    assert res.json()["assigned_to"] == other_analyst


def test_create_rejects_unknown_assignee(admin_headers, cases):
    res = _create(admin_headers, cases, assigned_to=10**9)
    assert res.status_code == 400
    assert cases == []


def test_reports_link_on_create_and_via_endpoint(
    analyst_headers, cases, created_reports
):
    on_create = _create_report(analyst_headers, created_reports)
    created = _create(analyst_headers, cases, report_id=on_create)
    assert created.status_code == 201
    assert created.json()["reports"] == [on_create]

    via_endpoint = _create_report(analyst_headers, created_reports)
    case = _create(analyst_headers, cases, title="Second case")
    case_id = case.json()["public_id"]
    linked = client.post(
        f"/api/v1/cases/{case_id}/reports",
        headers=analyst_headers,
        json={"report_public_id": via_endpoint},
    )
    assert linked.status_code == 200
    assert linked.json()["reports"] == [via_endpoint]

    other_case = _create(analyst_headers, cases, title="Third case")
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


def test_create_with_already_linked_report_does_not_create_a_case(
    analyst_headers, cases, created_reports
):
    report_id = _create_report(analyst_headers, created_reports)
    first = _create(analyst_headers, cases, report_id=report_id)
    assert first.status_code == 201

    def total() -> int:
        return client.get(
            "/api/v1/cases", headers=analyst_headers, params={"limit": 1}
        ).json()["total"]

    before = total()
    conflict = _create(analyst_headers, cases, report_id=report_id)
    assert conflict.status_code == 409
    assert total() == before


def test_patch_appends_assignment_and_priority_events(
    admin_headers, analyst_headers, other_analyst, cases
):
    created = _create(analyst_headers, cases)
    public_id = created.json()["public_id"]

    res = client.patch(
        f"/api/v1/cases/{public_id}",
        headers=admin_headers,
        json={"assigned_to": other_analyst, "priority": "critical"},
    )
    assert res.status_code == 200

    events = client.get(
        f"/api/v1/cases/{public_id}", headers=admin_headers
    ).json()["events"]
    by_kind = {event["kind"]: event for event in events}
    assert by_kind["assigned"]["metadata"] == {"from": None, "to": other_analyst}
    assert by_kind["priority_changed"]["metadata"] == {
        "from": "high", "to": "critical",
    }

    rows, _ = get_audit_logs(action="CASE_ASSIGNED", limit=1)
    assert rows[0]["target_id"] == public_id


def test_resolve_and_close_append_events_and_audit(
    admin_headers, analyst_headers, cases
):
    created = _create(analyst_headers, cases)
    public_id = created.json()["public_id"]

    client.patch(f"/api/v1/cases/{public_id}", headers=admin_headers,
                 json={"status": "triaged"})
    client.patch(f"/api/v1/cases/{public_id}", headers=admin_headers,
                 json={"status": "investigating"})
    resolved = client.patch(
        f"/api/v1/cases/{public_id}", headers=admin_headers,
        json={"status": "resolved", "resolution": "true_positive"},
    )
    assert resolved.status_code == 200

    events = client.get(
        f"/api/v1/cases/{public_id}", headers=admin_headers
    ).json()["events"]
    by_kind = {event["kind"]: event for event in events}
    assert by_kind["status_changed"]["metadata"]["to"] == "resolved"
    assert by_kind["resolution_set"]["metadata"] == {
        "from": None, "to": "true_positive",
    }

    rows, _ = get_audit_logs(action="CASE_RESOLVED", limit=1)
    assert rows[0]["target_id"] == public_id

    closed = client.patch(
        f"/api/v1/cases/{public_id}", headers=admin_headers,
        json={"status": "closed"},
    )
    assert closed.status_code == 200
    rows, _ = get_audit_logs(action="CASE_CLOSED", limit=1)
    assert rows[0]["target_id"] == public_id


def test_resolution_only_change_is_audited_as_update_not_resolved(
    admin_headers, cases
):
    created = _create(admin_headers, cases)
    public_id = created.json()["public_id"]
    client.patch(f"/api/v1/cases/{public_id}", headers=admin_headers,
                 json={"status": "triaged"})
    client.patch(f"/api/v1/cases/{public_id}", headers=admin_headers,
                 json={"status": "investigating"})

    res = client.patch(
        f"/api/v1/cases/{public_id}", headers=admin_headers,
        json={"resolution": "false_positive"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "investigating"

    resolved = db(
        "SELECT COUNT(*) FROM audit_logs "
        "WHERE target_id = %s AND action = 'CASE_RESOLVED'",
        (public_id,),
    )
    assert resolved[0][0] == 0
    updated = db(
        "SELECT COUNT(*) FROM audit_logs "
        "WHERE target_id = %s AND action = 'CASE_UPDATED'",
        (public_id,),
    )
    assert updated[0][0] >= 1
