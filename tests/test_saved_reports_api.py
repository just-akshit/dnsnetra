"""Saved report API behavior and role gates."""

import re
from io import BytesIO

import pytest
from fastapi.testclient import TestClient
from openpyxl import load_workbook

from api.audit import get_audit_logs
from api.main import app
from tests.auth_testkit import db

client = TestClient(app)

SEED_DOMAIN = "task10-export.example.test"


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


@pytest.fixture
def seeded_query_event():
    """Insert one recent event matching SEED_DOMAIN and always remove it."""
    rows = db(
        """
        INSERT INTO domain_query_history
            (timestamp, client_ip, domain, query_type, final_label,
             ti_source, response_code)
        VALUES (NOW(), '203.0.113.251', %s, 'A', 'Malicious', 'pytest', 'NOERROR')
        RETURNING id;
        """,
        (SEED_DOMAIN,),
    )
    event_id = rows[0][0]
    yield event_id
    db("DELETE FROM domain_query_history WHERE id = %s", (event_id,))


def test_support_cannot_export(support_headers):
    res = client.post(
        "/api/v1/reports/saved/RPT-0000-000001/export", headers=support_headers
    )
    assert res.status_code == 403


def test_export_unknown_report_is_404(analyst_headers):
    res = client.post(
        "/api/v1/reports/saved/RPT-0000-999999/export", headers=analyst_headers
    )
    assert res.status_code == 404


def test_entity_export_sets_download_headers(analyst_headers):
    expected_types = {
        "csv": "text/csv",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }
    for fmt, media_type in expected_types.items():
        res = client.get(
            f"/api/v1/reports/entity/export?entity=example.com&format={fmt}",
            headers=analyst_headers,
        )
        assert res.status_code == 200, res.text
        assert res.headers["cache-control"] == "no-store"
        assert res.headers["content-type"].startswith(media_type)
        disposition = res.headers["content-disposition"]
        assert disposition.startswith(
            'attachment; filename="dnsnetra_example.com_'
        ), disposition
        assert re.search(r"_\d{8}T\d{6}Z\." + fmt + '"$', disposition), disposition


def test_query_set_export_contains_real_rows(
    analyst_headers, created_reports, seeded_query_event
):
    created = client.post(
        "/api/v1/reports/saved",
        headers=analyst_headers,
        json={
            "kind": "query_set",
            "window": "24h",
            "filters": {"domain": SEED_DOMAIN},
        },
    )
    assert created.status_code == 201, created.text
    public_id = created.json()["public_id"]
    created_reports.append(public_id)

    csv_res = client.post(
        f"/api/v1/reports/saved/{public_id}/export?format=csv",
        headers=analyst_headers,
    )
    assert csv_res.status_code == 200, csv_res.text
    lines = [line for line in csv_res.text.splitlines() if line.strip()]
    assert lines[0].startswith("id,timestamp,client_ip,domain,query_type")
    assert any(SEED_DOMAIN in line for line in lines[1:]), lines

    rows, _ = get_audit_logs(action="REPORT_EXPORTED", limit=1)
    metadata = rows[0]["metadata"]
    assert metadata["exported_rows"] >= 1
    assert metadata["row_count"] == 1
    assert metadata["filters"] == {"domain": SEED_DOMAIN}

    xlsx_res = client.post(
        f"/api/v1/reports/saved/{public_id}/export?format=xlsx",
        headers=analyst_headers,
    )
    assert xlsx_res.status_code == 200, xlsx_res.text
    workbook = load_workbook(BytesIO(xlsx_res.content))
    values = [
        cell.value
        for row in workbook["Queries"].iter_rows()
        for cell in row
    ]
    assert SEED_DOMAIN in values
    summary = {
        row[0].value: row[1].value
        for row in workbook["Summary"].iter_rows()
        if row[0].value
    }
    assert summary["Row count at creation"] == 1
    assert summary["Rows exported"] == 1
