"""CSV safety and filter parity."""

import re
from io import BytesIO

from reporting.exporters import (
    build_xlsx,
    export_filename,
    sanitize_csv_cell,
    snapshot_csv_chunks,
)
from reporting.repository import ReportingRepository, like_pattern

SNAPSHOT = {
    "schema_version": 1,
    "kind": "entity_domain",
    "entity": {"type": "domain", "value": "=evil.example"},
    "window": {"start": None, "end": None, "label": "all time"},
    "observed_in_network": False,
    "dossier": {
        "domain": "=evil.example",
        "observed_in_network": False,
        "profile": {"total_queries": 7, "unique_clients": 2},
        "recent_queries": [
            {"timestamp": "2026-11-10T00:00:00Z", "client_ip": "10.0.0.5",
             "domain": "=evil.example", "query_type": "A",
             "final_label": "Malicious", "ti_source": "@feed"}
        ],
        "live_intel": {"checked_at": "2026-11-10T00:00:00Z", "verdict": {"state": "malicious"}},
    },
    "provenance": {"sources": ["domain_query_history"]},
}


def test_entity_csv_sanitizes_formula_cells():
    csv_text = "".join(snapshot_csv_chunks(SNAPSHOT))
    assert "'=evil.example" in csv_text
    assert "'@feed" in csv_text
    assert csv_text.startswith("section,field,value,source,checked_at")


def test_xlsx_has_the_six_sheets_and_safe_text():
    from openpyxl import load_workbook

    data = build_xlsx(SNAPSHOT)
    workbook = load_workbook(BytesIO(data))
    assert workbook.sheetnames == [
        "Summary", "Timeline", "Relationships", "Queries", "Intelligence", "Assessment"
    ]
    values = [cell.value for row in workbook["Queries"].iter_rows() for cell in row]
    assert "'=evil.example" in values


def test_xlsx_assessment_and_intelligence_carry_report_metadata():
    from openpyxl import load_workbook

    snapshot = {
        **SNAPSHOT,
        "dossier": {
            **SNAPSHOT["dossier"],
            "live_intel": {
                "checked_at": "2026-11-10T00:00:00Z",
                "verdict": {"state": "malicious"},
                "providers": [
                    {"provider": "virustotal", "status": "ok",
                     "malicious": 3, "total": 70},
                ],
            },
        },
    }
    report = {
        "public_id": "RPT-2026-000001",
        "status": "reviewed",
        "verdict": "Malicious",
        "conclusion": "Confirmed malicious.",
        "reviewed_by": 7,
        "row_count": 7,
    }
    workbook = load_workbook(BytesIO(build_xlsx(snapshot, report, exported_rows=1)))

    assessment = {
        row[0].value: row[1].value
        for row in workbook["Assessment"].iter_rows()
        if row[0].value
    }
    assert assessment["Report ID"] == "RPT-2026-000001"
    assert assessment["Status"] == "reviewed"
    assert assessment["Verdict"] == "Malicious"
    assert assessment["Conclusion"] == "Confirmed malicious."
    assert assessment["Reviewer"] == 7

    intelligence = [
        [cell.value for cell in row] for row in workbook["Intelligence"].iter_rows()
    ]
    assert ["Provider", "virustotal", "ok", 3, 70, "2026-11-10T00:00:00Z"] in intelligence

    summary = {
        row[0].value: row[1].value
        for row in workbook["Summary"].iter_rows()
        if row[0].value
    }
    assert summary["Report ID"] == "RPT-2026-000001"
    assert summary["Row count at creation"] == 7
    assert summary["Rows exported"] == 1


def test_export_filename_is_stamped_and_sanitized():
    name = export_filename('bad/name"x', "csv")
    assert name.startswith("dnsnetra_bad_name_x_")
    assert name.endswith(".csv")
    assert re.search(r"_\d{8}T\d{6}Z\.csv$", name)


def test_formula_cells_are_neutralized():
    assert sanitize_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert sanitize_csv_cell("+1") == "'+1"
    assert sanitize_csv_cell("-1") == "'-1"
    assert sanitize_csv_cell("@SUM") == "'@SUM"
    assert sanitize_csv_cell("example.com") == "example.com"
    assert sanitize_csv_cell(42) == 42


def test_like_pattern_escapes_metacharacters():
    assert like_pattern("%_x") == "%\\%\\_x%"


class _FakeCursor:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.log.append((" ".join(sql.split()), params))

    def fetchmany(self, size):
        return []


class _FakeConn:
    def __init__(self):
        self.log = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self, *args, **kwargs):
        return _FakeCursor(self.log)


def test_export_uses_ilike_for_domain_and_search():
    conn = _FakeConn()
    repo = ReportingRepository(connection_factory=lambda: conn)
    list(repo.stream_queries_csv(domain="example", search="foo", limit=10))

    sql = conn.log[-1][0]
    params = conn.log[-1][1]
    assert "domain ILIKE" in sql
    assert "client_ip ILIKE" in sql
    assert "%example%" in params
    assert params.count("%foo%") == 2
