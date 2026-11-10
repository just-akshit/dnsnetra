"""CSV safety and filter parity."""

import csv
import re
from io import BytesIO, StringIO

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


def _csv_rows(snapshot, report=None):
    reader = csv.DictReader(StringIO("".join(snapshot_csv_chunks(snapshot, report))))
    return list(reader)


def test_entity_csv_includes_evidence_sections():
    snapshot = {
        **SNAPSHOT,
        "dossier": {
            **SNAPSHOT["dossier"],
            "registration": {
                "status": "AVAILABLE",
                "source": "RDAP",
                "registrar": "=Evil Registrar",
                "created_at": "2020-01-01T00:00:00Z",
                "expires_at": "2030-01-01T00:00:00Z",
                "nameservers": ["ns1.example.com", "ns2.example.com"],
            },
            "dns_records": {
                "status": "AVAILABLE",
                "provider": "DNS Resolver",
                "a": ["192.0.2.10"],
                "mx": [{"priority": 10, "exchange": "mail.example.com"}],
            },
            "threat_intel": {
                "reputation": {
                    "status": "malicious",
                    "source": "@feed",
                    "confidence": 0.92,
                    "last_verified_at": "2026-11-09T00:00:00Z",
                },
                "daily_review": {
                    "status": "review_needed",
                    "review_count": 3,
                    "next_check_at": "2026-11-12T00:00:00Z",
                },
                "reviewed_clean": {
                    "status": "clean",
                    "verified_at": "2026-11-08T00:00:00Z",
                },
            },
        },
    }
    report = {
        "title": "=Report title",
        "status": "reviewed",
        "verdict": "Malicious",
        "conclusion": "=cmd|' /C calc'!A0",
        "reviewed_by": 7,
        "reviewed_at": "2026-11-11T00:00:00Z",
    }

    rows = _csv_rows(snapshot, report)
    by_key = {(row["section"], row["field"]): row["value"] for row in rows}

    assert by_key[("registration", "registrar")] == "'=Evil Registrar"
    assert by_key[("registration", "created")] == "2020-01-01T00:00:00Z"
    assert by_key[("registration", "expires")] == "2030-01-01T00:00:00Z"
    assert by_key[("registration", "nameservers")] == "ns1.example.com, ns2.example.com"

    assert by_key[("dns", "A")] == "192.0.2.10"
    assert by_key[("dns", "MX")] == "10 mail.example.com"

    assert by_key[("threat_intel", "reputation_status")] == "malicious"
    assert by_key[("threat_intel", "reputation_source")] == "'@feed"
    assert by_key[("threat_intel", "reputation_confidence")] == "0.92"
    assert by_key[("threat_intel", "daily_review_status")] == "review_needed"
    assert by_key[("threat_intel", "daily_review_count")] == "3"
    assert by_key[("threat_intel", "daily_review_next_check")] == "2026-11-12T00:00:00Z"
    assert by_key[("threat_intel", "reviewed_clean_status")] == "clean"

    assert by_key[("assessment", "title")] == "'=Report title"
    assert by_key[("assessment", "status")] == "reviewed"
    assert by_key[("assessment", "verdict")] == "Malicious"
    assert by_key[("assessment", "conclusion")] == "'=cmd|' /C calc'!A0"
    assert by_key[("assessment", "reviewer")] == "7"


def test_entity_csv_without_report_has_no_assessment_section():
    sections = {row["section"] for row in _csv_rows(SNAPSHOT)}
    assert "assessment" not in sections


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


def test_xlsx_sanitizes_user_supplied_report_metadata():
    from openpyxl import load_workbook

    report = {
        "public_id": "=RPT-2026-000001",
        "title": "=cmd|' /C calc'!A0",
        "status": "=1+1",
        "verdict": "=evil",
        "conclusion": "@SUM(A1:A9)",
        "reviewed_by": 7,
        "row_count": 1,
    }
    workbook = load_workbook(BytesIO(build_xlsx(SNAPSHOT, report, exported_rows=1)))

    cells = {}
    for sheet in ("Summary", "Assessment"):
        for row in workbook[sheet].iter_rows():
            if row[0].value:
                cells[(sheet, row[0].value)] = row[1]

    for (sheet, label), cell in cells.items():
        if label in ("Report ID", "Title", "Status", "Verdict", "Conclusion"):
            assert isinstance(cell.value, str), (sheet, label, cell.value)
            assert cell.value.startswith("'"), (sheet, label, cell.value)
            assert cell.data_type != "f", (sheet, label, cell.data_type)

    assert cells[("Summary", "Title")].value == "'=cmd|' /C calc'!A0"
    assert cells[("Assessment", "Conclusion")].value == "'@SUM(A1:A9)"


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
