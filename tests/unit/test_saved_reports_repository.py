"""Saved report schemas and SQL behavior."""

import json
from datetime import datetime, timezone

from dnsnetra.domains.reporting.report_repository import ReportRepository, format_public_id


def test_public_id_format():
    assert format_public_id("RPT", 2026, 7) == "RPT-2026-000007"


class _Cursor:
    def __init__(self, rows):
        self.rows = list(rows)
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.executed.append((" ".join(sql.split()), params))

    def fetchone(self):
        return self.rows.pop(0)


class _Conn:
    def __init__(self, rows):
        self._cursor = _Cursor(rows)
        self.committed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self, *args, **kwargs):
        return self._cursor

    def commit(self):
        self.committed = True


def test_create_inserts_a_snapshot_and_commits():
    row = {
        "id": 1,
        "public_id": "RPT-2026-000001",
        "kind": "entity_domain",
        "entity_type": "domain",
        "entity_value": "example.com",
        "title": "example.com",
        "window_start": None,
        "window_end": None,
        "filters": {},
        "snapshot": {"schema_version": 1},
        "row_count": 0,
        "status": "draft",
        "conclusion": None,
        "verdict": None,
        "created_by": 1,
        "reviewed_by": None,
        "reviewed_at": None,
        "case_id": None,
        "case_public_id": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    conn = _Conn([{"nextval": 1}, row])
    repo = ReportRepository(connection_factory=lambda: conn)

    report = repo.create(
        kind="entity_domain",
        entity_type="domain",
        entity_value="example.com",
        title="example.com",
        window_start=None,
        window_end=None,
        filters={},
        snapshot={"schema_version": 1},
        row_count=0,
        created_by=1,
    )

    assert report.public_id == "RPT-2026-000001"
    assert conn.committed is True
    assert "INSERT INTO reports" in conn._cursor.executed[1][0]
