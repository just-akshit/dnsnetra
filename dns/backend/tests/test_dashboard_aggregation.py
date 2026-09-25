"""
test_dashboard_aggregation.py
==============================
Integration tests for dashboard aggregation read model and FastAPI endpoints.

These tests exercise both the CSV-based DashboardAggregator (legacy)
and the PostgreSQL-based IncrementalAggregator (production path).

DECISIONS (documented per plan Phase 38):
  - TestNormalizedSource: was ahead of implementation — updated to use
    IncrementalAggregator, which now writes domain_details/client_details.
  - TestDomainDetail, TestClientDetail: now test incremental path.
  - TestAtomicity: retained — now tests incremental atomicity.
  - TestAPI: tests FastAPI endpoints after incremental aggregation.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
import sys

import pytest

BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from dashboard_aggregation.incremental_aggregator import IncrementalAggregator
from dashboard_aggregation.schema import initialize_dashboard_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_pg_row(
    id: int,
    domain: str,
    client_ip: str,
    final_label: str = "Clean",
    query_type: str = "A",
    response_code: str = "NOERROR",
    ti_source: str = None,
    ts_offset: int = 0,
) -> dict[str, Any]:
    dt = datetime(2026, 7, 19, 6, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=ts_offset)
    return {
        "id": id,
        "domain": domain,
        "client_ip": client_ip,
        "query_type": query_type,
        "timestamp": dt,
        "response_code": response_code,
        "registered_domain": domain,
        "tld": domain.split(".")[-1],
        "final_label": final_label,
        "ti_source": ti_source,
    }


# Represents the equivalent of old FIXTURE_ROWS in incremental form:
# evil.com (2 queries from 10.0.0.1, Malicious)
# good.com (1 query from 10.0.0.2, Clean)
# unknown.net (1 query from 10.0.0.2, Unknown)
FIXTURE_PG_ROWS = [
    make_pg_row(1, "evil.com", "10.0.0.1", final_label="Malicious", ti_source="OTX"),
    make_pg_row(2, "evil.com", "10.0.0.1", final_label="Malicious", query_type="AAAA", ti_source="OTX"),
    make_pg_row(3, "good.com", "10.0.0.2", final_label="Clean", ts_offset=3600),
    make_pg_row(4, "unknown.net", "10.0.0.2", final_label="Unknown", ts_offset=7200),
]


@pytest.fixture
def db_path(tmp_path: Path):
    """Provides a temporary dashboard.db path initialized with schema."""
    p = tmp_path / "dashboard.db"
    initialize_dashboard_db(p)
    return p


@pytest.fixture
def populated_db(db_path: Path):
    """Provides a dashboard.db populated with FIXTURE_PG_ROWS via IncrementalAggregator."""
    agg = _make_agg(db_path, FIXTURE_PG_ROWS)
    result = agg.run_incremental()
    assert result.status == "success", f"Fixture aggregation failed: {result.error_message}"
    return db_path


def _make_agg(db_path: Path, rows: list[dict]) -> IncrementalAggregator:
    agg = IncrementalAggregator(
        dashboard_db_path=db_path,
        aggregation_name="test",
    )
    mock_conn = object()
    agg._get_pg_connection = lambda: mock_conn

    def fetch(pg_conn, watermark_id):
        return [r for r in rows if r["id"] > watermark_id][: agg.batch_size]

    def count(pg_conn, watermark_id):
        return len([r for r in rows if r["id"] > watermark_id])

    agg._fetch_batch = fetch
    agg._count_pending_events = count
    return agg


# ---------------------------------------------------------------------------
# TestDomainDetail
# ---------------------------------------------------------------------------

class TestDomainDetail:
    def test_domain_counts(self, populated_db):
        conn = sqlite3.connect(populated_db)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM domain_details WHERE domain='evil.com'"
        ).fetchone()
        conn.close()
        assert row["total_queries"] == 2
        assert row["unique_clients"] == 1
        assert row["malicious_count"] == 2
        # Fields not in domain_query_history — must be NULL
        assert row["threat_score"] is None
        assert row["asn"] is None
        assert row["domain_age_days"] is None

    def test_domain_query_type_breakdown(self, populated_db):
        conn = sqlite3.connect(populated_db)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT query_type_breakdown FROM domain_details WHERE domain='evil.com'"
        ).fetchone()
        conn.close()
        qt = json.loads(row["query_type_breakdown"])
        assert qt.get("A", 0) == 1
        assert qt.get("AAAA", 0) == 1


# ---------------------------------------------------------------------------
# TestClientDetail
# ---------------------------------------------------------------------------

class TestClientDetail:
    def test_client_counts(self, populated_db):
        conn = sqlite3.connect(populated_db)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM client_details WHERE client_ip='10.0.0.2'"
        ).fetchone()
        conn.close()
        assert row["total_queries"] == 2
        assert row["unique_domains"] == 2
        top = json.loads(row["top_domains"])
        assert len(top) >= 1

    def test_client_malicious_count(self, populated_db):
        conn = sqlite3.connect(populated_db)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM client_details WHERE client_ip='10.0.0.1'"
        ).fetchone()
        conn.close()
        assert row["malicious_count"] == 2


# ---------------------------------------------------------------------------
# TestIdempotency
# ---------------------------------------------------------------------------

class TestIdempotency:
    def test_double_run_identical(self, db_path):
        agg = _make_agg(db_path, FIXTURE_PG_ROWS)
        agg.run_incremental()

        conn = sqlite3.connect(db_path)
        before = conn.execute(
            "SELECT total_queries, unique_clients FROM metrics_summary WHERE id=1"
        ).fetchone()
        domain_count_before = conn.execute("SELECT COUNT(*) FROM domain_details").fetchone()[0]
        conn.close()

        # Second run — no new events
        agg.run_incremental()

        conn = sqlite3.connect(db_path)
        after = conn.execute(
            "SELECT total_queries, unique_clients FROM metrics_summary WHERE id=1"
        ).fetchone()
        domain_count_after = conn.execute("SELECT COUNT(*) FROM domain_details").fetchone()[0]
        conn.close()

        assert before == after
        assert domain_count_before == domain_count_after
        assert before[0] == 4  # 4 total events
        assert before[1] == 2  # 2 unique clients


# ---------------------------------------------------------------------------
# TestAtomicity
# ---------------------------------------------------------------------------

class TestAtomicity:
    def test_failure_leaves_prior_snapshot(self, db_path):
        agg = _make_agg(db_path, FIXTURE_PG_ROWS)
        agg.run_incremental()

        conn = sqlite3.connect(db_path)
        prior = conn.execute(
            "SELECT total_queries FROM metrics_summary WHERE id=1"
        ).fetchone()[0]
        conn.close()
        assert prior == 4

        # Add new row but inject failure
        new_rows = FIXTURE_PG_ROWS + [
            make_pg_row(5, "new.com", "10.0.0.3", final_label="Malicious")
        ]
        agg2 = _make_agg(db_path, new_rows)

        # Inject crash
        agg2._upsert_domain_details = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("simulated failure")
        )

        result = agg2.run_incremental()
        assert result.status == "failed"

        conn = sqlite3.connect(db_path)
        still = conn.execute(
            "SELECT total_queries FROM metrics_summary WHERE id=1"
        ).fetchone()[0]
        failed = conn.execute(
            "SELECT status FROM aggregation_runs WHERE aggregation_name='test' ORDER BY started_at DESC LIMIT 1"
        ).fetchone()[0]
        conn.close()

        assert still == 4  # unchanged
        assert failed == "failed"


# ---------------------------------------------------------------------------
# TestAPI
# ---------------------------------------------------------------------------

class TestAPI:
    @pytest.fixture
    def client(self, populated_db, monkeypatch):
        monkeypatch.setenv("DASHBOARD_DB_PATH", str(populated_db))
        import dashboard_aggregation.config as cfg
        cfg.DASHBOARD_DB_PATH = populated_db

        # Reload api.db to pick up new path
        import api.db as db_mod
        db_mod.DASHBOARD_DB_PATH = populated_db

        from api.main import app
        from fastapi.testclient import TestClient
        return TestClient(app)

    def test_dashboard_bundle(self, client):
        r = client.get("/api/v1/dashboard")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "success"
        assert body["data"]["summary"]["total_queries"] == 4

    def test_domain_list_pagination(self, client):
        r = client.get("/api/v1/domains?page=1&page_size=2")
        assert r.status_code == 200
        assert len(r.json()["data"]) == 2
        assert r.json()["meta"]["total"] == 3

    def test_domain_detail(self, client):
        r = client.get("/api/v1/domains/evil.com")
        assert r.status_code == 200
        d = r.json()["data"]
        assert d["label"] == "malicious"
        assert d["stats"]["queries"] == 2

    def test_client_detail(self, client):
        r = client.get("/api/v1/clients/10.0.0.1")
        assert r.status_code == 200
        assert r.json()["data"]["stats"]["total_queries"] == 2

    def test_status(self, client):
        r = client.get("/api/v1/status")
        assert r.status_code == 200

    def test_domain_filter(self, client):
        r = client.get("/api/v1/domains?label=Malicious")
        assert r.status_code == 200
        for d in r.json()["data"]:
            assert d["last_label"] in ("Malicious", "malicious")
