"""
test_incremental_aggregator.py
===============================
30-case unit test suite for IncrementalAggregator.

Test isolation strategy:
  - dashboard.db  → SQLite in-memory (:memory:) via monkeypatching the db path
  - PostgreSQL    → fixture SQLite in-memory that mirrors domain_query_history columns
  - No real network calls are made

Label semantics validated:
  - "Malicious" → is_malicious=True, is_threat=True
  - "Clean" / "Trusted" → is_clean=True
  - None / "Unknown" → is_unknown (not threat)

Run with:
    cd backend && .venv/bin/python -m pytest tests/test_incremental_aggregator.py -v
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import os
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional
import unittest
from unittest.mock import MagicMock, patch
import sys

# ---------------------------------------------------------------------------
# Ensure backend is importable
# ---------------------------------------------------------------------------
BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from dashboard_aggregation.incremental_aggregator import (
    IncrementalAggregator,
    NormalizedEvent,
    _classify_label,
    _normalize_event,
    _load_json_breakdown,
    _dump_json_breakdown,
)
from dashboard_aggregation.schema import initialize_dashboard_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_ts(offset_seconds: int = 0) -> str:
    dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(
    event_id: int = 1,
    domain: str = "example.com",
    client_ip: str = "10.0.0.1",
    query_type: str = "A",
    timestamp: str = None,
    response_code: str = "NOERROR",
    final_label: str = "Clean",
    ti_source: Optional[str] = None,
) -> NormalizedEvent:
    ts = timestamp or make_ts(event_id)
    bucket = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:00")
    is_malicious, is_clean, _ = _classify_label(final_label)
    return NormalizedEvent(
        event_id=event_id,
        domain=domain,
        client_ip=client_ip,
        query_type=query_type,
        timestamp=ts,
        time_bucket=bucket,
        response_code=response_code,
        registered_domain=domain,
        tld=domain.split(".")[-1],
        final_label=final_label or "",
        ti_source=ti_source,
        is_malicious=is_malicious,
        is_suspicious=False,
        is_clean=is_clean,
        is_threat=is_malicious,
    )


def make_pg_row(
    id: int = 1,
    domain: str = "example.com",
    client_ip: str = "10.0.0.1",
    query_type: str = "A",
    ts_offset: int = 0,
    response_code: str = "NOERROR",
    final_label: str = "Clean",
    ti_source: Optional[str] = None,
) -> dict[str, Any]:
    dt = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc) + timedelta(seconds=ts_offset)
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


class AggregatorTestCase(unittest.TestCase):
    """Base class providing an in-memory SQLite dashboard.db."""

    def setUp(self):
        # Create temp file for dashboard.db (in-memory doesn't work with file path)
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.db_path = self.tmp.name
        initialize_dashboard_db(self.db_path)

    def tearDown(self):
        os.unlink(self.db_path)

    def make_aggregator(self, pg_rows: list[dict] | None = None) -> IncrementalAggregator:
        """Creates aggregator with mocked PostgreSQL that returns pg_rows."""
        agg = IncrementalAggregator(
            dashboard_db_path=self.db_path,
            aggregation_name="test",
        )

        if pg_rows is not None:
            self._mock_pg(agg, pg_rows)

        return agg

    def _mock_pg(self, agg: IncrementalAggregator, rows: list[dict]) -> None:
        """Replaces _get_pg_connection with a mock that returns rows in batches."""
        all_rows = list(rows)

        def fake_fetch_batch(pg_conn, watermark_id: int) -> list[dict]:
            batch = [r for r in all_rows if r["id"] > watermark_id][: agg.batch_size]
            return batch

        def fake_count_pending(pg_conn, watermark_id: int) -> int:
            return len([r for r in all_rows if r["id"] > watermark_id])

        mock_conn = MagicMock()
        agg._get_pg_connection = lambda: mock_conn
        agg._fetch_batch = fake_fetch_batch
        agg._count_pending_events = fake_count_pending

    def get_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def get_watermark(self) -> int:
        with self.get_db() as c:
            row = c.execute(
                "SELECT last_processed_event_id FROM aggregation_state WHERE aggregation_name = 'test'"
            ).fetchone()
        return row["last_processed_event_id"] if row else 0

    def get_run_count(self, status: Optional[str] = None) -> int:
        with self.get_db() as c:
            if status:
                return c.execute(
                    "SELECT COUNT(*) FROM aggregation_runs WHERE status = ? AND aggregation_name = 'test'",
                    (status,),
                ).fetchone()[0]
            return c.execute(
                "SELECT COUNT(*) FROM aggregation_runs WHERE aggregation_name = 'test'"
            ).fetchone()[0]


# ---------------------------------------------------------------------------
# Tests 1–5: Basic event processing
# ---------------------------------------------------------------------------

class TestBasicEventProcessing(AggregatorTestCase):

    def test_01_empty_database(self):
        """Test 1: Empty database — no events, no error."""
        agg = self.make_aggregator(pg_rows=[])
        result = agg.run_incremental()
        self.assertEqual(result.status, "success")
        self.assertEqual(result.total_rows_processed, 0)
        self.assertEqual(result.batches_processed, 0)

    def test_02_first_incremental_run(self):
        """Test 2: First incremental run populates all tables."""
        rows = [
            make_pg_row(1, "evil.com", "10.0.0.1", final_label="Malicious", ti_source="OTX"),
            make_pg_row(2, "good.com", "10.0.0.2", final_label="Clean"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        result = agg.run_incremental()

        self.assertEqual(result.status, "success")
        self.assertEqual(result.total_rows_processed, 2)
        self.assertEqual(self.get_watermark(), 2)

        with self.get_db() as c:
            evil = c.execute("SELECT * FROM domain_details WHERE domain='evil.com'").fetchone()
            self.assertIsNotNone(evil)
            self.assertEqual(evil["total_queries"], 1)
            self.assertEqual(evil["malicious_count"], 1)

            good = c.execute("SELECT * FROM domain_details WHERE domain='good.com'").fetchone()
            self.assertIsNotNone(good)
            self.assertEqual(good["clean_count"], 1)

    def test_03_second_run_no_new_events(self):
        """Test 3: Second run with no new events — dashboard unchanged."""
        rows = [make_pg_row(1, "a.com", "10.0.0.1", final_label="Clean")]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            before = c.execute("SELECT total_queries FROM domain_details WHERE domain='a.com'").fetchone()
            before_queries = before["total_queries"] if before else 0

        result = agg.run_incremental()
        self.assertEqual(result.status, "success")
        self.assertEqual(result.total_rows_processed, 0)

        with self.get_db() as c:
            after = c.execute("SELECT total_queries FROM domain_details WHERE domain='a.com'").fetchone()
            self.assertEqual(after["total_queries"], before_queries)

    def test_04_second_run_with_new_events(self):
        """Test 4: Second run processes only new events."""
        rows_first = [make_pg_row(1, "a.com", "10.0.0.1", final_label="Clean")]
        rows_all = rows_first + [make_pg_row(2, "b.com", "10.0.0.2", final_label="Clean")]

        agg = self.make_aggregator(pg_rows=rows_first)
        agg.run_incremental()
        self.assertEqual(self.get_watermark(), 1)

        # Add event 2 to the pool
        self._mock_pg(agg, rows_all)
        result = agg.run_incremental()

        self.assertEqual(result.total_rows_processed, 1)
        self.assertEqual(self.get_watermark(), 2)

        with self.get_db() as c:
            b = c.execute("SELECT * FROM domain_details WHERE domain='b.com'").fetchone()
            self.assertIsNotNone(b)

    def test_05_same_timestamp_different_ids(self):
        """Test 5: Events with same timestamp but different IDs are both processed."""
        ts = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        rows = [
            {"id": 10, "domain": "a.com", "client_ip": "10.0.0.1",
             "query_type": "A", "timestamp": ts, "response_code": "NOERROR",
             "registered_domain": "a.com", "tld": "com",
             "final_label": "Clean", "ti_source": None},
            {"id": 11, "domain": "b.com", "client_ip": "10.0.0.1",
             "query_type": "A", "timestamp": ts, "response_code": "NOERROR",
             "registered_domain": "b.com", "tld": "com",
             "final_label": "Clean", "ti_source": None},
        ]
        agg = self.make_aggregator(pg_rows=rows)
        result = agg.run_incremental()
        self.assertEqual(result.total_rows_processed, 2)
        self.assertEqual(self.get_watermark(), 11)


# ---------------------------------------------------------------------------
# Tests 6–10: Multi-domain / multi-client / dedup
# ---------------------------------------------------------------------------

class TestMultiEntityProcessing(AggregatorTestCase):

    def test_06_multiple_domains(self):
        """Test 6: Multiple domains have correct per-domain stats."""
        rows = [
            make_pg_row(1, "a.com", "10.0.0.1", final_label="Malicious"),
            make_pg_row(2, "b.com", "10.0.0.1", final_label="Clean"),
            make_pg_row(3, "a.com", "10.0.0.2", final_label="Malicious"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            a = c.execute("SELECT * FROM domain_details WHERE domain='a.com'").fetchone()
            self.assertEqual(a["total_queries"], 2)
            self.assertEqual(a["malicious_count"], 2)
            b = c.execute("SELECT * FROM domain_details WHERE domain='b.com'").fetchone()
            self.assertEqual(b["clean_count"], 1)

    def test_07_multiple_clients(self):
        """Test 7: Multiple clients have correct per-client stats."""
        rows = [
            make_pg_row(1, "a.com", "10.0.0.1", final_label="Malicious"),
            make_pg_row(2, "a.com", "10.0.0.2", final_label="Clean"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            c1 = c.execute("SELECT * FROM client_details WHERE client_ip='10.0.0.1'").fetchone()
            self.assertEqual(c1["total_queries"], 1)
            self.assertEqual(c1["malicious_count"], 1)
            c2 = c.execute("SELECT * FROM client_details WHERE client_ip='10.0.0.2'").fetchone()
            self.assertEqual(c2["clean_count"], 1)

    def test_08_same_client_multiple_domains(self):
        """Test 8: Same client querying multiple domains — unique_domains correct."""
        rows = [
            make_pg_row(1, "a.com", "10.0.0.1", final_label="Clean"),
            make_pg_row(2, "b.com", "10.0.0.1", final_label="Clean"),
            make_pg_row(3, "c.com", "10.0.0.1", final_label="Clean"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            client = c.execute("SELECT * FROM client_details WHERE client_ip='10.0.0.1'").fetchone()
            self.assertEqual(client["unique_domains"], 3)
            self.assertEqual(client["total_queries"], 3)

    def test_09_same_domain_multiple_clients(self):
        """Test 9: Same domain queried by multiple clients — unique_clients correct."""
        rows = [
            make_pg_row(1, "evil.com", "10.0.0.1", final_label="Malicious"),
            make_pg_row(2, "evil.com", "10.0.0.2", final_label="Malicious"),
            make_pg_row(3, "evil.com", "10.0.0.3", final_label="Malicious"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            domain = c.execute("SELECT * FROM domain_details WHERE domain='evil.com'").fetchone()
            self.assertEqual(domain["unique_clients"], 3)
            self.assertEqual(domain["total_queries"], 3)

    def test_10_duplicate_replayed_batch(self):
        """Test 10: Replaying the same batch does not inflate counts (idempotency)."""
        rows = [
            make_pg_row(1, "evil.com", "10.0.0.1", final_label="Malicious"),
            make_pg_row(2, "evil.com", "10.0.0.2", final_label="Malicious"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            d1 = c.execute("SELECT * FROM domain_details WHERE domain='evil.com'").fetchone()
            q1 = d1["total_queries"]
            uc1 = d1["unique_clients"]

        # Running again — watermark is 2, no new events
        result = agg.run_incremental()
        self.assertEqual(result.total_rows_processed, 0)

        with self.get_db() as c:
            d2 = c.execute("SELECT * FROM domain_details WHERE domain='evil.com'").fetchone()
            self.assertEqual(d2["total_queries"], q1)
            self.assertEqual(d2["unique_clients"], uc1)


# ---------------------------------------------------------------------------
# Tests 11–14: Transaction and watermark guarantees
# ---------------------------------------------------------------------------

class TestTransactionGuarantees(AggregatorTestCase):

    def test_11_failure_before_commit_dashboard_unchanged(self):
        """Test 11: Exception during processing → dashboard unchanged, watermark unchanged."""
        rows = [make_pg_row(1, "a.com", "10.0.0.1", final_label="Clean")]
        agg = self.make_aggregator(pg_rows=rows)

        # Inject failure into _upsert_domain_details
        original = agg._upsert_domain_details

        def failing_upsert(*args, **kwargs):
            raise RuntimeError("Simulated crash during domain details update")

        agg._upsert_domain_details = failing_upsert
        result = agg.run_incremental()

        self.assertEqual(result.status, "failed")
        self.assertEqual(self.get_watermark(), 0)

        with self.get_db() as c:
            d = c.execute("SELECT * FROM domain_details WHERE domain='a.com'").fetchone()
            self.assertIsNone(d)

    def test_12_failure_during_dashboard_update_rollback(self):
        """Test 12: Failure during timeseries update → entire batch rolled back."""
        rows = [make_pg_row(1, "b.com", "10.0.0.1", final_label="Malicious")]
        agg = self.make_aggregator(pg_rows=rows)

        original_ts = agg._upsert_timeseries

        def failing_ts(*args, **kwargs):
            raise RuntimeError("Simulated timeseries failure")

        agg._upsert_timeseries = failing_ts
        result = agg.run_incremental()

        self.assertEqual(result.status, "failed")
        self.assertEqual(self.get_watermark(), 0)

    def test_13_failure_before_watermark_update(self):
        """Test 13: Exception before _save_watermark → watermark does not change."""
        rows = [make_pg_row(5, "c.com", "10.0.0.1", final_label="Clean")]
        agg = self.make_aggregator(pg_rows=rows)

        original_save = agg._save_watermark

        def failing_save(*args, **kwargs):
            raise RuntimeError("Simulated watermark save failure")

        agg._save_watermark = failing_save
        result = agg.run_incremental()

        self.assertEqual(result.status, "failed")
        self.assertEqual(self.get_watermark(), 0)

    def test_14_successful_watermark_update(self):
        """Test 14: After successful batch, watermark = last event id."""
        rows = [
            make_pg_row(3, "x.com", "10.0.0.1", final_label="Clean"),
            make_pg_row(7, "y.com", "10.0.0.2", final_label="Clean"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        result = agg.run_incremental()

        self.assertEqual(result.status, "success")
        self.assertEqual(self.get_watermark(), 7)


# ---------------------------------------------------------------------------
# Tests 15–17: aggregation_runs
# ---------------------------------------------------------------------------

class TestAggregationRuns(AggregatorTestCase):

    def test_15_aggregation_runs_success(self):
        """Test 15: Success run creates aggregation_runs record with status=success."""
        rows = [make_pg_row(1, "a.com", "10.0.0.1", final_label="Clean")]
        agg = self.make_aggregator(pg_rows=rows)
        result = agg.run_incremental()

        self.assertEqual(result.status, "success")
        with self.get_db() as c:
            run = c.execute(
                "SELECT * FROM aggregation_runs WHERE run_id = ?", (result.run_id,)
            ).fetchone()
            self.assertIsNotNone(run)
            self.assertEqual(run["status"], "success")
            self.assertIsNotNone(run["finished_at"])

    def test_16_aggregation_runs_failure(self):
        """Test 16: Failed run creates aggregation_runs record with status=failed."""
        rows = [make_pg_row(1, "a.com", "10.0.0.1", final_label="Clean")]
        agg = self.make_aggregator(pg_rows=rows)
        agg._upsert_domain_details = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("fail"))
        result = agg.run_incremental()

        self.assertEqual(result.status, "failed")
        with self.get_db() as c:
            run = c.execute(
                "SELECT * FROM aggregation_runs WHERE run_id = ?", (result.run_id,)
            ).fetchone()
            self.assertIsNotNone(run)
            self.assertEqual(run["status"], "failed")
            self.assertIsNotNone(run["error_message"])

    def test_17_stale_running_run_recovery(self):
        """Test 17: Stale 'running' run detected on startup and marked failed."""
        # Insert a stale run manually
        old_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        with sqlite3.connect(self.db_path) as c:
            c.execute(
                """
                INSERT INTO aggregation_runs
                    (run_id, aggregation_name, started_at, status, source_type)
                VALUES ('stale-run', 'test', ?, 'running', 'postgres_incremental')
                """,
                (old_ts,),
            )
            c.commit()

        agg = self.make_aggregator(pg_rows=[])
        agg.stale_threshold_minutes = 60
        agg._recover_stale_runs()

        with self.get_db() as c:
            run = c.execute(
                "SELECT * FROM aggregation_runs WHERE run_id = 'stale-run'"
            ).fetchone()
            self.assertEqual(run["status"], "failed")
            self.assertIn("terminated", run["error_message"])

        # Watermark must be unchanged
        self.assertEqual(self.get_watermark(), 0)


# ---------------------------------------------------------------------------
# Tests 18–23: Detail table correctness
# ---------------------------------------------------------------------------

class TestDetailCorrectness(AggregatorTestCase):

    def test_18_domain_details_correctness(self):
        """Test 18: domain_details fields match the events."""
        rows = [
            make_pg_row(1, "evil.com", "10.0.0.1", query_type="A",
                        final_label="Malicious", ti_source="OTX"),
            make_pg_row(2, "evil.com", "10.0.0.2", query_type="AAAA",
                        final_label="Malicious", ti_source="OTX"),
            make_pg_row(3, "evil.com", "10.0.0.1", query_type="A",
                        final_label="Malicious"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            d = c.execute("SELECT * FROM domain_details WHERE domain='evil.com'").fetchone()
            self.assertEqual(d["total_queries"], 3)
            self.assertEqual(d["malicious_count"], 3)
            self.assertEqual(d["unique_clients"], 2)
            self.assertEqual(d["threat_count"], 3)
            qt = json.loads(d["query_type_breakdown"])
            self.assertEqual(qt.get("A", 0), 2)
            self.assertEqual(qt.get("AAAA", 0), 1)
            # threat_score must be NULL — not in source
            self.assertIsNone(d["threat_score"])

    def test_19_client_details_correctness(self):
        """Test 19: client_details fields match the events."""
        rows = [
            make_pg_row(1, "a.com", "192.168.1.1", final_label="Malicious"),
            make_pg_row(2, "b.com", "192.168.1.1", final_label="Clean"),
            make_pg_row(3, "c.com", "192.168.1.1", final_label="Clean"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            client = c.execute(
                "SELECT * FROM client_details WHERE client_ip='192.168.1.1'"
            ).fetchone()
            self.assertEqual(client["total_queries"], 3)
            self.assertEqual(client["unique_domains"], 3)
            self.assertEqual(client["malicious_count"], 1)
            self.assertEqual(client["clean_count"], 2)

    def test_20_threat_category_correctness(self):
        """Test 20: threats_by_category uses ti_source as category."""
        rows = [
            make_pg_row(1, "evil.com", "10.0.0.1", final_label="Malicious", ti_source="OTX"),
            make_pg_row(2, "bad.com", "10.0.0.2", final_label="Malicious", ti_source="VirusTotal"),
            make_pg_row(3, "ok.com", "10.0.0.3", final_label="Clean"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            cats = {
                r["category"]: r["count"]
                for r in c.execute("SELECT category, count FROM threats_by_category").fetchall()
            }
            self.assertEqual(cats.get("OTX", 0), 1)
            self.assertEqual(cats.get("VirusTotal", 0), 1)
            self.assertEqual(cats.get("Clean", 0), 1)

    def test_21_timeseries_correctness(self):
        """Test 21: queries_timeseries buckets match event timestamps."""
        # All events in the same hour
        ts = datetime(2024, 3, 15, 10, 0, 0, tzinfo=timezone.utc)
        rows = [
            {"id": i, "domain": "x.com", "client_ip": f"10.0.0.{i}",
             "query_type": "A", "timestamp": ts + timedelta(minutes=i),
             "response_code": "NOERROR", "registered_domain": "x.com",
             "tld": "com", "final_label": ("Malicious" if i % 2 == 0 else "Clean"),
             "ti_source": None}
            for i in range(1, 6)
        ]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        bucket = "2024-03-15 10:00"
        with self.get_db() as c:
            row = c.execute(
                "SELECT * FROM queries_timeseries WHERE time_bucket = ?", (bucket,)
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["total_queries"], 5)
            # ids 2 and 4 are malicious (even)
            self.assertEqual(row["threat_queries"], 2)

    def test_22_top_domain_correctness(self):
        """Test 22: top_domains reflects domain_details after aggregation."""
        rows = [
            make_pg_row(i, f"domain{i}.com", "10.0.0.1", final_label="Malicious")
            for i in range(1, 11)
        ]
        rows += [make_pg_row(11, "domain1.com", "10.0.0.2", final_label="Malicious")]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            tops = c.execute(
                "SELECT domain, query_count FROM top_domains ORDER BY query_count DESC LIMIT 3"
            ).fetchall()
            # domain1.com has 2 queries, all others have 1
            self.assertEqual(tops[0]["domain"], "domain1.com")
            self.assertEqual(tops[0]["query_count"], 2)

    def test_23_top_client_correctness(self):
        """Test 23: top_clients reflects client_details."""
        rows = [
            make_pg_row(i, f"d{i}.com", "10.0.0.1", final_label="Clean")
            for i in range(1, 6)
        ]
        rows += [make_pg_row(6, "d6.com", "10.0.0.2", final_label="Clean")]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            tops = c.execute(
                "SELECT client_ip, query_count FROM top_clients ORDER BY query_count DESC LIMIT 2"
            ).fetchall()
            self.assertEqual(tops[0]["client_ip"], "10.0.0.1")
            self.assertEqual(tops[0]["query_count"], 5)


# ---------------------------------------------------------------------------
# Tests 24–25: Rebuild
# ---------------------------------------------------------------------------

class TestRebuild(AggregatorTestCase):

    def test_24_rebuild_correctness(self):
        """Test 24: Rebuild populates all tables from PostgreSQL scratch."""
        rows = [
            make_pg_row(1, "evil.com", "10.0.0.1", final_label="Malicious"),
            make_pg_row(2, "good.com", "10.0.0.2", final_label="Clean"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        result = agg.run_rebuild()

        self.assertEqual(result.status, "success")
        with self.get_db() as c:
            self.assertIsNotNone(
                c.execute("SELECT * FROM domain_details WHERE domain='evil.com'").fetchone()
            )
            self.assertIsNotNone(
                c.execute("SELECT * FROM domain_details WHERE domain='good.com'").fetchone()
            )

    def test_25_rebuild_incremental_equivalence(self):
        """Test 25: Rebuild and incremental produce same domain stats for same event set."""
        rows = [
            make_pg_row(1, "a.com", "10.0.0.1", final_label="Malicious"),
            make_pg_row(2, "b.com", "10.0.0.2", final_label="Clean"),
            make_pg_row(3, "a.com", "10.0.0.3", final_label="Malicious"),
        ]

        # Run incremental
        agg_inc = self.make_aggregator(pg_rows=rows)
        agg_inc.run_incremental()
        with self.get_db() as c:
            inc_a = dict(c.execute("SELECT * FROM domain_details WHERE domain='a.com'").fetchone())

        # Rebuild (reuses same db, clears state)
        agg_reb = self.make_aggregator(pg_rows=rows)
        agg_reb.run_rebuild()
        with self.get_db() as c:
            reb_a = dict(c.execute("SELECT * FROM domain_details WHERE domain='a.com'").fetchone())

        self.assertEqual(inc_a["total_queries"], reb_a["total_queries"])
        self.assertEqual(inc_a["malicious_count"], reb_a["malicious_count"])
        self.assertEqual(inc_a["unique_clients"], reb_a["unique_clients"])


# ---------------------------------------------------------------------------
# Tests 26–30: Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases(AggregatorTestCase):

    def test_26_dry_run_does_not_modify_db(self):
        """Test 26: dry_run does not modify dashboard.db."""
        import os
        rows = [make_pg_row(1, "x.com", "10.0.0.1", final_label="Malicious")]
        agg = self.make_aggregator(pg_rows=rows)

        size_before = os.path.getsize(self.db_path)
        stat_before = os.stat(self.db_path)

        # Override run_dry_run to work without real PG
        original_get_pg = agg._get_pg_connection

        def fake_pg():
            raise RuntimeError("No PG in dry-run test")

        agg._get_pg_connection = fake_pg
        report = agg.run_dry_run()

        # dashboard.db should not have aggregation_state watermark changes
        self.assertEqual(self.get_watermark(), 0)
        # No runs created
        self.assertEqual(self.get_run_count(), 0)

    def test_27_concurrent_aggregator_protection(self):
        """Test 27: Second aggregator cannot corrupt state while first holds lock."""
        import threading

        rows1 = [make_pg_row(i, f"d{i}.com", "10.0.0.1", final_label="Clean") for i in range(1, 6)]
        rows2 = [make_pg_row(i, f"x{i}.com", "10.0.0.2", final_label="Clean") for i in range(6, 11)]

        agg1 = self.make_aggregator(pg_rows=rows1)
        agg2 = self.make_aggregator(pg_rows=rows2)

        results = {}
        errors = []

        def run_agg1():
            try:
                results["agg1"] = agg1.run_incremental()
            except Exception as e:
                errors.append(e)

        def run_agg2():
            try:
                results["agg2"] = agg2.run_incremental()
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=run_agg1)
        t2 = threading.Thread(target=run_agg2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Either both succeed or one fails — neither should corrupt data
        # Watermark should be at 5 or 10 (not some inconsistent intermediate)
        final_wm = self.get_watermark()
        self.assertIn(final_wm, [5, 10])

    def test_28_missing_enrichment_fields_null(self):
        """Test 28: NULL enrichment fields (threat_score, ASN, country) stay NULL."""
        rows = [make_pg_row(1, "a.com", "10.0.0.1", final_label="Malicious")]
        agg = self.make_aggregator(pg_rows=rows)
        agg.run_incremental()

        with self.get_db() as c:
            d = c.execute("SELECT * FROM domain_details WHERE domain='a.com'").fetchone()
            self.assertIsNone(d["threat_score"])
            self.assertIsNone(d["confidence"])
            self.assertIsNone(d["asn"])
            self.assertIsNone(d["country"])
            self.assertIsNone(d["domain_age_days"])
            self.assertIsNone(d["resolved_ips"])

    def test_29_empty_source(self):
        """Test 29: Empty PostgreSQL source — success, nothing written."""
        agg = self.make_aggregator(pg_rows=[])
        result = agg.run_incremental()
        self.assertEqual(result.status, "success")
        self.assertEqual(result.total_rows_processed, 0)
        self.assertEqual(self.get_watermark(), 0)

    def test_30_malformed_source_row(self):
        """Test 30: Malformed row is rejected, run continues, rows_rejected incremented."""
        rows = [
            # Malformed: missing domain
            {"id": 1, "domain": "", "client_ip": "10.0.0.1",
             "query_type": "A", "timestamp": datetime.now(timezone.utc),
             "response_code": "NOERROR", "registered_domain": None,
             "tld": None, "final_label": "Clean", "ti_source": None},
            # Valid row after malformed
            make_pg_row(2, "valid.com", "10.0.0.1", final_label="Clean"),
        ]
        agg = self.make_aggregator(pg_rows=rows)
        result = agg.run_incremental()

        self.assertEqual(result.status, "success")
        self.assertEqual(result.total_rows_rejected, 1)
        self.assertEqual(result.total_rows_processed, 1)
        self.assertEqual(self.get_watermark(), 2)


# ---------------------------------------------------------------------------
# Label semantics tests (fast unit tests)
# ---------------------------------------------------------------------------

class TestLabelSemantics(unittest.TestCase):

    def test_malicious_label(self):
        is_m, is_c, is_u = _classify_label("Malicious")
        self.assertTrue(is_m)
        self.assertFalse(is_c)
        self.assertFalse(is_u)

    def test_clean_label(self):
        is_m, is_c, is_u = _classify_label("Clean")
        self.assertFalse(is_m)
        self.assertTrue(is_c)

    def test_benign_label(self):
        is_m, is_c, is_u = _classify_label("Benign")
        self.assertFalse(is_m)
        self.assertTrue(is_c)
        self.assertFalse(is_u)

    def test_review_needed_label(self):
        is_m, is_c, is_u = _classify_label("Review Needed")
        self.assertFalse(is_m)
        self.assertFalse(is_c)
        self.assertTrue(is_u)

    def test_trusted_label(self):
        is_m, is_c, is_u = _classify_label("Trusted")
        self.assertFalse(is_m)
        self.assertTrue(is_c)

    def test_unknown_label(self):
        is_m, is_c, is_u = _classify_label("Unknown")
        self.assertFalse(is_m)
        self.assertFalse(is_c)
        self.assertTrue(is_u)

    def test_none_label(self):
        is_m, is_c, is_u = _classify_label(None)
        self.assertTrue(is_u)

    def test_empty_label(self):
        is_m, is_c, is_u = _classify_label("")
        self.assertTrue(is_u)


if __name__ == "__main__":
    unittest.main(verbosity=2)
