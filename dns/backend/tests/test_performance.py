"""
test_performance.py
====================
Performance benchmarks for IncrementalAggregator.

Measures:
  - events/sec throughput
  - batch processing duration
  - total aggregation duration
  - SQLite write duration

Targets:
  - 1,000 events   → < 2s
  - 10,000 events  → < 10s
  - 100,000 events → < 60s

Run with:
    cd backend && .venv/bin/python -m pytest tests/test_performance.py -v -s
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
import unittest

BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))

from dashboard_aggregation.incremental_aggregator import IncrementalAggregator
from dashboard_aggregation.schema import initialize_dashboard_db


def generate_rows(n: int, start_id: int = 1) -> list[dict[str, Any]]:
    """Generate n synthetic domain_query_history rows."""
    labels = ["Malicious", "Clean", "Trusted", "Unknown"]
    ti_sources = ["OTX", "VirusTotal", None]
    domains = [f"domain{i % 100}.com" for i in range(n)]
    clients = [f"10.0.{(i % 256)}.{(i // 256) % 256}" for i in range(n)]
    base_ts = datetime(2024, 1, 1, tzinfo=timezone.utc)

    rows = []
    for i in range(n):
        rows.append({
            "id": start_id + i,
            "domain": domains[i],
            "client_ip": clients[i],
            "query_type": ["A", "AAAA", "MX", "TXT"][i % 4],
            "timestamp": base_ts + timedelta(minutes=i),
            "response_code": ["NOERROR", "NXDOMAIN", "SERVFAIL"][i % 3],
            "registered_domain": domains[i],
            "tld": "com",
            "final_label": labels[i % len(labels)],
            "ti_source": ti_sources[i % len(ti_sources)],
        })
    return rows


class PerformanceTest(unittest.TestCase):

    def _run_benchmark(self, n_events: int, label: str, time_limit_s: float):
        """Generic benchmark runner."""
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()

        try:
            initialize_dashboard_db(tmp.name)
            rows = generate_rows(n_events)

            agg = IncrementalAggregator(
                dashboard_db_path=tmp.name,
                aggregation_name="perf_test",
                batch_size=10000,
            )
            mock_conn = object()
            agg._get_pg_connection = lambda: mock_conn

            def fake_fetch(pg_conn, watermark_id: int) -> list[dict]:
                return [r for r in rows if r["id"] > watermark_id][:agg.batch_size]

            def fake_count(pg_conn, watermark_id: int) -> int:
                return len([r for r in rows if r["id"] > watermark_id])

            agg._fetch_batch = fake_fetch
            agg._count_pending_events = fake_count

            start = time.perf_counter()
            result = agg.run_incremental()
            elapsed = time.perf_counter() - start

            throughput = n_events / elapsed if elapsed > 0 else float("inf")

            print(f"\n{'=' * 60}")
            print(f"  Benchmark: {label}")
            print(f"  Events:    {n_events:,}")
            print(f"  Status:    {result.status}")
            print(f"  Processed: {result.total_rows_processed:,}")
            print(f"  Rejected:  {result.total_rows_rejected:,}")
            print(f"  Batches:   {result.batches_processed}")
            print(f"  Duration:  {elapsed:.3f}s")
            print(f"  Throughput:{throughput:,.0f} events/sec")
            print(f"  Target:    <{time_limit_s}s")
            print(f"  {'✓ PASS' if elapsed < time_limit_s else '✗ SLOW'}")
            print(f"{'=' * 60}")

            self.assertEqual(result.status, "success")
            self.assertEqual(result.total_rows_processed, n_events)
            self.assertLess(
                elapsed, time_limit_s,
                f"{label}: {elapsed:.3f}s exceeded target of {time_limit_s}s "
                f"({throughput:,.0f} events/sec)",
            )

        finally:
            os.unlink(tmp.name)

    def test_perf_1k_events(self):
        """1,000 events should complete in < 2s."""
        self._run_benchmark(1_000, "1K events", time_limit_s=2.0)

    def test_perf_10k_events(self):
        """10,000 events should complete in < 10s."""
        self._run_benchmark(10_000, "10K events", time_limit_s=10.0)

    def test_perf_100k_events(self):
        """100,000 events should complete in < 60s."""
        self._run_benchmark(100_000, "100K events", time_limit_s=60.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
