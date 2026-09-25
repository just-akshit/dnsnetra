"""
Time-Window Analytics Performance Benchmark
============================================
Benchmarks database query execution time, API endpoint response time,
P50, and P95 latencies across rolling presets and custom historical windows.

Usage:
    cd backend && .venv/bin/python scripts/benchmark_time_window_analytics.py
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from statistics import median
from typing import Dict, List

from dotenv import load_dotenv

BACKEND_DIR = Path(__file__).parent.parent
sys.path.insert(0, str(BACKEND_DIR))
load_dotenv(BACKEND_DIR / ".env")

from fastapi.testclient import TestClient
from api.main import app
from analytics.domain_analytics import DomainAnalyticsService
from domain_profiling.connection import get_db_cursor


def percentile(data: List[float], p: float) -> float:
    """Calculates the p-th percentile (0 <= p <= 100)."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_data) - 1)
    d = k - f
    return sorted_data[f] + d * (sorted_data[c] - sorted_data[f])


def run_benchmark(iterations: int = 50) -> Dict[str, Any]:
    print("=" * 80)
    print("PHASE 4.2 TIME-WINDOW DNS ANALYTICS BENCHMARK")
    print("=" * 80)
    print(f"Executing {iterations} iterations per scenario...\n")

    client = TestClient(app)
    scenarios = [
        ("Last 5 Minutes Preset (5m)", "/api/v1/analytics/domains?window=5m"),
        ("Last 15 Minutes Preset (15m)", "/api/v1/analytics/domains?window=15m"),
        ("Last 60 Minutes Preset (60m)", "/api/v1/analytics/domains?window=60m"),
        ("Custom 24h Historical Range", "/api/v1/analytics/domains?start=2026-08-22T00:00:00Z&end=2026-08-23T00:00:00Z"),
        ("Custom 7-Day Historical Range", "/api/v1/analytics/domains?start=2026-08-17T00:00:00Z&end=2026-08-24T00:00:00Z"),
    ]

    results = []

    for name, url in scenarios:
        latencies_ms: List[float] = []

        # Warm up
        for _ in range(3):
            client.get(url)

        # Benchmark
        for _ in range(iterations):
            t0 = time.perf_counter()
            res = client.get(url)
            t1 = time.perf_counter()

            if res.status_code != 200:
                print(f"Error executing {url}: {res.status_code} - {res.text}")
                continue

            latencies_ms.append((t1 - t0) * 1000.0)

        p50 = percentile(latencies_ms, 50)
        p95 = percentile(latencies_ms, 95)
        p99 = percentile(latencies_ms, 99)
        avg = sum(latencies_ms) / len(latencies_ms) if latencies_ms else 0.0
        min_lat = min(latencies_ms) if latencies_ms else 0.0
        max_lat = max(latencies_ms) if latencies_ms else 0.0

        results.append({
            "scenario": name,
            "min_ms": min_lat,
            "avg_ms": avg,
            "p50_ms": p50,
            "p95_ms": p95,
            "p99_ms": p99,
            "max_ms": max_lat,
        })

        print(f"Scenario: {name}")
        print(f"  Min: {min_lat:.2f}ms | Avg: {avg:.2f}ms | P50: {p50:.2f}ms | P95: {p95:.2f}ms | P99: {p99:.2f}ms | Max: {max_lat:.2f}ms")
        print("-" * 80)

    # Database EXPLAIN ANALYZE verification
    print("\nDATABASE QUERY PLAN VERIFICATION (EXPLAIN ANALYZE BUFFERS):")
    with get_db_cursor() as cur:
        cur.execute("""
            EXPLAIN (ANALYZE, BUFFERS)
            SELECT 
                COUNT(*) AS total_queries,
                COUNT(DISTINCT domain) AS unique_fqdns,
                COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_registered_domains,
                COUNT(DISTINCT client_ip) AS unique_clients
            FROM domain_query_history
            WHERE timestamp >= NOW() - INTERVAL '15 minutes' AND timestamp < NOW();
        """)
        for row in cur.fetchall():
            print("  ", row[0])

    print("\nBenchmark completed successfully.")
    return results


if __name__ == "__main__":
    run_benchmark(iterations=30)
