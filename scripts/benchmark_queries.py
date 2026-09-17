#!/usr/bin/env python3
"""
scripts/benchmark_queries.py
============================
Benchmarks PostgreSQL query performance with `EXPLAIN (ANALYZE, BUFFERS)`.
Measures planning time, execution time, buffer hits, and scan types.
"""

import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from aggregator.config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
import psycopg2


def benchmark():
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )

    benchmarks = [
        (
            "1. Hourly Rollup Summary (telemetry_hourly_rollup)",
            """
            EXPLAIN (ANALYZE, BUFFERS)
            SELECT 
                SUM(total_queries), 
                SUM(clean_queries), 
                SUM(malicious_queries),
                SUM(suspicious_queries),
                SUM(unknown_queries)
            FROM telemetry_hourly_rollup;
            """,
        ),
        (
            "2. Windowed Distinct Entities (24h Index-Scan on domain_query_history)",
            """
            EXPLAIN (ANALYZE, BUFFERS)
            SELECT 
                COUNT(DISTINCT domain), 
                COUNT(DISTINCT client_ip)
            FROM domain_query_history
            WHERE timestamp >= NOW() - INTERVAL '24 hours';
            """,
        ),
        (
            "3. Windowed Top Malicious Domains (24h Index-Scan on domain_query_history)",
            """
            EXPLAIN (ANALYZE, BUFFERS)
            SELECT domain, COUNT(*) AS mal_count
            FROM domain_query_history
            WHERE final_label = 'Malicious'
              AND timestamp >= NOW() - INTERVAL '24 hours'
            GROUP BY domain
            ORDER BY mal_count DESC
            LIMIT 20;
            """,
        ),
        (
            "4. Lifetime Top Domains Ranking (domain_profiles)",
            """
            EXPLAIN (ANALYZE, BUFFERS)
            SELECT domain, total_queries, last_label
            FROM domain_profiles
            ORDER BY total_queries DESC
            LIMIT 20;
            """,
        ),
        (
            "5. Multi-Day Distinct Domains (telemetry_daily_domain_rollup)",
            """
            EXPLAIN (ANALYZE, BUFFERS)
            SELECT COUNT(DISTINCT domain)
            FROM telemetry_daily_domain_rollup
            WHERE bucket_date >= CURRENT_DATE - 7;
            """,
        ),
    ]

    print("=" * 80)
    print("DNSNetra PostgreSQL Query Performance Benchmark (EXPLAIN ANALYZE, BUFFERS)")
    print("=" * 80)

    with conn.cursor() as cur:
        for title, query in benchmarks:
            print(f"\n>>> {title}")
            cur.execute(query)
            plan_lines = [r[0] for r in cur.fetchall()]
            for line in plan_lines:
                print(f"    {line}")

    conn.close()
    print("\n" + "=" * 80)


if __name__ == "__main__":
    benchmark()
