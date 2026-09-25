"""
verify_reports_live.py
======================
Phase 12 Verification Script:
1. Tests FastAPI reporting endpoints against live PostgreSQL dns_threat_detection.
2. Compares raw SQL counts directly with FastAPI API response metrics.
3. Tests live DNS pipeline ingestion and verifies that new events reflect immediately
   in the reports API without manual data synchronization.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

from api.main import app
from analytics.time_window import resolve_time_window, format_iso8601_utc
from domain_profiling.connection import get_db_connection

client = TestClient(app)


def verify_live_reports_matching_sql():
    print("\n--- 1. Comparing FastAPI Report Endpoints directly against PostgreSQL SQL ---")
    start = "2026-08-28T00:00:00Z"
    end = "2026-08-29T00:00:00Z"
    tw = resolve_time_window(start=start, end=end)

    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Raw SQL metrics
            cur.execute("""
                SELECT COUNT(*) AS total_q,
                       COUNT(DISTINCT client_ip) AS unique_c,
                       COUNT(DISTINCT domain) AS unique_d,
                       COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS mal_q
                FROM domain_query_history
                WHERE timestamp >= %s AND timestamp < %s;
            """, (tw.start, tw.end))
            sql_summary = cur.fetchone()

            # SQL malicious domains count
            cur.execute("""
                SELECT COUNT(DISTINCT domain) AS mal_d_count
                FROM domain_query_history
                WHERE timestamp >= %s AND timestamp < %s
                  AND LOWER(COALESCE(final_label, '')) = 'malicious';
            """, (tw.start, tw.end))
            sql_mal_domains_total = cur.fetchone()["mal_d_count"]

    # Call FastAPI endpoints
    rep_resp = client.get(f"/api/v1/reports?start_time={start}&end_time={end}")
    assert rep_resp.status_code == 200
    api_summary = rep_resp.json()["data"]["summary"]

    print(f"  SQL total_queries:     {sql_summary['total_q']} | API: {api_summary['total_queries']}")
    print(f"  SQL malicious_queries: {sql_summary['mal_q']} | API: {api_summary['malicious_queries']}")
    print(f"  SQL unique_domains:    {sql_summary['unique_d']} | API: {api_summary['unique_domains']}")
    print(f"  SQL unique_clients:    {sql_summary['unique_c']} | API: {api_summary['unique_clients']}")

    assert sql_summary["total_q"] == api_summary["total_queries"]
    assert sql_summary["mal_q"] == api_summary["malicious_queries"]
    assert sql_summary["unique_d"] == api_summary["unique_domains"]
    assert sql_summary["unique_c"] == api_summary["unique_clients"]
    print("  => Summary metrics match 100%!")

    # Verify Malicious Domains endpoint count
    mal_resp = client.get(f"/api/v1/reports/malicious-domains?start_time={start}&end_time={end}")
    assert mal_resp.status_code == 200
    api_mal_total = mal_resp.json()["meta"]["total"]
    print(f"  SQL malicious_domains total: {sql_mal_domains_total} | API: {api_mal_total}")
    assert sql_mal_domains_total == api_mal_total
    print("  => Malicious domains count matches 100%!")


def verify_live_ingestion_reflection():
    print("\n--- 2. Ingesting Live DNS Query Event & Verifying Instant Report Reflection ---")
    now_utc = datetime.now(timezone.utc)
    test_domain = "live-report-verification-test.example.com"
    test_client = "192.168.99.88"

    # Query before count
    start_iso = format_iso8601_utc(now_utc - timedelta(minutes=5))
    end_iso = format_iso8601_utc(now_utc + timedelta(minutes=5))

    before_resp = client.get(f"/api/v1/reports?start_time={start_iso}&end_time={end_iso}")
    before_total = before_resp.json()["data"]["summary"]["total_queries"]

    # Ingest event directly into PostgreSQL domain_query_history
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO domain_query_history (
                    domain, client_ip, query_type, timestamp, response_code, registered_domain, tld, final_label, ti_source
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
            """, (test_domain, test_client, "A", now_utc, "NOERROR", "example.com", "com", "Malicious", "test-live-verification"))
        conn.commit()
    print(f"  Ingested DNS event: domain='{test_domain}', client='{test_client}', label='Malicious'")

    # Query after count immediately
    after_resp = client.get(f"/api/v1/reports?start_time={start_iso}&end_time={end_iso}")
    after_total = after_resp.json()["data"]["summary"]["total_queries"]
    print(f"  Reports total_queries before: {before_total} | after: {after_total}")
    assert after_total == before_total + 1

    # Verify the event appears in /reports/queries and /reports/flagged
    queries_resp = client.get(f"/api/v1/reports/queries?start_time={start_iso}&end_time={end_iso}&search={test_domain}")
    assert queries_resp.status_code == 200
    assert len(queries_resp.json()["data"]) >= 1
    assert queries_resp.json()["data"][0]["domain"] == test_domain

    flagged_resp = client.get(f"/api/v1/reports/flagged?start_time={start_iso}&end_time={end_iso}&search={test_domain}")
    assert flagged_resp.status_code == 200
    assert len(flagged_resp.json()["data"]) >= 1
    assert flagged_resp.json()["data"][0]["domain"] == test_domain
    print("  => Ingested event reflected immediately across /reports, /queries, and /flagged!")


def verify_live_entity_reports_matching_sql():
    print("\n--- 3. Verifying Entity-Centric Reports directly against PostgreSQL SQL ---")
    tw = resolve_time_window(window="7d")
    test_client_ip = "192.168.1.104"
    test_domain = "stackoverflow.com"

    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Client SQL
            cur.execute("""
                SELECT COUNT(*) AS total_q,
                       COUNT(DISTINCT domain) AS unique_d
                FROM domain_query_history
                WHERE client_ip = %s AND timestamp >= %s AND timestamp < %s;
            """, (test_client_ip, tw.start, tw.end))
            client_sql = cur.fetchone()

            # Domain SQL
            cur.execute("""
                SELECT COUNT(*) AS total_q,
                       COUNT(DISTINCT client_ip) AS unique_c
                FROM domain_query_history
                WHERE domain = %s AND timestamp >= %s AND timestamp < %s;
            """, (test_domain, tw.start, tw.end))
            domain_sql = cur.fetchone()

    # Call FastAPI Entity endpoints
    c_resp = client.get(f"/api/v1/reports/entity?entity={test_client_ip}&window=7d")
    assert c_resp.status_code == 200
    c_summary = c_resp.json()["data"]["summary"]

    print(f"  Client {test_client_ip} SQL queries: {client_sql['total_q']} | API: {c_summary['total_queries']}")
    print(f"  Client {test_client_ip} SQL domains: {client_sql['unique_d']} | API: {c_summary['unique_domains']}")
    assert client_sql["total_q"] == c_summary["total_queries"]
    assert client_sql["unique_d"] == c_summary["unique_domains"]

    d_resp = client.get(f"/api/v1/reports/entity?entity={test_domain}&window=7d")
    assert d_resp.status_code == 200
    d_summary = d_resp.json()["data"]["summary"]

    print(f"  Domain {test_domain} SQL queries: {domain_sql['total_q']} | API: {d_summary['total_queries']}")
    print(f"  Domain {test_domain} SQL clients: {domain_sql['unique_c']} | API: {d_summary['unique_clients']}")
    assert domain_sql["total_q"] == d_summary["total_queries"]
    assert domain_sql["unique_c"] == d_summary["unique_clients"]
    print("  => Entity Client and Domain metrics match raw PostgreSQL 100%!")


if __name__ == "__main__":
    verify_live_reports_matching_sql()
    verify_live_entity_reports_matching_sql()
    verify_live_ingestion_reflection()
    print("\n[SUCCESS] Phase 12 Live PostgreSQL Verification PASSED cleanly!\n")

