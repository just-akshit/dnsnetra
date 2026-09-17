"""
tests/test_data_reconciliation.py
=================================
Data reconciliation test suite comparing rollups and analytics against
ground truth in PostgreSQL `domain_query_history`.
"""

import pytest
import psycopg2
from aggregator.config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from aggregator.queries import get_summary_kpis, get_top_domains, get_top_malicious_domains


def get_test_conn():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


def test_total_query_reconciliation():
    """Verify sum of total_queries in telemetry_hourly_rollup matches raw history count."""
    with get_test_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM domain_query_history;")
            raw_count = cur.fetchone()[0]

            cur.execute("SELECT SUM(total_queries) FROM telemetry_hourly_rollup;")
            rollup_count = cur.fetchone()[0]

    assert raw_count == rollup_count, f"Mismatch: raw {raw_count} != rollup {rollup_count}"


def test_verdict_breakdown_reconciliation():
    """Verify verdict totals in rollups match exact counts in domain_query_history."""
    with get_test_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    COUNT(*) FILTER (WHERE final_label = 'Malicious') AS mal_raw,
                    COUNT(*) FILTER (WHERE final_label IN ('Benign', 'Clean', 'Trusted')) AS clean_raw,
                    COUNT(*) FILTER (WHERE final_label IN ('Suspicious', 'Review Needed')) AS susp_raw,
                    COUNT(*) FILTER (WHERE final_label NOT IN ('Malicious', 'Benign', 'Clean', 'Trusted', 'Suspicious', 'Review Needed')) AS unk_raw
                FROM domain_query_history;
            """)
            raw_mal, raw_clean, raw_susp, raw_unk = cur.fetchone()

            cur.execute("""
                SELECT 
                    SUM(malicious_queries),
                    SUM(clean_queries),
                    SUM(suspicious_queries),
                    SUM(unknown_queries)
                FROM telemetry_hourly_rollup;
            """)
            roll_mal, roll_clean, roll_susp, roll_unk = cur.fetchone()

    assert raw_mal == roll_mal, f"Malicious query mismatch: {raw_mal} != {roll_mal}"
    assert raw_clean == roll_clean, f"Clean query mismatch: {raw_clean} != {roll_clean}"
    assert raw_susp == roll_susp, f"Suspicious query mismatch: {raw_susp} != {roll_susp}"
    assert raw_unk == roll_unk, f"Unknown query mismatch: {raw_unk} != {roll_unk}"


def test_daily_domain_rollup_reconciliation():
    """Verify daily domain rollup matches total queries and distinct domains."""
    with get_test_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM domain_query_history;")
            raw_count = cur.fetchone()[0]

            cur.execute("SELECT SUM(query_count) FROM telemetry_daily_domain_rollup;")
            daily_count = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT domain) FROM domain_query_history;")
            raw_unique_domains = cur.fetchone()[0]

            cur.execute("SELECT COUNT(DISTINCT domain) FROM telemetry_daily_domain_rollup;")
            daily_unique_domains = cur.fetchone()[0]

    assert raw_count == daily_count, f"Daily query count mismatch: {raw_count} != {daily_count}"
    assert raw_unique_domains == daily_unique_domains, f"Unique domains mismatch: {raw_unique_domains} != {daily_unique_domains}"


def test_summary_kpi_contract():
    """Verify get_summary_kpis returns accurate, typesafe values matching ground truth."""
    kpis = get_summary_kpis()

    assert kpis["total_queries"] == 30181
    assert kpis["clean_queries"] == 23371
    assert kpis["malicious_queries"] == 4626
    assert kpis["suspicious_queries"] == 448
    assert kpis["unknown_queries"] == 1736
    assert kpis["unique_domains"] == 49
    assert kpis["unique_clients"] == 12
    assert 15.0 < kpis["threats_blocked_pct"] < 16.0
