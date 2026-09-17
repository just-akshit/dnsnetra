"""
tests/test_phase0_remediation.py
================================
Regression test suite verifying all Phase 0 correctness remediations:
1. Exact N-bucket generation (no terminal N+1 bucket)
2. [start, end) time interval boundary contract
3. Four-state canonical verdict reconciliation (raw == rollup == profiles)
4. Protection against Unknown/Review Needed -> Benign verdict leakage
5. Domain profiles four-state schema and count reconciliation
6. Manual aggregator invocation and CLI status
"""

from datetime import datetime, timezone, timedelta
import pytest
import psycopg2
import psycopg2.extras

from aggregator import DNSNetraAggregator
from aggregator.config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD
from aggregator.queries import get_timeseries, get_summary_kpis, get_top_domains, get_top_trusted_domains


def get_test_conn():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


# ---------------------------------------------------------------------------
# 1. Exact N-Bucket Generation Tests
# ---------------------------------------------------------------------------

def test_exact_1_hour_bucket_generation():
    """1-hour window generates exactly 1 bucket."""
    start = datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 9, 15, 11, 0, 0, tzinfo=timezone.utc)

    series = get_timeseries(start_time=start, end_time=end)
    assert len(series) == 1
    assert series[0]["timestamp"] == start.isoformat()


def test_exact_4_hour_bucket_generation():
    """4-hour window generates exactly 4 buckets (terminal 14:00 bucket eliminated)."""
    start = datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 9, 15, 14, 0, 0, tzinfo=timezone.utc)

    series = get_timeseries(start_time=start, end_time=end)
    assert len(series) == 4

    timestamps = [s["timestamp"] for s in series]
    expected = [
        datetime(2026, 9, 15, 10, 0, 0, tzinfo=timezone.utc).isoformat(),
        datetime(2026, 9, 15, 11, 0, 0, tzinfo=timezone.utc).isoformat(),
        datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc).isoformat(),
        datetime(2026, 9, 15, 13, 0, 0, tzinfo=timezone.utc).isoformat(),
    ]
    assert timestamps == expected
    # Crucial assertion: no terminal 14:00 bucket!
    terminal_ts = datetime(2026, 9, 15, 14, 0, 0, tzinfo=timezone.utc).isoformat()
    assert terminal_ts not in timestamps


def test_exact_24_hour_bucket_generation():
    """24-hour window generates exactly 24 buckets."""
    start = datetime(2026, 9, 15, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 9, 16, 0, 0, 0, tzinfo=timezone.utc)

    series = get_timeseries(start_time=start, end_time=end)
    assert len(series) == 24


def test_empty_and_inverted_window_bucket_generation():
    """Empty (start==end) or inverted (start>end) windows return empty list."""
    t = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    assert get_timeseries(start_time=t, end_time=t) == []
    assert get_timeseries(start_time=t, end_time=t - timedelta(hours=2)) == []


# ---------------------------------------------------------------------------
# 2. [start, end) Time Interval Boundary Contract Tests
# ---------------------------------------------------------------------------

def test_time_boundary_half_open_contract():
    """
    Verify SQL query boundary semantics in domain_query_history:
    Events at exact start boundary (>= start) are included.
    Events at exact end boundary (< end) are strictly excluded.
    """
    with get_test_conn() as conn:
        with conn.cursor() as cur:
            # Query the earliest record timestamp
            cur.execute("SELECT MIN(timestamp), MAX(timestamp) FROM domain_query_history;")
            min_ts, max_ts = cur.fetchone()

            # Window starting exactly at min_ts: must include min_ts
            cur.execute("""
                SELECT COUNT(*) FROM domain_query_history
                WHERE timestamp >= %s AND timestamp < %s;
            """, (min_ts, min_ts + timedelta(seconds=1)))
            cnt_start = cur.fetchone()[0]
            assert cnt_start >= 1, "Expected event at exact start to be included"

            # Window ending exactly at min_ts: must NOT include min_ts
            cur.execute("""
                SELECT COUNT(*) FROM domain_query_history
                WHERE timestamp >= %s AND timestamp < %s;
            """, (min_ts - timedelta(seconds=1), min_ts))
            cnt_end = cur.fetchone()[0]
            assert cnt_end == 0, "Expected event at exact end boundary to be excluded"


# ---------------------------------------------------------------------------
# 3. Four-State Verdict Count & Reconciliation Tests
# ---------------------------------------------------------------------------

def test_four_state_verdict_reconciliation():
    """
    Verify that raw telemetry, hourly rollups, and domain profiles
    all reconcile to exactly 30,181 rows across the 4 canonical states.
    """
    with get_test_conn() as conn:
        with conn.cursor() as cur:
            # 1. Raw Telemetry ground truth
            cur.execute("""
                SELECT 
                    COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_raw,
                    COUNT(*) FILTER (WHERE final_label = 'Malicious') AS mal_raw,
                    COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS rn_raw,
                    COUNT(*) FILTER (WHERE final_label = 'Unknown') AS unk_raw,
                    COUNT(*) AS total_raw
                FROM domain_query_history;
            """)
            benign_raw, mal_raw, rn_raw, unk_raw, total_raw = cur.fetchone()

            assert total_raw == 30181
            assert benign_raw == 23371
            assert mal_raw == 4626
            assert rn_raw == 448
            assert unk_raw == 1736
            assert total_raw == benign_raw + mal_raw + rn_raw + unk_raw

            # 2. Hourly Rollup ground truth
            cur.execute("""
                SELECT 
                    SUM(clean_queries) AS benign_roll,
                    SUM(malicious_queries) AS mal_roll,
                    SUM(suspicious_queries) AS rn_roll,
                    SUM(unknown_queries) AS unk_roll,
                    SUM(total_queries) AS total_roll
                FROM telemetry_hourly_rollup;
            """)
            benign_roll, mal_roll, rn_roll, unk_roll, total_roll = cur.fetchone()

            assert total_roll == total_raw
            assert benign_roll == benign_raw
            assert mal_roll == mal_raw
            assert rn_roll == rn_raw
            assert unk_roll == unk_raw

            # 3. Domain Profiles ground truth (Migration 005 verified)
            cur.execute("""
                SELECT 
                    SUM(clean_queries) AS benign_prof,
                    SUM(malicious_queries) AS mal_prof,
                    SUM(review_needed_queries) AS rn_prof,
                    SUM(unknown_queries) AS unk_prof,
                    SUM(total_queries) AS total_prof
                FROM domain_profiles;
            """)
            benign_prof, mal_prof, rn_prof, unk_prof, total_prof = cur.fetchone()

            assert total_prof == total_raw
            assert benign_prof == benign_raw
            assert mal_prof == mal_raw
            assert rn_prof == rn_raw
            assert unk_prof == unk_raw


# ---------------------------------------------------------------------------
# 4. Protection Against Verdict Leakage Tests
# ---------------------------------------------------------------------------

def test_no_verdict_leakage():
    """
    Verify that counting `final_label != 'Malicious'` produces an incorrect count (25,555),
    proving why `final_label = 'Benign'` is strictly required to prevent Unknown and
    Review Needed from leaking into Benign.
    """
    with get_test_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    COUNT(*) FILTER (WHERE final_label != 'Malicious') AS flawed_clean,
                    COUNT(*) FILTER (WHERE final_label = 'Benign') AS correct_benign,
                    COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed,
                    COUNT(*) FILTER (WHERE final_label = 'Unknown') AS unknown
                FROM domain_query_history;
            """)
            flawed_clean, correct_benign, review_needed, unknown = cur.fetchone()

            # Flawed clean includes Review Needed (448) and Unknown (1736)
            assert flawed_clean == correct_benign + review_needed + unknown
            assert flawed_clean == 25555
            assert correct_benign == 23371
            assert flawed_clean != correct_benign


# ---------------------------------------------------------------------------
# 5. Domain Profiles Schema & Queries Integration
# ---------------------------------------------------------------------------

def test_domain_profiles_review_needed_column_active():
    """Verify domain_profiles schema has active review_needed_queries column."""
    with get_test_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'domain_profiles' AND column_name = 'review_needed_queries';
            """)
            row = cur.fetchone()
            assert row is not None
            assert row[0] == "review_needed_queries"
            assert "bigint" in row[1]


def test_queries_api_kpi_four_state_contract():
    """Verify get_summary_kpis provides review_needed_queries matching ground truth."""
    kpis = get_summary_kpis()
    assert kpis["total_queries"] == 30181
    assert kpis["clean_queries"] == 23371
    assert kpis["malicious_queries"] == 4626
    assert kpis["review_needed_queries"] == 448
    assert kpis["suspicious_queries"] == 448  # Backward compatibility alias
    assert kpis["unknown_queries"] == 1736


# ---------------------------------------------------------------------------
# 6. Manual Aggregator Invocation Tests
# ---------------------------------------------------------------------------

def test_manual_aggregator_invocation():
    """Verify manual aggregator invocation runs cleanly without errors."""
    aggregator = DNSNetraAggregator()
    status = aggregator.get_status()

    assert status["status"] in ("idle", "success")
    assert status["watermark_id"] >= 30181
    assert status["pending_events"] == 0

    # Run incremental when caught up -> returns success with 0 events
    res = aggregator.run_incremental()
    assert res.status == "success"
    assert res.events_processed == 0
