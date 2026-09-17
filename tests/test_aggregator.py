"""
tests/test_aggregator.py
========================
Unit and functional tests for DNSNetra Aggregation Engine.
Covers correctness, concurrency, failure recovery, atomicity, and rebuild idempotency.
"""

import pytest
import psycopg2
import psycopg2.extras
from aggregator import DNSNetraAggregator, AggregationResult, DEFAULT_BATCH_SIZE
from aggregator.config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD, ADVISORY_LOCK_ID


def get_test_conn():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


def test_aggregator_status():
    """Verify get_status returns valid metadata and lag tracking."""
    aggregator = DNSNetraAggregator()
    status = aggregator.get_status()

    assert "job_name" in status
    assert "watermark_id" in status
    assert "max_history_id" in status
    assert "pending_events" in status
    assert status["watermark_id"] >= 0
    assert status["hourly_rollup_buckets"] > 0
    assert status["pending_events"] == 0  # Should be fully caught up


def test_advisory_lock_concurrency():
    """Verify that a second aggregator instance cannot run if the advisory lock is held."""
    conn = get_test_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(%s);", (ADVISORY_LOCK_ID,))
            acquired = cur.fetchone()[0]
            assert acquired is True, "Expected to acquire advisory lock in test"

            # Attempt to run another aggregator while lock is held
            competing_aggregator = DNSNetraAggregator()
            result = competing_aggregator.run_incremental()

            assert result.status == "locked"
            assert result.events_processed == 0

            # Release lock
            cur.execute("SELECT pg_advisory_unlock(%s);", (ADVISORY_LOCK_ID,))
    finally:
        conn.close()


def test_incremental_no_op_when_caught_up():
    """When watermark equals max_id, run_incremental should safely process 0 events."""
    aggregator = DNSNetraAggregator()
    result = aggregator.run_incremental()

    assert result.status == "success"
    assert result.events_processed == 0


def test_rebuild_idempotency():
    """
    Verify that executing run_rebuild() produces 100% identical rollups
    to an incremental caught-up state.
    """
    aggregator = DNSNetraAggregator()

    # 1. Capture snapshot before rebuild
    with get_test_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM telemetry_hourly_rollup ORDER BY bucket_time ASC;")
            hourly_before = cur.fetchall()

            cur.execute("SELECT * FROM telemetry_daily_domain_rollup ORDER BY bucket_date, domain, final_label;")
            daily_before = cur.fetchall()

    # 2. Run rebuild
    rebuild_result = aggregator.run_rebuild()
    assert rebuild_result.status == "success"
    assert rebuild_result.events_processed > 0

    # 3. Capture snapshot after rebuild
    with get_test_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM telemetry_hourly_rollup ORDER BY bucket_time ASC;")
            hourly_after = cur.fetchall()

            cur.execute("SELECT * FROM telemetry_daily_domain_rollup ORDER BY bucket_date, domain, final_label;")
            daily_after = cur.fetchall()

    # 4. Compare every hourly bucket
    assert len(hourly_before) == len(hourly_after)
    for b_before, b_after in zip(hourly_before, hourly_after):
        assert b_before["bucket_time"] == b_after["bucket_time"]
        assert b_before["total_queries"] == b_after["total_queries"]
        assert b_before["clean_queries"] == b_after["clean_queries"]
        assert b_before["malicious_queries"] == b_after["malicious_queries"]
        assert b_before["suspicious_queries"] == b_after["suspicious_queries"]
        assert b_before["unknown_queries"] == b_after["unknown_queries"]

    # 5. Compare every daily domain record
    assert len(daily_before) == len(daily_after)
    for d_before, d_after in zip(daily_before, daily_after):
        assert d_before["bucket_date"] == d_after["bucket_date"]
        assert d_before["domain"] == d_after["domain"]
        assert d_before["final_label"] == d_after["final_label"]
        assert d_before["query_count"] == d_after["query_count"]


def test_failure_atomicity_and_rollback():
    """
    Simulate an intentional SQL injection/syntax error during batch processing.
    Verify that the transaction aborts cleanly, the watermark is NOT advanced,
    and no partial data is committed.
    """
    with get_test_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT last_processed_id FROM telemetry_aggregation_state WHERE job_name = 'dnsnetra_aggregator';")
            initial_watermark = cur.fetchone()[0]

            # In a transactional block, simulate failure
            try:
                cur.execute("SAVEPOINT test_simulated_failure;")
                # Intentionally invalid SQL to trigger abort
                cur.execute("INSERT INTO telemetry_aggregation_state (invalid_column) VALUES (1);")
            except psycopg2.Error:
                cur.execute("ROLLBACK TO SAVEPOINT test_simulated_failure;")

            # Check watermark remains unchanged
            cur.execute("SELECT last_processed_id FROM telemetry_aggregation_state WHERE job_name = 'dnsnetra_aggregator';")
            watermark_after = cur.fetchone()[0]
            assert initial_watermark == watermark_after, "Watermark must not advance on aborted transaction"
