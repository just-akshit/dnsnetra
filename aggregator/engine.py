"""
aggregator/engine.py
====================
Core DNSNetra Aggregator Engine.

Provides high-performance, idempotent incremental aggregation from raw
`domain_query_history` into PostgreSQL rollups (`telemetry_hourly_rollup`,
`telemetry_daily_domain_rollup`), tracked via `telemetry_aggregation_state`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from collections import defaultdict

import psycopg2
import psycopg2.extras

from aggregator.config import (
    DB_HOST,
    DB_PORT,
    DB_NAME,
    DB_USER,
    DB_PASSWORD,
    DEFAULT_BATCH_SIZE,
    ADVISORY_LOCK_ID,
    JOB_NAME,
)

logger = logging.getLogger("dnsnetra.aggregator")


@dataclass
class AggregationResult:
    events_processed: int
    batches_run: int
    initial_watermark: int
    final_watermark: int
    status: str
    message: str = ""


class DNSNetraAggregator:
    """
    Native PostgreSQL Streaming & Batch Aggregator for DNSNetra.
    """

    def __init__(
        self,
        batch_size: int = DEFAULT_BATCH_SIZE,
        lock_id: int = ADVISORY_LOCK_ID,
        job_name: str = JOB_NAME,
    ) -> None:
        self.batch_size = batch_size
        self.lock_id = lock_id
        self.job_name = job_name

    def _get_connection(self):
        return psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
        )

    def _acquire_lock(self, cur) -> bool:
        cur.execute("SELECT pg_try_advisory_lock(%s);", (self.lock_id,))
        row = cur.fetchone()
        return bool(row and row[0])

    def _release_lock(self, cur) -> None:
        cur.execute("SELECT pg_advisory_unlock(%s);", (self.lock_id,))

    def get_status(self) -> Dict[str, Any]:
        """
        Returns the current aggregator state, watermark, and unprocessed event lag.
        """
        with self._get_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT last_processed_id, last_processed_timestamp, last_run_at, 
                           total_events_processed, status
                    FROM telemetry_aggregation_state
                    WHERE job_name = %s;
                """, (self.job_name,))
                state = cur.fetchone() or {
                    "last_processed_id": 0,
                    "last_processed_timestamp": None,
                    "last_run_at": None,
                    "total_events_processed": 0,
                    "status": "uninitialized",
                }

                cur.execute("SELECT COALESCE(MAX(id), 0) AS max_id, COUNT(*) AS total_history FROM domain_query_history;")
                history_meta = cur.fetchone() or {"max_id": 0, "total_history": 0}

                max_id = history_meta["max_id"]
                watermark = state["last_processed_id"]
                cur.execute("SELECT COUNT(*) AS pending FROM domain_query_history WHERE id > %s;", (watermark,))
                pending = cur.fetchone()["pending"]

                cur.execute("SELECT COUNT(*) AS hourly_buckets FROM telemetry_hourly_rollup;")
                hourly_buckets = cur.fetchone()["hourly_buckets"]

                cur.execute("SELECT COUNT(*) AS daily_domain_records FROM telemetry_daily_domain_rollup;")
                daily_domains = cur.fetchone()["daily_domain_records"]

                return {
                    "job_name": self.job_name,
                    "watermark_id": watermark,
                    "max_history_id": max_id,
                    "pending_events": pending,
                    "total_history_events": history_meta["total_history"],
                    "total_events_processed": state["total_events_processed"],
                    "last_run_at": state["last_run_at"],
                    "status": state["status"],
                    "hourly_rollup_buckets": hourly_buckets,
                    "daily_domain_rollup_records": daily_domains,
                }

    def run_dry_run(self) -> Dict[str, Any]:
        """
        Non-destructive inspection: reports watermark, pending events, event ID range,
        and estimated batches without modifying any database state.
        """
        status = self.get_status()
        pending = status["pending_events"]
        watermark = status["watermark_id"]
        first_pending_id = None
        last_pending_id = None
        estimated_batches = 0

        if pending > 0:
            with self._get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT MIN(id), MAX(id) FROM domain_query_history WHERE id > %s;",
                        (watermark,)
                    )
                    row = cur.fetchone()
                    if row:
                        first_pending_id, last_pending_id = row
            estimated_batches = (pending + self.batch_size - 1) // self.batch_size

        return {
            "current_watermark_id": watermark,
            "pending_event_count": pending,
            "total_history_events": status["total_history_events"],
            "max_history_id": status["max_history_id"],
            "first_pending_id": first_pending_id,
            "last_pending_id": last_pending_id,
            "estimated_batches": estimated_batches,
            "batch_size": self.batch_size,
        }

    def run_incremental(
        self,
        batch_size: Optional[int] = None,
        max_batches: Optional[int] = None,
    ) -> AggregationResult:
        """
        Processes pending events in batches from `domain_query_history` until caught up
        or until `max_batches` is reached.
        """
        b_size = batch_size or self.batch_size
        total_processed = 0
        batches_executed = 0

        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                if not self._acquire_lock(cur):
                    logger.warning("Could not acquire advisory lock %s. Another aggregator instance is running.", hex(self.lock_id))
                    return AggregationResult(
                        events_processed=0,
                        batches_run=0,
                        initial_watermark=0,
                        final_watermark=0,
                        status="locked",
                        message="Advisory lock busy",
                    )

            try:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT last_processed_id FROM telemetry_aggregation_state WHERE job_name = %s;",
                        (self.job_name,),
                    )
                    row = cur.fetchone()
                    initial_watermark = row[0] if row else 0

                current_watermark = initial_watermark

                while True:
                    if max_batches and batches_executed >= max_batches:
                        break

                    # Fetch batch of raw events strictly above watermark
                    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                        cur.execute("""
                            SELECT id, domain, client_ip, timestamp, final_label
                            FROM domain_query_history
                            WHERE id > %s
                            ORDER BY id ASC
                            LIMIT %s;
                        """, (current_watermark, b_size))
                        rows = cur.fetchall()

                    if not rows:
                        break

                    # Compute batch aggregates
                    batch_max_id = rows[-1]["id"]
                    batch_max_ts = rows[-1]["timestamp"]

                    # 1. Hourly rollups
                    # Key: bucket_time (datetime truncated to hour)
                    # Value: [total, clean, suspicious, malicious, unknown]
                    hourly_map: Dict[datetime, List[int]] = defaultdict(lambda: [0, 0, 0, 0, 0])

                    # 2. Daily domain rollups
                    # Key: (bucket_date, domain, final_label)
                    # Value: query_count
                    daily_domain_map: Dict[Tuple[Any, str, str], int] = defaultdict(int)

                    for r in rows:
                        ts: datetime = r["timestamp"]
                        bucket_time = ts.replace(minute=0, second=0, microsecond=0)
                        bucket_date = ts.date()
                        domain = str(r["domain"]).strip().lower()
                        label = str(r["final_label"] or "Unknown").strip()

                        # Categorize into 4 canonical buckets
                        norm_label = label.lower()
                        is_malicious = norm_label == "malicious"
                        is_clean = norm_label in ("benign", "clean", "trusted")
                        is_suspicious = norm_label in ("suspicious", "review needed", "review_needed")
                        is_unknown = not (is_malicious or is_clean or is_suspicious)

                        h_counts = hourly_map[bucket_time]
                        h_counts[0] += 1  # total
                        if is_clean:
                            h_counts[1] += 1
                        elif is_suspicious:
                            h_counts[2] += 1
                        elif is_malicious:
                            h_counts[3] += 1
                        else:
                            h_counts[4] += 1

                        canonical_label = (
                            "Malicious" if is_malicious
                            else "Benign" if is_clean
                            else "Review Needed" if is_suspicious
                            else "Unknown"
                        )
                        daily_domain_map[(bucket_date, domain, canonical_label)] += 1

                    # Atomic Transaction for the batch
                    with conn:
                        with conn.cursor() as cur:
                            # Upsert Hourly Rollups
                            hourly_tuples = [
                                (b_time, counts[0], counts[1], counts[2], counts[3], counts[4])
                                for b_time, counts in hourly_map.items()
                            ]
                            psycopg2.extras.execute_values(
                                cur,
                                """
                                INSERT INTO telemetry_hourly_rollup (
                                    bucket_time, total_queries, clean_queries, suspicious_queries, malicious_queries, unknown_queries, updated_at
                                ) VALUES %s
                                ON CONFLICT (bucket_time) DO UPDATE SET
                                    total_queries      = telemetry_hourly_rollup.total_queries + EXCLUDED.total_queries,
                                    clean_queries      = telemetry_hourly_rollup.clean_queries + EXCLUDED.clean_queries,
                                    suspicious_queries = telemetry_hourly_rollup.suspicious_queries + EXCLUDED.suspicious_queries,
                                    malicious_queries  = telemetry_hourly_rollup.malicious_queries + EXCLUDED.malicious_queries,
                                    unknown_queries    = telemetry_hourly_rollup.unknown_queries + EXCLUDED.unknown_queries,
                                    updated_at         = NOW();
                                """,
                                hourly_tuples,
                                template="(%s, %s, %s, %s, %s, %s, NOW())",
                            )

                            # Upsert Daily Domain Rollups
                            daily_tuples = [
                                (b_date, dom, lbl, cnt)
                                for (b_date, dom, lbl), cnt in daily_domain_map.items()
                            ]
                            psycopg2.extras.execute_values(
                                cur,
                                """
                                INSERT INTO telemetry_daily_domain_rollup (
                                    bucket_date, domain, final_label, query_count
                                ) VALUES %s
                                ON CONFLICT (bucket_date, domain, final_label) DO UPDATE SET
                                    query_count = telemetry_daily_domain_rollup.query_count + EXCLUDED.query_count;
                                """,
                                daily_tuples,
                                template="(%s, %s, %s, %s)",
                            )

                            # Advance watermark atomically with the rollups
                            cur.execute("""
                                UPDATE telemetry_aggregation_state
                                SET last_processed_id = %s,
                                    last_processed_timestamp = %s,
                                    last_run_at = NOW(),
                                    total_events_processed = total_events_processed + %s,
                                    status = 'idle'
                                WHERE job_name = %s;
                            """, (batch_max_id, batch_max_ts, len(rows), self.job_name))

                    current_watermark = batch_max_id
                    total_processed += len(rows)
                    batches_executed += 1
                    logger.info("Processed batch of %d events (watermark: %d)", len(rows), current_watermark)

                return AggregationResult(
                    events_processed=total_processed,
                    batches_run=batches_executed,
                    initial_watermark=initial_watermark,
                    final_watermark=current_watermark,
                    status="success",
                    message=f"Successfully processed {total_processed} events across {batches_executed} batches.",
                )

            finally:
                with conn.cursor() as cur:
                    self._release_lock(cur)

        finally:
            conn.close()

    def run_rebuild(self) -> AggregationResult:
        """
        Clears existing rollups, resets watermark to 0, and re-aggregates all historical events.
        """
        conn = self._get_connection()
        try:
            with conn.cursor() as cur:
                if not self._acquire_lock(cur):
                    return AggregationResult(
                        events_processed=0,
                        batches_run=0,
                        initial_watermark=0,
                        final_watermark=0,
                        status="locked",
                        message="Advisory lock busy",
                    )

            try:
                logger.info("Truncating rollups and resetting watermark for rebuild...")
                with conn:
                    with conn.cursor() as cur:
                        cur.execute("TRUNCATE TABLE telemetry_hourly_rollup;")
                        cur.execute("TRUNCATE TABLE telemetry_daily_domain_rollup;")
                        cur.execute("""
                            UPDATE telemetry_aggregation_state
                            SET last_processed_id = 0,
                                last_processed_timestamp = NULL,
                                total_events_processed = 0,
                                last_run_at = NOW(),
                                status = 'rebuilding'
                            WHERE job_name = %s;
                        """, (self.job_name,))
            finally:
                with conn.cursor() as cur:
                    self._release_lock(cur)

        finally:
            conn.close()

        # Execute full incremental run from watermark 0
        result = self.run_incremental()
        return result
