"""
Incremental Dashboard Aggregator
=================================
Reads new events from PostgreSQL `domain_query_history` since the last
successfully committed watermark and incrementally updates the SQLite
`dashboard.db` read model.

Architecture
------------
PostgreSQL domain_query_history
    ↓  WHERE id > last_processed_event_id
IncrementalAggregator (this module)
    ↓  batch upserts (atomic per batch)
dashboard.db (SQLite read model)

Transaction guarantee
---------------------
For every batch:

    BEGIN IMMEDIATE  (acquires SQLite write lock)
        update membership tables
        update domain_details
        update client_details
        update metrics_summary
        update queries_timeseries
        update threats_by_category
        update recent_flagged_domains
        update aggregation_state  ← watermark advances HERE
    COMMIT

The aggregation_runs record is written on a SEPARATE connection so that
run history is always visible even when the main transaction rolls back.

Label semantics (from domain_query_history.final_label)
--------------------------------------------------------
    "Malicious"           → malicious, is_threat=True
    "Clean" / "Trusted"   → clean, is_threat=False
    None / "Unknown" / *  → unknown, is_threat=False

threat_count = malicious_count (no threat_score in domain_query_history)
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Generator, Optional

from .config import (
    AGGREGATION_BATCH_SIZE,
    AGGREGATION_NAME,
    AGGREGATION_STALE_THRESHOLD_MINUTES,
    DASHBOARD_DB_PATH,
    PG_HOST,
    PG_NAME,
    PG_PASSWORD,
    PG_PORT,
    PG_USER,
    RECENT_FLAGGED_DOMAINS_LIMIT,
)
from .schema import initialize_dashboard_db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Watermark:
    last_processed_event_id: int = 0
    last_processed_event_timestamp: Optional[str] = None
    last_successful_run_id: Optional[str] = None


@dataclass
class NormalizedEvent:
    event_id: int
    domain: str
    client_ip: str
    query_type: str
    timestamp: str            # ISO-8601 string
    time_bucket: str          # "YYYY-MM-DD HH:00"
    response_code: str
    registered_domain: Optional[str]
    tld: Optional[str]
    final_label: str          # normalised lower-case
    ti_source: Optional[str]
    is_malicious: bool
    is_suspicious: bool
    is_clean: bool
    is_threat: bool


@dataclass
class BatchResult:
    first_event_id: int = 0
    last_event_id: int = 0
    first_event_timestamp: Optional[str] = None
    last_event_timestamp: Optional[str] = None
    rows_seen: int = 0
    rows_processed: int = 0
    rows_rejected: int = 0


@dataclass
class AggregationResult:
    run_id: str = ""
    status: str = "success"
    batches_processed: int = 0
    total_rows_seen: int = 0
    total_rows_processed: int = 0
    total_rows_rejected: int = 0
    first_event_id: Optional[int] = None
    last_event_id: Optional[int] = None
    error_message: Optional[str] = None
    duration_ms: int = 0


@dataclass
class DryRunReport:
    current_watermark_id: int = 0
    current_watermark_ts: Optional[str] = None
    pending_event_count: int = 0
    first_pending_id: Optional[int] = None
    last_pending_id: Optional[int] = None
    estimated_batches: int = 0


@dataclass
class StatusReport:
    aggregation_name: str = ""
    current_watermark_id: int = 0
    current_watermark_ts: Optional[str] = None
    last_successful_run_id: Optional[str] = None
    last_successful_run_started_at: Optional[str] = None
    last_run_id: Optional[str] = None
    last_run_status: Optional[str] = None
    last_run_duration_ms: Optional[int] = None
    last_run_started_at: Optional[str] = None
    pending_event_count: int = 0
    last_error: Optional[str] = None
    source_type: Optional[str] = None


# ---------------------------------------------------------------------------
# Label classification (preserving existing project semantics)
# ---------------------------------------------------------------------------

def _classify_label(final_label: Optional[str]) -> tuple[bool, bool, bool]:
    """
    Returns (is_malicious, is_clean, is_unknown).

    Based on actual final_label values written by domain_profiling:
        "Malicious"           → malicious
        "Clean" / "Trusted"   → clean
        None / "Unknown" / *  → unknown
    """
    label = (final_label or "").strip()
    if label == "Malicious":
        return True, False, False
    if label in ("Clean", "Trusted", "Benign"):
        return False, True, False
    return False, False, True  # Unknown / Review Needed / empty


def _normalize_event(row: dict[str, Any]) -> Optional[NormalizedEvent]:
    """
    Converts a raw domain_query_history row into a NormalizedEvent.
    Returns None if the row is malformed (missing mandatory fields).
    """
    try:
        event_id = int(row["id"])
        domain = str(row.get("domain") or "").strip()
        client_ip = str(row.get("client_ip") or "").strip()
        if not domain or not client_ip:
            logger.debug("Skipping row id=%s: missing domain or client_ip", event_id)
            return None

        raw_ts = row.get("timestamp")
        if raw_ts is None:
            logger.debug("Skipping row id=%s: missing timestamp", event_id)
            return None

        if isinstance(raw_ts, datetime):
            ts_dt = raw_ts if raw_ts.tzinfo else raw_ts.replace(tzinfo=timezone.utc)
        else:
            ts_str = str(raw_ts)
            # psycopg3 may return tz-aware strings; parse them
            ts_dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if ts_dt.tzinfo is None:
                ts_dt = ts_dt.replace(tzinfo=timezone.utc)

        ts_iso = ts_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        time_bucket = ts_dt.strftime("%Y-%m-%d %H:00")

        final_label = str(row.get("final_label") or "")
        is_malicious, is_clean, _is_unknown = _classify_label(final_label)
        # Suspicious label doesn't exist in domain_query_history; everything
        # non-malicious is either clean or unknown (not suspicious).
        is_suspicious = False
        is_threat = is_malicious

        return NormalizedEvent(
            event_id=event_id,
            domain=domain,
            client_ip=client_ip,
            query_type=str(row.get("query_type") or "OTHER").upper(),
            timestamp=ts_iso,
            time_bucket=time_bucket,
            response_code=str(row.get("response_code") or "UNKNOWN"),
            registered_domain=row.get("registered_domain") or None,
            tld=row.get("tld") or None,
            final_label=final_label,
            ti_source=row.get("ti_source") or None,
            is_malicious=is_malicious,
            is_suspicious=is_suspicious,
            is_clean=is_clean,
            is_threat=is_threat,
        )
    except Exception as exc:
        logger.warning("Failed to normalize event row id=%s: %s", row.get("id"), exc)
        return None


# ---------------------------------------------------------------------------
# JSON breakdown helpers
# ---------------------------------------------------------------------------

def _load_json_breakdown(json_str: Optional[str]) -> dict[str, int]:
    if not json_str:
        return {}
    try:
        return json.loads(json_str)
    except (ValueError, TypeError):
        return {}


def _dump_json_breakdown(d: dict[str, int]) -> str:
    return json.dumps(d, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Main aggregator class
# ---------------------------------------------------------------------------

class IncrementalAggregator:
    """
    Production incremental dashboard aggregator.

    Reads new events from PostgreSQL domain_query_history since the last
    successfully committed watermark and atomically updates dashboard.db.

    Only one active writer is supported. Concurrent invocations are
    prevented by SQLite BEGIN IMMEDIATE locking.
    """

    def __init__(
        self,
        dashboard_db_path=DASHBOARD_DB_PATH,
        pg_host: str = PG_HOST,
        pg_port: int = PG_PORT,
        pg_name: str = PG_NAME,
        pg_user: str = PG_USER,
        pg_password: str = PG_PASSWORD,
        batch_size: int = AGGREGATION_BATCH_SIZE,
        aggregation_name: str = AGGREGATION_NAME,
        recent_flagged_limit: int = RECENT_FLAGGED_DOMAINS_LIMIT,
        stale_threshold_minutes: int = AGGREGATION_STALE_THRESHOLD_MINUTES,
    ) -> None:
        from pathlib import Path
        self.dashboard_db_path = Path(dashboard_db_path)
        self.pg_host = pg_host
        self.pg_port = pg_port
        self.pg_name = pg_name
        self.pg_user = pg_user
        self.pg_password = pg_password
        self.batch_size = batch_size
        self.aggregation_name = aggregation_name
        self.recent_flagged_limit = recent_flagged_limit
        self.stale_threshold_minutes = stale_threshold_minutes

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def run_incremental(self) -> AggregationResult:
        """
        Normal production path.
        Processes only events after the current watermark.
        """
        import time
        start_ms = int(time.time() * 1000)
        run_id = str(uuid.uuid4())

        logger.info(
            "Aggregation started | run_id=%s name=%s mode=incremental",
            run_id, self.aggregation_name,
        )

        initialize_dashboard_db(self.dashboard_db_path)
        self._recover_stale_runs()
        self._start_run(run_id, source_type="postgres_incremental")

        try:
            pg_conn = self._get_pg_connection()
        except Exception as exc:
            err = f"PostgreSQL unavailable: {exc}"
            logger.error(err)
            self._fail_run(run_id, err)
            return AggregationResult(
                run_id=run_id, status="failed", error_message=err,
                duration_ms=int(time.time() * 1000) - start_ms,
            )

        result = AggregationResult(run_id=run_id)

        try:
            watermark = self._load_watermark()
            logger.info(
                "Watermark loaded | event_id=%d ts=%s",
                watermark.last_processed_event_id,
                watermark.last_processed_event_timestamp,
            )

            current_watermark_id = watermark.last_processed_event_id
            batch_num = 0

            while True:
                batch = self._fetch_batch(pg_conn, current_watermark_id)
                if not batch:
                    logger.info(
                        "No new events | watermark=%d batches_processed=%d",
                        current_watermark_id, batch_num,
                    )
                    break

                batch_num += 1
                logger.info(
                    "Batch %d | fetched=%d | id_range=[%d, %d]",
                    batch_num, len(batch), batch[0]["id"], batch[-1]["id"],
                )

                # Normalize
                events: list[NormalizedEvent] = []
                rejected = 0
                for row in batch:
                    ev = _normalize_event(row)
                    if ev is not None:
                        events.append(ev)
                    else:
                        rejected += 1

                batch_result = self._process_batch_atomic(
                    events,
                    run_id=run_id,
                    batch_num=batch_num,
                )

                current_watermark_id = batch_result.last_event_id
                result.total_rows_seen += batch_result.rows_seen + rejected
                result.total_rows_processed += batch_result.rows_processed
                result.total_rows_rejected += batch_result.rows_rejected + rejected

                if result.first_event_id is None:
                    result.first_event_id = batch_result.first_event_id
                result.last_event_id = batch_result.last_event_id

                # Update run progress
                self._update_run_progress(
                    run_id=run_id,
                    batch_num=batch_num,
                    result=result,
                    batch_result=batch_result,
                )

            result.batches_processed = batch_num
            result.status = "success"
            result.duration_ms = int(time.time() * 1000) - start_ms
            self._complete_run(run_id, result)
            logger.info(
                "Aggregation succeeded | run_id=%s batches=%d processed=%d duration_ms=%d",
                run_id, batch_num, result.total_rows_processed, result.duration_ms,
            )

        except Exception as exc:
            err = str(exc)
            result.status = "failed"
            result.error_message = err
            result.duration_ms = int(time.time() * 1000) - start_ms
            logger.error("Aggregation failed | run_id=%s error=%s", run_id, err, exc_info=True)
            self._fail_run(run_id, err)
        finally:
            try:
                pg_conn.close()
            except Exception:
                pass

        return result

    def run_rebuild(self) -> AggregationResult:
        """
        Disaster recovery / schema migration mode.
        Clears the entire read model and rebuilds from all retained PostgreSQL events.
        """
        import time
        start_ms = int(time.time() * 1000)
        run_id = str(uuid.uuid4())

        logger.info(
            "Rebuild started | run_id=%s name=%s", run_id, self.aggregation_name
        )

        initialize_dashboard_db(self.dashboard_db_path)
        self._start_run(run_id, source_type="postgres_rebuild")

        try:
            pg_conn = self._get_pg_connection()
        except Exception as exc:
            err = f"PostgreSQL unavailable: {exc}"
            logger.error(err)
            self._fail_run(run_id, err)
            return AggregationResult(
                run_id=run_id, status="failed", error_message=err,
                duration_ms=int(time.time() * 1000) - start_ms,
            )

        result = AggregationResult(run_id=run_id)

        try:
            # Atomically clear read model and reset watermark
            self._clear_read_model_atomic()
            logger.info("Read model cleared for rebuild")

            current_watermark_id = 0
            batch_num = 0

            while True:
                batch = self._fetch_batch(pg_conn, current_watermark_id)
                if not batch:
                    break

                batch_num += 1
                events: list[NormalizedEvent] = []
                rejected = 0
                for row in batch:
                    ev = _normalize_event(row)
                    if ev is not None:
                        events.append(ev)
                    else:
                        rejected += 1

                batch_result = self._process_batch_atomic(
                    events, run_id=run_id, batch_num=batch_num
                )

                current_watermark_id = batch_result.last_event_id
                result.total_rows_seen += batch_result.rows_seen + rejected
                result.total_rows_processed += batch_result.rows_processed
                result.total_rows_rejected += batch_result.rows_rejected + rejected

                if result.first_event_id is None:
                    result.first_event_id = batch_result.first_event_id
                result.last_event_id = batch_result.last_event_id

                self._update_run_progress(
                    run_id=run_id, batch_num=batch_num,
                    result=result, batch_result=batch_result,
                )

            result.batches_processed = batch_num
            result.status = "success"
            result.duration_ms = int(time.time() * 1000) - start_ms
            self._complete_run(run_id, result)
            logger.info(
                "Rebuild succeeded | run_id=%s batches=%d processed=%d duration_ms=%d",
                run_id, batch_num, result.total_rows_processed, result.duration_ms,
            )

        except Exception as exc:
            err = str(exc)
            result.status = "failed"
            result.error_message = err
            result.duration_ms = int(time.time() * 1000) - start_ms
            logger.error("Rebuild failed | run_id=%s error=%s", run_id, err, exc_info=True)
            self._fail_run(run_id, err)
        finally:
            try:
                pg_conn.close()
            except Exception:
                pass

        return result

    def run_dry_run(self) -> DryRunReport:
        """
        Non-destructive inspection.
        Reads current watermark and counts pending events.
        Does NOT modify dashboard.db, aggregation_state, or aggregation_runs.
        """
        initialize_dashboard_db(self.dashboard_db_path)
        watermark = self._load_watermark()

        report = DryRunReport(
            current_watermark_id=watermark.last_processed_event_id,
            current_watermark_ts=watermark.last_processed_event_timestamp,
        )

        try:
            pg_conn = self._get_pg_connection()
            with pg_conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM domain_query_history WHERE id > %s",
                    (watermark.last_processed_event_id,),
                )
                report.pending_event_count = int(cur.fetchone()[0])

                if report.pending_event_count > 0:
                    cur.execute(
                        """
                        SELECT MIN(id), MAX(id) FROM domain_query_history
                        WHERE id > %s
                        """,
                        (watermark.last_processed_event_id,),
                    )
                    row = cur.fetchone()
                    report.first_pending_id = row[0]
                    report.last_pending_id = row[1]

            pg_conn.close()
        except Exception as exc:
            logger.warning("Dry-run: PostgreSQL unavailable: %s", exc)

        if report.pending_event_count > 0:
            report.estimated_batches = max(
                1, (report.pending_event_count + self.batch_size - 1) // self.batch_size
            )

        return report

    def get_status(self) -> StatusReport:
        """
        Returns current watermark, run history, and pending event count.
        Does NOT modify any database.
        """
        initialize_dashboard_db(self.dashboard_db_path)
        watermark = self._load_watermark()

        report = StatusReport(
            aggregation_name=self.aggregation_name,
            current_watermark_id=watermark.last_processed_event_id,
            current_watermark_ts=watermark.last_processed_event_timestamp,
            last_successful_run_id=watermark.last_successful_run_id,
        )

        with self._sqlite_conn() as conn:
            conn.row_factory = sqlite3.Row
            # Last run overall
            row = conn.execute(
                """
                SELECT run_id, status, started_at, duration_ms, error_message, source_type
                FROM aggregation_runs
                WHERE aggregation_name = ?
                ORDER BY started_at DESC LIMIT 1
                """,
                (self.aggregation_name,),
            ).fetchone()
            if row:
                report.last_run_id = row["run_id"]
                report.last_run_status = row["status"]
                report.last_run_started_at = row["started_at"]
                report.last_run_duration_ms = row["duration_ms"]
                report.last_error = row["error_message"]
                report.source_type = row["source_type"]

            # Last successful run
            if watermark.last_successful_run_id:
                row2 = conn.execute(
                    "SELECT started_at FROM aggregation_runs WHERE run_id = ?",
                    (watermark.last_successful_run_id,),
                ).fetchone()
                if row2:
                    report.last_successful_run_started_at = row2["started_at"]

        # Pending events from PostgreSQL
        try:
            pg_conn = self._get_pg_connection()
            with pg_conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM domain_query_history WHERE id > %s",
                    (watermark.last_processed_event_id,),
                )
                report.pending_event_count = int(cur.fetchone()[0])
            pg_conn.close()
        except Exception as exc:
            logger.warning("Status: PostgreSQL unavailable: %s", exc)

        return report

    # -----------------------------------------------------------------------
    # Internal: PostgreSQL connection
    # -----------------------------------------------------------------------

    def _get_pg_connection(self):
        """Opens a psycopg3 connection to PostgreSQL. Raises on failure."""
        try:
            import psycopg
        except ImportError as exc:
            raise RuntimeError("psycopg (psycopg3) not installed") from exc

        conn = psycopg.connect(
            host=self.pg_host,
            port=self.pg_port,
            dbname=self.pg_name,
            user=self.pg_user,
            password=self.pg_password,
            connect_timeout=10,
        )
        return conn

    # -----------------------------------------------------------------------
    # Internal: SQLite connection helpers
    # -----------------------------------------------------------------------

    @contextmanager
    def _sqlite_conn(self) -> Generator[sqlite3.Connection, None, None]:
        """Plain SQLite connection (for reads and metadata writes)."""
        conn = sqlite3.connect(str(self.dashboard_db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _sqlite_write_conn(self) -> Generator[sqlite3.Connection, None, None]:
        """
        SQLite connection for atomic batch writes.
        Uses BEGIN IMMEDIATE to acquire the write lock immediately,
        preventing concurrent aggregators from corrupting state.
        """
        conn = sqlite3.connect(str(self.dashboard_db_path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.isolation_level = None  # manual transaction control
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            raise
        finally:
            conn.close()

    # -----------------------------------------------------------------------
    # Internal: Watermark
    # -----------------------------------------------------------------------

    def _load_watermark(self) -> Watermark:
        """Loads the current aggregation_state watermark from dashboard.db."""
        with self._sqlite_conn() as conn:
            row = conn.execute(
                """
                SELECT last_processed_event_id, last_processed_event_timestamp,
                       last_successful_run_id
                FROM aggregation_state
                WHERE aggregation_name = ?
                """,
                (self.aggregation_name,),
            ).fetchone()

        if row is None:
            return Watermark()

        return Watermark(
            last_processed_event_id=row["last_processed_event_id"] or 0,
            last_processed_event_timestamp=row["last_processed_event_timestamp"],
            last_successful_run_id=row["last_successful_run_id"],
        )

    def _save_watermark(
        self,
        conn: sqlite3.Connection,
        event_id: int,
        event_ts: Optional[str],
        run_id: str,
    ) -> None:
        """
        Saves the watermark inside an already-open transaction.
        MUST be called before COMMIT — never after.
        """
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            """
            INSERT INTO aggregation_state
                (aggregation_name, last_processed_event_id,
                 last_processed_event_timestamp, last_successful_run_id, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(aggregation_name) DO UPDATE SET
                last_processed_event_id = excluded.last_processed_event_id,
                last_processed_event_timestamp = excluded.last_processed_event_timestamp,
                last_successful_run_id = excluded.last_successful_run_id,
                updated_at = excluded.updated_at
            """,
            (self.aggregation_name, event_id, event_ts, run_id, now),
        )
        logger.debug("Watermark will advance to event_id=%d (pending COMMIT)", event_id)

    # -----------------------------------------------------------------------
    # Internal: aggregation_runs management
    # -----------------------------------------------------------------------

    def _start_run(self, run_id: str, source_type: str) -> None:
        """Creates an aggregation_runs record with status='running'."""
        now = datetime.now(timezone.utc).isoformat()
        with self._sqlite_conn() as conn:
            conn.execute(
                """
                INSERT INTO aggregation_runs
                    (run_id, aggregation_name, started_at, status, source_type,
                     source_identifier)
                VALUES (?, ?, ?, 'running', ?, ?)
                """,
                (
                    run_id, self.aggregation_name, now, source_type,
                    "domain_query_history",
                ),
            )
            conn.commit()
        logger.info("Run started | run_id=%s source_type=%s", run_id, source_type)

    def _update_run_progress(
        self,
        run_id: str,
        batch_num: int,
        result: AggregationResult,
        batch_result: BatchResult,
    ) -> None:
        """Updates aggregation_runs with current batch progress."""
        with self._sqlite_conn() as conn:
            conn.execute(
                """
                UPDATE aggregation_runs SET
                    batches_processed = ?,
                    first_event_id = COALESCE(first_event_id, ?),
                    last_event_id = ?,
                    first_event_timestamp = COALESCE(first_event_timestamp, ?),
                    last_event_timestamp = ?,
                    rows_seen = ?,
                    rows_processed = ?,
                    rows_rejected = ?
                WHERE run_id = ?
                """,
                (
                    batch_num,
                    result.first_event_id,
                    result.last_event_id,
                    batch_result.first_event_timestamp,
                    batch_result.last_event_timestamp,
                    result.total_rows_seen,
                    result.total_rows_processed,
                    result.total_rows_rejected,
                    run_id,
                ),
            )
            conn.commit()

    def _complete_run(self, run_id: str, result: AggregationResult) -> None:
        """Marks run as 'success' and records completion metadata."""
        now = datetime.now(timezone.utc).isoformat()
        with self._sqlite_conn() as conn:
            conn.execute(
                """
                UPDATE aggregation_runs SET
                    status = 'success',
                    finished_at = ?,
                    duration_ms = ?,
                    rows_seen = ?,
                    rows_processed = ?,
                    rows_rejected = ?,
                    batches_processed = ?,
                    first_event_id = ?,
                    last_event_id = ?
                WHERE run_id = ?
                """,
                (
                    now,
                    result.duration_ms,
                    result.total_rows_seen,
                    result.total_rows_processed,
                    result.total_rows_rejected,
                    result.batches_processed,
                    result.first_event_id,
                    result.last_event_id,
                    run_id,
                ),
            )
            conn.commit()

    def _fail_run(self, run_id: str, error_message: str) -> None:
        """Marks run as 'failed'. Does NOT touch aggregation_state watermark."""
        now = datetime.now(timezone.utc).isoformat()
        with self._sqlite_conn() as conn:
            conn.execute(
                """
                UPDATE aggregation_runs SET
                    status = 'failed',
                    finished_at = ?,
                    error_message = ?
                WHERE run_id = ?
                """,
                (now, error_message, run_id),
            )
            conn.commit()
        logger.info("Run marked failed | run_id=%s", run_id)

    def _recover_stale_runs(self) -> None:
        """
        Detects aggregation_runs records stuck in 'running' status
        (from crashed processes) and marks them 'failed'.
        Does NOT modify aggregation_state watermark.
        """
        threshold_minutes = self.stale_threshold_minutes
        now = datetime.now(timezone.utc)
        with self._sqlite_conn() as conn:
            rows = conn.execute(
                """
                SELECT run_id, started_at FROM aggregation_runs
                WHERE status = 'running' AND aggregation_name = ?
                """,
                (self.aggregation_name,),
            ).fetchall()

            for row in rows:
                try:
                    started = datetime.fromisoformat(
                        row["started_at"].replace("Z", "+00:00")
                    )
                    if started.tzinfo is None:
                        started = started.replace(tzinfo=timezone.utc)
                    age_minutes = (now - started).total_seconds() / 60
                    if age_minutes >= threshold_minutes:
                        conn.execute(
                            """
                            UPDATE aggregation_runs SET
                                status = 'failed',
                                finished_at = ?,
                                error_message = ?
                            WHERE run_id = ?
                            """,
                            (
                                now.isoformat(),
                                "Aggregation process terminated before completion.",
                                row["run_id"],
                            ),
                        )
                        logger.warning(
                            "Stale run detected and marked failed | run_id=%s age_min=%.1f",
                            row["run_id"], age_minutes,
                        )
                except Exception as exc:
                    logger.warning("Error recovering stale run %s: %s", row["run_id"], exc)

            conn.commit()

    # -----------------------------------------------------------------------
    # Internal: PostgreSQL event fetching
    # -----------------------------------------------------------------------

    def _fetch_batch(self, pg_conn, watermark_id: int) -> list[dict[str, Any]]:
        """
        Fetches up to self.batch_size events from domain_query_history
        with id > watermark_id, ordered by id ASC.
        Returns a list of dicts.
        """
        with pg_conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, domain, client_ip, query_type, timestamp,
                       response_code, registered_domain, tld, final_label, ti_source
                FROM domain_query_history
                WHERE id > %s
                ORDER BY id ASC
                LIMIT %s
                """,
                (watermark_id, self.batch_size),
            )
            columns = [desc[0] for desc in cur.description]
            rows = cur.fetchall()

        return [dict(zip(columns, row)) for row in rows]

    def _count_pending_events(self, pg_conn, watermark_id: int) -> int:
        """Returns the count of unprocessed events."""
        with pg_conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) FROM domain_query_history WHERE id > %s",
                (watermark_id,),
            )
            return int(cur.fetchone()[0])

    # -----------------------------------------------------------------------
    # Internal: Atomic batch processing
    # -----------------------------------------------------------------------

    def _process_batch_atomic(
        self,
        events: list[NormalizedEvent],
        run_id: str,
        batch_num: int,
    ) -> BatchResult:
        """
        Applies a batch of normalized events to dashboard.db atomically.

        Transaction: BEGIN IMMEDIATE ... COMMIT
        Watermark advances to the last event id inside this transaction.
        On failure the transaction is rolled back and the watermark stays unchanged.
        """
        if not events:
            return BatchResult()

        first_event = events[0]
        last_event = events[-1]

        result = BatchResult(
            first_event_id=first_event.event_id,
            last_event_id=last_event.event_id,
            first_event_timestamp=first_event.timestamp,
            last_event_timestamp=last_event.timestamp,
            rows_seen=len(events),
        )

        with self._sqlite_write_conn() as conn:
            # 1. Membership tables (idempotent INSERT OR IGNORE)
            self._upsert_domain_client_membership(conn, events)
            self._upsert_client_domain_membership(conn, events)

            # 2. Detail tables (with unique counts derived from membership)
            domains_touched = set(e.domain for e in events)
            clients_touched = set(e.client_ip for e in events)
            self._upsert_domain_details(conn, events)
            self._upsert_client_details(conn, events)
            self._update_unique_counts(conn, domains_touched, clients_touched)

            # 3. Summary tables
            self._upsert_metrics_summary(conn, events)
            self._upsert_timeseries(conn, events)
            self._upsert_threats_by_category(conn, events)
            self._upsert_recent_flagged(conn, events)

            # 4. Top-N tables (refreshed from detail tables)
            self._refresh_top_domains(conn)
            self._refresh_top_clients(conn)

            # 5. Advance watermark (INSIDE transaction)
            self._save_watermark(
                conn,
                event_id=last_event.event_id,
                event_ts=last_event.timestamp,
                run_id=run_id,
            )

            result.rows_processed = len(events)

        logger.info(
            "Batch %d committed | events=%d id_range=[%d, %d]",
            batch_num, len(events), first_event.event_id, last_event.event_id,
        )
        return result

    # -----------------------------------------------------------------------
    # Internal: Membership tables
    # -----------------------------------------------------------------------

    def _upsert_domain_client_membership(
        self, conn: sqlite3.Connection, events: list[NormalizedEvent]
    ) -> None:
        pairs = list({(e.domain, e.client_ip) for e in events})
        conn.executemany(
            "INSERT OR IGNORE INTO domain_client_membership (domain, client_ip) VALUES (?, ?)",
            pairs,
        )

    def _upsert_client_domain_membership(
        self, conn: sqlite3.Connection, events: list[NormalizedEvent]
    ) -> None:
        pairs = list({(e.client_ip, e.domain) for e in events})
        conn.executemany(
            "INSERT OR IGNORE INTO client_domain_membership (client_ip, domain) VALUES (?, ?)",
            pairs,
        )

    def _update_unique_counts(
        self,
        conn: sqlite3.Connection,
        domains: set[str],
        clients: set[str],
    ) -> None:
        """
        Recalculates unique_clients for each touched domain and
        unique_domains for each touched client using the membership tables.

        This is the correct approach — never += batch_unique_X.
        """
        now = datetime.now(timezone.utc).isoformat()

        # unique_clients per domain
        for domain in domains:
            row = conn.execute(
                "SELECT COUNT(*) FROM domain_client_membership WHERE domain = ?",
                (domain,),
            ).fetchone()
            unique_clients = row[0] if row else 0
            conn.execute(
                """
                UPDATE domain_details SET unique_clients = ?, updated_at = ?
                WHERE domain = ?
                """,
                (unique_clients, now, domain),
            )

        # unique_domains per client
        for client_ip in clients:
            row = conn.execute(
                "SELECT COUNT(*) FROM client_domain_membership WHERE client_ip = ?",
                (client_ip,),
            ).fetchone()
            unique_domains = row[0] if row else 0
            conn.execute(
                """
                UPDATE client_details SET unique_domains = ?, updated_at = ?
                WHERE client_ip = ?
                """,
                (unique_domains, now, client_ip),
            )

    # -----------------------------------------------------------------------
    # Internal: domain_details
    # -----------------------------------------------------------------------

    def _upsert_domain_details(
        self, conn: sqlite3.Connection, events: list[NormalizedEvent]
    ) -> None:
        """
        Incrementally upserts domain_details for all domains in the batch.

        Query type and response code breakdowns are stored as JSON.
        unique_clients is updated separately by _update_unique_counts.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Group events by domain
        from collections import defaultdict
        domain_groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for ev in events:
            domain_groups[ev.domain].append(ev)

        for domain, devs in domain_groups.items():
            # Load existing row
            existing = conn.execute(
                "SELECT * FROM domain_details WHERE domain = ?", (domain,)
            ).fetchone()

            if existing:
                ex = dict(existing)
                total_queries = ex["total_queries"] + len(devs)
                malicious_count = ex["malicious_count"] + sum(1 for e in devs if e.is_malicious)
                suspicious_count = ex["suspicious_count"] + sum(1 for e in devs if e.is_suspicious)
                clean_count = ex["clean_count"] + sum(1 for e in devs if e.is_clean)
                threat_count = malicious_count
                first_seen = ex["first_seen"]
                ts_list = [e.timestamp for e in devs] + ([first_seen] if first_seen else [])
                first_seen = min(ts_list)
                last_seen = max(e.timestamp for e in devs)
                if ex["last_seen"] and ex["last_seen"] > last_seen:
                    last_seen = ex["last_seen"]

                # Update last label from most recent event
                most_recent = max(devs, key=lambda e: e.timestamp)
                last_label = most_recent.final_label if most_recent.final_label else ex["last_label"]
                last_ti_source = most_recent.ti_source or ex["last_ti_source"]

                # Merge breakdowns
                qt_breakdown = _load_json_breakdown(ex["query_type_breakdown"])
                rc_breakdown = _load_json_breakdown(ex["response_code_breakdown"])
            else:
                total_queries = len(devs)
                malicious_count = sum(1 for e in devs if e.is_malicious)
                suspicious_count = sum(1 for e in devs if e.is_suspicious)
                clean_count = sum(1 for e in devs if e.is_clean)
                threat_count = malicious_count
                first_seen = min(e.timestamp for e in devs)
                last_seen = max(e.timestamp for e in devs)
                most_recent = max(devs, key=lambda e: e.timestamp)
                last_label = most_recent.final_label
                last_ti_source = most_recent.ti_source
                qt_breakdown: dict[str, int] = {}
                rc_breakdown: dict[str, int] = {}

            for ev in devs:
                qt_breakdown[ev.query_type] = qt_breakdown.get(ev.query_type, 0) + 1
                rc_breakdown[ev.response_code] = rc_breakdown.get(ev.response_code, 0) + 1

            conn.execute(
                """
                INSERT INTO domain_details
                    (domain, total_queries, unique_clients, threat_count,
                     malicious_count, suspicious_count, clean_count,
                     first_seen, last_seen, last_label, threat_score, confidence,
                     last_ti_source, label_reason, query_type_breakdown,
                     response_code_breakdown, asn, asn_org, country,
                     resolved_ips, domain_age_days, enrichment_json, updated_at)
                VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, NULL,
                        ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?)
                ON CONFLICT(domain) DO UPDATE SET
                    total_queries = excluded.total_queries,
                    threat_count = excluded.threat_count,
                    malicious_count = excluded.malicious_count,
                    suspicious_count = excluded.suspicious_count,
                    clean_count = excluded.clean_count,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen,
                    last_label = excluded.last_label,
                    last_ti_source = excluded.last_ti_source,
                    query_type_breakdown = excluded.query_type_breakdown,
                    response_code_breakdown = excluded.response_code_breakdown,
                    updated_at = excluded.updated_at
                """,
                (
                    domain, total_queries, threat_count,
                    malicious_count, suspicious_count, clean_count,
                    first_seen, last_seen, last_label,
                    last_ti_source,
                    _dump_json_breakdown(qt_breakdown),
                    _dump_json_breakdown(rc_breakdown),
                    now,
                ),
            )

    # -----------------------------------------------------------------------
    # Internal: client_details
    # -----------------------------------------------------------------------

    def _upsert_client_details(
        self, conn: sqlite3.Connection, events: list[NormalizedEvent]
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()

        from collections import defaultdict
        client_groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for ev in events:
            client_groups[ev.client_ip].append(ev)

        for client_ip, cevs in client_groups.items():
            existing = conn.execute(
                "SELECT * FROM client_details WHERE client_ip = ?", (client_ip,)
            ).fetchone()

            if existing:
                ex = dict(existing)
                total_queries = ex["total_queries"] + len(cevs)
                malicious_count = ex["malicious_count"] + sum(1 for e in cevs if e.is_malicious)
                suspicious_count = ex["suspicious_count"] + sum(1 for e in cevs if e.is_suspicious)
                clean_count = ex["clean_count"] + sum(1 for e in cevs if e.is_clean)
                threat_count = malicious_count
                ts_list = [e.timestamp for e in cevs]
                if ex["first_seen"]:
                    ts_list.append(ex["first_seen"])
                first_seen = min(ts_list)
                last_seen = max(e.timestamp for e in cevs)
                if ex["last_seen"] and ex["last_seen"] > last_seen:
                    last_seen = ex["last_seen"]
            else:
                total_queries = len(cevs)
                malicious_count = sum(1 for e in cevs if e.is_malicious)
                suspicious_count = sum(1 for e in cevs if e.is_suspicious)
                clean_count = sum(1 for e in cevs if e.is_clean)
                threat_count = malicious_count
                first_seen = min(e.timestamp for e in cevs)
                last_seen = max(e.timestamp for e in cevs)

            conn.execute(
                """
                INSERT INTO client_details
                    (client_ip, total_queries, unique_domains, threat_count,
                     malicious_count, suspicious_count, clean_count,
                     first_seen, last_seen, top_domains, updated_at)
                VALUES (?, ?, 0, ?, ?, ?, ?, ?, ?, NULL, ?)
                ON CONFLICT(client_ip) DO UPDATE SET
                    total_queries = excluded.total_queries,
                    threat_count = excluded.threat_count,
                    malicious_count = excluded.malicious_count,
                    suspicious_count = excluded.suspicious_count,
                    clean_count = excluded.clean_count,
                    first_seen = excluded.first_seen,
                    last_seen = excluded.last_seen,
                    updated_at = excluded.updated_at
                """,
                (
                    client_ip, total_queries, threat_count,
                    malicious_count, suspicious_count, clean_count,
                    first_seen, last_seen, now,
                ),
            )

        # Update top_domains JSON for each client touched
        for client_ip in client_groups:
            top_rows = conn.execute(
                """
                SELECT domain, COUNT(*) as cnt
                FROM client_domain_membership
                WHERE client_ip = ?
                GROUP BY domain
                ORDER BY cnt DESC
                LIMIT 10
                """,
                (client_ip,),
            ).fetchall()
            top_domains_json = json.dumps(
                [{"domain": r[0], "count": r[1]} for r in top_rows],
                separators=(",", ":"),
            )
            conn.execute(
                "UPDATE client_details SET top_domains = ? WHERE client_ip = ?",
                (top_domains_json, client_ip),
            )

    # -----------------------------------------------------------------------
    # Internal: metrics_summary
    # -----------------------------------------------------------------------

    def _upsert_metrics_summary(
        self, conn: sqlite3.Connection, events: list[NormalizedEvent]
    ) -> None:
        batch_total = len(events)
        batch_threats = sum(1 for e in events if e.is_threat)
        now = datetime.now(timezone.utc).isoformat()

        # unique_clients and unique_domains come from the detail tables
        unique_clients = conn.execute(
            "SELECT COUNT(*) FROM client_details"
        ).fetchone()[0]
        unique_domains = conn.execute(
            "SELECT COUNT(*) FROM domain_details"
        ).fetchone()[0]

        conn.execute(
            """
            INSERT INTO metrics_summary
                (id, total_queries, total_threats, threats_blocked_pct,
                 unique_clients, unique_domains, last_pipeline_run_at)
            VALUES (1, ?, ?, 0.0, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                total_queries = metrics_summary.total_queries + excluded.total_queries,
                total_threats = metrics_summary.total_threats + excluded.total_threats,
                threats_blocked_pct = CASE
                    WHEN metrics_summary.total_queries + excluded.total_queries = 0 THEN 0.0
                    ELSE ROUND(
                        CAST(metrics_summary.total_threats + excluded.total_threats AS REAL)
                        / CAST(metrics_summary.total_queries + excluded.total_queries AS REAL)
                        * 100.0, 2)
                    END,
                unique_clients = excluded.unique_clients,
                unique_domains = excluded.unique_domains,
                last_pipeline_run_at = excluded.last_pipeline_run_at
            """,
            (batch_total, batch_threats, unique_clients, unique_domains, now),
        )

    # -----------------------------------------------------------------------
    # Internal: queries_timeseries
    # -----------------------------------------------------------------------

    def _upsert_timeseries(
        self, conn: sqlite3.Connection, events: list[NormalizedEvent]
    ) -> None:
        from collections import defaultdict
        bucket_totals: dict[str, int] = defaultdict(int)
        bucket_threats: dict[str, int] = defaultdict(int)

        for ev in events:
            bucket_totals[ev.time_bucket] += 1
            if ev.is_threat:
                bucket_threats[ev.time_bucket] += 1

        records = [
            (bucket, bucket_totals[bucket], bucket_threats.get(bucket, 0))
            for bucket in bucket_totals
        ]
        conn.executemany(
            """
            INSERT INTO queries_timeseries (time_bucket, total_queries, threat_queries)
            VALUES (?, ?, ?)
            ON CONFLICT(time_bucket) DO UPDATE SET
                total_queries = queries_timeseries.total_queries + excluded.total_queries,
                threat_queries = queries_timeseries.threat_queries + excluded.threat_queries
            """,
            records,
        )

    # -----------------------------------------------------------------------
    # Internal: threats_by_category
    # -----------------------------------------------------------------------

    def _upsert_threats_by_category(
        self, conn: sqlite3.Connection, events: list[NormalizedEvent]
    ) -> None:
        from collections import defaultdict
        cat_counts: dict[str, int] = defaultdict(int)

        for ev in events:
            # Use ti_source as category if available, else final_label
            category = ev.ti_source or ev.final_label or "Unknown"
            cat_counts[category] += 1

        records = [(cat, count) for cat, count in cat_counts.items()]
        conn.executemany(
            """
            INSERT INTO threats_by_category (category, count, pct)
            VALUES (?, ?, 0.0)
            ON CONFLICT(category) DO UPDATE SET
                count = threats_by_category.count + excluded.count
            """,
            records,
        )
        # Recalculate percentages for all categories
        conn.execute(
            """
            UPDATE threats_by_category
            SET pct = CASE
                WHEN (SELECT SUM(count) FROM threats_by_category) = 0 THEN 0.0
                ELSE ROUND(CAST(count AS REAL)
                     / CAST((SELECT SUM(count) FROM threats_by_category) AS REAL)
                     * 100.0, 2)
            END
            """
        )

    # -----------------------------------------------------------------------
    # Internal: recent_flagged_domains
    # -----------------------------------------------------------------------

    def _upsert_recent_flagged(
        self, conn: sqlite3.Connection, events: list[NormalizedEvent]
    ) -> None:
        flagged = [e for e in events if e.is_malicious]
        if not flagged:
            return

        # Deduplicate: keep most recent event per domain
        from collections import defaultdict
        latest: dict[str, NormalizedEvent] = {}
        for ev in flagged:
            if ev.domain not in latest or ev.timestamp > latest[ev.domain].timestamp:
                latest[ev.domain] = ev

        for domain, ev in latest.items():
            conn.execute(
                """
                INSERT INTO recent_flagged_domains
                    (domain, label, label_reason, ti_source, confidence, flagged_at)
                VALUES (?, ?, NULL, ?, NULL, ?)
                """,
                (domain, ev.final_label or "Malicious", ev.ti_source, ev.timestamp),
            )

        # Retention: keep only the N most recent rows
        conn.execute(
            """
            DELETE FROM recent_flagged_domains
            WHERE id NOT IN (
                SELECT id FROM recent_flagged_domains
                ORDER BY flagged_at DESC
                LIMIT ?
            )
            """,
            (self.recent_flagged_limit,),
        )

    # -----------------------------------------------------------------------
    # Internal: top_domains / top_clients (derived from detail tables)
    # -----------------------------------------------------------------------

    def _refresh_top_domains(self, conn: sqlite3.Connection) -> None:
        """
        Refreshes top_domains from domain_details.
        Ranked by threat_count DESC, then total_queries DESC.
        Preserves existing top_domains schema (domain, query_count, label,
        threat_score, last_seen).
        """
        conn.execute("DELETE FROM top_domains")
        conn.execute(
            """
            INSERT INTO top_domains (domain, query_count, label, threat_score, last_seen)
            SELECT
                domain,
                total_queries,
                COALESCE(last_label, 'Unknown'),
                0.0,
                COALESCE(last_seen, '')
            FROM domain_details
            ORDER BY threat_count DESC, total_queries DESC
            LIMIT 100
            """
        )

    def _refresh_top_clients(self, conn: sqlite3.Connection) -> None:
        """
        Refreshes top_clients from client_details.
        Ranked by total_queries DESC.
        Preserves existing top_clients schema.
        """
        conn.execute("DELETE FROM top_clients")
        conn.execute(
            """
            INSERT INTO top_clients (client_ip, query_count, malicious_query_count, last_seen)
            SELECT
                client_ip,
                total_queries,
                malicious_count,
                COALESCE(last_seen, '')
            FROM client_details
            ORDER BY total_queries DESC
            LIMIT 100
            """
        )

    # -----------------------------------------------------------------------
    # Internal: Rebuild helpers
    # -----------------------------------------------------------------------

    def _clear_read_model_atomic(self) -> None:
        """
        Clears all read-model tables and resets aggregation_state in one
        atomic transaction. On failure the transaction is rolled back so
        the dashboard is not left in a partial state.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._sqlite_write_conn() as conn:
            for table in (
                "domain_client_membership",
                "client_domain_membership",
                "domain_details",
                "client_details",
                "metrics_summary",
                "threats_by_category",
                "queries_timeseries",
                "geo_distribution",
                "top_domains",
                "top_clients",
                "recent_flagged_domains",
            ):
                conn.execute(f"DELETE FROM {table}")

            # Reset watermark
            conn.execute(
                """
                INSERT INTO aggregation_state
                    (aggregation_name, last_processed_event_id,
                     last_processed_event_timestamp, last_successful_run_id, updated_at)
                VALUES (?, 0, NULL, NULL, ?)
                ON CONFLICT(aggregation_name) DO UPDATE SET
                    last_processed_event_id = 0,
                    last_processed_event_timestamp = NULL,
                    last_successful_run_id = NULL,
                    updated_at = excluded.updated_at
                """,
                (self.aggregation_name, now),
            )
