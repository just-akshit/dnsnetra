"""
Domain Analytics Service
========================
Executes production-grade Time-Window DNS Analytics using database-side
aggregations on the append-only PostgreSQL `domain_query_history` table.

Architectural Guarantees:
- Database-side aggregation with two bounded aggregate queries; no raw telemetry iteration in Python.
- Strict canonical half-open time boundary: [start, end).
- Historical observational integrity: relies exclusively on immutable historical labels recorded at query time.
- Deterministic timeline bucket alignment with complete zero-gap filling.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

import psycopg2.extras

from analytics.models import (
    AnalyticsWindow,
    DomainAnalyticsData,
    DomainAnalyticsMetrics,
    TimelineBucket,
)
from analytics.time_window import (
    TimeWindow,
    format_iso8601_utc,
    resolve_time_window,
)
from domain_profiling.connection import get_db_connection

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQL Aggregation Queries (Half-Open Interval [start, end))
# ---------------------------------------------------------------------------

SQL_SUMMARY_METRICS = """
SELECT 
    COUNT(*) AS total_queries,
    COUNT(DISTINCT domain) AS unique_fqdns,
    COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_registered_domains,
    COUNT(DISTINCT client_ip) AS unique_clients,
    COUNT(DISTINCT CASE WHEN LOWER(COALESCE(final_label, '')) = 'malicious' THEN COALESCE(NULLIF(registered_domain, ''), domain) END) AS malicious_domains,
    COUNT(DISTINCT CASE WHEN LOWER(COALESCE(final_label, '')) = 'suspicious' THEN COALESCE(NULLIF(registered_domain, ''), domain) END) AS suspicious_domains
FROM domain_query_history
WHERE timestamp >= %(start)s AND timestamp < %(end)s;
"""

SQL_TIMELINE_BUCKETS = """
SELECT 
    to_timestamp(floor(extract(epoch from timestamp) / %(bucket_seconds)s) * %(bucket_seconds)s) AT TIME ZONE 'UTC' AS bucket_time,
    COUNT(*) AS queries,
    COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_domains
FROM domain_query_history
WHERE timestamp >= %(start)s AND timestamp < %(end)s
GROUP BY bucket_time
ORDER BY bucket_time ASC;
"""


class DomainAnalyticsService:
    """
    Core analytics service for time-window DNS query telemetry.
    """

    @classmethod
    def get_analytics(
        cls,
        window: Optional[str] = None,
        start: Optional[Union[str, datetime]] = None,
        end: Optional[Union[str, datetime]] = None,
        now_override: Optional[datetime] = None,
    ) -> DomainAnalyticsData:
        """
        Calculates time-window DNS domain metrics and timeline activity.
        
        Args:
            window: Preset identifier ('5m', '10m', '15m', '30m', '45m', '60m').
            start: Custom start timestamp (ISO8601 string or datetime).
            end: Custom end timestamp (ISO8601 string or datetime).
            now_override: Optional fixed timestamp for deterministic testing.
            
        Returns:
            DomainAnalyticsData containing the active window, metrics, and timeline.
        """
        # 1. Resolve and validate the active time window
        time_win = resolve_time_window(
            window=window,
            start=start,
            end=end,
            now_override=now_override,
        )

        logger.debug(
            "Executing domain analytics for window [%s, %s) with bucket_size=%ds",
            time_win.start_iso,
            time_win.end_iso,
            time_win.bucket_seconds,
        )

        # 2. Execute bounded aggregate queries against PostgreSQL
        metrics_dict, raw_buckets = cls._execute_queries(time_win)

        # 3. Align raw timeline rows with deterministic bucket grid (zero-gap filling)
        timeline = cls._align_timeline_buckets(time_win, raw_buckets)

        # 4. Construct validated response model
        return DomainAnalyticsData(
            window=AnalyticsWindow(
                start=time_win.start_iso,
                end=time_win.end_iso,
                duration_minutes=time_win.duration_minutes,
            ),
            metrics=DomainAnalyticsMetrics(
                total_queries=int(metrics_dict.get("total_queries") or 0),
                unique_fqdns=int(metrics_dict.get("unique_fqdns") or 0),
                unique_registered_domains=int(metrics_dict.get("unique_registered_domains") or 0),
                unique_clients=int(metrics_dict.get("unique_clients") or 0),
                malicious_domains=int(metrics_dict.get("malicious_domains") or 0),
                suspicious_domains=int(metrics_dict.get("suspicious_domains") or 0),
            ),
            timeline=timeline,
        )

    @classmethod
    def _execute_queries(
        cls, time_win: TimeWindow
    ) -> Tuple[Dict[str, Any], Dict[str, Dict[str, int]]]:
        """
        Executes the two bounded database aggregate queries in PostgreSQL.
        """
        params = {
            "start": time_win.start,
            "end": time_win.end,
            "bucket_seconds": time_win.bucket_seconds,
        }

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # Query 1: Summary metrics across the window
                cur.execute(SQL_SUMMARY_METRICS, params)
                summary_row = cur.fetchone() or {}

                # Query 2: Timeline buckets
                cur.execute(SQL_TIMELINE_BUCKETS, params)
                bucket_rows = cur.fetchall() or []

        # Index returned buckets by their UTC ISO8601 timestamp string
        buckets_map: Dict[str, Dict[str, int]] = {}
        for r in bucket_rows:
            b_time = r.get("bucket_time")
            if isinstance(b_time, datetime):
                b_key = format_iso8601_utc(b_time)
            elif isinstance(b_time, str):
                b_key = format_iso8601_utc(datetime.fromisoformat(b_time))
            else:
                continue

            buckets_map[b_key] = {
                "queries": int(r.get("queries") or 0),
                "unique_domains": int(r.get("unique_domains") or 0),
            }

        return dict(summary_row), buckets_map

    @classmethod
    def _align_timeline_buckets(
        cls, time_win: TimeWindow, buckets_map: Dict[str, Dict[str, int]]
    ) -> List[TimelineBucket]:
        """
        Generates the complete deterministic list of timeline buckets,
        populating known database aggregates or 0 for empty intervals.
        """
        bucket_timestamps = time_win.generate_bucket_timestamps()
        aligned_buckets: List[TimelineBucket] = []

        for b_dt in bucket_timestamps:
            iso_key = format_iso8601_utc(b_dt)
            data = buckets_map.get(iso_key, {"queries": 0, "unique_domains": 0})
            aligned_buckets.append(
                TimelineBucket(
                    timestamp=iso_key,
                    queries=data["queries"],
                    unique_domains=data["unique_domains"],
                )
            )

        return aligned_buckets
