"""
reporting/repository.py
=======================
PostgreSQL data access layer for DNSNetra Reporting Engine.
Pure SQL, parameterized queries, deterministic sorting, and zero HTTP dependencies.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras

from domain_profiling.connection import get_db_connection
from .schemas import CanonicalVerdict

logger = logging.getLogger(__name__)


class ReportingRepository:
    """
    Repository providing optimized database query operations for reporting.
    """

    def __init__(self, connection_factory=None) -> None:
        self._connection_factory = connection_factory or get_db_connection

    def _get_conn(self):
        return self._connection_factory()

    # -----------------------------------------------------------------------
    # 1. Summary Queries
    # -----------------------------------------------------------------------

    def get_all_time_summary(self) -> Dict[str, Any]:
        """
        Retrieves all-time query volume and entity counts.
        Combines telemetry_hourly_rollup, client_profiles, and domain_profiles.
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(total_queries), 0) AS total_queries,
                        COALESCE(SUM(clean_queries), 0) AS benign_queries,
                        COALESCE(SUM(suspicious_queries), 0) AS review_needed_queries,
                        COALESCE(SUM(malicious_queries), 0) AS malicious_queries,
                        COALESCE(SUM(unknown_queries), 0) AS unknown_queries
                    FROM telemetry_hourly_rollup;
                """)
                counts = cur.fetchone() or {}

                cur.execute("SELECT COUNT(*) AS unique_clients FROM client_profiles;")
                c_row = cur.fetchone() or {}

                cur.execute("SELECT COUNT(*) AS unique_domains FROM domain_profiles;")
                d_row = cur.fetchone() or {}

                return {
                    "total_queries": int(counts.get("total_queries") or 0),
                    "benign_queries": int(counts.get("benign_queries") or 0),
                    "malicious_queries": int(counts.get("malicious_queries") or 0),
                    "review_needed_queries": int(counts.get("review_needed_queries") or 0),
                    "unknown_queries": int(counts.get("unknown_queries") or 0),
                    "unique_clients": int(c_row.get("unique_clients") or 0),
                    "unique_domains": int(d_row.get("unique_domains") or 0),
                }

    def get_aligned_window_summary(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """
        Retrieves summary for an exact hourly-aligned interval [start_time, end_time).
        Uses telemetry_hourly_rollup for additive sums and domain_query_history for distinct cardinality.
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(total_queries), 0) AS total_queries,
                        COALESCE(SUM(clean_queries), 0) AS benign_queries,
                        COALESCE(SUM(suspicious_queries), 0) AS review_needed_queries,
                        COALESCE(SUM(malicious_queries), 0) AS malicious_queries,
                        COALESCE(SUM(unknown_queries), 0) AS unknown_queries
                    FROM telemetry_hourly_rollup
                    WHERE bucket_time >= %s AND bucket_time < %s;
                """, (start_time, end_time))
                counts = cur.fetchone() or {}

                cur.execute("""
                    SELECT 
                        COUNT(DISTINCT client_ip) AS unique_clients,
                        COUNT(DISTINCT domain) AS unique_domains
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s;
                """, (start_time, end_time))
                distincts = cur.fetchone() or {}

                return {
                    "total_queries": int(counts.get("total_queries") or 0),
                    "benign_queries": int(counts.get("benign_queries") or 0),
                    "malicious_queries": int(counts.get("malicious_queries") or 0),
                    "review_needed_queries": int(counts.get("review_needed_queries") or 0),
                    "unknown_queries": int(counts.get("unknown_queries") or 0),
                    "unique_clients": int(distincts.get("unique_clients") or 0),
                    "unique_domains": int(distincts.get("unique_domains") or 0),
                }

    def get_raw_window_summary(self, start_time: datetime, end_time: datetime) -> Dict[str, Any]:
        """
        Retrieves summary directly from domain_query_history for partial-hour or unaligned windows.
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        COUNT(*) AS total_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Unknown' OR final_label IS NULL) AS unknown_queries,
                        COUNT(DISTINCT client_ip) AS unique_clients,
                        COUNT(DISTINCT domain) AS unique_domains
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s;
                """, (start_time, end_time))
                row = cur.fetchone() or {}
                return {
                    "total_queries": int(row.get("total_queries") or 0),
                    "benign_queries": int(row.get("benign_queries") or 0),
                    "malicious_queries": int(row.get("malicious_queries") or 0),
                    "review_needed_queries": int(row.get("review_needed_queries") or 0),
                    "unknown_queries": int(row.get("unknown_queries") or 0),
                    "unique_clients": int(row.get("unique_clients") or 0),
                    "unique_domains": int(row.get("unique_domains") or 0),
                }

    # -----------------------------------------------------------------------
    # 2. Timeseries Queries
    # -----------------------------------------------------------------------

    def get_aligned_timeseries(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """
        Fetches hourly rollup buckets from telemetry_hourly_rollup.
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        bucket_time,
                        total_queries,
                        clean_queries AS benign_queries,
                        malicious_queries,
                        suspicious_queries AS review_needed_queries,
                        unknown_queries
                    FROM telemetry_hourly_rollup
                    WHERE bucket_time >= %s AND bucket_time < %s
                    ORDER BY bucket_time ASC;
                """, (start_time, end_time))
                return [dict(r) for r in cur.fetchall()]

    def get_raw_timeseries(
        self, start_time: datetime, end_time: datetime, width_seconds: int = 3600
    ) -> List[Dict[str, Any]]:
        """
        Fetches bucket totals directly from domain_query_history for width_seconds,
        strictly clipped to [start_time, end_time).
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT 
                        to_timestamp(
                            CASE 
                                WHEN %s = 604800 THEN (floor((EXTRACT(EPOCH FROM timestamp) - 345600) / 604800) * 604800 + 345600)
                                ELSE (floor(EXTRACT(EPOCH FROM timestamp) / %s) * %s)
                            END
                        ) AS bucket_time,
                        COUNT(*) AS total_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Unknown' OR final_label IS NULL) AS unknown_queries
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s
                    GROUP BY bucket_time
                    ORDER BY bucket_time ASC;
                """, (width_seconds, width_seconds, width_seconds, start_time, end_time))
                return [dict(r) for r in cur.fetchall()]

    # -----------------------------------------------------------------------
    # 3. Top Clients Queries
    # -----------------------------------------------------------------------

    def get_all_time_top_clients(self, limit: int, offset: int) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Retrieves all-time ranked clients from client_profiles.
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT COUNT(*) FROM client_profiles;")
                total = cur.fetchone()["count"]

                cur.execute("""
                    SELECT 
                        host(client_ip) AS client_ip,
                        total_queries,
                        unique_domains,
                        benign_queries,
                        malicious_queries,
                        review_needed_queries,
                        unknown_queries,
                        last_domain,
                        last_query_type,
                        to_char(first_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                        to_char(last_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM client_profiles
                    ORDER BY total_queries DESC, client_ip ASC
                    LIMIT %s OFFSET %s;
                """, (limit, offset))
                return total, [dict(r) for r in cur.fetchall()]

    def get_windowed_top_clients(
        self, start_time: datetime, end_time: datetime, limit: int, offset: int
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Retrieves windowed ranked clients from domain_query_history.
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT COUNT(DISTINCT client_ip)
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s;
                """, (start_time, end_time))
                total = cur.fetchone()["count"]

                cur.execute("""
                    SELECT 
                        client_ip,
                        COUNT(*) AS total_queries,
                        COUNT(DISTINCT domain) AS unique_domains,
                        COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Unknown' OR final_label IS NULL) AS unknown_queries,
                        (ARRAY_AGG(domain ORDER BY timestamp DESC, id DESC))[1] AS last_domain,
                        (ARRAY_AGG(query_type ORDER BY timestamp DESC, id DESC))[1] AS last_query_type,
                        to_char(MIN(timestamp) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                        to_char(MAX(timestamp) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s
                    GROUP BY client_ip
                    ORDER BY total_queries DESC, client_ip ASC
                    LIMIT %s OFFSET %s;
                """, (start_time, end_time, limit, offset))
                return total, [dict(r) for r in cur.fetchall()]

    # -----------------------------------------------------------------------
    # 4. Top Domains Queries
    # -----------------------------------------------------------------------

    def get_all_time_top_domains(self, limit: int, offset: int) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Retrieves all-time ranked domains from domain_profiles.
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT COUNT(*) FROM domain_profiles;")
                total = cur.fetchone()["count"]

                cur.execute("""
                    SELECT 
                        domain,
                        total_queries,
                        unique_clients,
                        clean_queries AS benign_queries,
                        malicious_queries,
                        review_needed_queries,
                        unknown_queries,
                        last_label AS latest_verdict,
                        to_char(first_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                        to_char(last_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_profiles
                    ORDER BY total_queries DESC, domain ASC
                    LIMIT %s OFFSET %s;
                """, (limit, offset))
                return total, [dict(r) for r in cur.fetchall()]

    def get_windowed_top_domains(
        self, start_time: datetime, end_time: datetime, limit: int, offset: int
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Retrieves windowed ranked domains from domain_query_history without verdict filter.
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT COUNT(DISTINCT domain)
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s;
                """, (start_time, end_time))
                total = cur.fetchone()["count"]

                cur.execute("""
                    SELECT 
                        domain,
                        COUNT(*) AS total_queries,
                        COUNT(DISTINCT client_ip) AS unique_clients,
                        COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Unknown' OR final_label IS NULL) AS unknown_queries,
                        (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                        to_char(MIN(timestamp) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                        to_char(MAX(timestamp) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s
                    GROUP BY domain
                    ORDER BY total_queries DESC, domain ASC
                    LIMIT %s OFFSET %s;
                """, (start_time, end_time, limit, offset))
                return total, [dict(r) for r in cur.fetchall()]

    def get_filtered_top_domains(
        self,
        verdict: str,
        start_time: Optional[datetime],
        end_time: Optional[datetime],
        limit: int,
        offset: int,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Retrieves ranked domains strictly scoped to an event-population matching the verdict.
        Only events matching the verdict participate in metrics and ranking.
        """
        params: List[Any] = [verdict]
        time_clause = ""
        if start_time and end_time:
            time_clause = "AND timestamp >= %s AND timestamp < %s"
            params.extend([start_time, end_time])

        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # 1. Total distinct domains in this filtered event population
                count_sql = f"""
                    SELECT COUNT(DISTINCT domain)
                    FROM domain_query_history
                    WHERE final_label = %s {time_clause};
                """
                cur.execute(count_sql, tuple(params))
                total = cur.fetchone()["count"]

                query_sql = f"""
                    SELECT 
                        domain,
                        COUNT(*) AS total_queries,
                        COUNT(DISTINCT client_ip) AS unique_clients,
                        COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_queries,
                        COUNT(*) FILTER (WHERE final_label = 'Unknown' OR final_label IS NULL) AS unknown_queries,
                        %s AS latest_verdict,
                        to_char(MIN(timestamp) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                        to_char(MAX(timestamp) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_query_history
                    WHERE final_label = %s {time_clause}
                    GROUP BY domain
                    ORDER BY total_queries DESC, domain ASC
                    LIMIT %s OFFSET %s;
                """
                query_params: List[Any] = [verdict, verdict]
                if start_time and end_time:
                    query_params.extend([start_time, end_time])
                query_params.extend([limit, offset])
                cur.execute(query_sql, tuple(query_params))
                return total, [dict(r) for r in cur.fetchall()]

    # -----------------------------------------------------------------------
    # 5. Query Event Log
    # -----------------------------------------------------------------------

    def get_queries(
        self,
        client_ip: Optional[str] = None,
        domain: Optional[str] = None,
        verdict: Optional[str] = None,
        query_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        """
        Multi-criteria paginated query on authoritative domain_query_history.
        """
        clauses = []
        params: List[Any] = []

        if client_ip:
            clauses.append("client_ip = %s")
            params.append(client_ip.strip())

        if domain:
            clauses.append("domain = %s")
            params.append(domain.strip().lower())

        if verdict:
            clauses.append("final_label = %s")
            params.append(verdict)

        if query_type:
            clauses.append("query_type = %s")
            params.append(query_type.strip().upper())

        if start_time and end_time:
            clauses.append("timestamp >= %s AND timestamp < %s")
            params.extend([start_time, end_time])
        elif start_time:
            clauses.append("timestamp >= %s")
            params.append(start_time)
        elif end_time:
            clauses.append("timestamp < %s")
            params.append(end_time)

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # 1. Total matching count
                cur.execute(f"SELECT COUNT(*) FROM domain_query_history {where_sql};", tuple(params))
                total = cur.fetchone()["count"]

                # 2. Paginated items
                items_params = list(params)
                items_params.extend([limit, offset])

                cur.execute(f"""
                    SELECT 
                        id,
                        to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS timestamp,
                        client_ip,
                        domain,
                        query_type,
                        response_code,
                        final_label,
                        ti_source,
                        registered_domain,
                        tld
                    FROM domain_query_history
                    {where_sql}
                    ORDER BY timestamp DESC, id DESC
                    LIMIT %s OFFSET %s;
                """, tuple(items_params))

                return total, [dict(r) for r in cur.fetchall()]

    def stream_queries_csv(
        self,
        client_ip: Optional[str] = None,
        domain: Optional[str] = None,
        verdict: Optional[str] = None,
        query_type: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 5000,
        chunk_size: int = 1000,
    ):
        """
        Yields RFC 4180 compliant CSV string chunks for bounded query export.
        Uses parameterized SQL and streaming cursor to prevent unbounded memory usage.
        """
        import csv
        import io

        clauses = []
        params: List[Any] = []

        if client_ip:
            clauses.append("client_ip = %s")
            params.append(client_ip.strip())

        if domain:
            clauses.append("domain = %s")
            params.append(domain.strip().lower())

        if verdict:
            clauses.append("final_label = %s")
            params.append(verdict)

        if query_type:
            clauses.append("query_type = %s")
            params.append(query_type.strip().upper())

        if start_time and end_time:
            clauses.append("timestamp >= %s AND timestamp < %s")
            params.extend([start_time, end_time])
        elif start_time:
            clauses.append("timestamp >= %s")
            params.append(start_time)
        elif end_time:
            clauses.append("timestamp < %s")
            params.append(end_time)

        where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        query_params = list(params)
        query_params.append(limit)

        fieldnames = [
            "id",
            "timestamp",
            "client_ip",
            "domain",
            "query_type",
            "response_code",
            "verdict",
            "ti_source",
            "registered_domain",
            "tld",
        ]

        # 1. Output CSV header
        header_buf = io.StringIO()
        writer = csv.DictWriter(header_buf, fieldnames=fieldnames)
        writer.writeheader()
        yield header_buf.getvalue()

        with self._get_conn() as conn:
            cursor_name = f"csv_cur_{id(conn)}_{datetime.now().strftime('%H%M%S%f')}"
            with conn.cursor(name=cursor_name, cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.itersize = chunk_size
                cur.execute(f"""
                    SELECT 
                        id,
                        to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS timestamp,
                        client_ip,
                        domain,
                        query_type,
                        response_code,
                        final_label AS verdict,
                        ti_source,
                        registered_domain,
                        tld
                    FROM domain_query_history
                    {where_sql}
                    ORDER BY timestamp DESC, id DESC
                    LIMIT %s;
                """, tuple(query_params))

                while True:
                    rows = cur.fetchmany(chunk_size)
                    if not rows:
                        break
                    buf = io.StringIO()
                    chunk_writer = csv.DictWriter(buf, fieldnames=fieldnames)
                    for r in rows:
                        chunk_writer.writerow(dict(r))
                    yield buf.getvalue()


