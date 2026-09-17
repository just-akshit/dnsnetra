"""
aggregator/queries.py
=====================
High-performance backend analytics and query interfaces for DNSNetra.

Bridges pre-aggregated PostgreSQL rollups (`telemetry_hourly_rollup`, 
`telemetry_daily_domain_rollup`), entity profiles (`domain_profiles`, `client_profiles`),
and composite-indexed raw history (`domain_query_history`).
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List
import psycopg2
import psycopg2.extras

from aggregator.config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD


def _get_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


def _normalize_datetime(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def get_summary_kpis(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Returns high-level summary KPIs (total queries, threats, clean queries,
    unique domains, and unique clients) for the given time window or all-time.
    """
    start_time = _normalize_datetime(start_time)
    end_time = _normalize_datetime(end_time)

    with _get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if start_time and end_time:
                # 1. Volume counters from hourly rollups
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(total_queries), 0) AS total_queries,
                        COALESCE(SUM(clean_queries), 0) AS clean_queries,
                        COALESCE(SUM(suspicious_queries), 0) AS suspicious_queries,
                        COALESCE(SUM(malicious_queries), 0) AS malicious_queries,
                        COALESCE(SUM(unknown_queries), 0) AS unknown_queries
                    FROM telemetry_hourly_rollup
                    WHERE bucket_time >= %s AND bucket_time < %s;
                """, (start_time, end_time))
                rollup_counts = cur.fetchone() or {}

                # 2. Distinct counts via composite indexed scans on domain_query_history
                cur.execute("""
                    SELECT 
                        COUNT(DISTINCT domain) AS unique_domains,
                        COUNT(DISTINCT client_ip) AS unique_clients
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s;
                """, (start_time, end_time))
                distinct_counts = cur.fetchone() or {}

                total_q = int(rollup_counts.get("total_queries") or 0)
                clean_q = int(rollup_counts.get("clean_queries") or 0)
                susp_q = int(rollup_counts.get("suspicious_queries") or 0)
                mal_q = int(rollup_counts.get("malicious_queries") or 0)
                unk_q = int(rollup_counts.get("unknown_queries") or 0)
                threat_pct = round((mal_q * 100.0) / total_q, 2) if total_q > 0 else 0.0

                return {
                    "time_window": {
                        "start": start_time.isoformat(),
                        "end": end_time.isoformat(),
                    },
                    "total_queries": total_q,
                    "clean_queries": clean_q,
                    "suspicious_queries": susp_q,
                    "review_needed_queries": susp_q,
                    "malicious_queries": mal_q,
                    "unknown_queries": unk_q,
                    "threats_blocked_pct": threat_pct,
                    "unique_domains": int(distinct_counts.get("unique_domains") or 0),
                    "unique_clients": int(distinct_counts.get("unique_clients") or 0),
                }

            else:
                # All-time view: combine rollups with pre-aggregated profiles
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(total_queries), 0) AS total_queries,
                        COALESCE(SUM(clean_queries), 0) AS clean_queries,
                        COALESCE(SUM(suspicious_queries), 0) AS suspicious_queries,
                        COALESCE(SUM(malicious_queries), 0) AS malicious_queries,
                        COALESCE(SUM(unknown_queries), 0) AS unknown_queries
                    FROM telemetry_hourly_rollup;
                """)
                rollup_counts = cur.fetchone() or {}

                cur.execute("SELECT COUNT(*) AS unique_domains FROM domain_profiles;")
                unique_domains = cur.fetchone()["unique_domains"]

                cur.execute("SELECT COUNT(*) AS unique_clients FROM client_profiles;")
                unique_clients = cur.fetchone()["unique_clients"]

                total_q = int(rollup_counts.get("total_queries") or 0)
                clean_q = int(rollup_counts.get("clean_queries") or 0)
                susp_q = int(rollup_counts.get("suspicious_queries") or 0)
                mal_q = int(rollup_counts.get("malicious_queries") or 0)
                unk_q = int(rollup_counts.get("unknown_queries") or 0)
                threat_pct = round((mal_q * 100.0) / total_q, 2) if total_q > 0 else 0.0

                return {
                    "time_window": "all_time",
                    "total_queries": total_q,
                    "clean_queries": clean_q,
                    "suspicious_queries": susp_q,
                    "review_needed_queries": susp_q,
                    "malicious_queries": mal_q,
                    "unknown_queries": unk_q,
                    "threats_blocked_pct": threat_pct,
                    "unique_domains": int(unique_domains or 0),
                    "unique_clients": int(unique_clients or 0),
                }


def get_timeseries(
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Returns zero-gap filled hourly query and threat timeseries from `telemetry_hourly_rollup`.
    Strictly conforms to [start, end) half-open time interval:
    - 1 hour -> exactly 1 bucket
    - 4 hours -> exactly 4 buckets (terminal end bucket excluded)
    - 24 hours -> exactly 24 buckets
    - start >= end -> 0 buckets
    """
    start_time = _normalize_datetime(start_time)
    end_time = _normalize_datetime(end_time)

    with _get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if start_time and end_time:
                if start_time >= end_time:
                    return []

                cur.execute("""
                    SELECT 
                        bucket_time,
                        total_queries,
                        clean_queries,
                        suspicious_queries,
                        malicious_queries,
                        unknown_queries
                    FROM telemetry_hourly_rollup
                    WHERE bucket_time >= %s AND bucket_time < %s
                    ORDER BY bucket_time ASC;
                """, (start_time, end_time))
                db_rows = {r["bucket_time"]: r for r in cur.fetchall()}

                # Generate deterministic continuous hour sequence for [start, end)
                res = []
                curr = start_time.replace(minute=0, second=0, microsecond=0)
                while curr < end_time:
                    match = db_rows.get(curr)
                    if match:
                        res.append({
                            "timestamp": curr.isoformat(),
                            "total_queries": match["total_queries"],
                            "clean_queries": match["clean_queries"],
                            "suspicious_queries": match["suspicious_queries"],
                            "review_needed_queries": match["suspicious_queries"],
                            "malicious_queries": match["malicious_queries"],
                            "unknown_queries": match["unknown_queries"],
                        })
                    else:
                        res.append({
                            "timestamp": curr.isoformat(),
                            "total_queries": 0,
                            "clean_queries": 0,
                            "suspicious_queries": 0,
                            "review_needed_queries": 0,
                            "malicious_queries": 0,
                            "unknown_queries": 0,
                        })
                    curr += timedelta(hours=1)
                return res
            else:
                cur.execute("""
                    SELECT 
                        bucket_time,
                        total_queries,
                        clean_queries,
                        suspicious_queries,
                        malicious_queries,
                        unknown_queries
                    FROM telemetry_hourly_rollup
                    ORDER BY bucket_time ASC;
                """)
                return [
                    {
                        "timestamp": r["bucket_time"].isoformat(),
                        "total_queries": r["total_queries"],
                        "clean_queries": r["clean_queries"],
                        "suspicious_queries": r["suspicious_queries"],
                        "review_needed_queries": r["suspicious_queries"],
                        "malicious_queries": r["malicious_queries"],
                        "unknown_queries": r["unknown_queries"],
                    }
                    for r in cur.fetchall()
                ]


def get_top_domains(
    limit: int = 20,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Returns top queried domains.
    Understands that a domain may have multiple verdicts over time.
    """
    start_time = _normalize_datetime(start_time)
    end_time = _normalize_datetime(end_time)

    with _get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if start_time and end_time:
                cur.execute("""
                    SELECT 
                        domain,
                        COUNT(*) AS query_count,
                        COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_count,
                        COUNT(*) FILTER (WHERE final_label = 'Benign') AS clean_count,
                        COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_count,
                        COUNT(*) FILTER (WHERE final_label = 'Unknown') AS unknown_count,
                        (ARRAY_AGG(final_label ORDER BY timestamp DESC))[1] AS latest_label,
                        to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s
                    GROUP BY domain
                    ORDER BY query_count DESC
                    LIMIT %s;
                """, (start_time, end_time, limit))
                return [dict(r) for r in cur.fetchall()]
            else:
                cur.execute("""
                    SELECT 
                        domain,
                        total_queries AS query_count,
                        malicious_queries AS malicious_count,
                        clean_queries AS clean_count,
                        review_needed_queries AS review_needed_count,
                        unknown_queries AS unknown_count,
                        last_label AS latest_label,
                        to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_profiles
                    ORDER BY total_queries DESC
                    LIMIT %s;
                """, (limit,))
                return [dict(r) for r in cur.fetchall()]


def get_top_malicious_domains(
    limit: int = 20,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Returns domains with highest malicious activity.
    """
    start_time = _normalize_datetime(start_time)
    end_time = _normalize_datetime(end_time)

    with _get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if start_time and end_time:
                cur.execute("""
                    SELECT 
                        domain,
                        COUNT(*) AS malicious_queries,
                        to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_query_history
                    WHERE final_label = 'Malicious'
                      AND timestamp >= %s AND timestamp < %s
                    GROUP BY domain
                    ORDER BY malicious_queries DESC
                    LIMIT %s;
                """, (start_time, end_time, limit))
                return [dict(r) for r in cur.fetchall()]
            else:
                cur.execute("""
                    SELECT 
                        domain,
                        malicious_queries,
                        to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_profiles
                    WHERE malicious_queries > 0
                    ORDER BY malicious_queries DESC
                    LIMIT %s;
                """, (limit,))
                return [dict(r) for r in cur.fetchall()]


def get_top_trusted_domains(
    limit: int = 20,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Returns domains with highest clean/benign activity.
    """
    start_time = _normalize_datetime(start_time)
    end_time = _normalize_datetime(end_time)

    with _get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if start_time and end_time:
                cur.execute("""
                    SELECT 
                        domain,
                        COUNT(*) AS clean_queries,
                        to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_query_history
                    WHERE final_label = 'Benign'
                      AND timestamp >= %s AND timestamp < %s
                    GROUP BY domain
                    ORDER BY clean_queries DESC
                    LIMIT %s;
                """, (start_time, end_time, limit))
                return [dict(r) for r in cur.fetchall()]
            else:
                cur.execute("""
                    SELECT 
                        domain,
                        clean_queries,
                        to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_profiles
                    WHERE clean_queries > 0
                    ORDER BY clean_queries DESC
                    LIMIT %s;
                """, (limit,))
                return [dict(r) for r in cur.fetchall()]


def get_top_clients(
    limit: int = 20,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Returns top client IPs by query volume and threat count.
    """
    start_time = _normalize_datetime(start_time)
    end_time = _normalize_datetime(end_time)
    with _get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if start_time and end_time:
                cur.execute("""
                    SELECT 
                        client_ip,
                        COUNT(*) AS query_count,
                        COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_queries,
                        to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_query_history
                    WHERE timestamp >= %s AND timestamp < %s
                    GROUP BY client_ip
                    ORDER BY query_count DESC
                    LIMIT %s;
                """, (start_time, end_time, limit))
                return [dict(r) for r in cur.fetchall()]
            else:
                cur.execute("""
                    SELECT 
                        host(client_ip) AS client_ip,
                        total_queries AS query_count,
                        malicious_queries,
                        to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM client_profiles
                    ORDER BY total_queries DESC
                    LIMIT %s;
                """, (limit,))
                return [dict(r) for r in cur.fetchall()]


def get_daily_review_queue(limit: int = 20) -> List[Dict[str, Any]]:
    """
    Returns pending domains under daily review.
    """
    with _get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    domain, status, review_count, review_reason,
                    to_char(first_seen_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                    to_char(next_check_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS next_check
                FROM daily_review_domains
                WHERE status = 'review_needed'
                ORDER BY next_check_at ASC
                LIMIT %s;
            """, (limit,))
            return [dict(r) for r in cur.fetchall()]
