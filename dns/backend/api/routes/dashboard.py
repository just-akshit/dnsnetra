"""
Dashboard API Routes
====================
All endpoints prefixed /api/v1 — reads directly from PostgreSQL (`dns_threat_detection`)
using the thread-safe connection pool in `domain_profiling.connection`.

Architecture:
    PostgreSQL (dns_threat_detection)
        ├── domain_query_history (raw event stream & time-window telemetry)
        ├── domain_profiles      (domain lifetime aggregates)
        ├── client_profiles      (client IP tracking)
        ├── client_history       (client-domain interaction counts)
        └── reputation_domains   (active threat intelligence overlay)
        ↓
    FastAPI (this layer — read-only)
        ↓
    Next.js Dashboard
"""

from __future__ import annotations

from typing import Optional, List, Dict, Any
from fastapi import APIRouter, HTTPException, Query
import psycopg2.extras

from domain_profiling.connection import get_db_connection
from analytics.time_window import resolve_time_window, TimeWindow
from api.models import (
    GeoDistributionResponse,
    GeoEntry,
    MetricsSummary,
    MetricsSummaryResponse,
    RecentFlaggedDomain,
    RecentFlaggedDomainsResponse,
    ThreatCategoriesResponse,
    ThreatCategory,
    TimeseriesBucket,
    TimeseriesResponse,
    TopClient,
    TopClientsResponse,
    TopDomain,
    TopDomainsResponse,
)

router = APIRouter(prefix="/api/v1", tags=["Dashboard"])


def _resolve_optional_window(
    window: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> Optional[TimeWindow]:
    """
    Helper to resolve a time window if parameters are provided.
    Precedence: custom start_time/end_time > preset window.
    """
    if start_time and end_time:
        return resolve_time_window(start=start_time, end=end_time)
    elif window and window.strip():
        return resolve_time_window(window=window.strip())
    return None


# ------------------------------------------------------------------
# GET /api/v1/dashboard  — bundle endpoint
# ------------------------------------------------------------------

@router.get("/dashboard")
def get_dashboard_bundle(
    window: Optional[str] = Query(None, description="Rolling window preset (e.g. 5m, 1h, 24h, 7d)"),
    start_time: Optional[str] = Query(None, description="ISO8601 UTC start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO8601 UTC end timestamp"),
):
    """
    Returns the full dashboard bundle: summary, timeseries, categories,
    top domains, top clients, and recent flagged domains.
    When a time range is provided, all metrics reflect that period.
    """
    try:
        tw = _resolve_optional_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if tw:
                    # 1. Time-scoped Summary KPIs from domain_query_history
                    cur.execute("""
                        SELECT COUNT(*) AS total_queries,
                               COUNT(DISTINCT client_ip) AS unique_clients,
                               COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_domains,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS total_threats,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_pipeline_run_at
                        FROM domain_query_history
                        WHERE timestamp >= %(start)s AND timestamp < %(end)s;
                    """, {"start": tw.start, "end": tw.end})
                    summary_raw = cur.fetchone() or {}
                    total_q = summary_raw.get("total_queries") or 0
                    total_t = summary_raw.get("total_threats") or 0
                    blocked_pct = round((total_t * 100.0) / total_q, 2) if total_q > 0 else 0.0

                    summary_data = {
                        "total_queries": total_q,
                        "total_threats": total_t,
                        "threats_blocked_pct": blocked_pct,
                        "unique_clients": summary_raw.get("unique_clients") or 0,
                        "unique_domains": summary_raw.get("unique_domains") or 0,
                        "last_pipeline_run_at": summary_raw.get("last_pipeline_run_at") or tw.end_iso,
                    }

                    # 2. Dynamic Timeseries with zero-gap filling
                    cur.execute("""
                        SELECT to_timestamp(floor(extract(epoch from timestamp) / %(b_sec)s) * %(b_sec)s) AT TIME ZONE 'UTC' AS bucket_time,
                               COUNT(*) AS total_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS threat_queries
                        FROM domain_query_history
                        WHERE timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY bucket_time
                        ORDER BY bucket_time ASC;
                    """, {"start": tw.start, "end": tw.end, "b_sec": tw.bucket_seconds})
                    db_buckets = {r["bucket_time"]: r for r in cur.fetchall()}

                    # Generate complete deterministic sequence of buckets
                    all_bucket_dts = tw.generate_bucket_timestamps()
                    ts_rows = []
                    for b_dt in all_bucket_dts:
                        # Match naive UTC representation
                        match = db_buckets.get(b_dt.replace(tzinfo=None))
                        time_str = b_dt.strftime("%Y-%m-%d %H:%M")
                        if match:
                            ts_rows.append({
                                "time_bucket": time_str,
                                "total_queries": match["total_queries"],
                                "threat_queries": match["threat_queries"],
                            })
                        else:
                            ts_rows.append({
                                "time_bucket": time_str,
                                "total_queries": 0,
                                "threat_queries": 0,
                            })

                    # 3. Time-scoped Threat Categories
                    cur.execute("""
                        SELECT COALESCE(NULLIF(ti_source, ''), 'Internal Engine') AS category,
                               COUNT(*) AS count,
                               ROUND(COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM domain_query_history WHERE LOWER(COALESCE(final_label, '')) = 'malicious' AND timestamp >= %(start)s AND timestamp < %(end)s), 0), 2)::float AS pct
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY category
                        ORDER BY count DESC
                        LIMIT 20;
                    """, {"start": tw.start, "end": tw.end})
                    cat_rows = cur.fetchall()

                    # 4. Time-scoped Top Domains from domain_query_history
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               CASE 
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) IN ('suspicious', 'review_needed', 'review needed') THEN 'Review Needed'
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) IN ('clean', 'benign') THEN 'Benign'
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) = 'malicious' THEN 'Malicious'
                                   ELSE 'Unknown'
                               END AS label,
                               NULL::float AS threat_score,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        ORDER BY query_count DESC
                        LIMIT 20;
                    """, {"start": tw.start, "end": tw.end})
                    top_domain_rows = cur.fetchall()

                    # 5. Time-scoped Top Clients from domain_query_history
                    cur.execute("""
                        SELECT client_ip,
                               COUNT(*) AS query_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_query_count,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY client_ip
                        ORDER BY query_count DESC
                        LIMIT 20;
                    """, {"start": tw.start, "end": tw.end})
                    top_client_rows = cur.fetchall()

                    # 6. Time-scoped Recent Flagged from domain_query_history
                    cur.execute("""
                        SELECT domain,
                               COALESCE(final_label, 'Malicious') AS label,
                               COALESCE(ti_source, 'Threat Intelligence') AS label_reason,
                               COALESCE(ti_source, 'Internal Engine') AS ti_source,
                               NULL::float AS confidence,
                               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS flagged_at
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        ORDER BY timestamp DESC
                        LIMIT 20;
                    """, {"start": tw.start, "end": tw.end})
                    flagged_rows = cur.fetchall()

                else:
                    # Default: all-time telemetry view
                    cur.execute("""
                        SELECT COUNT(*) AS total_queries,
                               COUNT(DISTINCT client_ip) AS unique_clients,
                               COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_domains,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS total_threats,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_pipeline_run_at
                        FROM domain_query_history;
                    """)
                    summary_raw = cur.fetchone() or {}
                    total_q = summary_raw.get("total_queries") or 0
                    total_t = summary_raw.get("total_threats") or 0
                    blocked_pct = round((total_t * 100.0) / total_q, 2) if total_q > 0 else 0.0

                    summary_data = {
                        "total_queries": total_q,
                        "total_threats": total_t,
                        "threats_blocked_pct": blocked_pct,
                        "unique_clients": summary_raw.get("unique_clients") or 0,
                        "unique_domains": summary_raw.get("unique_domains") or 0,
                        "last_pipeline_run_at": summary_raw.get("last_pipeline_run_at") or "",
                    }

                    cur.execute("""
                        SELECT to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD HH24:00') AS time_bucket,
                               COUNT(*) AS total_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS threat_queries
                        FROM domain_query_history
                        GROUP BY date_trunc('hour', timestamp)
                        ORDER BY date_trunc('hour', timestamp) ASC;
                    """)
                    ts_rows = cur.fetchall()

                    cur.execute("""
                        SELECT COALESCE(NULLIF(ti_source, ''), 'Internal Engine') AS category,
                               COUNT(*) AS count,
                               ROUND(COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM domain_query_history WHERE LOWER(COALESCE(final_label, '')) = 'malicious'), 0), 2)::float AS pct
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                        GROUP BY category
                        ORDER BY count DESC
                        LIMIT 20;
                    """)
                    cat_rows = cur.fetchall()

                    cur.execute("""
                        SELECT domain, total_queries AS query_count, COALESCE(last_label, 'Unknown') AS label,
                               NULL::float AS threat_score,
                               COALESCE(to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '') AS last_seen
                        FROM domain_profiles
                        ORDER BY total_queries DESC
                        LIMIT 20;
                    """)
                    top_domain_rows = cur.fetchall()

                    cur.execute("""
                        SELECT host(cp.client_ip) AS client_ip,
                               COALESCE(SUM(ch.visit_count), 0) AS query_count,
                               COALESCE(t.threat_count, 0) AS malicious_query_count,
                               COALESCE(to_char(cp.last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '') AS last_seen
                        FROM client_profiles cp
                        LEFT JOIN client_history ch ON cp.client_ip = ch.client_ip
                        LEFT JOIN (
                            SELECT client_ip, COUNT(*) AS threat_count
                            FROM domain_query_history
                            WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                            GROUP BY client_ip
                        ) t ON host(cp.client_ip) = t.client_ip
                        GROUP BY cp.client_ip, cp.last_seen, t.threat_count
                        ORDER BY query_count DESC
                        LIMIT 20;
                    """)
                    top_client_rows = cur.fetchall()

                    cur.execute("""
                        SELECT domain,
                               COALESCE(final_label, 'Malicious') AS label,
                               COALESCE(ti_source, 'Threat Intelligence') AS label_reason,
                               COALESCE(ti_source, 'Internal Engine') AS ti_source,
                               NULL::float AS confidence,
                               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS flagged_at
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                        ORDER BY timestamp DESC
                        LIMIT 20;
                    """)
                    flagged_rows = cur.fetchall()

        return {
            "status": "success",
            "data": {
                "summary": summary_data,
                "timeseries": [dict(r) for r in ts_rows],
                "categories": [dict(r) for r in cat_rows],
                "top_domains": [dict(r) for r in top_domain_rows],
                "top_clients": [dict(r) for r in top_client_rows],
                "recent_flagged": [dict(r) for r in flagged_rows],
                "aggregation": {
                    "last_watermark_id": 0,
                    "last_watermark_ts": summary_data["last_pipeline_run_at"],
                    "last_status": "active",
                    "name": "postgresql",
                },
            },
        }
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Dashboard bundle error: {e}")


# ------------------------------------------------------------------
# GET /api/v1/summary
# ------------------------------------------------------------------

@router.get("/summary", response_model=MetricsSummaryResponse)
def get_summary(
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    """Returns the pipeline metrics snapshot from PostgreSQL, optionally filtered by time."""
    try:
        tw = _resolve_optional_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if tw:
                    cur.execute("""
                        SELECT COUNT(*) AS total_queries,
                               COUNT(DISTINCT client_ip) AS unique_clients,
                               COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_domains,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS total_threats,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_pipeline_run_at
                        FROM domain_query_history
                        WHERE timestamp >= %(start)s AND timestamp < %(end)s;
                    """, {"start": tw.start, "end": tw.end})
                else:
                    cur.execute("""
                        SELECT COUNT(*) AS total_queries,
                               COUNT(DISTINCT client_ip) AS unique_clients,
                               COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_domains,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS total_threats,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_pipeline_run_at
                        FROM domain_query_history;
                    """)
                row = cur.fetchone()

        if not row or row["total_queries"] == 0:
            return MetricsSummaryResponse(data=None)

        total_q = row["total_queries"]
        total_t = row["total_threats"]
        blocked_pct = round((total_t * 100.0) / total_q, 2) if total_q > 0 else 0.0

        return MetricsSummaryResponse(
            data=MetricsSummary(
                total_queries=total_q,
                total_threats=total_t,
                threats_blocked_pct=blocked_pct,
                unique_clients=row["unique_clients"],
                unique_domains=row["unique_domains"],
                last_pipeline_run_at=row["last_pipeline_run_at"] or (tw.end_iso if tw else ""),
            )
        )
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying summary: {e}")


# ------------------------------------------------------------------
# GET /api/v1/threats/timeseries
# ------------------------------------------------------------------

@router.get("/threats/timeseries", response_model=TimeseriesResponse)
def get_threats_timeseries(
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    """Returns query and threat timeseries data, dynamically bucketed when time range provided."""
    try:
        tw = _resolve_optional_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if tw:
                    cur.execute("""
                        SELECT to_timestamp(floor(extract(epoch from timestamp) / %(b_sec)s) * %(b_sec)s) AT TIME ZONE 'UTC' AS bucket_time,
                               COUNT(*) AS total_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS threat_queries
                        FROM domain_query_history
                        WHERE timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY bucket_time
                        ORDER BY bucket_time ASC;
                    """, {"start": tw.start, "end": tw.end, "b_sec": tw.bucket_seconds})
                    db_buckets = {r["bucket_time"]: r for r in cur.fetchall()}

                    all_bucket_dts = tw.generate_bucket_timestamps()
                    rows = []
                    for b_dt in all_bucket_dts:
                        match = db_buckets.get(b_dt.replace(tzinfo=None))
                        time_str = b_dt.strftime("%Y-%m-%d %H:%M")
                        rows.append(
                            TimeseriesBucket(
                                time_bucket=time_str,
                                total_queries=match["total_queries"] if match else 0,
                                threat_queries=match["threat_queries"] if match else 0,
                            )
                        )
                else:
                    cur.execute("""
                        SELECT to_char(date_trunc('hour', timestamp), 'YYYY-MM-DD HH24:00') AS time_bucket,
                               COUNT(*) AS total_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS threat_queries
                        FROM domain_query_history
                        GROUP BY date_trunc('hour', timestamp)
                        ORDER BY date_trunc('hour', timestamp) ASC;
                    """)
                    rows = [
                        TimeseriesBucket(
                            time_bucket=r["time_bucket"],
                            total_queries=r["total_queries"],
                            threat_queries=r["threat_queries"],
                        )
                        for r in cur.fetchall()
                    ]

        return TimeseriesResponse(data=rows)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying timeseries: {e}")


# ------------------------------------------------------------------
# GET /api/v1/threats/categories
# ------------------------------------------------------------------

@router.get("/threats/categories", response_model=ThreatCategoriesResponse)
def get_threats_categories(
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    """Returns threat breakdown by category/ti_source from PostgreSQL, optionally filtered by time."""
    try:
        tw = _resolve_optional_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if tw:
                    cur.execute("""
                        SELECT COALESCE(NULLIF(ti_source, ''), 'Internal Engine') AS category,
                               COUNT(*) AS count,
                               ROUND(COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM domain_query_history WHERE LOWER(COALESCE(final_label, '')) = 'malicious' AND timestamp >= %(start)s AND timestamp < %(end)s), 0), 2)::float AS pct
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY category
                        ORDER BY count DESC
                        LIMIT 20;
                    """, {"start": tw.start, "end": tw.end})
                else:
                    cur.execute("""
                        SELECT COALESCE(NULLIF(ti_source, ''), 'Internal Engine') AS category,
                               COUNT(*) AS count,
                               ROUND(COUNT(*) * 100.0 / NULLIF((SELECT COUNT(*) FROM domain_query_history WHERE LOWER(COALESCE(final_label, '')) = 'malicious'), 0), 2)::float AS pct
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                        GROUP BY category
                        ORDER BY count DESC
                        LIMIT 20;
                    """)
                rows = cur.fetchall()

        return ThreatCategoriesResponse(
            data=[
                ThreatCategory(
                    category=r["category"],
                    count=r["count"],
                    pct=r["pct"],
                )
                for r in rows
            ]
        )
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying categories: {e}")


# ------------------------------------------------------------------
# GET /api/v1/threats/geo
# ------------------------------------------------------------------

@router.get("/threats/geo", response_model=GeoDistributionResponse)
def get_threats_geo():
    """
    Returns geo distribution data.
    GeoIP is currently disabled — returns empty data structure.
    """
    return GeoDistributionResponse(geoip_enabled=False, data=[])


# ------------------------------------------------------------------
# GET /api/v1/domains  — paginated domain list with search and filter
# ------------------------------------------------------------------

@router.get("/domains")
def get_domains(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    label: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    """
    Returns a paginated list of domains from PostgreSQL.
    Supports lifetime domain_profiles or time-scoped domain_query_history events.
    """
    try:
        tw = _resolve_optional_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if tw:
                    where_clauses = ["timestamp >= %s", "timestamp < %s"]
                    params: List[Any] = [tw.start, tw.end]

                    if label and label.lower() != "all":
                        lbl_norm = label.lower().strip()
                        if lbl_norm in ("review_needed", "review needed", "suspicious"):
                            where_clauses.append("LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed', 'suspicious')")
                        elif lbl_norm in ("benign", "clean"):
                            where_clauses.append("LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')")
                        else:
                            where_clauses.append("LOWER(final_label) = LOWER(%s)")
                            params.append(label)

                    if search and search.strip():
                        where_clauses.append("domain ILIKE %s")
                        params.append(f"%{search.strip()}%")

                    where_sql = f"WHERE {' AND '.join(where_clauses)}"

                    count_query = f"SELECT COUNT(DISTINCT domain) FROM domain_query_history {where_sql};"
                    cur.execute(count_query, params)
                    total = cur.fetchone()["count"]

                    offset = (page - 1) * page_size
                    data_query = f"""
                        SELECT domain,
                               COUNT(*) AS total_queries,
                               COUNT(*) AS query_count,
                               COUNT(DISTINCT client_ip) AS unique_clients,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS threat_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) != 'malicious') AS clean_count,
                               CASE 
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) IN ('suspicious', 'review_needed', 'review needed') THEN 'Review Needed'
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) IN ('clean', 'benign') THEN 'Benign'
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) = 'malicious' THEN 'Malicious'
                                   ELSE 'Unknown'
                               END AS last_label,
                               CASE 
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) IN ('suspicious', 'review_needed', 'review needed') THEN 'review_needed'
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) IN ('clean', 'benign') THEN 'benign'
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) = 'malicious' THEN 'malicious'
                                   ELSE 'unknown'
                               END AS label,
                               NULL::float AS threat_score,
                               NULL::float AS confidence,
                               COALESCE(MODE() WITHIN GROUP (ORDER BY ti_source), 'internal') AS last_ti_source,
                               NULL::text AS label_reason,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        {where_sql}
                        GROUP BY domain
                        ORDER BY threat_count DESC, total_queries DESC
                        LIMIT %s OFFSET %s;
                    """
                    cur.execute(data_query, params + [page_size, offset])
                    rows = cur.fetchall()
                else:
                    where_clauses = []
                    params = []

                    if label and label.lower() != "all":
                        where_clauses.append("LOWER(last_label) = LOWER(%s)")
                        params.append(label)

                    if search and search.strip():
                        where_clauses.append("domain ILIKE %s")
                        params.append(f"%{search.strip()}%")

                    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

                    count_query = f"SELECT COUNT(*) FROM domain_profiles {where_sql};"
                    cur.execute(count_query, params)
                    total = cur.fetchone()["count"]

                    offset = (page - 1) * page_size
                    data_query = f"""
                        SELECT domain, total_queries, total_queries AS query_count, unique_clients,
                               malicious_queries AS threat_count, malicious_queries AS malicious_count,
                               clean_queries AS clean_count, unknown_queries AS unknown_count,
                               COALESCE(last_label, 'unknown') AS last_label,
                               LOWER(COALESCE(last_label, 'unknown')) AS label,
                               NULL::float AS threat_score, NULL::float AS confidence,
                               last_ti_source, NULL::text AS label_reason,
                               to_char(first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_profiles
                        {where_sql}
                        ORDER BY malicious_queries DESC, total_queries DESC
                        LIMIT %s OFFSET %s;
                    """
                    cur.execute(data_query, params + [page_size, offset])
                    rows = cur.fetchall()

        return {
            "data": [dict(r) for r in rows],
            "meta": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "pages": max(1, (total + page_size - 1) // page_size),
            },
        }
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying domains: {e}")


# ------------------------------------------------------------------
# GET /api/v1/domains/top
# ------------------------------------------------------------------

@router.get("/domains/top", response_model=TopDomainsResponse)
def get_top_domains(
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    """
    Returns top queried domains.
    When a time range is provided, calculated strictly from domain_query_history.
    When no time range is provided, returns lifetime ranking from domain_profiles.
    """
    try:
        tw = _resolve_optional_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if tw:
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), 'Unknown') AS label,
                               NULL::float AS threat_score,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        ORDER BY query_count DESC
                        LIMIT 20;
                    """, {"start": tw.start, "end": tw.end})
                else:
                    cur.execute("""
                        SELECT domain, total_queries AS query_count, COALESCE(last_label, 'Unknown') AS label,
                               NULL::float AS threat_score,
                               COALESCE(to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '') AS last_seen
                        FROM domain_profiles
                        ORDER BY total_queries DESC
                        LIMIT 20;
                    """)
                rows = cur.fetchall()

        return TopDomainsResponse(
            data=[
                TopDomain(
                    domain=r["domain"],
                    query_count=r["query_count"],
                    label=r["label"],
                    threat_score=r["threat_score"] or 0.0,
                    last_seen=r["last_seen"],
                )
                for r in rows
            ]
        )
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying top domains: {e}")


# ------------------------------------------------------------------
# GET /api/v1/domains/recent
# ------------------------------------------------------------------

@router.get("/domains/recent", response_model=RecentFlaggedDomainsResponse)
def get_recent_flagged_domains(
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    """Returns recently flagged (malicious) domains from PostgreSQL, optionally filtered by time."""
    try:
        tw = _resolve_optional_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if tw:
                    cur.execute("""
                        SELECT domain,
                               COALESCE(final_label, 'Malicious') AS label,
                               COALESCE(ti_source, 'Threat Intelligence') AS label_reason,
                               COALESCE(ti_source, 'Internal Engine') AS ti_source,
                               NULL::float AS confidence,
                               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS flagged_at
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        ORDER BY timestamp DESC
                        LIMIT 50;
                    """, {"start": tw.start, "end": tw.end})
                else:
                    cur.execute("""
                        SELECT domain,
                               COALESCE(final_label, 'Malicious') AS label,
                               COALESCE(ti_source, 'Threat Intelligence') AS label_reason,
                               COALESCE(ti_source, 'Internal Engine') AS ti_source,
                               NULL::float AS confidence,
                               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS flagged_at
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                        ORDER BY timestamp DESC
                        LIMIT 50;
                    """)
                rows = cur.fetchall()

        return RecentFlaggedDomainsResponse(
            data=[
                RecentFlaggedDomain(
                    domain=r["domain"],
                    label=r["label"],
                    label_reason=r["label_reason"],
                    ti_source=r["ti_source"],
                    confidence=r["confidence"],
                    flagged_at=r["flagged_at"],
                )
                for r in rows
            ]
        )
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying recent flagged domains: {e}")


# ------------------------------------------------------------------
# GET /api/v1/domains/{domain}
# ------------------------------------------------------------------

@router.get("/domains/{domain}")
def get_domain_detail(domain: str):
    """
    Returns enriched domain information strictly from PostgreSQL (`domain_profiles`
    and active reputation in `reputation_domains`).
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT domain, total_queries, unique_clients,
                           malicious_queries AS threat_count, malicious_queries AS malicious_count,
                           clean_queries AS clean_count, unknown_queries AS unknown_count,
                           query_a_count, query_aaaa_count, query_mx_count,
                           query_txt_count, query_ns_count, query_other_count,
                           COALESCE(last_label, 'unknown') AS last_label,
                           last_ti_source,
                           to_char(first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                           to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_profiles
                    WHERE domain = %s;
                """, (domain,))
                row = cur.fetchone()

        if not row:
            raise HTTPException(
                status_code=404,
                detail=f"Domain '{domain}' not found in telemetry database",
            )

        qt = {
            "A": row["query_a_count"] or 0,
            "AAAA": row["query_aaaa_count"] or 0,
            "MX": row["query_mx_count"] or 0,
            "TXT": row["query_txt_count"] or 0,
            "NS": row["query_ns_count"] or 0,
            "OTHER": row["query_other_count"] or 0,
        }

        raw_last = (row["last_label"] or "unknown").lower().strip()
        if raw_last in ("suspicious", "review_needed", "review needed"):
            final_label = "review_needed"
        elif raw_last in ("clean", "trusted", "benign"):
            final_label = "benign"
        elif raw_last == "malicious":
            final_label = "malicious"
        else:
            final_label = "unknown"
        threat_score = None
        confidence = None
        ti_source = row["last_ti_source"]
        label_reason = None

        # Check authoritative reputation overlay
        try:
            from labeler.intel.reputation import get_domain as _get_rep_domain
            from labeler.intel.manager import is_trusted as _is_trusted
            import tldextract

            ext = tldextract.extract(domain)
            reg_d = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain or domain

            rep_record = _get_rep_domain(domain)
            valid_malicious_rep = False

            if rep_record:
                rep_status = rep_record.get("status") if isinstance(rep_record, dict) else getattr(rep_record, "status", None)
                rep_source = rep_record.get("source") if isinstance(rep_record, dict) else getattr(rep_record, "source", None)
                rep_conf = rep_record.get("confidence") if isinstance(rep_record, dict) else getattr(rep_record, "confidence", None)
                rep_scope = rep_record.get("match_scope") if isinstance(rep_record, dict) else getattr(rep_record, "match_scope", None)
                matched_d = rep_record.get("matched_domain") if isinstance(rep_record, dict) else getattr(rep_record, "matched_domain", None)

                if rep_status == "malicious" and rep_scope in ("EXACT_FQDN", "REGISTERED_DOMAIN", "CORRELATED", "EXTERNAL_PROVIDER"):
                    if not (rep_scope == "REGISTERED_DOMAIN" and matched_d and _is_trusted(matched_d)):
                        valid_malicious_rep = True
                        final_label = "malicious"
                        ti_source = rep_source or ti_source
                        confidence = rep_conf
                        threat_score = 100.0
                        label_reason = f"Flagged as {rep_status} by {rep_source}"

            if not valid_malicious_rep and final_label != "malicious":
                if _is_trusted(domain) or _is_trusted(reg_d):
                    final_label = "benign"
                    ti_source = "trusted"
        except Exception:
            pass

        return {
            "data": {
                "domain": row["domain"],
                "label": final_label,
                "threat_score": threat_score,
                "confidence": confidence,
                "stats": {
                    "queries": row["total_queries"],
                    "total_queries": row["total_queries"],
                    "unique_clients": row["unique_clients"],
                    "threats": row["threat_count"],
                    "threat_count": row["threat_count"],
                    "malicious": row["malicious_count"],
                    "suspicious": 0,
                    "clean": row["clean_count"],
                },
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "threat_intel": {
                    "source": ti_source,
                    "label_reason": label_reason,
                },
                "network": {
                    "asn": None,
                    "asn_org": None,
                    "country": None,
                    "resolved_ips": None,
                },
                "dns": {
                    "query_type_breakdown": qt,
                    "response_code_breakdown": {},
                    "domain_age_days": None,
                },
                "enrichment": {},
                "source": "postgresql",
            }
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Domain detail error: {exc}")


# ------------------------------------------------------------------
# GET /api/v1/clients  — paginated client list with search
# ------------------------------------------------------------------

@router.get("/clients")
def get_clients(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    """
    Returns a paginated list of clients from PostgreSQL.
    Supports lifetime client_profiles or time-scoped domain_query_history events.
    """
    try:
        tw = _resolve_optional_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if tw:
                    where_clauses = ["timestamp >= %s", "timestamp < %s"]
                    params: List[Any] = [tw.start, tw.end]

                    if search and search.strip():
                        where_clauses.append("client_ip ILIKE %s")
                        params.append(f"%{search.strip()}%")

                    where_sql = f"WHERE {' AND '.join(where_clauses)}"

                    cur.execute(f"SELECT COUNT(DISTINCT client_ip) FROM domain_query_history {where_sql};", params)
                    total = cur.fetchone()["count"]

                    offset = (page - 1) * page_size
                    data_query = f"""
                        SELECT client_ip,
                               COUNT(*) AS total_queries,
                               COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_domains,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS threat_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) != 'malicious') AS clean_count,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        {where_sql}
                        GROUP BY client_ip
                        ORDER BY total_queries DESC
                        LIMIT %s OFFSET %s;
                    """
                    cur.execute(data_query, params + [page_size, offset])
                    rows = cur.fetchall()
                else:
                    where_clauses = []
                    params = []

                    if search and search.strip():
                        where_clauses.append("host(cp.client_ip) ILIKE %s")
                        params.append(f"%{search.strip()}%")

                    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

                    count_query = f"SELECT COUNT(*) FROM client_profiles cp {where_sql};"
                    cur.execute(count_query, params)
                    total = cur.fetchone()["count"]

                    offset = (page - 1) * page_size
                    data_query = f"""
                        SELECT host(cp.client_ip) AS client_ip,
                               COALESCE(SUM(ch.visit_count), 0) AS total_queries,
                               COUNT(DISTINCT ch.domain) AS unique_domains,
                               COALESCE(t.threat_count, 0) AS threat_count,
                               COALESCE(t.threat_count, 0) AS malicious_count,
                               COALESCE(SUM(ch.visit_count), 0) - COALESCE(t.threat_count, 0) AS clean_count,
                               to_char(cp.first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(cp.last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM client_profiles cp
                        LEFT JOIN client_history ch ON cp.client_ip = ch.client_ip
                        LEFT JOIN (
                            SELECT client_ip, COUNT(*) AS threat_count
                            FROM domain_query_history
                            WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                            GROUP BY client_ip
                        ) t ON host(cp.client_ip) = t.client_ip
                        {where_sql}
                        GROUP BY cp.client_ip, cp.first_seen, cp.last_seen, t.threat_count
                        ORDER BY total_queries DESC
                        LIMIT %s OFFSET %s;
                    """
                    cur.execute(data_query, params + [page_size, offset])
                    rows = cur.fetchall()

        return {
            "data": [dict(r) for r in rows],
            "meta": {
                "page": page,
                "page_size": page_size,
                "total": total,
                "pages": max(1, (total + page_size - 1) // page_size),
            },
        }
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying clients: {e}")


# ------------------------------------------------------------------
# GET /api/v1/clients/top
# ------------------------------------------------------------------

@router.get("/clients/top", response_model=TopClientsResponse)
def get_top_clients(
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    """
    Returns top client IPs by query count from PostgreSQL.
    When a time range is provided, calculated strictly from domain_query_history.
    When no time range is provided, returns lifetime ranking.
    """
    try:
        tw = _resolve_optional_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if tw:
                    cur.execute("""
                        SELECT client_ip,
                               COUNT(*) AS query_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_query_count,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY client_ip
                        ORDER BY query_count DESC
                        LIMIT 20;
                    """, {"start": tw.start, "end": tw.end})
                else:
                    cur.execute("""
                        SELECT host(cp.client_ip) AS client_ip,
                               COALESCE(SUM(ch.visit_count), 0) AS query_count,
                               COALESCE(t.threat_count, 0) AS malicious_query_count,
                               COALESCE(to_char(cp.last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '') AS last_seen
                        FROM client_profiles cp
                        LEFT JOIN client_history ch ON cp.client_ip = ch.client_ip
                        LEFT JOIN (
                            SELECT client_ip, COUNT(*) AS threat_count
                            FROM domain_query_history
                            WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                            GROUP BY client_ip
                        ) t ON host(cp.client_ip) = t.client_ip
                        GROUP BY cp.client_ip, cp.last_seen, t.threat_count
                        ORDER BY query_count DESC
                        LIMIT 20;
                    """)
                rows = cur.fetchall()

        return TopClientsResponse(
            data=[
                TopClient(
                    client_ip=r["client_ip"],
                    query_count=r["query_count"],
                    malicious_query_count=r["malicious_query_count"],
                    last_seen=r["last_seen"],
                )
                for r in rows
            ]
        )
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error querying top clients: {e}")


# ------------------------------------------------------------------
# GET /api/v1/clients/{client_ip}
# ------------------------------------------------------------------

@router.get("/clients/{client_ip}")
def get_client_detail(client_ip: str):
    """
    Returns client intelligence from PostgreSQL (`client_profiles`,
    `client_history`, and `domain_query_history`).
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # 1. Fetch client base profile & lifetime stats
                cur.execute("""
                    SELECT host(cp.client_ip) AS client_ip,
                           COALESCE(SUM(ch.visit_count), 0) AS total_queries,
                           COUNT(DISTINCT ch.domain) AS unique_domains,
                           COALESCE(t.threat_count, 0) AS threat_count,
                           COALESCE(t.threat_count, 0) AS malicious_count,
                           COALESCE(SUM(ch.visit_count), 0) - COALESCE(t.threat_count, 0) AS clean_count,
                           to_char(cp.first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                           to_char(cp.last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM client_profiles cp
                    LEFT JOIN client_history ch ON cp.client_ip = ch.client_ip
                    LEFT JOIN (
                        SELECT client_ip, COUNT(*) AS threat_count
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                        GROUP BY client_ip
                    ) t ON host(cp.client_ip) = t.client_ip
                    WHERE host(cp.client_ip) = %s
                    GROUP BY cp.client_ip, cp.first_seen, cp.last_seen, t.threat_count;
                """, (client_ip,))
                row = cur.fetchone()

                if not row:
                    raise HTTPException(
                        status_code=404,
                        detail=f"Client '{client_ip}' not found in telemetry database",
                    )

                # 2. Top queried domains for this client from client_history
                cur.execute("""
                    SELECT domain, visit_count AS count
                    FROM client_history
                    WHERE host(client_ip) = %s
                    ORDER BY visit_count DESC
                    LIMIT 10;
                """, (client_ip,))
                top_domains = [dict(r) for r in cur.fetchall()]

        return {
            "data": {
                "client_ip": row["client_ip"],
                "stats": {
                    "total_queries": row["total_queries"],
                    "unique_domains": row["unique_domains"],
                    "threat_count": row["threat_count"],
                    "malicious_count": row["malicious_count"],
                    "suspicious_count": 0,
                    "clean_count": row["clean_count"],
                },
                "first_seen": row["first_seen"],
                "last_seen": row["last_seen"],
                "top_domains": top_domains,
                "source": "postgresql",
            }
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Client detail error: {exc}")


# ------------------------------------------------------------------
# GET /api/v1/status
# ------------------------------------------------------------------

@router.get("/status")
def get_aggregation_status():
    """
    Returns genuine operational status of the PostgreSQL telemetry store.
    Does NOT report fake SQLite or aggregator statuses.
    """
    try:
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT COUNT(*) AS total_queries,
                           to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_event_ts
                    FROM domain_query_history;
                """)
                q_row = cur.fetchone() or {}

                cur.execute("SELECT COUNT(*) AS total_domains FROM domain_profiles;")
                d_row = cur.fetchone() or {}

                cur.execute("SELECT COUNT(*) AS total_clients FROM client_profiles;")
                c_row = cur.fetchone() or {}

        return {
            "status": "healthy",
            "database": "postgresql",
            "total_queries": q_row.get("total_queries") or 0,
            "unique_domains": d_row.get("total_domains") or 0,
            "unique_clients": c_row.get("total_clients") or 0,
            "last_event_ts": q_row.get("last_event_ts"),
        }
    except Exception as exc:
        return {
            "status": "error",
            "database": "postgresql",
            "error": str(exc),
        }
