"""
FastAPI Router: Reports API (PostgreSQL Only)
==============================================
Provides dynamic time-scoped analytical reporting for the DNS Threat Detection System:
1. GET /api/v1/reports                   - Report summary KPIs and continuous zero-filled timeseries
2. GET /api/v1/reports/queries           - Paginated DNS query events
3. GET /api/v1/reports/domains           - Paginated domains ranked by volume with latest_verdict
4. GET /api/v1/reports/malicious-domains - Paginated domains having >= 1 malicious event
5. GET /api/v1/reports/clients           - Paginated client endpoints ranked by volume
6. GET /api/v1/reports/flagged           - Paginated flagged/malicious query events
7. GET /api/v1/reports/export/csv        - Streaming CSV export matching exact endpoint datasets

Architecture Invariants:
- PostgreSQL (dns_threat_detection) is the sole source of truth.
- All interval queries use canonical half-open [start_time, end_time).
- Time resolution is strictly delegated to TimeWindowResolver (custom > preset, default 24h).
- Zero-data intervals return HTTP 200 with zero metrics and empty lists (never 500).
- Lifetime counters (domain_profiles/client_profiles) are never used for time-scoped activity.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import math
import re
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
import psycopg2.extras

from domain_profiling.connection import get_db_connection
from analytics.time_window import resolve_time_window, TimeWindow


router = APIRouter(prefix="/api/v1/reports", tags=["Reports"])


# ===========================================================================
# Centralized Time Window Resolution Helper
# ===========================================================================

def _resolve_reports_window(
    window: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> TimeWindow:
    """
    Resolves the report time window using the authoritative TimeWindowResolver.
    Strictly enforces mutual exclusivity:
    - If both preset window and custom start_time/end_time are provided, raises HTTP 400.
    - If custom range is requested, BOTH start_time and end_time must be provided.
    - Default: '24h' preset if neither is supplied.
    """
    has_window = bool(window and window.strip())
    has_start = bool(start_time and start_time.strip())
    has_end = bool(end_time and end_time.strip())

    if has_window and (has_start or has_end):
        raise HTTPException(
            status_code=400,
            detail="Cannot specify both 'window' preset and custom 'start_time'/'end_time' parameters.",
        )

    if has_start or has_end:
        if not (has_start and has_end):
            raise HTTPException(
                status_code=400,
                detail="Both 'start' and 'end' must be provided for a custom time range.",
            )
        try:
            return resolve_time_window(start=start_time.strip(), end=end_time.strip())
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))

    preset = window.strip() if has_window else "24h"
    try:
        return resolve_time_window(window=preset)
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))


# ===========================================================================
# Deterministic Entity Validation Helper (Phase 5)
# ===========================================================================

def _validate_entity(entity: str, explicit_type: Optional[str] = None) -> Tuple[str, str]:
    """
    Deterministically validates an entity identifier.
    Returns (clean_entity, entity_type: 'client' | 'domain').
    Raises HTTPException(400) if invalid or ambiguous.
    """
    clean = entity.strip()
    if not clean:
        raise HTTPException(status_code=400, detail="Entity identifier must not be empty.")

    exp_type = (explicit_type or "").strip().lower()
    if exp_type and exp_type not in ("client", "domain"):
        raise HTTPException(status_code=400, detail=f"Invalid entity_type '{explicit_type}'. Must be 'client' or 'domain'.")

    # 1. Check IP Address (IPv4 or IPv6)
    is_valid_ip = False
    try:
        ipaddress.ip_address(clean)
        is_valid_ip = True
    except ValueError:
        is_valid_ip = False

    if is_valid_ip:
        if exp_type == "domain":
            raise HTTPException(status_code=400, detail=f"Entity '{clean}' is an IP address, but entity_type was specified as 'domain'.")
        return clean, "client"

    # 2. Check RFC Hostname / Domain Syntax
    clean_domain = clean.lower()
    is_valid_domain = False
    if len(clean_domain) <= 253 and "." in clean_domain:
        labels = clean_domain.split(".")
        if len(labels) >= 2 and len(labels[-1]) >= 2 and labels[-1].isalpha():
            label_pattern = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
            if all(label_pattern.match(lbl) for lbl in labels):
                is_valid_domain = True

    if is_valid_domain:
        if exp_type == "client":
            raise HTTPException(status_code=400, detail=f"Entity '{clean}' is a domain name, but entity_type was specified as 'client'.")
        return clean_domain, "domain"

    raise HTTPException(
        status_code=400,
        detail=f"Invalid entity identifier '{clean}'. Must be a valid IPv4/IPv6 address or valid domain name (e.g. '192.168.1.104' or 'stackoverflow.com').",
    )


# ===========================================================================
# Reusable Core Query Functions (Shared between JSON endpoints & CSV export)
# ===========================================================================

def _fetch_report_queries(
    cur,
    tw: TimeWindow,
    search: Optional[str] = None,
    label: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """Fetches paginated DNS query records from domain_query_history."""
    where_clauses = ["timestamp >= %(start)s", "timestamp < %(end)s"]
    params: Dict[str, Any] = {"start": tw.start, "end": tw.end}

    if label and label.strip() and label.lower() != "all":
        lbl_norm = label.strip().lower()
        if lbl_norm in ("review_needed", "review needed"):
            where_clauses.append("LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')")
        elif lbl_norm in ("benign", "clean"):
            where_clauses.append("LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')")
        elif lbl_norm == "malicious":
            where_clauses.append("LOWER(COALESCE(final_label, '')) = 'malicious'")
        elif lbl_norm == "unknown":
            where_clauses.append("LOWER(COALESCE(final_label, '')) = 'unknown'")
        else:
            where_clauses.append("LOWER(COALESCE(final_label, '')) = %(label)s")
            params["label"] = lbl_norm

    if search and search.strip():
        where_clauses.append("(domain ILIKE %(search)s OR client_ip ILIKE %(search)s)")
        params["search"] = f"%{search.strip()}%"

    where_sql = " AND ".join(where_clauses)

    count_sql = f"SELECT COUNT(*) AS total FROM domain_query_history WHERE {where_sql};"
    cur.execute(count_sql, params)
    total = cur.fetchone()["total"]

    params["limit"] = limit
    params["offset"] = offset

    data_sql = f"""
        SELECT id,
               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS timestamp,
               client_ip,
               domain,
               query_type,
               COALESCE(final_label, 'Unknown') AS final_label,
               COALESCE(ti_source, '') AS ti_source,
               COALESCE(response_code, '') AS response_code
        FROM domain_query_history
        WHERE {where_sql}
        ORDER BY timestamp DESC, id DESC
        LIMIT %(limit)s OFFSET %(offset)s;
    """
    cur.execute(data_sql, params)
    rows = cur.fetchall()
    return rows, total


def _fetch_report_domains(
    cur,
    tw: TimeWindow,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """Fetches paginated domains ranked by query volume in the selected interval."""
    where_clauses = ["timestamp >= %(start)s", "timestamp < %(end)s"]
    params: Dict[str, Any] = {"start": tw.start, "end": tw.end}

    if search and search.strip():
        where_clauses.append("domain ILIKE %(search)s")
        params["search"] = f"%{search.strip()}%"

    where_sql = " AND ".join(where_clauses)

    count_sql = f"SELECT COUNT(DISTINCT domain) AS total FROM domain_query_history WHERE {where_sql};"
    cur.execute(count_sql, params)
    total = cur.fetchone()["total"]

    params["limit"] = limit
    params["offset"] = offset

    data_sql = f"""
        SELECT domain,
               COUNT(*) AS query_count,
               COUNT(DISTINCT client_ip) AS unique_clients,
               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen,
               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict
        FROM domain_query_history
        WHERE {where_sql}
        GROUP BY domain
        ORDER BY query_count DESC, domain ASC
        LIMIT %(limit)s OFFSET %(offset)s;
    """
    cur.execute(data_sql, params)
    rows = cur.fetchall()
    return rows, total


def _fetch_report_malicious_domains(
    cur,
    tw: TimeWindow,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """Fetches paginated domains having >= 1 malicious event in the selected interval."""
    where_clauses = ["timestamp >= %(start)s", "timestamp < %(end)s"]
    params: Dict[str, Any] = {"start": tw.start, "end": tw.end}

    if search and search.strip():
        where_clauses.append("domain ILIKE %(search)s")
        params["search"] = f"%{search.strip()}%"

    where_sql = " AND ".join(where_clauses)

    # Count distinct domains with >= 1 malicious event
    count_sql = f"""
        SELECT COUNT(DISTINCT domain) AS total
        FROM domain_query_history
        WHERE {where_sql}
          AND LOWER(COALESCE(final_label, '')) = 'malicious';
    """
    cur.execute(count_sql, params)
    total = cur.fetchone()["total"]

    params["limit"] = limit
    params["offset"] = offset

    data_sql = f"""
        SELECT domain,
               COUNT(*) AS query_count,
               COUNT(DISTINCT client_ip) AS unique_clients,
               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen,
               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
               COALESCE((ARRAY_AGG(ti_source ORDER BY timestamp DESC, id DESC) FILTER (WHERE ti_source IS NOT NULL AND ti_source != ''))[1], 'internal') AS ti_source
        FROM domain_query_history
        WHERE {where_sql}
        GROUP BY domain
        HAVING COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') > 0
        ORDER BY malicious_queries DESC, query_count DESC, domain ASC
        LIMIT %(limit)s OFFSET %(offset)s;
    """
    cur.execute(data_sql, params)
    rows = cur.fetchall()
    return rows, total


def _fetch_report_clients(
    cur,
    tw: TimeWindow,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """Fetches paginated client endpoints ranked by query volume in the selected interval."""
    where_clauses = ["timestamp >= %(start)s", "timestamp < %(end)s"]
    params: Dict[str, Any] = {"start": tw.start, "end": tw.end}

    if search and search.strip():
        where_clauses.append("client_ip ILIKE %(search)s")
        params["search"] = f"%{search.strip()}%"

    where_sql = " AND ".join(where_clauses)

    count_sql = f"SELECT COUNT(DISTINCT client_ip) AS total FROM domain_query_history WHERE {where_sql};"
    cur.execute(count_sql, params)
    total = cur.fetchone()["total"]

    params["limit"] = limit
    params["offset"] = offset

    data_sql = f"""
        SELECT client_ip,
               COUNT(*) AS query_count,
               COUNT(DISTINCT domain) AS unique_domains,
               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
        FROM domain_query_history
        WHERE {where_sql}
        GROUP BY client_ip
        ORDER BY query_count DESC, client_ip ASC
        LIMIT %(limit)s OFFSET %(offset)s;
    """
    cur.execute(data_sql, params)
    rows = cur.fetchall()
    return rows, total


def _fetch_report_flagged(
    cur,
    tw: TimeWindow,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> Tuple[List[Dict[str, Any]], int]:
    """Fetches paginated flagged/malicious query events in the selected interval."""
    where_clauses = [
        "timestamp >= %(start)s",
        "timestamp < %(end)s",
        "LOWER(COALESCE(final_label, '')) = 'malicious'",
    ]
    params: Dict[str, Any] = {"start": tw.start, "end": tw.end}

    if search and search.strip():
        where_clauses.append("(domain ILIKE %(search)s OR client_ip ILIKE %(search)s)")
        params["search"] = f"%{search.strip()}%"

    where_sql = " AND ".join(where_clauses)

    count_sql = f"SELECT COUNT(*) AS total FROM domain_query_history WHERE {where_sql};"
    cur.execute(count_sql, params)
    total = cur.fetchone()["total"]

    params["limit"] = limit
    params["offset"] = offset

    data_sql = f"""
        SELECT id,
               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS timestamp,
               client_ip,
               domain,
               query_type,
               final_label,
               COALESCE(ti_source, '') AS ti_source,
               COALESCE(response_code, '') AS response_code
        FROM domain_query_history
        WHERE {where_sql}
        ORDER BY timestamp DESC, id DESC
        LIMIT %(limit)s OFFSET %(offset)s;
    """
    cur.execute(data_sql, params)
    rows = cur.fetchall()
    return rows, total


# ===========================================================================
# 1. GET /api/v1/reports — Overview Summary & Timeseries
# ===========================================================================

@router.get("", summary="Get report summary KPIs and continuous time-series")
def get_report_overview(
    window: Optional[str] = Query(None, description="Preset window (e.g. '15m', '24h', '7d')"),
    start_time: Optional[str] = Query(None, description="ISO8601 UTC start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO8601 UTC end timestamp"),
):
    """
    Returns report-level summary KPIs and adaptive timeseries for the requested time range.
    Zero-data intervals return HTTP 200 with zero metrics rather than errors.
    """
    try:
        tw = _resolve_reports_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # 1. Summary KPIs
                cur.execute("""
                    SELECT COUNT(*) AS total_queries,
                           COUNT(DISTINCT client_ip) AS unique_clients,
                           COUNT(DISTINCT domain) AS unique_domains,
                           COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                           COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) AS benign_queries,
                           COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed', 'suspicious')) AS review_needed_queries,
                           COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown' OR final_label IS NULL) AS unknown_queries
                    FROM domain_query_history
                    WHERE timestamp >= %(start)s AND timestamp < %(end)s;
                """, {"start": tw.start, "end": tw.end})
                raw = cur.fetchone() or {}

                total_q = raw.get("total_queries") or 0
                malicious_q = raw.get("malicious_queries") or 0
                benign_q = raw.get("benign_queries") or 0
                review_needed_q = raw.get("review_needed_queries") or 0
                unknown_q = raw.get("unknown_queries") or 0
                unique_d = raw.get("unique_domains") or 0
                unique_c = raw.get("unique_clients") or 0
                threat_pct = round((malicious_q * 100.0) / total_q, 2) if total_q > 0 else 0.0

                summary = {
                    "total_queries": total_q,
                    "malicious_queries": malicious_q,
                    "benign_queries": benign_q,
                    "review_needed_queries": review_needed_q,
                    "unknown_queries": unknown_q,
                    "unique_domains": unique_d,
                    "unique_clients": unique_c,
                    "threat_percentage": threat_pct,
                }

                # 2. Continuous Timeseries
                cur.execute("""
                    SELECT to_timestamp(floor(extract(epoch from timestamp) / %(b_sec)s) * %(b_sec)s) AT TIME ZONE 'UTC' AS bucket_time,
                           COUNT(*) AS total_queries,
                           COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries
                    FROM domain_query_history
                    WHERE timestamp >= %(start)s AND timestamp < %(end)s
                    GROUP BY bucket_time
                    ORDER BY bucket_time ASC;
                """, {"start": tw.start, "end": tw.end, "b_sec": tw.bucket_seconds})
                db_buckets = {r["bucket_time"]: r for r in cur.fetchall()}

                all_bucket_dts = tw.generate_bucket_timestamps()
                timeseries = []
                for b_dt in all_bucket_dts:
                    match_dt = b_dt.astimezone(timezone.utc).replace(tzinfo=None)
                    row = db_buckets.get(match_dt)
                    timeseries.append({
                        "time_bucket": b_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "total_queries": row["total_queries"] if row else 0,
                        "malicious_queries": row["malicious_queries"] if row else 0,
                    })

                return {
                    "status": "success",
                    "data": {
                        "time_range": {
                            "start": tw.start_iso,
                            "end": tw.end_iso,
                            "preset": tw.preset,
                            "bucket_seconds": tw.bucket_seconds,
                        },
                        "summary": summary,
                        "timeseries": timeseries,
                    },
                }

    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error generating report overview: {exc}")


# ===========================================================================
# 2. GET /api/v1/reports/queries — Paginated DNS Query Events
# ===========================================================================

@router.get("/queries", summary="Get paginated DNS query records")
def get_report_queries(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=500, description="Page size"),
    search: Optional[str] = Query(None, description="Search by domain or client IP"),
    label: Optional[str] = Query(None, description="Filter by label (e.g. 'Malicious', 'Benign')"),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    try:
        tw = _resolve_reports_window(window, start_time, end_time)
        offset = (page - 1) * page_size

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                rows, total = _fetch_report_queries(
                    cur, tw, search=search, label=label, limit=page_size, offset=offset
                )
                pages = math.ceil(total / page_size) if total > 0 else 0

                return {
                    "status": "success",
                    "data": rows,
                    "meta": {
                        "page": page,
                        "page_size": page_size,
                        "total": total,
                        "pages": pages,
                        "time_range": {
                            "start": tw.start_iso,
                            "end": tw.end_iso,
                            "preset": tw.preset,
                        },
                    },
                }
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error fetching report queries: {exc}")


# ===========================================================================
# 3. GET /api/v1/reports/domains — Paginated Top Domains
# ===========================================================================

@router.get("/domains", summary="Get paginated top domains in time range")
def get_report_domains(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    try:
        tw = _resolve_reports_window(window, start_time, end_time)
        offset = (page - 1) * page_size

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                rows, total = _fetch_report_domains(
                    cur, tw, search=search, limit=page_size, offset=offset
                )
                pages = math.ceil(total / page_size) if total > 0 else 0

                return {
                    "status": "success",
                    "data": rows,
                    "meta": {
                        "page": page,
                        "page_size": page_size,
                        "total": total,
                        "pages": pages,
                        "time_range": {
                            "start": tw.start_iso,
                            "end": tw.end_iso,
                            "preset": tw.preset,
                        },
                    },
                }
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error fetching report domains: {exc}")


# ===========================================================================
# 4. GET /api/v1/reports/malicious-domains — Domains with >= 1 Malicious Event
# ===========================================================================

@router.get("/malicious-domains", summary="Get domains with >= 1 malicious event in range")
def get_report_malicious_domains(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    try:
        tw = _resolve_reports_window(window, start_time, end_time)
        offset = (page - 1) * page_size

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                rows, total = _fetch_report_malicious_domains(
                    cur, tw, search=search, limit=page_size, offset=offset
                )
                pages = math.ceil(total / page_size) if total > 0 else 0

                return {
                    "status": "success",
                    "data": rows,
                    "meta": {
                        "page": page,
                        "page_size": page_size,
                        "total": total,
                        "pages": pages,
                        "time_range": {
                            "start": tw.start_iso,
                            "end": tw.end_iso,
                            "preset": tw.preset,
                        },
                    },
                }
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error fetching report malicious domains: {exc}")


# ===========================================================================
# 5. GET /api/v1/reports/clients — Paginated Client Activity
# ===========================================================================

@router.get("/clients", summary="Get paginated client activity in time range")
def get_report_clients(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    try:
        tw = _resolve_reports_window(window, start_time, end_time)
        offset = (page - 1) * page_size

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                rows, total = _fetch_report_clients(
                    cur, tw, search=search, limit=page_size, offset=offset
                )
                pages = math.ceil(total / page_size) if total > 0 else 0

                return {
                    "status": "success",
                    "data": rows,
                    "meta": {
                        "page": page,
                        "page_size": page_size,
                        "total": total,
                        "pages": pages,
                        "time_range": {
                            "start": tw.start_iso,
                            "end": tw.end_iso,
                            "preset": tw.preset,
                        },
                    },
                }
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error fetching report clients: {exc}")


# ===========================================================================
# 6. GET /api/v1/reports/flagged — Paginated Flagged Queries
# ===========================================================================

@router.get("/flagged", summary="Get paginated flagged query events in time range")
def get_report_flagged(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    search: Optional[str] = Query(None),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
):
    try:
        tw = _resolve_reports_window(window, start_time, end_time)
        offset = (page - 1) * page_size

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                rows, total = _fetch_report_flagged(
                    cur, tw, search=search, limit=page_size, offset=offset
                )
                pages = math.ceil(total / page_size) if total > 0 else 0

                return {
                    "status": "success",
                    "data": rows,
                    "meta": {
                        "page": page,
                        "page_size": page_size,
                        "total": total,
                        "pages": pages,
                        "time_range": {
                            "start": tw.start_iso,
                            "end": tw.end_iso,
                            "preset": tw.preset,
                        },
                    },
                }
    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error fetching report flagged queries: {exc}")


# ===========================================================================
# 7. GET /api/v1/reports/entity — Entity-Centric Report (Client IP or Domain)
# ===========================================================================

@router.get("/entity", summary="Get entity-centric report (Client IP or Domain)")
def get_entity_report(
    entity: str = Query(..., description="Target entity (Client IP e.g. '192.168.1.104' or Domain e.g. 'google.com')"),
    entity_type: Optional[str] = Query(None, description="Explicit entity type: 'client' or 'domain'. Auto-detected if omitted."),
    window: Optional[str] = Query(None, description="Preset window (e.g. '7d', '24h', '6h')"),
    start_time: Optional[str] = Query(None, description="ISO8601 UTC start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO8601 UTC end timestamp"),
    page: int = Query(1, ge=1, description="Page number for query history"),
    page_size: int = Query(50, ge=1, le=500, description="Page size for query history"),
):
    clean_entity, determined_type = _validate_entity(entity, entity_type)

    try:
        tw = _resolve_reports_window(window, start_time, end_time)

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if determined_type == "client":
                    # 1. Summary (Strictly read-only aggregate from domain_query_history)
                    cur.execute("""
                        SELECT COUNT(*) AS total_queries,
                               COUNT(DISTINCT domain) AS unique_domains,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) AS benign_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')) AS review_needed_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown') AS unknown_queries,
                               COUNT(DISTINCT domain) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_domains,
                               COUNT(DISTINCT domain) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) AS benign_domains,
                               COUNT(DISTINCT domain) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')) AS review_needed_domains,
                               COUNT(DISTINCT domain) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown') AS unknown_domains,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s;
                    """, {"client_ip": clean_entity, "start": tw.start, "end": tw.end})
                    summary_raw = cur.fetchone() or {}
                    tot_q = summary_raw.get("total_queries") or 0
                    mal_q = summary_raw.get("malicious_queries") or 0
                    ben_q = summary_raw.get("benign_queries") or 0
                    rev_q = summary_raw.get("review_needed_queries") or 0
                    unk_q = summary_raw.get("unknown_queries") or 0
                    mal_d = summary_raw.get("malicious_domains") or 0
                    ben_d = summary_raw.get("benign_domains") or 0
                    rev_d = summary_raw.get("review_needed_domains") or 0
                    unk_d = summary_raw.get("unknown_domains") or 0
                    uniq_d = summary_raw.get("unique_domains") or 0
                    threat_pct = round((mal_d * 100.0) / uniq_d, 2) if uniq_d > 0 else 0.0

                    summary = {
                        "entity": clean_entity,
                        "entity_type": "client",
                        "total_queries": tot_q,
                        "unique_domains": uniq_d,
                        "malicious_queries": mal_q,
                        "benign_queries": ben_q,
                        "review_needed_queries": rev_q,
                        "unknown_queries": unk_q,
                        "malicious_domains": mal_d,
                        "benign_domains": ben_d,
                        "review_needed_domains": rev_d,
                        "unknown_domains": unk_d,
                        "first_seen": summary_raw.get("first_seen"),
                        "last_seen": summary_raw.get("last_seen"),
                        "threat_percentage": threat_pct,
                    }

                    # 2. Dataset 1: Most Queried Domains (Deterministic ordering)
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) AS benign_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')) AS review_needed_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown') AS unknown_queries,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        ORDER BY query_count DESC, domain ASC
                        LIMIT 100;
                    """, {"client_ip": clean_entity, "start": tw.start, "end": tw.end})
                    most_queried_domains = cur.fetchall()

                    # 3. Dataset 2: Malicious Domains (Only malicious_queries > 0)
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               COALESCE((ARRAY_AGG(ti_source ORDER BY timestamp DESC, id DESC) FILTER (WHERE ti_source IS NOT NULL AND ti_source != ''))[1], 'internal') AS ti_source,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        HAVING COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') > 0
                        ORDER BY malicious_queries DESC, query_count DESC, domain ASC
                        LIMIT 100;
                    """, {"client_ip": clean_entity, "start": tw.start, "end": tw.end})
                    malicious_domains = cur.fetchall()

                    # 4. Dataset 3: Benign Domains (Positive benign evidence AND zero malicious queries)
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        HAVING COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) > 0
                           AND COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') = 0
                        ORDER BY query_count DESC, domain ASC
                        LIMIT 100;
                    """, {"client_ip": clean_entity, "start": tw.start, "end": tw.end})
                    benign_domains = cur.fetchall()

                    # 5. Dataset 4: Review Needed Domains (Only review_needed events)
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        HAVING COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')) > 0
                        ORDER BY query_count DESC, domain ASC
                        LIMIT 100;
                    """, {"client_ip": clean_entity, "start": tw.start, "end": tw.end})
                    review_needed_domains = cur.fetchall()

                    # 6. Dataset 5: Unknown Domains (Actual pipeline/telemetry failures)
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        HAVING COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown') > 0
                        ORDER BY query_count DESC, domain ASC
                        LIMIT 100;
                    """, {"client_ip": clean_entity, "start": tw.start, "end": tw.end})
                    unknown_domains = cur.fetchall()

                    # 7. Dataset 6: Complete Query History (Server-side paginated, newest first)
                    offset = (page - 1) * page_size
                    cur.execute("""
                        SELECT COUNT(*) AS total
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s;
                    """, {"client_ip": clean_entity, "start": tw.start, "end": tw.end})
                    hist_total = cur.fetchone()["total"]

                    cur.execute("""
                        SELECT id,
                               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS timestamp,
                               client_ip,
                               domain,
                               query_type,
                               COALESCE(final_label, 'Unknown') AS final_label,
                               COALESCE(ti_source, '') AS ti_source,
                               COALESCE(response_code, '') AS response_code
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        ORDER BY timestamp DESC, id DESC
                        LIMIT %(limit)s OFFSET %(offset)s;
                    """, {"client_ip": clean_entity, "start": tw.start, "end": tw.end, "limit": page_size, "offset": offset})
                    query_history = cur.fetchall()
                    hist_pages = (hist_total + page_size - 1) // page_size if page_size > 0 else 1

                    return {
                        "status": "success",
                        "data": {
                            "summary": summary,
                            "most_queried_domains": most_queried_domains,
                            "malicious_domains": malicious_domains,
                            "benign_domains": benign_domains,
                            "review_needed_domains": review_needed_domains,
                            "unknown_domains": unknown_domains,
                            "clean_domains": benign_domains,               # legacy compatibility
                            "suspicious_domains": review_needed_domains,   # legacy compatibility
                            "query_history": query_history,
                            "meta": {
                                "page": page,
                                "page_size": page_size,
                                "total": hist_total,
                                "pages": hist_pages,
                                "time_range": {
                                    "start": tw.start_iso,
                                    "end": tw.end_iso,
                                    "preset": tw.preset,
                                },
                            },
                        },
                    }

                else:  # determined_type == "domain"
                    # 1. Summary (Strictly read-only aggregate from domain_query_history)
                    cur.execute("""
                        SELECT COUNT(*) AS total_queries,
                               COUNT(DISTINCT client_ip) AS unique_clients,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) AS benign_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')) AS review_needed_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown') AS unknown_queries,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE domain ILIKE %(domain)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s;
                    """, {"domain": clean_entity, "start": tw.start, "end": tw.end})
                    summary_raw = cur.fetchone() or {}
                    tot_q = summary_raw.get("total_queries") or 0
                    mal_q = summary_raw.get("malicious_queries") or 0
                    ben_q = summary_raw.get("benign_queries") or 0
                    rev_q = summary_raw.get("review_needed_queries") or 0
                    unk_q = summary_raw.get("unknown_queries") or 0
                    threat_pct = round((mal_q * 100.0) / tot_q, 2) if tot_q > 0 else 0.0

                    summary = {
                        "entity": clean_entity,
                        "entity_type": "domain",
                        "total_queries": tot_q,
                        "unique_clients": summary_raw.get("unique_clients") or 0,
                        "malicious_queries": mal_q,
                        "benign_queries": ben_q,
                        "review_needed_queries": rev_q,
                        "unknown_queries": unk_q,
                        "first_seen": summary_raw.get("first_seen"),
                        "last_seen": summary_raw.get("last_seen"),
                        "threat_percentage": threat_pct,
                    }

                    # 2. Dataset 1: Clients Querying This Domain (Deterministic ordering)
                    cur.execute("""
                        SELECT client_ip,
                               COUNT(*) AS query_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) AS benign_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')) AS review_needed_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown') AS unknown_queries,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE domain ILIKE %(domain)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY client_ip
                        ORDER BY query_count DESC, client_ip ASC
                        LIMIT 100;
                    """, {"domain": clean_entity, "start": tw.start, "end": tw.end})
                    clients_querying = cur.fetchall()

                    # 3. Dataset 2: Complete Query History (Server-side paginated, newest first)
                    offset = (page - 1) * page_size
                    cur.execute("""
                        SELECT COUNT(*) AS total
                        FROM domain_query_history
                        WHERE domain ILIKE %(domain)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s;
                    """, {"domain": clean_entity, "start": tw.start, "end": tw.end})
                    hist_total = cur.fetchone()["total"]

                    cur.execute("""
                        SELECT id,
                               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS timestamp,
                               client_ip,
                               domain,
                               query_type,
                               COALESCE(final_label, 'Unknown') AS final_label,
                               COALESCE(ti_source, '') AS ti_source,
                               COALESCE(response_code, '') AS response_code
                        FROM domain_query_history
                        WHERE domain ILIKE %(domain)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        ORDER BY timestamp DESC, id DESC
                        LIMIT %(limit)s OFFSET %(offset)s;
                    """, {"domain": clean_entity, "start": tw.start, "end": tw.end, "limit": page_size, "offset": offset})
                    query_history = cur.fetchall()
                    hist_pages = math.ceil(hist_total / page_size) if hist_total > 0 else 0

                    return {
                        "status": "success",
                        "data": {
                            "summary": summary,
                            "clients_querying": clients_querying,
                            "query_history": query_history,
                            "meta": {
                                "page": page,
                                "page_size": page_size,
                                "total": hist_total,
                                "pages": hist_pages,
                                "time_range": {
                                    "start": tw.start_iso,
                                    "end": tw.end_iso,
                                    "preset": tw.preset,
                                },
                            },
                        },
                    }

    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error generating entity report: {exc}")


# ===========================================================================
# 8. GET /api/v1/reports/export/csv — Consistent Streaming CSV Export
# ===========================================================================

@router.get("/export/csv", summary="Export report dataset as CSV stream")
def export_report_csv(
    table: str = Query(..., description="Target dataset (queries, domains, malicious-domains, clients, flagged, client-domains, client-malicious, client-clean, client-benign, client-review-needed, client-unknown, client-queries, domain-clients, domain-queries)"),
    entity: Optional[str] = Query(None, description="Entity identifier (required for entity tables)"),
    entity_type: Optional[str] = Query(None),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    label: Optional[str] = Query(None),
    limit: int = Query(5000, ge=1, le=10000, description="Max rows to export"),
):
    """
    Streams CSV data using the exact same underlying SQL query logic as the JSON endpoints,
    guaranteeing 100% data consistency between the user interface and export files.
    """
    valid_tables = {
        "queries", "domains", "malicious-domains", "clients", "flagged",
        "client-domains", "client-malicious", "client-clean", "client-benign",
        "client-review-needed", "client-unknown", "client-queries",
        "domain-clients", "domain-queries",
    }
    clean_table = table.strip().lower()
    if clean_table not in valid_tables:
        options = ", ".join(sorted(valid_tables))
        raise HTTPException(status_code=400, detail=f"Invalid table '{table}'. Supported: {options}")

    if clean_table.startswith("client-") or clean_table.startswith("domain-"):
        if not entity or not entity.strip():
            raise HTTPException(status_code=400, detail=f"Parameter 'entity' is required for table '{table}'.")

    try:
        tw = _resolve_reports_window(window, start_time, end_time)
        clean_ent = entity.strip() if entity else ""

        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if clean_table == "queries":
                    rows, _ = _fetch_report_queries(cur, tw, search=search, label=label, limit=limit, offset=0)
                    fieldnames = ["id", "timestamp", "client_ip", "domain", "query_type", "final_label", "ti_source", "response_code"]
                elif clean_table == "domains":
                    rows, _ = _fetch_report_domains(cur, tw, search=search, limit=limit, offset=0)
                    fieldnames = ["domain", "query_count", "unique_clients", "malicious_queries", "first_seen", "last_seen", "latest_verdict"]
                elif clean_table == "malicious-domains":
                    rows, _ = _fetch_report_malicious_domains(cur, tw, search=search, limit=limit, offset=0)
                    fieldnames = ["domain", "query_count", "unique_clients", "malicious_queries", "first_seen", "last_seen", "latest_verdict", "ti_source"]
                elif clean_table == "clients":
                    rows, _ = _fetch_report_clients(cur, tw, search=search, limit=limit, offset=0)
                    fieldnames = ["client_ip", "query_count", "unique_domains", "malicious_queries", "first_seen", "last_seen"]
                elif clean_table == "flagged":
                    rows, _ = _fetch_report_flagged(cur, tw, search=search, limit=limit, offset=0)
                    fieldnames = ["id", "timestamp", "client_ip", "domain", "query_type", "final_label", "ti_source", "response_code"]

                # Entity Client Tables
                elif clean_table == "client-domains":
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) AS benign_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')) AS review_needed_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown') AS unknown_queries,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        ORDER BY query_count DESC, domain ASC
                        LIMIT %(limit)s;
                    """, {"client_ip": clean_ent, "start": tw.start, "end": tw.end, "limit": limit})
                    rows = cur.fetchall()
                    fieldnames = ["domain", "query_count", "malicious_queries", "benign_queries", "review_needed_queries", "unknown_queries", "latest_verdict", "first_seen", "last_seen"]

                elif clean_table == "client-malicious":
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               COALESCE((ARRAY_AGG(ti_source ORDER BY timestamp DESC, id DESC) FILTER (WHERE ti_source IS NOT NULL AND ti_source != ''))[1], 'internal') AS ti_source,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        HAVING COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') > 0
                        ORDER BY malicious_queries DESC, query_count DESC, domain ASC
                        LIMIT %(limit)s;
                    """, {"client_ip": clean_ent, "start": tw.start, "end": tw.end, "limit": limit})
                    rows = cur.fetchall()
                    fieldnames = ["domain", "query_count", "malicious_queries", "latest_verdict", "ti_source", "first_seen", "last_seen"]

                elif clean_table in ("client-clean", "client-benign"):
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        HAVING COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) > 0
                           AND COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') = 0
                        ORDER BY query_count DESC, domain ASC
                        LIMIT %(limit)s;
                    """, {"client_ip": clean_ent, "start": tw.start, "end": tw.end, "limit": limit})
                    rows = cur.fetchall()
                    fieldnames = ["domain", "query_count", "latest_verdict", "first_seen", "last_seen"]

                elif clean_table == "client-review-needed":
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        HAVING COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')) > 0
                        ORDER BY query_count DESC, domain ASC
                        LIMIT %(limit)s;
                    """, {"client_ip": clean_ent, "start": tw.start, "end": tw.end, "limit": limit})
                    rows = cur.fetchall()
                    fieldnames = ["domain", "query_count", "latest_verdict", "first_seen", "last_seen"]

                elif clean_table == "client-unknown":
                    cur.execute("""
                        SELECT domain,
                               COUNT(*) AS query_count,
                               (ARRAY_AGG(final_label ORDER BY timestamp DESC, id DESC))[1] AS latest_verdict,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY domain
                        HAVING COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown') > 0
                        ORDER BY query_count DESC, domain ASC
                        LIMIT %(limit)s;
                    """, {"client_ip": clean_ent, "start": tw.start, "end": tw.end, "limit": limit})
                    rows = cur.fetchall()
                    fieldnames = ["domain", "query_count", "latest_verdict", "first_seen", "last_seen"]

                elif clean_table == "client-queries":
                    cur.execute("""
                        SELECT id,
                               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS timestamp,
                               client_ip,
                               domain,
                               query_type,
                               COALESCE(final_label, 'Unknown') AS final_label,
                               COALESCE(ti_source, '') AS ti_source,
                               COALESCE(response_code, '') AS response_code
                        FROM domain_query_history
                        WHERE client_ip = %(client_ip)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        ORDER BY timestamp DESC, id DESC
                        LIMIT %(limit)s;
                    """, {"client_ip": clean_ent, "start": tw.start, "end": tw.end, "limit": limit})
                    rows = cur.fetchall()
                    fieldnames = ["id", "timestamp", "client_ip", "domain", "query_type", "final_label", "ti_source", "response_code"]

                # Entity Domain Tables
                elif clean_table == "domain-clients":
                    cur.execute("""
                        SELECT client_ip,
                               COUNT(*) AS query_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('benign', 'clean')) AS benign_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) IN ('review_needed', 'review needed')) AS review_needed_queries,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'unknown') AS unknown_queries,
                               to_char(MIN(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE domain ILIKE %(domain)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        GROUP BY client_ip
                        ORDER BY query_count DESC, client_ip ASC
                        LIMIT %(limit)s;
                    """, {"domain": clean_ent, "start": tw.start, "end": tw.end, "limit": limit})
                    rows = cur.fetchall()
                    fieldnames = ["client_ip", "query_count", "malicious_queries", "benign_queries", "review_needed_queries", "unknown_queries", "first_seen", "last_seen"]

                elif clean_table == "domain-queries":
                    cur.execute("""
                        SELECT id,
                               to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS timestamp,
                               client_ip,
                               domain,
                               query_type,
                               COALESCE(final_label, 'Unknown') AS final_label,
                               COALESCE(ti_source, '') AS ti_source,
                               COALESCE(response_code, '') AS response_code
                        FROM domain_query_history
                        WHERE domain ILIKE %(domain)s
                          AND timestamp >= %(start)s AND timestamp < %(end)s
                        ORDER BY timestamp DESC, id DESC
                        LIMIT %(limit)s;
                    """, {"domain": clean_ent, "start": tw.start, "end": tw.end, "limit": limit})
                    rows = cur.fetchall()
                    fieldnames = ["id", "timestamp", "client_ip", "domain", "query_type", "final_label", "ti_source", "response_code"]

        prefix_tag = f"{clean_table}_{clean_ent}" if clean_ent else clean_table
        filename = f"report_{prefix_tag}_{tw.start.strftime('%Y%m%d%H%M')}_{tw.end.strftime('%Y%m%d%H%M')}.csv"

        def generate_csv_stream():
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

            for r in rows:
                writer.writerow(dict(r))
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)

        return StreamingResponse(
            generate_csv_stream(),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    except HTTPException:
        raise
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error generating CSV export: {exc}")

