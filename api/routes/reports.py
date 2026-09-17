"""
api/routes/reports.py
=====================
Analytical reporting endpoints backed by ReportingService, ReportingRepository,
and time_engine:
- GET /api/v1/reports
- GET /api/v1/reports/summary
- GET /api/v1/reports/timeseries
- GET /api/v1/reports/clients
- GET /api/v1/reports/domains
- GET /api/v1/reports/queries
- Compatibility routes: /malicious-domains, /flagged, /entity, /export/csv
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse

from api.auth import get_current_user
from api.schemas import (
    CanonicalVerdict,
    ClientSummaryItem,
    DomainSummaryItem,
    EntityReportResponse,
    PaginatedResponse,
    QueryEventItem,
    ReportingSummary,
    TimeseriesBucketResponse,
    TimeseriesResponse,
)
from investigation.schemas import (
    EntityNotFoundError,
    InvalidEntityError,
)
from investigation.service import InvestigationService
from labeler.intel.database import normalize_domain
from reporting.schemas import ReportingValidationError
from reporting.service import ReportingService
from time_engine import (
    ResolvedTimeRange,
    TemporalDefaultPolicy,
    format_iso8601_utc,
    resolve_time_range,
)

logger = logging.getLogger("api_reports")

router = APIRouter(prefix="/api/v1/reports", tags=["Reporting"])


def _parse_pagination(
    limit: int = 50,
    offset: int = 0,
    page: Optional[int] = None,
    page_size: Optional[int] = None,
) -> tuple[int, int]:
    """Normalize pagination parameters supporting limit/offset and legacy page/page_size."""
    eff_limit = limit
    eff_offset = offset

    if page_size is not None and page_size >= 1:
        eff_limit = page_size
    if page is not None and page >= 1:
        eff_offset = (page - 1) * eff_limit

    if eff_limit < 1 or eff_limit > 1000:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="limit must be between 1 and 1000",
        )
    if eff_offset < 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="offset must be non-negative",
        )
    return eff_limit, eff_offset


def _resolve_temporal(
    window: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    bucket: Optional[str] = None,
    default_policy: TemporalDefaultPolicy = TemporalDefaultPolicy.ALL_TIME,
) -> ResolvedTimeRange:
    """Resolve temporal parameters once using time_engine."""
    try:
        return resolve_time_range(
            window=window,
            start_time=start_time,
            end_time=end_time,
            bucket=bucket,
            default_policy=default_policy,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc


def _build_timeseries_response(tr: ResolvedTimeRange, service: ReportingService) -> TimeseriesResponse:
    """Compose complete timeseries response with Phase 2C resolved bucket metadata."""
    s_iso = format_iso8601_utc(tr.start) if tr.start else ""
    e_iso = format_iso8601_utc(tr.end) if tr.end else ""
    b_label = tr.bucket_spec.bucket_label if tr.bucket_spec else "1h"
    source = tr.bucket_source.value.upper() if tr.bucket_source else "AUTO"

    if tr.is_empty:
        return TimeseriesResponse(
            start_time=s_iso,
            end_time=e_iso,
            bucket_size=b_label,
            bucket_source=source,
            buckets=[],
        )

    ts_data = service.get_timeseries(time_range=tr)
    counts_map = {b.timestamp: b for b in ts_data.buckets}

    resolved_buckets = tr.generate_buckets()
    buckets: list[TimeseriesBucketResponse] = []
    for rb in resolved_buckets:
        ts_str = format_iso8601_utc(rb.bucket_start)
        cb = counts_map.get(ts_str)
        buckets.append(
            TimeseriesBucketResponse(
                timestamp=ts_str,
                bucket_start=format_iso8601_utc(rb.bucket_start),
                bucket_end=format_iso8601_utc(rb.bucket_end),
                effective_start=format_iso8601_utc(rb.effective_start),
                effective_end=format_iso8601_utc(rb.effective_end),
                is_partial=rb.is_partial,
                covered_seconds=rb.covered_seconds,
                bucket_source=source,
                total_queries=cb.total_queries if cb else 0,
                benign_queries=cb.benign_queries if cb else 0,
                malicious_queries=cb.malicious_queries if cb else 0,
                review_needed_queries=cb.review_needed_queries if cb else 0,
                unknown_queries=cb.unknown_queries if cb else 0,
            )
        )

    return TimeseriesResponse(
        start_time=s_iso,
        end_time=e_iso,
        bucket_size=b_label,
        bucket_source=source,
        buckets=buckets,
    )


# ---------------------------------------------------------------------------
# 1. Summary
# ---------------------------------------------------------------------------

@router.get(
    "/summary",
    response_model=ReportingSummary,
    summary="Reporting KPI Summary",
    description="High-level reporting summary metrics and canonical verdict breakdown for a temporal window or all-time.",
)
def get_report_summary(
    window: Optional[str] = Query(None, description="Preset window (e.g. 15m, 1h, 24h, 7d, today)"),
    start_time: Optional[str] = Query(None, description="ISO-8601 start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO-8601 end timestamp"),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> ReportingSummary:
    """Canonical summary endpoint."""
    service = ReportingService()
    tr = _resolve_temporal(window=window, start_time=start_time, end_time=end_time)
    return service.get_summary(time_range=tr)


@router.get(
    "",
    response_model=ReportingSummary,
    summary="Reporting Summary (alias)",
    description="Compatibility entry point; delegates directly to the canonical summary implementation.",
)
def get_reports_root(
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> ReportingSummary:
    """Compatibility entry point delegating to get_report_summary."""
    return get_report_summary(window=window, start_time=start_time, end_time=end_time, current_user=current_user)


# ---------------------------------------------------------------------------
# 2. Timeseries
# ---------------------------------------------------------------------------

@router.get(
    "/timeseries",
    response_model=TimeseriesResponse,
    summary="Chronological Timeseries Sequence",
    description="Continuous bucketed query volume with full Phase 2C resolution metadata and 4 canonical verdict counters.",
)
def get_report_timeseries(
    window: Optional[str] = Query(None, description="Preset window (e.g. 1h, 6h, 24h, 7d, 30d)"),
    start_time: Optional[str] = Query(None, description="ISO-8601 start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO-8601 end timestamp"),
    bucket: Optional[str] = Query(None, description="Explicit bucket width (e.g. 5m, 1h, 1d)"),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> TimeseriesResponse:
    """Canonical timeseries endpoint."""
    service = ReportingService()
    tr = _resolve_temporal(
        window=window,
        start_time=start_time,
        end_time=end_time,
        bucket=bucket,
        default_policy=TemporalDefaultPolicy.ROLLING_24H,
    )
    if tr.is_all_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="All-time timeseries is not permitted.",
        )
    return _build_timeseries_response(tr, service)


# ---------------------------------------------------------------------------
# 3. Clients
# ---------------------------------------------------------------------------

@router.get(
    "/clients",
    response_model=PaginatedResponse[ClientSummaryItem],
    summary="Ranked Client Activity Reporting",
    description="Deterministic client query volume ranking with canonical pagination and optional temporal filtering.",
)
def get_report_clients(
    limit: int = Query(50, ge=1, le=1000, description="Max items to return"),
    offset: int = Query(0, ge=0, description="Offset index"),
    page: Optional[int] = Query(None, ge=1, description="Legacy page number alias"),
    page_size: Optional[int] = Query(None, ge=1, le=1000, description="Legacy page size alias"),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> PaginatedResponse[ClientSummaryItem]:
    """Client reporting endpoint."""
    eff_limit, eff_offset = _parse_pagination(limit, offset, page, page_size)
    service = ReportingService()
    has_temporal = any(p is not None for p in (window, start_time, end_time))
    tr = _resolve_temporal(window=window, start_time=start_time, end_time=end_time) if has_temporal else None

    result = service.get_top_clients(
        limit=eff_limit,
        offset=eff_offset,
        time_range=tr,
    )
    return PaginatedResponse[ClientSummaryItem](
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        has_more=result.has_more,
        items=result.items,
    )


# ---------------------------------------------------------------------------
# 4. Domains
# ---------------------------------------------------------------------------

@router.get(
    "/domains",
    response_model=PaginatedResponse[DomainSummaryItem],
    summary="Ranked Domain Activity Reporting",
    description="Deterministic domain ranking supporting canonical verdict filtering and temporal windows.",
)
def get_report_domains(
    limit: int = Query(50, ge=1, le=1000, description="Max items to return"),
    offset: int = Query(0, ge=0, description="Offset index"),
    page: Optional[int] = Query(None, ge=1, description="Legacy page number alias"),
    page_size: Optional[int] = Query(None, ge=1, le=1000, description="Legacy page size alias"),
    verdict: Optional[str] = Query(None, description="Canonical verdict filter (Benign, Malicious, Review Needed, Unknown)"),
    label: Optional[str] = Query(None, description="Verdict filter alias"),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> PaginatedResponse[DomainSummaryItem]:
    """Domain reporting endpoint."""
    eff_limit, eff_offset = _parse_pagination(limit, offset, page, page_size)
    service = ReportingService()

    verdict_param = verdict or label
    canon_verdict: Optional[str] = None
    if verdict_param and verdict_param.strip() and verdict_param.strip().lower() != "all":
        canon_verdict = CanonicalVerdict.from_str(verdict_param).value

    has_temporal = any(p is not None for p in (window, start_time, end_time))
    tr = _resolve_temporal(window=window, start_time=start_time, end_time=end_time) if has_temporal else None

    result = service.get_top_domains(
        limit=eff_limit,
        offset=eff_offset,
        verdict_filter=canon_verdict,
        time_range=tr,
    )
    return PaginatedResponse[DomainSummaryItem](
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        has_more=result.has_more,
        items=result.items,
    )


# ---------------------------------------------------------------------------
# 5. Queries Log
# ---------------------------------------------------------------------------

@router.get(
    "/queries",
    response_model=PaginatedResponse[QueryEventItem],
    summary="Event-Level DNS Query Log",
    description="Multi-criteria paginated query search across authoritative domain_query_history with deterministic sorting.",
)
def get_report_queries(
    limit: int = Query(50, ge=1, le=1000, description="Max items to return"),
    offset: int = Query(0, ge=0, description="Offset index"),
    page: Optional[int] = Query(None, ge=1, description="Legacy page number alias"),
    page_size: Optional[int] = Query(None, ge=1, le=1000, description="Legacy page size alias"),
    client_ip: Optional[str] = Query(None, description="Filter by client IP"),
    domain: Optional[str] = Query(None, description="Filter by domain name"),
    verdict: Optional[str] = Query(None, description="Filter by canonical verdict"),
    label: Optional[str] = Query(None, description="Verdict filter alias"),
    query_type: Optional[str] = Query(None, description="Filter by DNS query type (e.g. A, AAAA, TXT)"),
    search: Optional[str] = Query(None, description="Free text search (matched against domain or client_ip)"),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> PaginatedResponse[QueryEventItem]:
    """Query log reporting endpoint."""
    eff_limit, eff_offset = _parse_pagination(limit, offset, page, page_size)
    service = ReportingService()

    # Domain / client search disambiguation
    filter_ip = client_ip
    filter_dom = domain

    if search and search.strip():
        term = search.strip()
        try:
            ipaddress.ip_address(term)
            filter_ip = filter_ip or term
        except ValueError:
            filter_dom = filter_dom or term

    # Canonical verdict normalization
    verdict_param = verdict or label
    canon_verdict: Optional[str] = None
    if verdict_param and verdict_param.strip() and verdict_param.strip().lower() != "all":
        canon_verdict = CanonicalVerdict.from_str(verdict_param).value

    has_temporal = any(p is not None for p in (window, start_time, end_time))
    tr = _resolve_temporal(window=window, start_time=start_time, end_time=end_time) if has_temporal else None

    try:
        result = service.get_queries(
            client_ip=filter_ip,
            domain=filter_dom,
            verdict=canon_verdict,
            query_type=query_type,
            time_range=tr,
            limit=eff_limit,
            offset=eff_offset,
        )
    except ReportingValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return PaginatedResponse[QueryEventItem](
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        has_more=result.has_more,
        items=result.items,
    )


# ---------------------------------------------------------------------------
# 6. Compatibility Endpoints
# ---------------------------------------------------------------------------

@router.get(
    "/malicious-domains",
    response_model=PaginatedResponse[DomainSummaryItem],
    summary="Malicious Domains Reporting (compatibility)",
    description="Compatibility endpoint delegating directly to canonical domain reporting with verdict=Malicious.",
)
def get_report_malicious_domains(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    page: Optional[int] = Query(None, ge=1),
    page_size: Optional[int] = Query(None, ge=1, le=1000),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> PaginatedResponse[DomainSummaryItem]:
    """Delegates to get_top_domains with verdict=Malicious."""
    eff_limit, eff_offset = _parse_pagination(limit, offset, page, page_size)
    service = ReportingService()
    has_temporal = any(p is not None for p in (window, start_time, end_time))
    tr = _resolve_temporal(window=window, start_time=start_time, end_time=end_time) if has_temporal else None

    result = service.get_top_domains(
        limit=eff_limit,
        offset=eff_offset,
        verdict_filter=CanonicalVerdict.MALICIOUS.value,
        time_range=tr,
    )
    return PaginatedResponse[DomainSummaryItem](
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        has_more=result.has_more,
        items=result.items,
    )


@router.get(
    "/flagged",
    response_model=PaginatedResponse[QueryEventItem],
    summary="Flagged Queries Reporting (compatibility)",
    description="Compatibility endpoint delegating to canonical query reporting with verdict='Review Needed'.",
)
def get_report_flagged(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    page: Optional[int] = Query(None, ge=1),
    page_size: Optional[int] = Query(None, ge=1, le=1000),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> PaginatedResponse[QueryEventItem]:
    """Delegates to get_queries with verdict='Review Needed'."""
    eff_limit, eff_offset = _parse_pagination(limit, offset, page, page_size)
    service = ReportingService()
    has_temporal = any(p is not None for p in (window, start_time, end_time))
    tr = _resolve_temporal(window=window, start_time=start_time, end_time=end_time) if has_temporal else None

    result = service.get_queries(
        verdict=CanonicalVerdict.REVIEW_NEEDED.value,
        time_range=tr,
        limit=eff_limit,
        offset=eff_offset,
    )
    return PaginatedResponse[QueryEventItem](
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        has_more=result.has_more,
        items=result.items,
    )


@router.get(
    "/entity",
    response_model=EntityReportResponse,
    summary="Entity Forensic Reporting",
    description="Unified entity reporting endpoint supporting domain or client IP lookups with complete forensic dossier.",
)
def get_report_entity(
    entity: str = Query(..., min_length=1, description="Entity identifier (domain name or client IP)"),
    entity_type: Optional[str] = Query(None, description="Optional entity type ('domain' or 'client'). Auto-detected if omitted."),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> EntityReportResponse:
    """Canonical entity reporting endpoint reusing InvestigationService."""
    clean_entity = entity.strip()
    if not clean_entity:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Entity identifier cannot be empty.",
        )

    inv_service = InvestigationService()

    eff_type = entity_type.strip().lower() if entity_type and entity_type.strip() else None
    if eff_type and eff_type not in ("domain", "client"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="entity_type must be either 'domain' or 'client'.",
        )

    if eff_type is None:
        try:
            ipaddress.ip_address(clean_entity)
            eff_type = "client"
        except ValueError:
            eff_type = "domain"

    if eff_type == "client":
        try:
            dossier = inv_service.get_client_dossier(clean_entity)
            return EntityReportResponse(
                entity=clean_entity,
                entity_type="client",
                client_dossier=dossier,
            )
        except EntityNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except InvalidEntityError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    else:  # domain
        try:
            dossier = inv_service.get_domain_dossier(clean_entity)
            return EntityReportResponse(
                entity=clean_entity,
                entity_type="domain",
                domain_dossier=dossier,
            )
        except EntityNotFoundError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except InvalidEntityError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/export/csv",
    summary="Export DNS Query Log as CSV",
    description="Streams query event log as RFC 4180 CSV using identical filter semantics to /reports/queries.",
)
def get_report_export_csv(
    limit: int = Query(5000, ge=1, le=50000, description="Max query rows to export (1 to 50,000)"),
    client_ip: Optional[str] = Query(None, description="Filter by client IP"),
    domain: Optional[str] = Query(None, description="Filter by domain name"),
    verdict: Optional[str] = Query(None, description="Filter by canonical verdict"),
    label: Optional[str] = Query(None, description="Verdict filter alias"),
    query_type: Optional[str] = Query(None, description="Filter by DNS query type (e.g. A, AAAA, TXT)"),
    search: Optional[str] = Query(None, description="Search term across domain or client IP"),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> StreamingResponse:
    """Streaming CSV export endpoint."""
    service = ReportingService()

    filter_ip = client_ip
    filter_dom = domain
    if search and search.strip():
        term = search.strip()
        try:
            ipaddress.ip_address(term)
            filter_ip = filter_ip or term
        except ValueError:
            filter_dom = filter_dom or term

    verdict_param = verdict or label
    canon_verdict: Optional[str] = None
    if verdict_param and verdict_param.strip() and verdict_param.strip().lower() != "all":
        canon_verdict = CanonicalVerdict.from_str(verdict_param).value

    has_temporal = any(p is not None for p in (window, start_time, end_time))
    tr = _resolve_temporal(window=window, start_time=start_time, end_time=end_time) if has_temporal else None

    try:
        generator = service.stream_queries_csv(
            client_ip=filter_ip,
            domain=filter_dom,
            verdict=canon_verdict,
            query_type=query_type,
            time_range=tr,
            limit=limit,
        )
    except ReportingValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    headers = {
        "Content-Disposition": 'attachment; filename="dnsnetra_queries_export.csv"',
        "Cache-Control": "no-cache, no-store, must-revalidate",
    }
    return StreamingResponse(generator, media_type="text/csv", headers=headers)

