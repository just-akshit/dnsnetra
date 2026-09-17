"""
api/routes/dashboard.py
=======================
Controlled dashboard composition endpoint returning complete Overview dashboard data
in one coherent, single-temporal-range response.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from api.auth import get_current_user
from api.schemas import (
    CanonicalVerdict,
    DailyReviewSummaryItem,
    DashboardKPIs,
    DashboardResponse,
    ResolvedTimeRangeMeta,
    TimeseriesBucketResponse,
    TimeseriesResponse,
)
from labeler.intel.daily_review import list_daily_review_domains
from reporting.service import ReportingService
from time_engine import (
    ResolvedTimeRange,
    TemporalDefaultPolicy,
    format_iso8601_utc,
    resolve_time_range,
)

logger = logging.getLogger("api_dashboard")

router = APIRouter(prefix="/api/v1/dashboard", tags=["Dashboard"])


def _build_timeseries_response(tr: ResolvedTimeRange, service: ReportingService) -> Optional[TimeseriesResponse]:
    """Compose complete timeseries response with Phase 2C resolved bucket metadata."""
    if tr.is_all_time:
        return None

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


@router.get(
    "",
    response_model=DashboardResponse,
    summary="Unified Overview Dashboard Bundle",
    description="Returns coherent KPI metrics, continuous timeseries, top clients, and top domains for a single resolved temporal range.",
)
def get_dashboard(
    window: Optional[str] = Query(None, description="Preset window (e.g. 15m, 1h, 6h, 24h, 7d, 30d, today, yesterday)"),
    start_time: Optional[str] = Query(None, description="ISO-8601 start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO-8601 end timestamp"),
    bucket: Optional[str] = Query(None, description="Explicit bucket size (e.g. 5m, 1h, 1d)"),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> DashboardResponse:
    """Controlled dashboard composition endpoint."""
    reporting_service = ReportingService()

    # 1. Resolve temporal range ONCE for the entire dashboard bundle
    if window == "all_time":
        tr = resolve_time_range(
            window=None,
            start_time=None,
            end_time=None,
            bucket=None,
            default_policy=TemporalDefaultPolicy.ALL_TIME,
        )
    else:
        try:
            tr = resolve_time_range(
                window=window,
                start_time=start_time,
                end_time=end_time,
                bucket=bucket,
                default_policy=TemporalDefaultPolicy.ROLLING_24H,
            )
        except Exception as exc:
            from fastapi import HTTPException, status
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


    # 2. Compute summary & KPIs for the resolved range
    summary = reporting_service.get_summary(time_range=tr)

    # Reconcile total enrolled clients from client profiles
    all_time_summary = reporting_service.repository.get_all_time_summary()
    total_clients_count = all_time_summary["unique_clients"]

    # Reconcile malicious & unknown domain counts in this range
    if tr.is_empty:
        malicious_domains_count = 0
        unknown_domains_count = 0
    elif tr.is_all_time:
        mal_total, _ = reporting_service.repository.get_filtered_top_domains(
            CanonicalVerdict.MALICIOUS.value, None, None, limit=1, offset=0
        )
        unk_total, _ = reporting_service.repository.get_filtered_top_domains(
            CanonicalVerdict.UNKNOWN.value, None, None, limit=1, offset=0
        )
        malicious_domains_count = mal_total
        unknown_domains_count = unk_total
    else:
        mal_total, _ = reporting_service.repository.get_filtered_top_domains(
            CanonicalVerdict.MALICIOUS.value, tr.start, tr.observable_end, limit=1, offset=0
        )
        unk_total, _ = reporting_service.repository.get_filtered_top_domains(
            CanonicalVerdict.UNKNOWN.value, tr.start, tr.observable_end, limit=1, offset=0
        )
        malicious_domains_count = mal_total
        unknown_domains_count = unk_total

    kpis = DashboardKPIs(
        total_queries=summary.total_queries,
        total_clients=total_clients_count,
        unique_domains=summary.unique_domains,
        unique_clients=summary.unique_clients,
        malicious_domains=malicious_domains_count,
        unknown_domains=unknown_domains_count,
        verdict_breakdown=summary.verdict_breakdown,
        malicious_query_percentage=summary.malicious_query_percentage,
    )

    # 3. Compute continuous timeseries
    timeseries = _build_timeseries_response(tr, reporting_service)

    # 4. Top entities for this window
    top_clients = reporting_service.get_top_clients(time_range=tr, limit=10).items
    top_domains = reporting_service.get_top_domains(time_range=tr, limit=10).items
    top_benign = reporting_service.get_top_domains(
        time_range=tr, verdict_filter=CanonicalVerdict.BENIGN, limit=10
    ).items
    top_malicious = reporting_service.get_top_domains(
        time_range=tr, verdict_filter=CanonicalVerdict.MALICIOUS, limit=10
    ).items

    # 5. Daily review queue preview (system queue)
    review_records, _ = list_daily_review_domains(limit=10)
    daily_review_items = [
        DailyReviewSummaryItem(
            id=r.id,
            domain=r.domain,
            status=r.status.value if hasattr(r.status, "value") else str(r.status),
            reason=r.review_reason,
            next_check_at=format_iso8601_utc(r.next_check_at) if r.next_check_at else None,
            review_count=r.review_count,
            is_due=r.is_due,
        )
        for r in review_records
    ]

    time_meta = ResolvedTimeRangeMeta(
        start=format_iso8601_utc(tr.start) if tr.start else None,
        end=format_iso8601_utc(tr.end) if tr.end else None,
        resolved_now=format_iso8601_utc(tr.resolved_now),
        preset=tr.preset,
        bucket_label=tr.bucket_spec.bucket_label if tr.bucket_spec else None,
        bucket_seconds=tr.bucket_spec.bucket_seconds if tr.bucket_spec else None,
        bucket_source=tr.bucket_source.value.upper() if tr.bucket_source else None,
        is_all_time=tr.is_all_time,
    )

    return DashboardResponse(
        time_range=time_meta,
        summary=kpis,
        timeseries=timeseries,
        top_clients=top_clients,
        top_domains=top_domains,
        top_benign_domains=top_benign,
        top_malicious_domains=top_malicious,
        daily_review_domains=daily_review_items,
    )
