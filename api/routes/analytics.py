"""
api/routes/analytics.py
=======================
DNS domain analytics composed from ReportingService:
- GET /api/v1/analytics/domains
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import get_current_user
from api.schemas import (
    AnalyticsMetrics,
    AnalyticsTimelineBucket,
    AnalyticsWindow,
    CanonicalVerdict,
    DomainAnalyticsResponse,
)
from reporting.service import ReportingService
from time_engine import (
    TemporalDefaultPolicy,
    format_iso8601_utc,
    resolve_time_range,
)

logger = logging.getLogger("api_analytics")

router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics"])


@router.get(
    "/domains",
    response_model=DomainAnalyticsResponse,
    summary="Time-Window Domain DNS Analytics",
    description="Domain activity metrics and activity timeline composed cleanly from ReportingService and time_engine.",
)
def get_domain_analytics(
    window: Optional[str] = Query(None, description="Preset window (e.g. 15m, 1h, 24h, 7d)"),
    start: Optional[str] = Query(None, description="ISO-8601 start timestamp"),
    end: Optional[str] = Query(None, description="ISO-8601 end timestamp"),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> DomainAnalyticsResponse:
    """Compose domain analytics using shared ReportingService logic."""
    # Map legacy "60m" to canonical "1h"
    norm_window = window
    if norm_window == "60m":
        norm_window = "1h"

    try:
        tr = resolve_time_range(
            window=norm_window,
            start_time=start,
            end_time=end,
            default_policy=TemporalDefaultPolicy.ROLLING_24H,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    if tr.is_all_time:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain analytics requires a bounded time window.",
        )

    service = ReportingService()
    summary = service.get_summary(time_range=tr)
    ts = service.get_timeseries(time_range=tr)

    # Reconcile domain counts for the window
    if tr.is_empty:
        mal_domains = 0
        rev_domains = 0
        unk_domains = 0
    else:
        mal_domains, _ = service.repository.get_filtered_top_domains(
            CanonicalVerdict.MALICIOUS.value, tr.start, tr.observable_end, limit=1, offset=0
        )
        rev_domains, _ = service.repository.get_filtered_top_domains(
            CanonicalVerdict.REVIEW_NEEDED.value, tr.start, tr.observable_end, limit=1, offset=0
        )
        unk_domains, _ = service.repository.get_filtered_top_domains(
            CanonicalVerdict.UNKNOWN.value, tr.start, tr.observable_end, limit=1, offset=0
        )

    dur_mins = round(tr.duration_seconds / 60.0, 2)
    s_iso = format_iso8601_utc(tr.start)
    e_iso = format_iso8601_utc(tr.end)

    timeline = [
        AnalyticsTimelineBucket(
            timestamp=b.timestamp,
            queries=b.total_queries,
            benign_queries=b.benign_queries,
            malicious_queries=b.malicious_queries,
            review_needed_queries=b.review_needed_queries,
            unknown_queries=b.unknown_queries,
        )
        for b in ts.buckets
    ]

    metrics = AnalyticsMetrics(
        total_queries=summary.total_queries,
        unique_domains=summary.unique_domains,
        unique_clients=summary.unique_clients,
        malicious_domains=mal_domains,
        review_needed_domains=rev_domains,
        unknown_domains=unk_domains,
        benign_queries=summary.verdict_breakdown.benign,
        malicious_queries=summary.verdict_breakdown.malicious,
        review_needed_queries=summary.verdict_breakdown.review_needed,
        unknown_queries=summary.verdict_breakdown.unknown,
    )

    return DomainAnalyticsResponse(
        window=AnalyticsWindow(
            start=s_iso,
            end=e_iso,
            duration_minutes=dur_mins,
        ),
        metrics=metrics,
        timeline=timeline,
    )
