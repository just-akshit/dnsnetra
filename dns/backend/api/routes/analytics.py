"""
Analytics API Routes
====================
Provides Time-Window DNS Analytics endpoints:
- GET /api/v1/analytics/domains

Supports preset rolling windows ('5m', '10m', '15m', '30m', '45m', '60m') and
custom ISO8601 UTC time ranges.
"""

from __future__ import annotations

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Query

from analytics.domain_analytics import DomainAnalyticsService
from analytics.models import DomainAnalyticsResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/analytics", tags=["Analytics"])


@router.get(
    "/domains",
    response_model=DomainAnalyticsResponse,
    summary="Get Time-Window DNS Domain Analytics",
    description="""
    Calculates time-window DNS query telemetry metrics and non-additive timeline activity
    over a rolling preset window ending at server UTC now or a custom ISO8601 UTC range.
    
    Metrics provided:
    - total_queries: Total DNS query records in window
    - unique_fqdns: Total distinct Fully Qualified Domain Names
    - unique_registered_domains: Primary "Domains Observed" KPI (apex domains under public suffixes)
    - unique_clients: Total distinct client IPs
    - malicious_domains: Total distinct registered domains classified as malicious
    - suspicious_domains: Total distinct registered domains classified as suspicious
    - timeline: Deterministic bucketed query volume and distinct domain activity (guaranteed <= 100 buckets)
    """,
)
def get_domain_analytics(
    window: Optional[str] = Query(
        None,
        description="Preset rolling window ending at server UTC now ('5m', '10m', '15m', '30m', '45m', '60m')",
    ),
    start: Optional[str] = Query(
        None,
        description="Custom start timestamp in UTC ISO8601 format (inclusive)",
    ),
    end: Optional[str] = Query(
        None,
        description="Custom end timestamp in UTC ISO8601 format (exclusive)",
    ),
):
    """
    Executes database-side time-window domain telemetry analytics.
    """
    try:
        data = DomainAnalyticsService.get_analytics(
            window=window,
            start=start,
            end=end,
        )
        return DomainAnalyticsResponse(status="success", data=data)
    except ValueError as exc:
        logger.warning("Invalid time window analytics request: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.error("Domain analytics query failed: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Time-window analytics query failed: {exc}",
        )
