"""
api/schemas/dashboard.py
========================
Pydantic contracts for the unified /api/v1/dashboard composition endpoint.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from reporting.schemas import (
    ClientSummaryItem,
    DomainSummaryItem,
    VerdictBreakdown,
)
from .common import ResolvedTimeRangeMeta
from .reports import TimeseriesResponse


class DashboardKPIs(BaseModel):
    """
    Exactly six canonical KPI concepts + four-state verdict breakdown.
    Semantics:
    - total_clients: Lifetime enrolled client endpoints in client_profiles (fleet size, independent of temporal window).
    - unique_clients: Distinct client endpoints observed making queries within the resolved temporal window.
    - unique_domains: Distinct domain names queried within the resolved temporal window.
    - total_queries: Total DNS query events within the resolved temporal window.
    - malicious_domains: Distinct domains queried with Malicious verdict within the resolved temporal window.
    - unknown_domains: Distinct domains queried with Unknown verdict within the resolved temporal window.
    - verdict_breakdown: Query-event counts by canonical verdict (Benign + Malicious + Review Needed + Unknown == total_queries).
    - malicious_query_percentage: Percentage of queries that are Malicious in the window.
    """
    model_config = ConfigDict(frozen=True)

    total_queries: int = Field(..., description="Total queries observed in resolved window")
    total_clients: int = Field(..., description="Total enrolled client endpoints in system (lifetime fleet metric)")
    unique_domains: int = Field(..., description="Distinct domains queried in resolved window")
    unique_clients: int = Field(..., description="Distinct clients active in resolved window")
    malicious_domains: int = Field(..., description="Domains with malicious queries in resolved window")
    unknown_domains: int = Field(..., description="Domains with unknown queries in resolved window")
    verdict_breakdown: VerdictBreakdown = Field(default_factory=VerdictBreakdown)
    malicious_query_percentage: float = Field(0.0, description="Percentage of queries that are Malicious")


class DailyReviewSummaryItem(BaseModel):
    """Essential queue status item for daily review domains on the overview dashboard."""
    model_config = ConfigDict(frozen=True)

    id: int
    domain: str
    status: str
    reason: Optional[str] = None
    next_check_at: Optional[str] = None
    review_count: int = 1
    is_due: bool = False


class DashboardResponse(BaseModel):
    """
    Coherent, single-temporal-range dashboard composition response.
    """
    model_config = ConfigDict(frozen=True)

    time_range: ResolvedTimeRangeMeta
    summary: DashboardKPIs
    timeseries: Optional[TimeseriesResponse] = Field(None, description="Chronological query timeseries (null for all-time where timeseries is undefined)")
    top_clients: List[ClientSummaryItem] = Field(default_factory=list)
    top_domains: List[DomainSummaryItem] = Field(default_factory=list)
    top_benign_domains: List[DomainSummaryItem] = Field(default_factory=list)
    top_malicious_domains: List[DomainSummaryItem] = Field(default_factory=list)
    daily_review_domains: List[DailyReviewSummaryItem] = Field(default_factory=list)



__all__ = [
    "DashboardKPIs",
    "DailyReviewSummaryItem",
    "DashboardResponse",
]
