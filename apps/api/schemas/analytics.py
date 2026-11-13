"""
api/schemas/analytics.py
========================
Response models for GET /api/v1/analytics/domains composed from ReportingService.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AnalyticsWindow(BaseModel):
    model_config = ConfigDict(frozen=True)

    start: str
    end: str
    duration_minutes: float


class AnalyticsMetrics(BaseModel):
    model_config = ConfigDict(frozen=True)

    total_queries: int
    unique_domains: int
    unique_clients: int
    malicious_domains: int
    review_needed_domains: int
    unknown_domains: int
    benign_queries: int
    malicious_queries: int
    review_needed_queries: int
    unknown_queries: int


class AnalyticsTimelineBucket(BaseModel):
    model_config = ConfigDict(frozen=True)

    timestamp: str
    queries: int
    benign_queries: int = 0
    malicious_queries: int = 0
    review_needed_queries: int = 0
    unknown_queries: int = 0


class DomainAnalyticsResponse(BaseModel):
    """
    Analytics response composed cleanly from ReportingService and time_engine.
    """
    model_config = ConfigDict(frozen=True)

    window: AnalyticsWindow
    metrics: AnalyticsMetrics
    timeline: List[AnalyticsTimelineBucket] = Field(default_factory=list)


__all__ = [
    "AnalyticsWindow",
    "AnalyticsMetrics",
    "AnalyticsTimelineBucket",
    "DomainAnalyticsResponse",
]
