"""
Analytics Data Models
=====================
Pydantic and data models for Time-Window DNS Analytics.
Defines strict contracts for metrics, time windows, and timeline buckets.
"""

from __future__ import annotations

from typing import List
from pydantic import BaseModel, Field


class AnalyticsWindow(BaseModel):
    """Metadata describing the active query time window."""
    start: str = Field(..., description="UTC ISO8601 start timestamp (inclusive)")
    end: str = Field(..., description="UTC ISO8601 end timestamp (exclusive)")
    duration_minutes: float = Field(..., description="Window duration in minutes")


class DomainAnalyticsMetrics(BaseModel):
    """
    Summary metrics aggregated across the entire half-open time window [start, end).
    
    Semantics:
    - total_queries: Total DNS query records observed (COUNT(*))
    - unique_fqdns: Total distinct Fully Qualified Domain Names (COUNT(DISTINCT domain))
    - unique_registered_domains: Total distinct registered apex domains (COUNT(DISTINCT registered_domain))
    - unique_clients: Total distinct client IPs making queries (COUNT(DISTINCT client_ip))
    - malicious_domains: Total distinct registered domains classified as malicious at query time
    - suspicious_domains: Total distinct registered domains classified as suspicious at query time
    """
    total_queries: int = Field(0, description="Total DNS queries in time window")
    unique_fqdns: int = Field(0, description="Unique Fully Qualified Domain Names")
    unique_registered_domains: int = Field(0, description="Unique registered apex domains (Primary KPI)")
    unique_clients: int = Field(0, description="Unique client IP addresses")
    malicious_domains: int = Field(0, description="Unique registered domains with malicious classification")
    suspicious_domains: int = Field(0, description="Unique registered domains with suspicious classification")


class TimelineBucket(BaseModel):
    """
    Activity metric for a single discrete time bucket within the window.
    
    IMPORTANT:
    `unique_domains` is unique WITHIN THIS BUCKET ONLY. It is non-additive and
    MUST NOT be summed across buckets to derive the window-level unique domain count.
    """
    timestamp: str = Field(..., description="UTC ISO8601 start timestamp of the bucket")
    queries: int = Field(0, description="Total DNS queries observed in this bucket")
    unique_domains: int = Field(0, description="Unique registered domains observed in this bucket")


class DomainAnalyticsData(BaseModel):
    """Payload container for time-window domain analytics."""
    window: AnalyticsWindow
    metrics: DomainAnalyticsMetrics
    timeline: List[TimelineBucket] = Field(default_factory=list)


class DomainAnalyticsResponse(BaseModel):
    """Top-level standard API response for /api/v1/analytics/domains."""
    status: str = "success"
    data: DomainAnalyticsData
