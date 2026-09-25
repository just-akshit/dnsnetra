"""
API Pydantic Response Models
============================
Pydantic models matching each dashboard.db table for API response validation.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


# ------------------------------------------------------------------
# metrics_summary
# ------------------------------------------------------------------

class MetricsSummary(BaseModel):
    """Single-row pipeline run snapshot."""
    total_queries: int = 0
    total_threats: int = 0
    threats_blocked_pct: float = 0.0
    unique_clients: int = 0
    unique_domains: int = 0
    last_pipeline_run_at: str = ""


class MetricsSummaryResponse(BaseModel):
    """Wrapper response for /api/v1/summary."""
    data: Optional[MetricsSummary] = None


# ------------------------------------------------------------------
# threats_by_category
# ------------------------------------------------------------------

class ThreatCategory(BaseModel):
    """A single threat category row."""
    category: str
    count: int = 0
    pct: float = 0.0


class ThreatCategoriesResponse(BaseModel):
    """Response for /api/v1/threats/categories."""
    data: List[ThreatCategory] = Field(default_factory=list)


# ------------------------------------------------------------------
# queries_timeseries
# ------------------------------------------------------------------

class TimeseriesBucket(BaseModel):
    """A single hourly time bucket row."""
    time_bucket: str
    total_queries: int = 0
    threat_queries: int = 0


class TimeseriesResponse(BaseModel):
    """Response for /api/v1/threats/timeseries."""
    data: List[TimeseriesBucket] = Field(default_factory=list)


# ------------------------------------------------------------------
# geo_distribution
# ------------------------------------------------------------------

class GeoEntry(BaseModel):
    """A single country/ASN geo row."""
    country: str
    asn: str
    query_count: int = 0
    threat_count: int = 0


class GeoDistributionResponse(BaseModel):
    """Response for /api/v1/threats/geo."""
    geoip_enabled: bool = False
    data: List[GeoEntry] = Field(default_factory=list)


# ------------------------------------------------------------------
# top_domains
# ------------------------------------------------------------------

class TopDomain(BaseModel):
    """A single top domain row."""
    domain: str
    query_count: int = 0
    label: str = ""
    threat_score: float = 0.0
    last_seen: str = ""


class TopDomainsResponse(BaseModel):
    """Response for /api/v1/domains/top."""
    data: List[TopDomain] = Field(default_factory=list)


# ------------------------------------------------------------------
# recent_flagged_domains
# ------------------------------------------------------------------

class RecentFlaggedDomain(BaseModel):
    """A single recently flagged domain row."""
    domain: str
    label: str = ""
    label_reason: Optional[str] = None
    ti_source: Optional[str] = None
    confidence: Optional[float] = None
    flagged_at: str = ""


class RecentFlaggedDomainsResponse(BaseModel):
    """Response for /api/v1/domains/recent."""
    data: List[RecentFlaggedDomain] = Field(default_factory=list)


# ------------------------------------------------------------------
# top_clients
# ------------------------------------------------------------------

class TopClient(BaseModel):
    """A single top client IP row."""
    client_ip: str
    query_count: int = 0
    malicious_query_count: int = 0
    last_seen: str = ""


class TopClientsResponse(BaseModel):
    """Response for /api/v1/clients/top."""
    data: List[TopClient] = Field(default_factory=list)


# ------------------------------------------------------------------
# Time-Window Analytics (Phase 4.2)
# ------------------------------------------------------------------
from analytics.models import (
    AnalyticsWindow,
    DomainAnalyticsMetrics,
    TimelineBucket,
    DomainAnalyticsData,
    DomainAnalyticsResponse,
)

