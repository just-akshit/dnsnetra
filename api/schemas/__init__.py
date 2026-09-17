"""
api/schemas/__init__.py
=======================
Central export for all API schemas.
"""

from .common import (
    CanonicalVerdict,
    ErrorResponse,
    PaginatedResponse,
    ResolvedTimeRangeMeta,
    VerdictBreakdown,
)
from .dashboard import (
    DailyReviewSummaryItem,
    DashboardKPIs,
    DashboardResponse,
)
from .reports import (
    ClientSummaryItem,
    DomainSummaryItem,
    EntityReportResponse,
    QueryEventItem,
    ReportOverviewResponse,
    ReportingSummary,
    TimeseriesBucketResponse,
    TimeseriesResponse,
)
from .status import (
    AggregationStatus,
    DatabaseHealth,
    SystemStatusResponse,
)
from .analytics import (
    AnalyticsMetrics,
    AnalyticsTimelineBucket,
    AnalyticsWindow,
    DomainAnalyticsResponse,
)

__all__ = [
    "CanonicalVerdict",
    "VerdictBreakdown",
    "PaginatedResponse",
    "ResolvedTimeRangeMeta",
    "ErrorResponse",
    "DashboardKPIs",
    "DailyReviewSummaryItem",
    "DashboardResponse",
    "ReportingSummary",
    "ClientSummaryItem",
    "DomainSummaryItem",
    "QueryEventItem",
    "TimeseriesBucketResponse",
    "TimeseriesResponse",
    "ReportOverviewResponse",
    "EntityReportResponse",
    "DatabaseHealth",
    "AggregationStatus",
    "SystemStatusResponse",
    "AnalyticsWindow",
    "AnalyticsMetrics",
    "AnalyticsTimelineBucket",
    "DomainAnalyticsResponse",
]
