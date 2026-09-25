"""
Analytics Package
=================
Modular, production-grade analytics capabilities for the DNS Threat Detection System.
Provides time-window telemetry abstractions, database-side aggregations, and metrics models.
"""

from analytics.models import (
    AnalyticsWindow,
    DomainAnalyticsMetrics,
    TimelineBucket,
    DomainAnalyticsData,
    DomainAnalyticsResponse,
)
from analytics.time_window import TimeWindow, WindowPreset, resolve_time_window
from analytics.domain_analytics import DomainAnalyticsService

__all__ = [
    "AnalyticsWindow",
    "DomainAnalyticsMetrics",
    "TimelineBucket",
    "DomainAnalyticsData",
    "DomainAnalyticsResponse",
    "TimeWindow",
    "WindowPreset",
    "resolve_time_window",
    "DomainAnalyticsService",
]
