"""
reporting
=========
DNSNetra Reporting Engine subsystem.
Provides database access, domain models, and service interfaces for high-performance reporting.
"""

from .schemas import (
    CanonicalVerdict,
    VerdictBreakdown,
    ReportingSummary,
    TimeseriesBucket,
    ReportingTimeseries,
    ClientSummaryItem,
    DomainSummaryItem,
    QueryEventItem,
    PaginatedResult,
    ReportingError,
    InvalidTimeRangeError,
    ReportingValidationError,
)
from .repository import ReportingRepository
from .service import ReportingService

__all__ = [
    "CanonicalVerdict",
    "VerdictBreakdown",
    "ReportingSummary",
    "TimeseriesBucket",
    "ReportingTimeseries",
    "ClientSummaryItem",
    "DomainSummaryItem",
    "QueryEventItem",
    "PaginatedResult",
    "ReportingError",
    "InvalidTimeRangeError",
    "ReportingValidationError",
    "ReportingRepository",
    "ReportingService",
]
