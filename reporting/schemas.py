"""
reporting/schemas.py
====================
Domain contracts, typed models, and exceptions for DNSNetra Reporting Engine.
Pure Python dataclasses / Pydantic models with ZERO HTTP / web framework dependencies.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Dict, Generic, List, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field


T = TypeVar("T")


class CanonicalVerdict(str, Enum):
    """Canonical four-state application verdicts."""
    BENIGN = "Benign"
    MALICIOUS = "Malicious"
    REVIEW_NEEDED = "Review Needed"
    UNKNOWN = "Unknown"

    @classmethod
    def from_str(cls, value: Any) -> CanonicalVerdict:
        if isinstance(value, cls):
            return value
        if hasattr(value, "value"):
            value = value.value
        if not value:
            return cls.UNKNOWN
        val = str(value).strip().lower().replace("-", " ").replace("_", " ")
        if val in ("benign", "clean", "trusted", "whitelist", "whitelisted"):
            return cls.BENIGN
        if val in ("malicious", "malware", "phishing", "c2", "threat", "blacklist", "blacklisted"):
            return cls.MALICIOUS
        if val in ("review needed", "review_needed", "suspicious", "review", "inconclusive"):
            return cls.REVIEW_NEEDED
        return cls.UNKNOWN


class VerdictBreakdown(BaseModel):
    """Four-state canonical verdict counters."""
    model_config = ConfigDict(frozen=True)

    benign: int = 0
    malicious: int = 0
    review_needed: int = 0
    unknown: int = 0


class ReportingSummary(BaseModel):
    """High-level reporting summary metrics across a window or all-time."""
    model_config = ConfigDict(frozen=True)

    time_window: Optional[Dict[str, str]] = None
    total_queries: int = 0
    unique_clients: int = 0
    unique_domains: int = 0
    verdict_breakdown: VerdictBreakdown = Field(default_factory=VerdictBreakdown)
    malicious_query_percentage: float = 0.0


class TimeseriesBucket(BaseModel):
    """Chronological hourly bucket for timeseries reporting."""
    model_config = ConfigDict(frozen=True)

    timestamp: str  # ISO8601 UTC representation of bucket floor
    total_queries: int = 0
    benign_queries: int = 0
    malicious_queries: int = 0
    review_needed_queries: int = 0
    unknown_queries: int = 0


class ReportingTimeseries(BaseModel):
    """Complete chronological timeseries sequence."""
    model_config = ConfigDict(frozen=True)

    start_time: str  # ISO8601 UTC
    end_time: str    # ISO8601 UTC
    bucket_size: str = "1h"
    buckets: List[TimeseriesBucket] = Field(default_factory=list)


class ClientSummaryItem(BaseModel):
    """Per-client aggregated query activity metrics."""
    model_config = ConfigDict(frozen=True)

    client_ip: str
    total_queries: int
    unique_domains: int
    benign_queries: int
    malicious_queries: int
    review_needed_queries: int
    unknown_queries: int
    last_domain: Optional[str] = None
    last_query_type: Optional[str] = None
    first_seen: str  # ISO8601 UTC
    last_seen: str   # ISO8601 UTC


class DomainSummaryItem(BaseModel):
    """Per-domain aggregated query activity metrics."""
    model_config = ConfigDict(frozen=True)

    domain: str
    total_queries: int
    unique_clients: int
    benign_queries: int
    malicious_queries: int
    review_needed_queries: int
    unknown_queries: int
    latest_verdict: Optional[str] = None
    first_seen: str  # ISO8601 UTC
    last_seen: str   # ISO8601 UTC


class QueryEventItem(BaseModel):
    """Authoritative event-level record from domain_query_history."""
    model_config = ConfigDict(frozen=True)

    id: int
    timestamp: str  # ISO8601 UTC
    client_ip: str
    domain: str
    query_type: str
    response_code: Optional[str] = None
    final_label: str
    ti_source: Optional[str] = None
    registered_domain: Optional[str] = None
    tld: Optional[str] = None


class PaginatedResult(BaseModel, Generic[T]):
    """Standardized collection pagination container."""
    model_config = ConfigDict(frozen=True)

    total: int
    limit: int
    offset: int
    has_more: bool
    items: List[T] = Field(default_factory=list)


from time_engine.exceptions import (
    InvalidTimeRangeError,
    TimeEngineValidationError,
)


# --- Domain Exceptions ---

class ReportingError(Exception):
    """Base domain exception for reporting module."""
    pass


class ReportingValidationError(TimeEngineValidationError, ReportingError):
    """Raised when an invalid query parameter or temporal specification is provided."""
    pass
