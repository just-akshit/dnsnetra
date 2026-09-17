"""
api/schemas/reports.py
======================
Reporting endpoint schemas and timeseries response models.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field

from investigation.schemas import ClientDossier, DomainDossier
from reporting.schemas import (
    ClientSummaryItem,
    DomainSummaryItem,
    QueryEventItem,
    ReportingSummary,
    VerdictBreakdown,
)
from .common import ResolvedTimeRangeMeta


class TimeseriesBucketResponse(BaseModel):
    """
    Timeline bucket containing full Phase 2C resolved interval properties and query counters.
    """
    model_config = ConfigDict(frozen=True)

    timestamp: str = Field(..., description="ISO-8601 UTC bucket floor timestamp")
    bucket_start: str = Field(..., description="ISO-8601 UTC start of full grid bucket")
    bucket_end: str = Field(..., description="ISO-8601 UTC end of full grid bucket")
    effective_start: str = Field(..., description="ISO-8601 UTC effective query start in this bucket")
    effective_end: str = Field(..., description="ISO-8601 UTC effective query end in this bucket")
    is_partial: bool = Field(..., description="True if query range only partially covers this bucket")
    covered_seconds: float = Field(..., description="Duration in seconds covered by query range")
    bucket_source: str = Field("AUTO", description="Source of bucket interval: PRESET_DEFAULT, EXPLICIT, AUTO")

    total_queries: int = Field(0, description="Total queries observed in bucket")
    benign_queries: int = Field(0, description="Benign queries in bucket")
    malicious_queries: int = Field(0, description="Malicious queries in bucket")
    review_needed_queries: int = Field(0, description="Review Needed queries in bucket")
    unknown_queries: int = Field(0, description="Unknown queries in bucket")


class TimeseriesResponse(BaseModel):
    """
    Continuous chronological timeseries sequence with bucket resolution metadata.
    """
    model_config = ConfigDict(frozen=True)

    start_time: str = Field(..., description="ISO-8601 UTC start of requested range")
    end_time: str = Field(..., description="ISO-8601 UTC end of requested range")
    bucket_size: str = Field(..., description="Display label for bucket width (e.g. '1h')")
    bucket_source: str = Field(..., description="Resolution origin (PRESET_DEFAULT, EXPLICIT, AUTO)")
    buckets: List[TimeseriesBucketResponse] = Field(default_factory=list)


class ReportOverviewResponse(BaseModel):
    """
    Unified report summary and timeseries bundle.
    """
    model_config = ConfigDict(frozen=True)

    time_range: ResolvedTimeRangeMeta
    summary: ReportingSummary
    timeseries: TimeseriesResponse


class EntityReportResponse(BaseModel):
    """
    Unified entity-oriented reporting response wrapping domain or client forensic dossier.
    """
    model_config = ConfigDict(frozen=True)

    entity: str = Field(..., description="Queried entity identifier (domain name or client IP)")
    entity_type: str = Field(..., description="Entity category: 'domain' or 'client'")
    domain_dossier: Optional[DomainDossier] = Field(None, description="Forensic dossier if entity is a domain")
    client_dossier: Optional[ClientDossier] = Field(None, description="Forensic dossier if entity is a client")


__all__ = [
    "ReportingSummary",
    "VerdictBreakdown",
    "ClientSummaryItem",
    "DomainSummaryItem",
    "QueryEventItem",
    "TimeseriesBucketResponse",
    "TimeseriesResponse",
    "ReportOverviewResponse",
    "EntityReportResponse",
]
