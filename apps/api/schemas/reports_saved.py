"""HTTP contracts for saved reports."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from dnsnetra.domains.reporting.report_schemas import ReportKind, ReportStatus, SavedReportDetail, SavedReportSummary
from dnsnetra.domains.reporting.schemas import CanonicalVerdict


class ReportCreateRequest(BaseModel):
    kind: ReportKind
    entity: Optional[str] = None
    window: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    filters: dict[str, Any] = Field(default_factory=dict)
    title: Optional[str] = None
    refresh: bool = False


class ReportReviewRequest(BaseModel):
    status: Optional[ReportStatus] = None
    verdict: Optional[CanonicalVerdict] = None
    conclusion: Optional[str] = None


class ReportListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[SavedReportSummary]


__all__ = [
    "ReportCreateRequest", "ReportReviewRequest", "ReportListResponse",
    "SavedReportDetail", "SavedReportSummary",
]
