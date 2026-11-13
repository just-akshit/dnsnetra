"""HTTP contracts for cases."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from dnsnetra.domains.cases.schemas import CaseDetail, CaseSummary


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    priority: str = "medium"
    entity_type: Optional[str] = None
    entity_value: Optional[str] = None
    assigned_to: Optional[int] = None
    report_id: Optional[str] = None


class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[int] = None
    resolution: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None


class CaseCommentRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=10_000)


class CaseReportLinkRequest(BaseModel):
    report_public_id: str


__all__ = [
    "CaseCreateRequest", "CaseUpdateRequest", "CaseCommentRequest",
    "CaseReportLinkRequest", "CaseDetail", "CaseSummary",
]
