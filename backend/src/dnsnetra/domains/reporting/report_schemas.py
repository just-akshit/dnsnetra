"""Domain models for saved reports."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ReportKind(str, Enum):
    ENTITY_DOMAIN = "entity_domain"
    ENTITY_CLIENT = "entity_client"
    QUERY_SET = "query_set"


class ReportStatus(str, Enum):
    DRAFT = "draft"
    NEEDS_REVIEW = "needs_review"
    REVIEWED = "reviewed"
    ARCHIVED = "archived"


class SavedReportSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    public_id: str
    kind: str
    entity_type: Optional[str] = None
    entity_value: Optional[str] = None
    title: str
    status: str
    verdict: Optional[str] = None
    created_by: Optional[int] = None
    reviewed_at: Optional[datetime] = None
    case_public_id: Optional[str] = None
    created_at: datetime


class SavedReportDetail(SavedReportSummary):
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    filters: dict[str, Any] = Field(default_factory=dict)
    snapshot: dict[str, Any] = Field(default_factory=dict)
    conclusion: Optional[str] = None
    reviewed_by: Optional[int] = None
    row_count: int = 0
