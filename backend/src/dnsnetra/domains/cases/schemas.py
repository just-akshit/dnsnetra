"""Case and timeline contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class CaseStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    AWAITING_INFO = "awaiting_info"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CasePriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseResolution(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    DUPLICATE = "duplicate"
    NO_ACTION = "no_action"


class CaseEventKind(str, Enum):
    CREATED = "created"
    COMMENT = "comment"
    STATUS_CHANGED = "status_changed"
    ASSIGNED = "assigned"
    PRIORITY_CHANGED = "priority_changed"
    RESOLUTION_SET = "resolution_set"
    REPORT_LINKED = "report_linked"
    REPORT_UNLINKED = "report_unlinked"


class CaseEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    kind: str
    actor_id: Optional[int] = None
    body: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class CaseSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int = Field(exclude=True)
    public_id: str
    title: str
    status: str
    priority: str
    entity_type: Optional[str] = None
    entity_value: Optional[str] = None
    assigned_to: Optional[int] = None
    created_by: Optional[int] = None
    resolution: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CaseDetail(CaseSummary):
    description: Optional[str] = None
    resolved_by: Optional[int] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    events: list[CaseEvent] = Field(default_factory=list)
    reports: list[str] = Field(default_factory=list)
