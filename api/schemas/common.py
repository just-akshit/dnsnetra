"""
api/schemas/common.py
=====================
Shared Pydantic schemas, enums, pagination containers, and metadata contracts.
"""

from __future__ import annotations

from typing import Generic, List, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field

from reporting.schemas import CanonicalVerdict, VerdictBreakdown

T = TypeVar("T")


class PaginatedResponse(BaseModel, Generic[T]):
    """
    Canonical pagination container used consistently across all collection endpoints.
    """
    model_config = ConfigDict(frozen=True)

    total: int = Field(..., description="Total items matching filter criteria")
    limit: int = Field(..., ge=1, le=1000, description="Max items requested")
    offset: int = Field(..., ge=0, description="Index offset of first item")
    has_more: bool = Field(..., description="Whether additional items exist beyond limit+offset")
    items: List[T] = Field(default_factory=list, description="Page items")


class ResolvedTimeRangeMeta(BaseModel):
    """
    Metadata describing the single resolved temporal window used by the operation.
    """
    model_config = ConfigDict(frozen=True)

    start: Optional[str] = Field(None, description="ISO-8601 UTC start of requested interval")
    end: Optional[str] = Field(None, description="ISO-8601 UTC end of requested interval")
    resolved_now: str = Field(..., description="ISO-8601 UTC timestamp when 'now' was anchored")
    preset: Optional[str] = Field(None, description="Window preset identifier if provided")
    bucket_label: Optional[str] = Field(None, description="Resolved bucket width label (e.g. '1h')")
    bucket_seconds: Optional[int] = Field(None, description="Resolved bucket width in seconds")
    bucket_source: Optional[str] = Field(None, description="Bucket resolution source (PRESET_DEFAULT, EXPLICIT, AUTO)")
    is_all_time: bool = Field(False, description="Whether this represents an all-time lifetime query")


class ErrorResponse(BaseModel):
    """Standardized error envelope for client errors."""
    detail: str = Field(..., description="Human-readable description of the error")


__all__ = [
    "CanonicalVerdict",
    "VerdictBreakdown",
    "PaginatedResponse",
    "ResolvedTimeRangeMeta",
    "ErrorResponse",
]
