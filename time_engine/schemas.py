"""
time_engine/schemas.py
======================
Frozen domain models and enums for DNSNetra Centralized Temporal Engine.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .exceptions import InvalidTimeRangeError


class TemporalDefaultPolicy(str, Enum):
    """Supported fallback policies when no temporal parameters are supplied."""
    ALL_TIME = "all_time"
    ROLLING_24H = "rolling_24h"


class WindowPreset(str, Enum):
    """Canonical supported rolling and calendar window presets."""
    M15 = "15m"
    M30 = "30m"
    H1 = "1h"
    H6 = "6h"
    H12 = "12h"
    H24 = "24h"
    D7 = "7d"
    D30 = "30d"
    TODAY = "today"
    YESTERDAY = "yesterday"


class BucketResolutionSource(str, Enum):
    """Structural origin of resolved timeline bucket width."""
    PRESET_DEFAULT = "preset_default"
    EXPLICIT = "explicit"
    AUTO = "auto"


class BucketSpec(BaseModel):
    """Immutable specification of bucket width and display label."""
    model_config = ConfigDict(frozen=True)

    bucket_seconds: int
    bucket_label: str


class PresetSpec(BaseModel):
    """Immutable specification of a window preset and its default bucket."""
    model_config = ConfigDict(frozen=True)

    preset_name: str
    duration_seconds: Optional[int] = None
    default_bucket: BucketSpec


class ResolvedBucket(BaseModel):
    """
    Immutable representation of a single timeline bucket intersecting a query interval.
    Carries full UTC grid boundaries, effective query boundaries, and partial coverage.
    """
    model_config = ConfigDict(frozen=True)

    bucket_start: datetime
    bucket_end: datetime
    effective_start: datetime
    effective_end: datetime
    is_partial: bool
    covered_seconds: float


class ResolvedTimeRange(BaseModel):
    """
    Authoritative, immutable temporal domain object for all DNSNetra analytical queries.
    Encapsulates bounded interval queries or all-time lifetime queries.
    """
    model_config = ConfigDict(frozen=True)

    start: Optional[datetime] = None
    end: Optional[datetime] = None
    resolved_now: datetime
    preset: Optional[str] = None
    bucket_spec: Optional[BucketSpec] = None
    bucket_source: Optional[BucketResolutionSource] = None
    is_all_time: bool = False
    default_policy: TemporalDefaultPolicy = TemporalDefaultPolicy.ALL_TIME

    @model_validator(mode="after")
    def _validate_state(self) -> ResolvedTimeRange:
        if self.resolved_now.tzinfo is None or self.resolved_now.tzinfo != timezone.utc:
            raise InvalidTimeRangeError("resolved_now must be timezone-aware and normalized to UTC.")

        if self.is_all_time:
            if (
                self.start is not None
                or self.end is not None
                or self.bucket_spec is not None
                or self.bucket_source is not None
            ):
                raise InvalidTimeRangeError(
                    "All-time mode requires start=None, end=None, bucket_spec=None, and bucket_source=None."
                )
        else:
            if (
                self.start is None
                or self.end is None
                or self.bucket_spec is None
                or self.bucket_source is None
            ):
                raise InvalidTimeRangeError(
                    "Bounded mode requires non-None start, end, bucket_spec, and bucket_source."
                )
            if self.start.tzinfo is None or self.start.tzinfo != timezone.utc:
                raise InvalidTimeRangeError("start must be timezone-aware and normalized to UTC.")
            if self.end.tzinfo is None or self.end.tzinfo != timezone.utc:
                raise InvalidTimeRangeError("end must be timezone-aware and normalized to UTC.")
            if self.start > self.end:
                raise InvalidTimeRangeError(
                    f"start ({self.start.isoformat()}) must be earlier than or equal to end ({self.end.isoformat()})."
                )
        return self

    @property
    def observable_end(self) -> Optional[datetime]:
        """
        Upper bound of observable historical telemetry.
        Clamped to min(end, resolved_now) so future-timestamped events are excluded.
        """
        if self.is_all_time:
            return None
        return min(self.end, self.resolved_now)

    @property
    def duration_seconds(self) -> float:
        """Returns the exact requested duration in seconds."""
        if self.is_all_time:
            raise InvalidTimeRangeError("duration_seconds is invalid for all-time queries.")
        return (self.end - self.start).total_seconds()

    @property
    def is_hour_aligned(self) -> bool:
        """Returns True if both start and end fall exactly on UTC full calendar hours."""
        if self.is_all_time:
            return False
        return (
            self.start.minute == 0
            and self.start.second == 0
            and self.start.microsecond == 0
            and self.end.minute == 0
            and self.end.second == 0
            and self.end.microsecond == 0
        )

    @property
    def is_empty(self) -> bool:
        """Returns True if the bounded range has zero duration (start == end)."""
        if self.is_all_time:
            return False
        return self.start == self.end

    def generate_buckets(self) -> List[ResolvedBucket]:
        """
        Generates the deterministic sequence of intersecting UTC grid buckets.
        Raises InvalidTimeRangeError if called in all-time mode.
        """
        if self.is_all_time:
            raise InvalidTimeRangeError("generate_buckets is invalid for all-time queries.")
        if self.is_empty:
            return []

        # Local import inside method to avoid circular import
        from .resolver import generate_resolved_buckets
        return generate_resolved_buckets(self.start, self.end, self.bucket_spec.bucket_seconds)
