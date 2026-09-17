"""
time_engine
===========
Authoritative centralized temporal engine for DNSNetra.
Provides immutable ISO-8601 parsing, UTC normalization, bucket-grid arithmetic,
exact intersecting bucket calculations, auto-bucketing, and validation.
"""

from .exceptions import (
    InvalidTimeRangeError,
    TimeEngineError,
    TimeEngineValidationError,
)
from .resolver import (
    MAX_TIMELINE_BUCKETS,
    auto_select_bucket_width,
    count_intersecting_buckets,
    format_iso8601_utc,
    generate_resolved_buckets,
    parse_and_validate_explicit_bucket,
    parse_iso8601_utc,
    resolve_time_range,
)
from .schemas import (
    BucketResolutionSource,
    BucketSpec,
    PresetSpec,
    ResolvedBucket,
    ResolvedTimeRange,
    TemporalDefaultPolicy,
    WindowPreset,
)

__all__ = [
    "TimeEngineError",
    "TimeEngineValidationError",
    "InvalidTimeRangeError",
    "MAX_TIMELINE_BUCKETS",
    "BucketResolutionSource",
    "BucketSpec",
    "PresetSpec",
    "ResolvedBucket",
    "ResolvedTimeRange",
    "TemporalDefaultPolicy",
    "WindowPreset",
    "resolve_time_range",
    "count_intersecting_buckets",
    "generate_resolved_buckets",
    "auto_select_bucket_width",
    "parse_and_validate_explicit_bucket",
    "parse_iso8601_utc",
    "format_iso8601_utc",
]
