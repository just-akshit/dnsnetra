"""
time_engine/resolver.py
=======================
Authoritative temporal resolver, parsing, bucket-grid arithmetic,
and auto-bucketing algorithm for DNSNetra.
"""

from __future__ import annotations

import math
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from .exceptions import InvalidTimeRangeError, TimeEngineValidationError
from .schemas import (
    BucketResolutionSource,
    BucketSpec,
    PresetSpec,
    ResolvedBucket,
    ResolvedTimeRange,
    TemporalDefaultPolicy,
    WindowPreset,
)

MAX_TIMELINE_BUCKETS = 100

EPOCH_UTC = datetime(1970, 1, 1, tzinfo=timezone.utc)
# Thursday Jan 1 1970 was Unix epoch. Monday Jan 5 1970 00:00:00 UTC was 4 days later:
WEEK_ANCHOR_US = 4 * 86400 * 1_000_000

# Canonical supported explicit bucket widths (frozen set of 16)
CANONICAL_BUCKET_WIDTHS: Dict[str, int] = {
    "1s": 1,
    "5s": 5,
    "10s": 10,
    "30s": 30,
    "1m": 60,
    "5m": 300,
    "10m": 600,
    "15m": 900,
    "30m": 1800,
    "1h": 3600,
    "2h": 7200,
    "3h": 10800,
    "6h": 21600,
    "12h": 43200,
    "1d": 86400,
    "1w": 604800,
}

# Reverse mapping from seconds to label for standard widths
SECONDS_TO_LABEL: Dict[int, str] = {v: k for k, v in CANONICAL_BUCKET_WIDTHS.items()}

# Candidate widths for auto-bucketing in strictly ascending order
AUTO_BUCKET_CANDIDATES: List[int] = [
    1, 5, 10, 30, 60, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400, 604800
]

# Authoritative, immutable preset registry mapping window names to PresetSpec
PRESET_REGISTRY: Dict[str, PresetSpec] = {
    "15m": PresetSpec(
        preset_name="15m",
        duration_seconds=900,
        default_bucket=BucketSpec(bucket_seconds=60, bucket_label="1m"),
    ),
    "1h": PresetSpec(
        preset_name="1h",
        duration_seconds=3600,
        default_bucket=BucketSpec(bucket_seconds=300, bucket_label="5m"),
    ),
    "6h": PresetSpec(
        preset_name="6h",
        duration_seconds=21600,
        default_bucket=BucketSpec(bucket_seconds=900, bucket_label="15m"),
    ),
    "24h": PresetSpec(
        preset_name="24h",
        duration_seconds=86400,
        default_bucket=BucketSpec(bucket_seconds=3600, bucket_label="1h"),
    ),
    "7d": PresetSpec(
        preset_name="7d",
        duration_seconds=604800,
        default_bucket=BucketSpec(bucket_seconds=21600, bucket_label="6h"),
    ),
    "30d": PresetSpec(
        preset_name="30d",
        duration_seconds=2592000,
        default_bucket=BucketSpec(bucket_seconds=86400, bucket_label="1d"),
    ),
    "today": PresetSpec(
        preset_name="today",
        duration_seconds=None,
        default_bucket=BucketSpec(bucket_seconds=3600, bucket_label="1h"),
    ),
    "yesterday": PresetSpec(
        preset_name="yesterday",
        duration_seconds=None,
        default_bucket=BucketSpec(bucket_seconds=3600, bucket_label="1h"),
    ),
}

# Derived mapping of rolling presets (those with fixed durations)
ROLLING_PRESETS: Dict[str, PresetSpec] = {
    k: v for k, v in PRESET_REGISTRY.items() if v.duration_seconds is not None
}


# ---------------------------------------------------------------------------
# Exact Integer Microsecond Epoch Helpers
# ---------------------------------------------------------------------------

def dt_to_epoch_us(dt: datetime) -> int:
    """Converts a timezone-aware UTC datetime to exact integer microseconds from Unix epoch."""
    if dt.tzinfo is None:
        raise TimeEngineValidationError(f"Cannot calculate epoch for naive datetime: {dt!r}")
    dt_utc = dt.astimezone(timezone.utc)
    delta = dt_utc - EPOCH_UTC
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def epoch_us_to_dt(us: int) -> datetime:
    """Converts exact integer microseconds from Unix epoch to a timezone-aware UTC datetime."""
    days, rem = divmod(us, 86400 * 1_000_000)
    secs, microsecs = divmod(rem, 1_000_000)
    return EPOCH_UTC + timedelta(days=days, seconds=secs, microseconds=microsecs)


# ---------------------------------------------------------------------------
# ISO-8601 Parsing and Formatting
# ---------------------------------------------------------------------------

def parse_iso8601_utc(ts: Union[str, datetime]) -> datetime:
    """
    Parses an ISO-8601 string or validates a datetime object.
    Strictly enforces timezone awareness and normalizes immediately to UTC.
    Naive datetimes or missing timezone offsets are strictly rejected.
    """
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            raise TimeEngineValidationError(
                f"Naive datetime {ts!r} is not allowed. All timestamps must be timezone-aware."
            )
        return ts.astimezone(timezone.utc)

    if not isinstance(ts, str) or not ts.strip():
        raise TimeEngineValidationError(f"Timestamp must be a non-empty string. Received: {ts!r}")

    cleaned = ts.strip()
    try:
        dt = datetime.fromisoformat(cleaned)
    except Exception as exc:
        raise TimeEngineValidationError(f"Invalid ISO-8601 timestamp string '{cleaned}': {exc}") from exc

    if dt.tzinfo is None:
        raise TimeEngineValidationError(
            f"Timestamp '{cleaned}' is missing a timezone offset. "
            "All timestamps must explicitly specify UTC ('Z') or an explicit offset (e.g. '+00:00', '+05:30')."
        )
    return dt.astimezone(timezone.utc)


def format_iso8601_utc(dt: datetime) -> str:
    """
    Serializes a timezone-aware datetime as a canonical UTC string with trailing 'Z'.
    Preserves microsecond precision when non-zero.
    """
    if dt.tzinfo is None:
        raise TimeEngineValidationError(f"Cannot format naive datetime: {dt!r}")
    dt_utc = dt.astimezone(timezone.utc)
    if dt_utc.microsecond == 0:
        return dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ---------------------------------------------------------------------------
# Exact Intersecting Bucket Counting & Generation
# ---------------------------------------------------------------------------

def count_intersecting_buckets(start: datetime, end: datetime, width_seconds: int) -> int:
    """
    Calculates the exact number of UTC calendar/epoch-grid buckets of width width_seconds
    that have a non-empty intersection with the half-open interval [start, end).
    Uses exact integer microsecond arithmetic.
    """
    if start >= end:
        return 0

    w_us = width_seconds * 1_000_000
    start_us = dt_to_epoch_us(start)
    # The half-open interval [start, end) includes up to end - 1 microsecond:
    last_us = dt_to_epoch_us(end) - 1

    # Week buckets align to Monday 00:00:00 UTC
    anchor = WEEK_ANCHOR_US if width_seconds == 604800 else 0

    first_bucket_idx = (start_us - anchor) // w_us
    last_bucket_idx = (last_us - anchor) // w_us

    return int(last_bucket_idx - first_bucket_idx + 1)


def generate_resolved_buckets(start: datetime, end: datetime, width_seconds: int) -> List[ResolvedBucket]:
    """
    Generates the complete, deterministic list of intersecting ResolvedBucket instances
    spanning [start, end) on the canonical UTC grid.
    """
    if start >= end:
        return []

    w_us = width_seconds * 1_000_000
    start_us = dt_to_epoch_us(start)
    last_us = dt_to_epoch_us(end) - 1

    anchor = WEEK_ANCHOR_US if width_seconds == 604800 else 0

    first_bucket_idx = (start_us - anchor) // w_us
    last_bucket_idx = (last_us - anchor) // w_us

    buckets: List[ResolvedBucket] = []
    for idx in range(first_bucket_idx, last_bucket_idx + 1):
        b_start_us = anchor + idx * w_us
        b_end_us = b_start_us + w_us

        b_start = epoch_us_to_dt(b_start_us)
        b_end = epoch_us_to_dt(b_end_us)

        eff_start = max(b_start, start)
        eff_end = min(b_end, end)

        is_partial = (eff_start != b_start) or (eff_end != b_end)
        covered_sec = (eff_end - eff_start).total_seconds()

        buckets.append(
            ResolvedBucket(
                bucket_start=b_start,
                bucket_end=b_end,
                effective_start=eff_start,
                effective_end=eff_end,
                is_partial=is_partial,
                covered_seconds=covered_sec,
            )
        )

    return buckets


# ---------------------------------------------------------------------------
# Sizing and Validation Strategies
# ---------------------------------------------------------------------------

def auto_select_bucket_width(start: datetime, end: datetime) -> BucketSpec:
    """
    Selects the optimal bucket width for [start, end) by finding the smallest
    candidate width whose exact intersecting bucket count satisfies N <= MAX_TIMELINE_BUCKETS (100).
    Guarantees N <= 100 for all valid intervals.
    """
    if start >= end:
        return BucketSpec(bucket_seconds=3600, bucket_label="1h")

    for w in AUTO_BUCKET_CANDIDATES:
        if count_intersecting_buckets(start, end, w) <= MAX_TIMELINE_BUCKETS:
            return BucketSpec(bucket_seconds=w, bucket_label=SECONDS_TO_LABEL[w])

    # Fallback for ranges > 700 weeks (~13.4 years):
    duration_sec = (end - start).total_seconds()
    days = max(8, math.ceil(duration_sec / (MAX_TIMELINE_BUCKETS * 86400)))
    while count_intersecting_buckets(start, end, days * 86400) > MAX_TIMELINE_BUCKETS:
        days += 1

    return BucketSpec(bucket_seconds=days * 86400, bucket_label=f"{days}d")


def parse_and_validate_explicit_bucket(
    bucket_str: str, start: datetime, end: datetime
) -> BucketSpec:
    """
    Validates an explicitly requested bucket width against the canonical set.
    Rejects unsupported formats or requests yielding N > MAX_TIMELINE_BUCKETS.
    Never silently auto-widens explicit requests.
    """
    if not bucket_str or not isinstance(bucket_str, str) or not bucket_str.strip():
        raise TimeEngineValidationError(
            f"Explicit bucket width must be a non-empty string. Received: {bucket_str!r}"
        )

    clean_b = bucket_str.strip().lower()
    if clean_b not in CANONICAL_BUCKET_WIDTHS:
        valid_opts = ", ".join(CANONICAL_BUCKET_WIDTHS.keys())
        raise TimeEngineValidationError(
            f"Invalid bucket width '{bucket_str}'. Supported bucket widths are: {valid_opts}."
        )

    b_sec = CANONICAL_BUCKET_WIDTHS[clean_b]
    n_buckets = count_intersecting_buckets(start, end, b_sec)
    if n_buckets > MAX_TIMELINE_BUCKETS:
        raise InvalidTimeRangeError(
            f"Requested bucket width '{clean_b}' over duration {(end - start).total_seconds():.0f}s "
            f"produces {n_buckets} intersecting buckets, exceeding the maximum allowed limit of {MAX_TIMELINE_BUCKETS}. "
            "Choose a coarser bucket width or a shorter time range."
        )

    return BucketSpec(bucket_seconds=b_sec, bucket_label=clean_b)


# ---------------------------------------------------------------------------
# Core Public Resolver API
# ---------------------------------------------------------------------------

def resolve_time_range(
    window: Optional[str] = None,
    start_time: Optional[Union[str, datetime]] = None,
    end_time: Optional[Union[str, datetime]] = None,
    bucket: Optional[str] = None,
    default_policy: TemporalDefaultPolicy = TemporalDefaultPolicy.ALL_TIME,
    now_override: Optional[Union[str, datetime]] = None,
) -> ResolvedTimeRange:
    """
    Authoritative resolution entry point for all DNSNetra analytical queries.
    Parses, normalizes, validates, and freezes input into an immutable ResolvedTimeRange.
    """
    # 1. Resolve request-level server now (frozen instant)
    if now_override is not None:
        resolved_now = parse_iso8601_utc(now_override)
    else:
        resolved_now = datetime.now(timezone.utc)

    if window is not None and not window.strip():
        raise TimeEngineValidationError("Window preset cannot be an empty or whitespace string.")

    has_window = bool(window and window.strip())
    has_start = start_time is not None and (
        not isinstance(start_time, str) or bool(start_time.strip())
    )
    has_end = end_time is not None and (not isinstance(end_time, str) or bool(end_time.strip()))

    # 2. Parameter Mutual Exclusivity Validation
    if has_window and (has_start or has_end):
        raise TimeEngineValidationError(
            "Cannot specify both 'window' preset and custom 'start_time'/'end_time' parameters."
        )

    if has_start != has_end:
        raise TimeEngineValidationError(
            "Both 'start_time' and 'end_time' must be provided for a custom time range."
        )

    # 3. Case A: No temporal parameters provided (Apply default policy)
    if not has_window and not has_start and not has_end:
        if bucket is not None and bucket.strip():
            raise TimeEngineValidationError("Bucket width cannot be specified without a time range.")

        if default_policy == TemporalDefaultPolicy.ALL_TIME:
            return ResolvedTimeRange(
                is_all_time=True,
                resolved_now=resolved_now,
                default_policy=default_policy,
                bucket_source=None,
            )
        elif default_policy == TemporalDefaultPolicy.ROLLING_24H:
            # Fall through to resolve "24h" preset
            has_window = True
            window = "24h"
        else:
            raise TimeEngineValidationError(f"Unknown default policy: {default_policy!r}")

    # 4. Case B: Preset Window (Rolling or Calendar)
    if has_window:
        norm_preset = window.strip().lower()

        if norm_preset not in PRESET_REGISTRY:
            supported_rolling = ", ".join(ROLLING_PRESETS.keys())
            raise TimeEngineValidationError(
                f"Invalid window preset '{window}'. Supported rolling presets: {supported_rolling}; "
                "calendar presets: today, yesterday."
            )

        preset_spec = PRESET_REGISTRY[norm_preset]
        default_bucket = preset_spec.default_bucket

        if preset_spec.duration_seconds is not None:
            duration = timedelta(seconds=preset_spec.duration_seconds)
            start_dt = resolved_now - duration
            end_dt = resolved_now
        elif norm_preset == WindowPreset.TODAY.value:
            today_midnight = resolved_now.replace(hour=0, minute=0, second=0, microsecond=0)
            start_dt = today_midnight
            end_dt = today_midnight + timedelta(days=1)
        elif norm_preset == WindowPreset.YESTERDAY.value:
            today_midnight = resolved_now.replace(hour=0, minute=0, second=0, microsecond=0)
            start_dt = today_midnight - timedelta(days=1)
            end_dt = today_midnight
        else:
            raise TimeEngineValidationError(f"Unhandled preset: {norm_preset}")

        # Bucket width resolution (explicit overrides preset default)
        if bucket is not None and bucket.strip():
            b_spec = parse_and_validate_explicit_bucket(bucket, start_dt, end_dt)
            b_source = BucketResolutionSource.EXPLICIT
        else:
            b_spec = default_bucket
            b_source = BucketResolutionSource.PRESET_DEFAULT

        return ResolvedTimeRange(
            start=start_dt,
            end=end_dt,
            resolved_now=resolved_now,
            preset=norm_preset,
            bucket_spec=b_spec,
            bucket_source=b_source,
            is_all_time=False,
            default_policy=default_policy,
        )

    # 5. Case C: Custom Time Range
    start_dt = parse_iso8601_utc(start_time)
    end_dt = parse_iso8601_utc(end_time)

    if start_dt > end_dt:
        raise InvalidTimeRangeError(
            f"start_time ({format_iso8601_utc(start_dt)}) must be earlier than or equal to "
            f"end_time ({format_iso8601_utc(end_dt)})."
        )

    # Future range validation policy
    if start_dt >= resolved_now:
        raise InvalidTimeRangeError(
            f"Requested time range is entirely in the future: start_time ({format_iso8601_utc(start_dt)}) "
            f">= current server time ({format_iso8601_utc(resolved_now)})."
        )

    # Zero-length range (start == end)
    if start_dt == end_dt:
        if bucket is not None and bucket.strip():
            b_spec = parse_and_validate_explicit_bucket(bucket, start_dt, end_dt)
            b_source = BucketResolutionSource.EXPLICIT
        else:
            b_spec = BucketSpec(bucket_seconds=3600, bucket_label="1h")
            b_source = BucketResolutionSource.AUTO
        return ResolvedTimeRange(
            start=start_dt,
            end=end_dt,
            resolved_now=resolved_now,
            preset=None,
            bucket_spec=b_spec,
            bucket_source=b_source,
            is_all_time=False,
            default_policy=default_policy,
        )

    # Bucket width resolution for custom range
    if bucket is not None and bucket.strip():
        b_spec = parse_and_validate_explicit_bucket(bucket, start_dt, end_dt)
        b_source = BucketResolutionSource.EXPLICIT
    else:
        b_spec = auto_select_bucket_width(start_dt, end_dt)
        b_source = BucketResolutionSource.AUTO

    return ResolvedTimeRange(
        start=start_dt,
        end=end_dt,
        resolved_now=resolved_now,
        preset=None,
        bucket_spec=b_spec,
        bucket_source=b_source,
        is_all_time=False,
        default_policy=default_policy,
    )
