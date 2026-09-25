"""
Time Window Resolver & Sizing Strategy
=======================================
Provides validation, normalization, and deterministic bucket resolution
for rolling presets and custom ISO8601 UTC time windows.

Guarantees:
- Canonical half-open intervals: [start, end)
- Server-side UTC consistency
- Timeline bucket count strictly <= MAX_TIMELINE_BUCKETS (100)
- Maximum historical duration <= MAX_HISTORY_DAYS (30 days)
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import List, Optional, Tuple, Union


MAX_HISTORY_DAYS = 730  # 2 years to cleanly support 6mo (180d) and 1y (365d)
MAX_HISTORY_MINUTES = MAX_HISTORY_DAYS * 24 * 60  # 1,051,200 minutes
MAX_TIMELINE_BUCKETS = 100


class WindowPreset(str, Enum):
    """Supported rolling window presets."""
    M1 = "1m"
    M5 = "5m"
    M10 = "10m"
    M15 = "15m"
    M30 = "30m"
    M45 = "45m"
    M60 = "60m"
    H1 = "1h"
    H6 = "6h"
    H12 = "12h"
    H24 = "24h"
    D7 = "7d"
    D30 = "30d"
    M6 = "6mo"
    M6_ALT = "6m"
    Y1 = "1y"


PRESET_CONFIG = {
    WindowPreset.M1: {"minutes": 1, "bucket_seconds": 10},        # 6 buckets (10s)
    WindowPreset.M5: {"minutes": 5, "bucket_seconds": 60},        # 5 buckets (1m)
    WindowPreset.M10: {"minutes": 10, "bucket_seconds": 60},      # 10 buckets (1m)
    WindowPreset.M15: {"minutes": 15, "bucket_seconds": 60},      # 15 buckets (1m)
    WindowPreset.M30: {"minutes": 30, "bucket_seconds": 120},     # 15 buckets (2m)
    WindowPreset.M45: {"minutes": 45, "bucket_seconds": 180},     # 15 buckets (3m)
    WindowPreset.M60: {"minutes": 60, "bucket_seconds": 300},     # 12 buckets (5m)
    WindowPreset.H1: {"minutes": 60, "bucket_seconds": 300},      # 12 buckets (5m)
    WindowPreset.H6: {"minutes": 360, "bucket_seconds": 900},     # 24 buckets (15m)
    WindowPreset.H12: {"minutes": 720, "bucket_seconds": 1800},   # 24 buckets (30m)
    WindowPreset.H24: {"minutes": 1440, "bucket_seconds": 3600},  # 24 buckets (1h)
    WindowPreset.D7: {"minutes": 10080, "bucket_seconds": 21600}, # 28 buckets (6h)
    WindowPreset.D30: {"minutes": 43200, "bucket_seconds": 86400},# 30 buckets (1d)
    # Rolling 180 days for 6-month analysis
    WindowPreset.M6: {"minutes": 259200, "bucket_seconds": 604800},   # ~26 buckets (1w)
    WindowPreset.M6_ALT: {"minutes": 259200, "bucket_seconds": 604800},
    # Rolling 365 days for 1-year analysis
    WindowPreset.Y1: {"minutes": 525600, "bucket_seconds": 604800},   # ~52 buckets (1w)
}

# Standard human-friendly bucket intervals (in seconds)
CANDIDATE_BUCKET_INTERVALS = [
    10,      # 10 sec
    15,      # 15 sec
    30,      # 30 sec
    60,      # 1 min
    120,     # 2 min
    180,     # 3 min
    300,     # 5 min
    600,     # 10 min
    900,     # 15 min
    1200,    # 20 min
    1800,    # 30 min
    3600,    # 1 hour
    7200,    # 2 hours
    10800,   # 3 hours
    14400,   # 4 hours
    21600,   # 6 hours
    28800,   # 8 hours
    43200,   # 12 hours
    86400,   # 24 hours (1 day)
    172800,  # 2 days
    604800,  # 7 days (1 week)
    1209600, # 14 days (2 weeks)
    2592000, # 30 days (1 month)
]


def parse_iso8601_utc(ts_str: str) -> datetime:
    """
    Parses an ISO8601 timestamp string and ensures it is timezone-aware in UTC.
    Accepts formats such as:
      - 2026-08-24T00:00:00Z
      - 2026-08-24T00:00:00+00:00
      - 2026-08-24T05:30:00+05:30
      - 2026-08-24 00:00:00
    """
    if not ts_str or not isinstance(ts_str, str):
        raise ValueError("Timestamp must be a non-empty string.")

    cleaned = ts_str.strip()
    # Replace trailing 'Z' or 'z' with '+00:00' for fromisoformat compatibility
    if cleaned.endswith("Z") or cleaned.endswith("z"):
        cleaned = cleaned[:-1] + "+00:00"

    try:
        dt = datetime.fromisoformat(cleaned)
    except Exception as exc:
        raise ValueError(f"Invalid ISO8601 timestamp '{ts_str}': {exc}") from exc

    if dt.tzinfo is None:
        # Naive datetime is treated as UTC
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        # Convert any other timezone to UTC
        dt = dt.astimezone(timezone.utc)

    return dt


def format_iso8601_utc(dt: datetime) -> str:
    """Formats a datetime as UTC ISO8601 string with trailing 'Z'."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_optimal_bucket_seconds(duration_seconds: float) -> int:
    """
    Calculates the optimal bucket interval in seconds for a given duration,
    strictly guaranteeing that total_buckets <= MAX_TIMELINE_BUCKETS (100).
    Tuned for chart visual quality and human-friendly intervals.
    """
    if duration_seconds <= 0:
        return 60

    min_required_bucket = math.ceil(duration_seconds / MAX_TIMELINE_BUCKETS)

    # Prefer visualization-friendly scales based on range duration
    if duration_seconds <= 90:             # <= 1.5 min
        preferred = 10                     # 10s buckets
    elif duration_seconds <= 5 * 60:        # <= 5 min
        preferred = 60                     # 1m buckets
    elif duration_seconds <= 15 * 60:       # <= 15 min
        preferred = 60                     # 1m buckets
    elif duration_seconds <= 30 * 60:       # <= 30 min
        preferred = 120                    # 2m buckets
    elif duration_seconds <= 60 * 60:       # <= 1 hour
        preferred = 300                    # 5m buckets
    elif duration_seconds <= 5 * 3600:      # <= 5 hours
        preferred = 900                    # 15m buckets
    elif duration_seconds <= 12 * 3600:     # <= 12 hours
        preferred = 1800                   # 30m buckets
    elif duration_seconds <= 24 * 3600:     # <= 24 hours
        preferred = 3600                   # 1 hour buckets
    elif duration_seconds <= 7 * 86400:     # <= 7 days
        preferred = 21600                  # 6 hour buckets
    elif duration_seconds <= 30 * 86400:    # <= 30 days
        preferred = 86400                  # 1 day buckets
    elif duration_seconds <= 180 * 86400:   # <= 180 days (6 months)
        preferred = 604800                 # 1 week buckets (~26 buckets)
    else:                                   # > 180 days (up to 1-2 years)
        preferred = 604800                 # 1 week buckets (52 buckets for 1 year)

    chosen = max(preferred, min_required_bucket)

    # Find the smallest human-friendly candidate >= chosen
    for candidate in CANDIDATE_BUCKET_INTERVALS:
        if candidate >= chosen:
            chosen = candidate
            break
    else:
        # If larger than largest candidate, round up to whole days
        chosen = math.ceil(chosen / 86400) * 86400

    # Hard invariant assertion: must be <= MAX_TIMELINE_BUCKETS
    while math.ceil(duration_seconds / chosen) > MAX_TIMELINE_BUCKETS:
        chosen += 60

    return chosen


@dataclass(frozen=True)
class TimeWindow:
    """
    Immutable representation of an active half-open time window [start, end).
    """
    start: datetime
    end: datetime
    bucket_seconds: int
    preset: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        return (self.end - self.start).total_seconds()

    @property
    def duration_minutes(self) -> float:
        return round(self.duration_seconds / 60.0, 2)

    @property
    def start_iso(self) -> str:
        return format_iso8601_utc(self.start)

    @property
    def end_iso(self) -> str:
        return format_iso8601_utc(self.end)

    @property
    def bucket_count(self) -> int:
        if self.duration_seconds <= 0 or self.bucket_seconds <= 0:
            return 0
        return math.ceil(self.duration_seconds / self.bucket_seconds)

    def generate_bucket_timestamps(self) -> List[datetime]:
        """
        Generates the deterministic sequence of UTC bucket start timestamps
        spanning the half-open interval [start, end).
        """
        if self.duration_seconds <= 0 or self.bucket_seconds <= 0:
            return []

        # Floor start to nearest bucket boundary based on epoch for determinism
        start_epoch = math.floor(self.start.timestamp() / self.bucket_seconds) * self.bucket_seconds
        end_epoch = self.end.timestamp()

        buckets: List[datetime] = []
        current_epoch = start_epoch

        # Generate bucket start times while bucket_start < end
        while current_epoch < end_epoch:
            b_dt = datetime.fromtimestamp(current_epoch, tz=timezone.utc)
            buckets.append(b_dt)
            current_epoch += self.bucket_seconds
            if len(buckets) >= MAX_TIMELINE_BUCKETS:
                break

        return buckets


def resolve_time_window(
    window: Optional[str] = None,
    start: Optional[Union[str, datetime]] = None,
    end: Optional[Union[str, datetime]] = None,
    now_override: Optional[datetime] = None,
) -> TimeWindow:
    """
    Resolves and validates a time window specification into an immutable TimeWindow.
    
    Precedence:
      custom start/end > preset window
      
    Accepts:
      - window: preset string ('1m', '5m', '15m', '30m', '1h', '6h', '12h', '24h', '7d', '30d', '6mo', '1y')
      - or start and end: ISO8601 strings or datetimes.
      
    Raises ValueError with actionable messages if arguments are invalid.
    """
    server_now = now_override or datetime.now(timezone.utc)
    if server_now.tzinfo is None:
        server_now = server_now.replace(tzinfo=timezone.utc)

    has_window = bool(window and window.strip())
    has_start = start is not None and (not isinstance(start, str) or bool(start.strip()))
    has_end = end is not None and (not isinstance(end, str) or bool(end.strip()))

    if has_window and (has_start or has_end):
        raise ValueError("Cannot specify both 'window' preset and custom 'start'/'end' parameters.")

    if not has_window and not (has_start and has_end):
        if has_start and not has_end:
            raise ValueError("Both 'start' and 'end' must be provided for a custom time range.")
        if has_end and not has_start:
            raise ValueError("Both 'start' and 'end' must be provided for a custom time range.")
        raise ValueError("Must provide either a 'window' preset (e.g. '15m') or custom 'start' and 'end' timestamps.")

    if has_window:
        norm_preset = window.strip().lower()
        try:
            preset_enum = WindowPreset(norm_preset)
        except ValueError as exc:
            valid_options = ", ".join(p.value for p in WindowPreset)
            raise ValueError(f"Invalid window preset '{window}'. Supported options: {valid_options}") from exc

        cfg = PRESET_CONFIG[preset_enum]
        mins = cfg["minutes"]
        bucket_sec = cfg["bucket_seconds"]

        end_dt = server_now
        start_dt = end_dt - timedelta(minutes=mins)

        return TimeWindow(
            start=start_dt,
            end=end_dt,
            bucket_seconds=bucket_sec,
            preset=norm_preset,
        )

    # Custom range resolution
    start_dt = parse_iso8601_utc(start) if isinstance(start, str) else start
    end_dt = parse_iso8601_utc(end) if isinstance(end, str) else end

    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=timezone.utc)
    else:
        start_dt = start_dt.astimezone(timezone.utc)

    if end_dt.tzinfo is None:
        end_dt = end_dt.replace(tzinfo=timezone.utc)
    else:
        end_dt = end_dt.astimezone(timezone.utc)

    # Range order check
    if start_dt >= end_dt:
        raise ValueError(
            f"Invalid range: start timestamp ({format_iso8601_utc(start_dt)}) "
            f"must be strictly before end timestamp ({format_iso8601_utc(end_dt)})."
        )

    duration_sec = (end_dt - start_dt).total_seconds()
    duration_min = duration_sec / 60.0

    # Max range check
    if duration_min > MAX_HISTORY_MINUTES:
        raise ValueError(
            f"Requested time range ({duration_min:.1f} minutes) exceeds the maximum "
            f"supported historical range of {MAX_HISTORY_DAYS} days ({MAX_HISTORY_MINUTES} minutes)."
        )

    bucket_sec = compute_optimal_bucket_seconds(duration_sec)

    return TimeWindow(
        start=start_dt,
        end=end_dt,
        bucket_seconds=bucket_sec,
        preset=None,
    )
