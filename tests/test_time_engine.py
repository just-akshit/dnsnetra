"""
tests/test_time_engine.py
=========================
Exhaustive verification of the DNSNetra Centralized Temporal Engine.
Tests all mathematical invariants, edge cases, canonical presets, explicit bucket validation,
auto-bucketing minimality, coverage conservation, and future range semantics.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
import pytest

from time_engine import (
    BucketSpec,
    InvalidTimeRangeError,
    MAX_TIMELINE_BUCKETS,
    ResolvedBucket,
    ResolvedTimeRange,
    TemporalDefaultPolicy,
    TimeEngineValidationError,
    WindowPreset,
    auto_select_bucket_width,
    count_intersecting_buckets,
    format_iso8601_utc,
    generate_resolved_buckets,
    parse_and_validate_explicit_bucket,
    parse_iso8601_utc,
    resolve_time_range,
)
from time_engine.resolver import (
    AUTO_BUCKET_CANDIDATES,
    CANONICAL_BUCKET_WIDTHS,
    dt_to_epoch_us,
    epoch_us_to_dt,
)


# ===========================================================================
# 1. ISO-8601 Parsing, Serialization, and Normalization
# ===========================================================================

class TestISO8601ParsingAndNormalization:
    """Verifies strict timezone requirements, UTC normalization, and microsecond fidelity."""

    def test_parse_valid_utc_z(self):
        dt = parse_iso8601_utc("2026-09-16T12:00:00Z")
        assert dt == datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        assert dt.tzinfo == timezone.utc

    def test_parse_valid_positive_offset(self):
        # 17:30 +05:30 -> 12:00 UTC
        dt = parse_iso8601_utc("2026-09-16T17:30:00+05:30")
        assert dt == datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        assert dt.tzinfo == timezone.utc

    def test_parse_valid_negative_offset(self):
        # 08:00 -04:00 -> 12:00 UTC
        dt = parse_iso8601_utc("2026-09-16T08:00:00-04:00")
        assert dt == datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        assert dt.tzinfo == timezone.utc

    def test_reject_naive_timestamp_string(self):
        with pytest.raises(TimeEngineValidationError) as exc:
            parse_iso8601_utc("2026-09-16T12:00:00")
        assert "missing a timezone offset" in str(exc.value)

    def test_reject_naive_datetime_object(self):
        naive_dt = datetime(2026, 9, 16, 12, 0, 0)
        with pytest.raises(TimeEngineValidationError) as exc:
            parse_iso8601_utc(naive_dt)
        assert "Naive datetime" in str(exc.value)

    def test_reject_empty_or_malformed_string(self):
        with pytest.raises(TimeEngineValidationError):
            parse_iso8601_utc("")
        with pytest.raises(TimeEngineValidationError):
            parse_iso8601_utc("   ")
        with pytest.raises(TimeEngineValidationError):
            parse_iso8601_utc("not-a-timestamp")

    def test_microsecond_preservation(self):
        ts_str = "2026-09-16T12:00:00.123456Z"
        dt = parse_iso8601_utc(ts_str)
        assert dt.microsecond == 123456
        formatted = format_iso8601_utc(dt)
        assert formatted == "2026-09-16T12:00:00.123456Z"

    def test_canonical_serialization_zero_microseconds(self):
        dt = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        formatted = format_iso8601_utc(dt)
        assert formatted == "2026-09-16T12:00:00Z"

    def test_epoch_microsecond_converters(self):
        dt = datetime(2026, 9, 16, 12, 34, 56, 789012, tzinfo=timezone.utc)
        us = dt_to_epoch_us(dt)
        assert us > 0
        reconstructed = epoch_us_to_dt(us)
        assert reconstructed == dt


# ===========================================================================
# 2. Interval Semantics, Disjointness, and Boundaries
# ===========================================================================

class TestIntervalSemanticsAndInvariants:
    """Verifies [start, end) half-open semantics, empty ranges, and inverted ranges."""

    def test_valid_start_earlier_than_end(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(
            start_time="2026-09-16T10:00:00Z",
            end_time="2026-09-16T11:00:00Z",
            now_override=now,
        )
        assert tr.start == datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)
        assert tr.end == datetime(2026, 9, 16, 11, 0, 0, tzinfo=timezone.utc)
        assert tr.duration_seconds == 3600.0
        assert tr.is_empty is False

    def test_valid_empty_range_start_equals_end(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(
            start_time="2026-09-16T10:00:00Z",
            end_time="2026-09-16T10:00:00Z",
            now_override=now,
        )
        assert tr.is_empty is True
        assert tr.duration_seconds == 0.0
        assert tr.generate_buckets() == []

    def test_inverted_range_rejected(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(InvalidTimeRangeError) as exc:
            resolve_time_range(
                start_time="2026-09-16T11:00:00Z",
                end_time="2026-09-16T10:00:00Z",
                now_override=now,
            )
        assert "must be earlier than or equal to end_time" in str(exc.value)

    def test_adjacent_disjoint_windows(self):
        # [10:00, 11:00) and [11:00, 12:00)
        t_event = datetime(2026, 9, 16, 11, 0, 0, tzinfo=timezone.utc)
        w1_start = datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)
        w1_end = datetime(2026, 9, 16, 11, 0, 0, tzinfo=timezone.utc)

        w2_start = datetime(2026, 9, 16, 11, 0, 0, tzinfo=timezone.utc)
        w2_end = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)

        # In [start, end), w1 contains start <= t < end
        in_w1 = (w1_start <= t_event < w1_end)
        in_w2 = (w2_start <= t_event < w2_end)
        assert in_w1 is False
        assert in_w2 is True


# ===========================================================================
# 3. Now Resolution
# ===========================================================================

class TestNowResolution:
    """Verifies that resolved_now is frozen once per request."""

    def test_now_override_frozen(self):
        frozen_instant = datetime(2026, 9, 16, 15, 30, 45, tzinfo=timezone.utc)
        tr = resolve_time_range(window="1h", now_override=frozen_instant)
        assert tr.resolved_now == frozen_instant
        assert tr.end == frozen_instant
        assert tr.start == frozen_instant - timedelta(hours=1)


# ===========================================================================
# 4. Rolling Presets
# ===========================================================================

class TestRollingPresets:
    """Verifies canonical rolling presets and default bucket widths."""

    @pytest.mark.parametrize(
        "preset,expected_duration,expected_bucket_label,expected_bucket_sec",
        [
            ("15m", timedelta(minutes=15), "1m", 60),
            ("1h", timedelta(hours=1), "5m", 300),
            ("6h", timedelta(hours=6), "15m", 900),
            ("24h", timedelta(hours=24), "1h", 3600),
            ("7d", timedelta(days=7), "6h", 21600),
            ("30d", timedelta(days=30), "1d", 86400),
        ],
    )
    def test_canonical_rolling_presets(
        self, preset, expected_duration, expected_bucket_label, expected_bucket_sec
    ):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(window=preset, now_override=now)
        assert tr.end == now
        assert tr.start == now - expected_duration
        assert tr.duration_seconds == expected_duration.total_seconds()
        assert tr.bucket_spec.bucket_label == expected_bucket_label
        assert tr.bucket_spec.bucket_seconds == expected_bucket_sec

    @pytest.mark.parametrize("invalid_preset", ["60m", "6m", "45m", "90m", "1w", "unknown", ""])
    def test_reject_invalid_rolling_presets(self, invalid_preset):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(TimeEngineValidationError):
            resolve_time_range(window=invalid_preset, now_override=now)


# ===========================================================================
# 5. Calendar Presets
# ===========================================================================

class TestCalendarPresets:
    """Verifies today and yesterday UTC calendar windows."""

    def test_today_preset(self):
        now = datetime(2026, 9, 16, 15, 30, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(window="today", now_override=now)
        assert tr.start == datetime(2026, 9, 16, 0, 0, 0, tzinfo=timezone.utc)
        assert tr.end == datetime(2026, 9, 17, 0, 0, 0, tzinfo=timezone.utc)
        assert tr.bucket_spec.bucket_label == "1h"
        assert tr.bucket_spec.bucket_seconds == 3600
        # Partially future: observable_end clamped to now
        assert tr.observable_end == now

    def test_yesterday_preset(self):
        now = datetime(2026, 9, 16, 15, 30, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(window="yesterday", now_override=now)
        assert tr.start == datetime(2026, 9, 15, 0, 0, 0, tzinfo=timezone.utc)
        assert tr.end == datetime(2026, 9, 16, 0, 0, 0, tzinfo=timezone.utc)
        assert tr.bucket_spec.bucket_label == "1h"
        assert tr.bucket_spec.bucket_seconds == 3600
        # Entirely historical: observable_end is end
        assert tr.observable_end == tr.end


# ===========================================================================
# 6. Centralized Default Policies
# ===========================================================================

class TestDefaultPolicies:
    """Verifies default behavior when temporal parameters are omitted."""

    def test_default_policy_all_time(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(default_policy=TemporalDefaultPolicy.ALL_TIME, now_override=now)
        assert tr.is_all_time is True
        assert tr.start is None
        assert tr.end is None
        assert tr.bucket_spec is None
        assert tr.preset is None
        assert tr.observable_end is None

    def test_default_policy_rolling_24h(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(default_policy=TemporalDefaultPolicy.ROLLING_24H, now_override=now)
        assert tr.is_all_time is False
        assert tr.preset == "24h"
        assert tr.start == now - timedelta(hours=24)
        assert tr.end == now
        assert tr.bucket_spec.bucket_label == "1h"


# ===========================================================================
# 7. Canonical Explicit Bucket Set and Validation
# ===========================================================================

class TestExplicitBucketSet:
    """Verifies the 16 canonical explicit widths and input normalization."""

    @pytest.mark.parametrize("bucket_label", list(CANONICAL_BUCKET_WIDTHS.keys()))
    def test_all_canonical_bucket_widths_accepted_when_fits(self, bucket_label):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        # Choose a duration where N <= 100 for each width
        sec = CANONICAL_BUCKET_WIDTHS[bucket_label]
        start = now - timedelta(seconds=min(sec * 10, 86400))
        spec = parse_and_validate_explicit_bucket(bucket_label, start, now)
        assert spec.bucket_label == bucket_label
        assert spec.bucket_seconds == sec

    def test_case_insensitivity_and_whitespace_trimming(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        start = now - timedelta(hours=2)
        spec1 = parse_and_validate_explicit_bucket(" 15m ", start, now)
        assert spec1.bucket_label == "15m"
        assert spec1.bucket_seconds == 900

        spec2 = parse_and_validate_explicit_bucket("1H", start, now)
        assert spec2.bucket_label == "1h"
        assert spec2.bucket_seconds == 3600

    @pytest.mark.parametrize(
        "invalid_bucket", ["2m", "7m", "17m", "90m", "36h", "0s", "-5m", "unknown", ""]
    )
    def test_reject_invalid_bucket_widths(self, invalid_bucket):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        start = now - timedelta(hours=2)
        with pytest.raises(TimeEngineValidationError):
            parse_and_validate_explicit_bucket(invalid_bucket, start, now)


# ===========================================================================
# 8. Preset vs Explicit Bucket Precedence & Max Limit Enforcement
# ===========================================================================

class TestPresetVsExplicitPrecedence:
    """Verifies that explicit bucket overrides preset default, but is rejected if N > 100."""

    def test_explicit_bucket_overrides_preset_default(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        # window=24h with bucket=15m: 24h = 96 15m buckets <= 100 -> Accepted
        tr = resolve_time_range(window="24h", bucket="15m", now_override=now)
        assert tr.preset == "24h"
        assert tr.bucket_spec.bucket_label == "15m"
        assert tr.bucket_spec.bucket_seconds == 900
        assert tr.duration_seconds == 86400.0

    def test_explicit_bucket_exceeding_max_rejected(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        # window=24h with bucket=1m: 24h = 1440 1m buckets > 100 -> Rejected
        with pytest.raises(InvalidTimeRangeError) as exc:
            resolve_time_range(window="24h", bucket="1m", now_override=now)
        assert "exceeding the maximum allowed limit of 100" in str(exc.value)

    def test_explicit_bucket_never_silently_widened(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        # 30d with bucket=1m -> must reject, not silently coarsen
        start = now - timedelta(days=30)
        with pytest.raises(InvalidTimeRangeError):
            resolve_time_range(start_time=start, end_time=now, bucket="1m", now_override=now)


# ===========================================================================
# 9. Exact Intersecting Bucket Counting & Canonical Examples
# ===========================================================================

class TestExactIntersectingBucketCounting:
    """Verifies the authoritative count_intersecting_buckets function on frozen contract examples."""

    def test_contract_example_1_aligned(self):
        # [10:00, 11:00), W=1h -> 1
        d1 = datetime(2026, 9, 16, 10, 0, tzinfo=timezone.utc)
        d2 = datetime(2026, 9, 16, 11, 0, tzinfo=timezone.utc)
        assert count_intersecting_buckets(d1, d2, 3600) == 1

    def test_contract_example_2_unaligned_1h(self):
        # [10:37, 11:37), W=1h -> 2
        d1 = datetime(2026, 9, 16, 10, 37, tzinfo=timezone.utc)
        d2 = datetime(2026, 9, 16, 11, 37, tzinfo=timezone.utc)
        assert count_intersecting_buckets(d1, d2, 3600) == 2

    def test_contract_example_3_unaligned_24h_yields_25_buckets(self):
        # [10:37, next-day 10:37), W=1h -> 25 (The frozen 24h / 25-bucket rule)
        d1 = datetime(2026, 9, 16, 10, 37, tzinfo=timezone.utc)
        d2 = datetime(2026, 9, 17, 10, 37, tzinfo=timezone.utc)
        assert count_intersecting_buckets(d1, d2, 3600) == 25

    def test_contract_example_4_empty_range(self):
        # start == end -> 0
        d1 = datetime(2026, 9, 16, 10, 0, tzinfo=timezone.utc)
        assert count_intersecting_buckets(d1, d1, 3600) == 0

    def test_microsecond_boundary_precision(self):
        # [10:00:00.000000, 11:00:00.000001), W=1h -> 2 (just 1 microsecond spillover)
        d1 = datetime(2026, 9, 16, 10, 0, 0, 0, tzinfo=timezone.utc)
        d2 = datetime(2026, 9, 16, 11, 0, 0, 1, tzinfo=timezone.utc)
        assert count_intersecting_buckets(d1, d2, 3600) == 2

        # [10:00:00.000000, 11:00:00.000000), W=1h -> 1 (exact boundary, half-open excluded)
        d3 = datetime(2026, 9, 16, 11, 0, 0, 0, tzinfo=timezone.utc)
        assert count_intersecting_buckets(d1, d3, 3600) == 1


# ===========================================================================
# 10. Partial Bucket Model & Coverage Conservation
# ===========================================================================

class TestPartialBucketModelAndCoverage:
    """Verifies ResolvedBucket properties, is_partial calculation, and coverage conservation."""

    def test_25_bucket_partial_boundaries_and_coverage(self):
        # [10:37, next-day 10:37), W=1h
        d1 = datetime(2026, 9, 16, 10, 37, tzinfo=timezone.utc)
        d2 = datetime(2026, 9, 17, 10, 37, tzinfo=timezone.utc)

        buckets = generate_resolved_buckets(d1, d2, 3600)
        assert len(buckets) == 25

        # Leading bucket
        assert buckets[0].bucket_start == datetime(2026, 9, 16, 10, 0, tzinfo=timezone.utc)
        assert buckets[0].bucket_end == datetime(2026, 9, 16, 11, 0, tzinfo=timezone.utc)
        assert buckets[0].effective_start == d1
        assert buckets[0].effective_end == datetime(2026, 9, 16, 11, 0, tzinfo=timezone.utc)
        assert buckets[0].is_partial is True
        assert buckets[0].covered_seconds == (60 - 37) * 60 == 1380.0

        # Trailing bucket
        assert buckets[-1].bucket_start == datetime(2026, 9, 17, 10, 0, tzinfo=timezone.utc)
        assert buckets[-1].bucket_end == datetime(2026, 9, 17, 11, 0, tzinfo=timezone.utc)
        assert buckets[-1].effective_start == datetime(2026, 9, 17, 10, 0, tzinfo=timezone.utc)
        assert buckets[-1].effective_end == d2
        assert buckets[-1].is_partial is True
        assert buckets[-1].covered_seconds == 37 * 60 == 2220.0

        # Interior buckets
        for b in buckets[1:-1]:
            assert b.is_partial is False
            assert b.covered_seconds == 3600.0
            assert b.effective_start == b.bucket_start
            assert b.effective_end == b.bucket_end

        # Continuity
        for i in range(len(buckets) - 1):
            assert buckets[i].bucket_end == buckets[i + 1].bucket_start
            assert buckets[i].effective_end == buckets[i + 1].effective_start

        # Coverage Conservation: SUM(covered_seconds) == duration
        total_covered = sum(b.covered_seconds for b in buckets)
        assert total_covered == (d2 - d1).total_seconds() == 86400.0


# ===========================================================================
# 11. Automatic Bucket Selection & Mathematical Invariants
# ===========================================================================

class TestAutoBucketing:
    """Verifies automatic bucket selection minimality, exact N <= 100, and fallback behavior."""

    def test_auto_bucket_transition_around_theoretical_threshold(self):
        """
        Tests the transition around D_max = 100W - r for each candidate width.
        Verifies that N(start, start + D_max) <= 100 and N(start, start + D_max + 1us) == 101.
        """
        base_dt = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc)

        for w in AUTO_BUCKET_CANDIDATES[:-1]:  # Skip 1w for overflow check
            offsets = [
                0,
                1,  # 1 microsecond
                w // 2,
                w - 1,
            ]
            for offset_sec in offsets:
                start = base_dt + timedelta(seconds=offset_sec)
                # Theoretical maximum duration that yields exactly <= 100 intersecting buckets:
                # r = offset_sec % w
                # D_max = 100 * w - r seconds
                r = offset_sec % w
                d_max_sec = 100 * w - r

                # Range with D_max:
                end_fit = start + timedelta(seconds=d_max_sec)
                n_fit = count_intersecting_buckets(start, end_fit, w)
                assert n_fit <= 100, f"For W={w} offset={offset_sec}, N={n_fit} exceeds 100"

                # Range with D_max + 1 microsecond:
                end_exceed = start + timedelta(seconds=d_max_sec, microseconds=1)
                n_exceed = count_intersecting_buckets(start, end_exceed, w)
                assert n_exceed == 101, f"For W={w} offset={offset_sec}, N={n_exceed} != 101"

    def test_auto_bucket_minimality(self):
        """
        Verifies that for an auto-selected width W:
        N(start, end, W) <= 100 and for every W' < W: N(start, end, W') > 100.
        """
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        test_durations = [
            timedelta(seconds=45),       # fits 1s (45 buckets)
            timedelta(minutes=4),        # fits 5s (48 buckets)
            timedelta(minutes=45),       # fits 30s (90 buckets)
            timedelta(hours=4),          # fits 5m (48 buckets)
            timedelta(hours=24),         # fits 15m (96-97 buckets)
            timedelta(days=7),           # fits 2h (84-85 buckets)
            timedelta(days=30),          # fits 12h (60-61 buckets)
            timedelta(days=90),          # fits 1d (90-91 buckets)
            timedelta(days=365),         # fits 1w (52-53 buckets)
        ]

        for dur in test_durations:
            start = now - dur
            spec = auto_select_bucket_width(start, now)
            n_selected = count_intersecting_buckets(start, now, spec.bucket_seconds)
            assert n_selected <= 100, f"Selected {spec.bucket_label} had N={n_selected} > 100"

            # Check minimality: all smaller candidate widths must have N > 100
            for smaller_w in AUTO_BUCKET_CANDIDATES:
                if smaller_w < spec.bucket_seconds:
                    n_smaller = count_intersecting_buckets(start, now, smaller_w)
                    assert n_smaller > 100, (
                        f"Minimality violated for duration {dur}: smaller width {smaller_w}s "
                        f"had N={n_smaller} <= 100, but {spec.bucket_seconds}s was chosen"
                    )

    def test_auto_bucket_fallback_beyond_one_week(self):
        """For ranges > 700 weeks (~13.4 years), fallback selects whole days guaranteeing N <= 100."""
        start = datetime(2000, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        end = datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc)  # 25 years
        spec = auto_select_bucket_width(start, end)
        n = count_intersecting_buckets(start, end, spec.bucket_seconds)
        assert n <= 100
        assert spec.bucket_seconds % 86400 == 0
        assert spec.bucket_label.endswith("d")

    def test_randomized_property_auto_bucketing(self):
        """Randomized property test: for 50 arbitrary random ranges, auto-selection is valid and minimal."""
        random.seed(42)
        base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

        for _ in range(50):
            offset_sec = random.randint(0, 86400 * 7)
            dur_sec = random.randint(1, 86400 * 400)
            dur_us = random.randint(0, 999999)

            start = base + timedelta(seconds=offset_sec, microseconds=dur_us)
            end = start + timedelta(seconds=dur_sec)

            spec = auto_select_bucket_width(start, end)
            n = count_intersecting_buckets(start, end, spec.bucket_seconds)
            assert n <= 100

            # Verify minimality among candidate widths
            if spec.bucket_seconds in AUTO_BUCKET_CANDIDATES:
                idx = AUTO_BUCKET_CANDIDATES.index(spec.bucket_seconds)
                if idx > 0:
                    prev_w = AUTO_BUCKET_CANDIDATES[idx - 1]
                    assert count_intersecting_buckets(start, end, prev_w) > 100


# ===========================================================================
# 12. Future Range Semantics
# ===========================================================================

class TestFutureRangeSemantics:
    """Verifies historical, partially future, and entirely future range policies."""

    def test_historical_range_observable_end_equals_end(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(
            start_time="2026-09-16T08:00:00Z",
            end_time="2026-09-16T10:00:00Z",
            now_override=now,
        )
        assert tr.observable_end == datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)

    def test_partially_future_range_clamped_to_now(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(
            start_time="2026-09-16T10:00:00Z",
            end_time="2026-09-16T14:00:00Z",
            now_override=now,
        )
        assert tr.start == datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)
        assert tr.end == datetime(2026, 9, 16, 14, 0, 0, tzinfo=timezone.utc)
        assert tr.observable_end == now

    def test_entirely_future_range_rejected_start_greater_than_now(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(InvalidTimeRangeError) as exc:
            resolve_time_range(
                start_time="2026-09-16T13:00:00Z",
                end_time="2026-09-16T15:00:00Z",
                now_override=now,
            )
        assert "entirely in the future" in str(exc.value)

    def test_entirely_future_range_rejected_start_equals_now(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(InvalidTimeRangeError) as exc:
            resolve_time_range(
                start_time="2026-09-16T12:00:00Z",
                end_time="2026-09-16T14:00:00Z",
                now_override=now,
            )
        assert "entirely in the future" in str(exc.value)


# ===========================================================================
# 13. All-Time Mode Invariants
# ===========================================================================

class TestAllTimeModeInvariants:
    """Verifies mutual exclusivity of all-time vs bounded mode."""

    def test_all_time_disallows_duration_seconds(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(default_policy=TemporalDefaultPolicy.ALL_TIME, now_override=now)
        with pytest.raises(InvalidTimeRangeError):
            _ = tr.duration_seconds

    def test_all_time_disallows_generate_buckets(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(default_policy=TemporalDefaultPolicy.ALL_TIME, now_override=now)
        with pytest.raises(InvalidTimeRangeError):
            tr.generate_buckets()


# ===========================================================================
# 14. Input Parameter Mutual Exclusivity
# ===========================================================================

class TestInputMutualExclusivity:
    """Verifies that mutually exclusive parameters are strictly rejected."""

    def test_window_combined_with_start_rejected(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(TimeEngineValidationError) as exc:
            resolve_time_range(window="24h", start_time="2026-09-16T00:00:00Z", now_override=now)
        assert "Cannot specify both 'window' preset and custom" in str(exc.value)

    def test_window_combined_with_end_rejected(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(TimeEngineValidationError) as exc:
            resolve_time_range(window="24h", end_time="2026-09-16T12:00:00Z", now_override=now)
        assert "Cannot specify both 'window' preset and custom" in str(exc.value)

    def test_start_without_end_rejected(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(TimeEngineValidationError) as exc:
            resolve_time_range(start_time="2026-09-16T00:00:00Z", now_override=now)
        assert "Both 'start_time' and 'end_time' must be provided" in str(exc.value)

    def test_bucket_without_range_rejected_in_default_mode(self):
        now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
        with pytest.raises(TimeEngineValidationError) as exc:
            resolve_time_range(bucket="15m", now_override=now)
        assert "Bucket width cannot be specified without a time range" in str(exc.value)


# ===========================================================================
# 15. PostgreSQL Session Timezone Invariance (Section 36)
# ===========================================================================

class TestSessionTimezoneInvariance:
    """
    Verifies Section 36: Analytical results and UTC formatting must remain
    identical regardless of PostgreSQL session timezone (UTC, Asia/Kolkata, America/New_York).
    """

    def test_session_timezone_invariance(self):
        import psycopg2
        from domain_profiling.config import DBConfig
        from reporting.repository import ReportingRepository
        from reporting.service import ReportingService

        timezones = ["UTC", "Asia/Kolkata", "America/New_York"]
        results = []

        start = datetime(2026, 9, 16, 6, 0, 0, tzinfo=timezone.utc)
        end = datetime(2026, 9, 16, 8, 0, 0, tzinfo=timezone.utc)
        now = datetime(2026, 9, 16, 8, 0, 0, tzinfo=timezone.utc)
        tr = resolve_time_range(start_time=start, end_time=end, bucket="1h", now_override=now)

        for tz in timezones:
            def make_conn(session_tz=tz):
                params = DBConfig.get_connection_params()
                conn = psycopg2.connect(**params)
                with conn.cursor() as cur:
                    cur.execute(f"SET TIME ZONE '{session_tz}';")
                return conn

            repo = ReportingRepository(connection_factory=make_conn)
            svc = ReportingService(repository=repo)

            summary = svc.get_summary(tr)
            ts = svc.get_timeseries(tr)
            queries = svc.get_queries(time_range=tr, limit=5)

            results.append({
                "tz": tz,
                "summary_total": summary.total_queries,
                "summary_window": summary.time_window,
                "ts_buckets": [(b.timestamp, b.total_queries) for b in ts.buckets],
                "query_timestamps": [q.timestamp for q in queries.items],
            })

        # All session timezones must yield identical analytical outputs
        baseline = results[0]
        for r in results[1:]:
            assert r["summary_total"] == baseline["summary_total"]
            assert r["summary_window"] == baseline["summary_window"]
            assert r["ts_buckets"] == baseline["ts_buckets"]
            assert r["query_timestamps"] == baseline["query_timestamps"]
            for ts_str in r["query_timestamps"]:
                assert ts_str.endswith("Z")

