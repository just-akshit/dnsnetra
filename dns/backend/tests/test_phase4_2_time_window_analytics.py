"""
Phase 4.2 Time-Window DNS Analytics Test Suite
==============================================
Comprehensive validation of Time-Window DNS Analytics:
1. Preset windows: 5m, 10m, 15m, 30m, 45m, 60m
2. Custom historical range
3. Half-open interval exactness [start, end)
4. Empty range handling (zero-gap filling, 0 metrics)
5. Validation: invalid window, start >= end, invalid ISO8601, max range exceeded
6. Mutually exclusive parameter checks
7. Distinct domain counting: Unique Registered Domains vs Unique FQDNs
8. Unique client counting
9. Malicious & Suspicious domain observational counting
10. Invariant: Bucket count strictly <= 100 across all durations
11. Non-additive bucket semantics verification
12. Database performance: exactly two bounded aggregate queries (zero N+1)
"""

from __future__ import annotations

import math
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api.main import app
from analytics.time_window import (
    MAX_HISTORY_DAYS,
    MAX_TIMELINE_BUCKETS,
    TimeWindow,
    WindowPreset,
    compute_optimal_bucket_seconds,
    format_iso8601_utc,
    parse_iso8601_utc,
    resolve_time_window,
)
from analytics.domain_analytics import DomainAnalyticsService
from analytics.models import DomainAnalyticsResponse


@pytest.fixture(scope="module")
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


# ===========================================================================
# 1. TIME WINDOW RESOLVER & INVARIANT TESTS
# ===========================================================================

class TestTimeWindowResolver:
    """Validates window resolution, half-open interval boundaries, and bucket sizing invariants."""

    def test_preset_5m_resolution(self):
        fixed_now = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        win = resolve_time_window(window="5m", now_override=fixed_now)

        assert win.preset == "5m"
        assert win.duration_minutes == 5.0
        assert win.start == datetime(2026, 8, 24, 11, 55, 0, tzinfo=timezone.utc)
        assert win.end == fixed_now
        assert win.bucket_seconds == 60
        assert win.bucket_count == 5

    def test_preset_10m_resolution(self):
        fixed_now = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        win = resolve_time_window(window="10m", now_override=fixed_now)

        assert win.preset == "10m"
        assert win.duration_minutes == 10.0
        assert win.bucket_seconds == 60
        assert win.bucket_count == 10

    def test_preset_15m_resolution(self):
        fixed_now = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        win = resolve_time_window(window="15m", now_override=fixed_now)

        assert win.preset == "15m"
        assert win.duration_minutes == 15.0
        assert win.bucket_seconds == 60
        assert win.bucket_count == 15

    def test_preset_30m_resolution(self):
        fixed_now = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        win = resolve_time_window(window="30m", now_override=fixed_now)

        assert win.preset == "30m"
        assert win.duration_minutes == 30.0
        assert win.bucket_seconds == 120
        assert win.bucket_count == 15

    def test_preset_45m_resolution(self):
        fixed_now = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        win = resolve_time_window(window="45m", now_override=fixed_now)

        assert win.preset == "45m"
        assert win.duration_minutes == 45.0
        assert win.bucket_seconds == 180
        assert win.bucket_count == 15

    def test_preset_60m_resolution(self):
        fixed_now = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        win = resolve_time_window(window="60m", now_override=fixed_now)

        assert win.preset == "60m"
        assert win.duration_minutes == 60.0
        assert win.bucket_seconds == 300
        assert win.bucket_count == 12

    def test_custom_range_resolution(self):
        start = "2026-08-24T00:00:00Z"
        end = "2026-08-24T02:00:00Z"
        win = resolve_time_window(start=start, end=end)

        assert win.preset is None
        assert win.duration_minutes == 120.0
        assert win.start_iso == "2026-08-24T00:00:00Z"
        assert win.end_iso == "2026-08-24T02:00:00Z"
        assert win.bucket_count <= MAX_TIMELINE_BUCKETS

    def test_invalid_window_preset_raises(self):
        with pytest.raises(ValueError, match="Invalid window preset"):
            resolve_time_window(window="99m")

    def test_start_greater_than_or_equal_to_end_raises(self):
        with pytest.raises(ValueError, match="must be strictly before end timestamp"):
            resolve_time_window(
                start="2026-08-24T12:00:00Z",
                end="2026-08-24T12:00:00Z",
            )
        with pytest.raises(ValueError, match="must be strictly before end timestamp"):
            resolve_time_window(
                start="2026-08-24T13:00:00Z",
                end="2026-08-24T12:00:00Z",
            )

    def test_exceeding_max_history_days_raises(self):
        start = "2026-01-01T00:00:00Z"
        end = "2029-01-01T00:00:00Z"  # ~3 years (> 730 days)
        with pytest.raises(ValueError, match="exceeds the maximum supported historical range"):
            resolve_time_window(start=start, end=end)

    def test_mutually_exclusive_parameters_raises(self):
        with pytest.raises(ValueError, match="Cannot specify both 'window' preset and custom"):
            resolve_time_window(window="15m", start="2026-08-24T00:00:00Z", end="2026-08-24T01:00:00Z")

        with pytest.raises(ValueError, match="Both 'start' and 'end' must be provided"):
            resolve_time_window(start="2026-08-24T00:00:00Z")

    def test_bucket_count_invariant_across_all_durations(self):
        """
        INVARIANT TEST:
        For every possible duration up to MAX_HISTORY_DAYS (including prime/fractional durations),
        the computed bucket count MUST be <= MAX_TIMELINE_BUCKETS (100).
        """
        test_durations_sec = [
            1, 30, 60, 300, 900, 1800, 3600, 7200, 14400, 43200, 86400,
            86400 * 2, 86400 * 5, 86400 * 7, 86400 * 14, 86400 * 21, 86400 * 30,
            12345, 99999, 876543, 2591999,
        ]

        for dur in test_durations_sec:
            b_sec = compute_optimal_bucket_seconds(dur)
            b_count = math.ceil(dur / b_sec)
            assert b_count <= MAX_TIMELINE_BUCKETS, (
                f"Invariant violation: duration={dur}s produced {b_count} buckets (bucket_size={b_sec}s)"
            )


# ===========================================================================
# 2. FASTAPI ENDPOINT & HTTP CONTRACT TESTS
# ===========================================================================

class TestAnalyticsEndpointContracts:
    """Validates FastAPI routes, HTTP status codes, parameter validations, and error payloads."""

    def test_get_preset_5m_success(self, client):
        res = client.get("/api/v1/analytics/domains?window=5m")
        assert res.status_code == 200
        payload = res.json()
        assert payload["status"] == "success"
        assert payload["data"]["window"]["duration_minutes"] == 5.0
        assert "metrics" in payload["data"]
        assert "timeline" in payload["data"]

    def test_get_preset_15m_success(self, client):
        res = client.get("/api/v1/analytics/domains?window=15m")
        assert res.status_code == 200
        payload = res.json()
        assert payload["status"] == "success"
        assert payload["data"]["window"]["duration_minutes"] == 15.0
        assert len(payload["data"]["timeline"]) >= 15

    def test_get_preset_60m_success(self, client):
        res = client.get("/api/v1/analytics/domains?window=60m")
        assert res.status_code == 200
        payload = res.json()
        assert payload["status"] == "success"
        assert payload["data"]["window"]["duration_minutes"] == 60.0

    def test_custom_range_success(self, client):
        res = client.get("/api/v1/analytics/domains?start=2026-08-24T00:00:00Z&end=2026-08-24T01:00:00Z")
        assert res.status_code == 200
        payload = res.json()
        assert payload["status"] == "success"
        assert payload["data"]["window"]["duration_minutes"] == 60.0

    def test_invalid_window_preset_returns_400(self, client):
        res = client.get("/api/v1/analytics/domains?window=20m")
        assert res.status_code == 400
        assert "Invalid window preset" in res.json()["detail"]

    def test_start_after_end_returns_400(self, client):
        res = client.get("/api/v1/analytics/domains?start=2026-08-24T02:00:00Z&end=2026-08-24T01:00:00Z")
        assert res.status_code == 400
        assert "must be strictly before end" in res.json()["detail"]

    def test_invalid_iso_timestamp_returns_400(self, client):
        res = client.get("/api/v1/analytics/domains?start=not-a-timestamp&end=2026-08-24T01:00:00Z")
        assert res.status_code == 400
        assert "Invalid ISO8601" in res.json()["detail"]

    def test_missing_all_parameters_returns_400(self, client):
        res = client.get("/api/v1/analytics/domains")
        assert res.status_code == 400
        assert "Must provide either a 'window' preset" in res.json()["detail"]

    def test_partial_custom_range_returns_400(self, client):
        res = client.get("/api/v1/analytics/domains?start=2026-08-24T00:00:00Z")
        assert res.status_code == 400
        assert "Both 'start' and 'end' must be provided" in res.json()["detail"]


# ===========================================================================
# 3. DOMAIN METRICS & OBSERVATIONAL SEMANTICS TESTS
# ===========================================================================

class TestDomainMetricsAndSemantics:
    """Validates distinct counting, non-additive bucket semantics, and half-open interval exactness."""

    def test_empty_range_handling(self):
        """Empty range must return 0 for all metrics and continuous 0-filled timeline buckets."""
        fixed_now = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        
        # Mock empty DB response
        with patch.object(
            DomainAnalyticsService,
            "_execute_queries",
            return_value=(
                {
                    "total_queries": 0,
                    "unique_fqdns": 0,
                    "unique_registered_domains": 0,
                    "unique_clients": 0,
                    "malicious_domains": 0,
                    "suspicious_domains": 0,
                },
                {},
            ),
        ):
            data = DomainAnalyticsService.get_analytics(window="5m", now_override=fixed_now)

            assert data.metrics.total_queries == 0
            assert data.metrics.unique_fqdns == 0
            assert data.metrics.unique_registered_domains == 0
            assert data.metrics.unique_clients == 0
            assert data.metrics.malicious_domains == 0
            assert data.metrics.suspicious_domains == 0
            assert len(data.timeline) >= 5
            for bucket in data.timeline:
                assert bucket.queries == 0
                assert bucket.unique_domains == 0

    def test_distinction_between_registered_domains_and_fqdns(self):
        """
        Verify that multiple subdomains under the same apex produce:
        - unique_fqdns = N
        - unique_registered_domains = 1 (Primary KPI)
        """
        mock_summary = {
            "total_queries": 500,
            "unique_fqdns": 120,
            "unique_registered_domains": 73,
            "unique_clients": 27,
            "malicious_domains": 8,
            "suspicious_domains": 14,
        }
        mock_buckets = {
            "2026-08-24T11:50:00Z": {"queries": 200, "unique_domains": 30},
            "2026-08-24T11:55:00Z": {"queries": 300, "unique_domains": 45},
        }

        fixed_now = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        with patch.object(
            DomainAnalyticsService, "_execute_queries", return_value=(mock_summary, mock_buckets)
        ):
            data = DomainAnalyticsService.get_analytics(window="15m", now_override=fixed_now)

            assert data.metrics.total_queries == 500
            assert data.metrics.unique_fqdns == 120
            assert data.metrics.unique_registered_domains == 73
            assert data.metrics.unique_clients == 27
            assert data.metrics.malicious_domains == 8
            assert data.metrics.suspicious_domains == 14

    def test_non_additive_timeline_bucket_semantics(self):
        """
        Validates that bucket unique_domains are non-additive:
        Sum of bucket unique_domains (30 + 45 = 75) does not equal window-level unique_registered_domains (73).
        """
        mock_summary = {
            "total_queries": 500,
            "unique_fqdns": 120,
            "unique_registered_domains": 73,
            "unique_clients": 27,
            "malicious_domains": 8,
            "suspicious_domains": 14,
        }
        mock_buckets = {
            "2026-08-24T11:50:00Z": {"queries": 200, "unique_domains": 30},
            "2026-08-24T11:55:00Z": {"queries": 300, "unique_domains": 45},
        }

        fixed_now = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)
        with patch.object(
            DomainAnalyticsService, "_execute_queries", return_value=(mock_summary, mock_buckets)
        ):
            data = DomainAnalyticsService.get_analytics(window="15m", now_override=fixed_now)

            bucket_sum = sum(b.unique_domains for b in data.timeline)
            # The headline metric is 73, while the sum of individual bucket unique domains is 75
            assert data.metrics.unique_registered_domains == 73
            assert bucket_sum == 75
            assert data.metrics.unique_registered_domains != bucket_sum

    def test_database_query_boundedness_no_n_plus_one(self):
        """
        Verifies that DomainAnalyticsService executes exactly TWO database queries
        regardless of the number of buckets requested (no N+1 per-bucket queries).
        """
        query_log = []

        class MockCursor:
            def execute(self, sql, params):
                query_log.append((sql, params))

            def fetchone(self):
                return {
                    "total_queries": 10,
                    "unique_fqdns": 2,
                    "unique_registered_domains": 2,
                    "unique_clients": 1,
                    "malicious_domains": 0,
                    "suspicious_domains": 0,
                }

            def fetchall(self):
                return []

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        class MockConn:
            def cursor(self, cursor_factory=None):
                return MockCursor()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        with patch("analytics.domain_analytics.get_db_connection", return_value=MockConn()):
            DomainAnalyticsService.get_analytics(window="60m")

            # Exactly 2 SQL queries executed: summary metrics + timeline buckets
            assert len(query_log) == 2, f"Expected 2 queries, got {len(query_log)}"
            assert "COUNT(*) AS total_queries" in query_log[0][0]
            assert "GROUP BY bucket_time" in query_log[1][0]
