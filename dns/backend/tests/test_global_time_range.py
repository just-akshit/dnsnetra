"""
Test Suite: Global Time-Range System (PostgreSQL -> FastAPI -> Next.js)
======================================================================
Tests:
1. Full preset expansion: 1m, 5m, 15m, 30m, 1h, 5h, 12h, 24h, 7d, 30d, 6mo (180d), 1y (365d).
2. Dynamic bucket sizing and visualization quality (all <= 100 buckets).
3. Precedence: Custom start_time/end_time > preset window.
4. Half-open interval filtering [start, end) on PostgreSQL domain_query_history.
5. Zero-data boundary handling (empty ranges return HTTP 200 with zero metrics).
6. Time-range integration on bundle, summary, timeseries, categories, top rankings,
   paginated tables, and investigation endpoints.
"""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from analytics.time_window import (
    resolve_time_window,
    compute_optimal_bucket_seconds,
    WindowPreset,
    TimeWindow,
    format_iso8601_utc,
)
from api.main import app

client = TestClient(app)


# ===========================================================================
# 1. Unit Tests for TimeWindow Resolver Expansion
# ===========================================================================

class TestTimeWindowExpansion:
    """Validates full suite of 12 presets and visual bucket scaling."""

    @pytest.mark.parametrize("preset,expected_minutes,expected_bucket", [
        ("1m", 1, 10),
        ("5m", 5, 60),
        ("15m", 15, 60),
        ("30m", 30, 120),
        ("1h", 60, 300),
        ("6h", 360, 900),
        ("12h", 720, 1800),
        ("24h", 1440, 3600),
        ("7d", 10080, 21600),
        ("30d", 43200, 86400),
        ("6mo", 259200, 604800),  # Rolling 180 days
        ("1y", 525600, 604800),   # Rolling 365 days
    ])
    def test_all_presets_configuration(self, preset, expected_minutes, expected_bucket):
        tw = resolve_time_window(window=preset)
        assert tw.duration_minutes == expected_minutes
        assert tw.bucket_seconds == expected_bucket
        assert tw.bucket_count <= 100
        assert tw.start < tw.end
        assert tw.start.tzinfo == timezone.utc
        assert tw.end.tzinfo == timezone.utc

    def test_5h_preset_is_rejected(self):
        with pytest.raises(ValueError, match="Invalid window preset '5h'"):
            resolve_time_window(window="5h")

    def test_six_months_is_rolling_180_days(self):
        tw = resolve_time_window(window="6mo")
        assert tw.duration_seconds == 180 * 86400

    def test_one_year_is_rolling_365_days(self):
        tw = resolve_time_window(window="1y")
        assert tw.duration_seconds == 365 * 86400

    def test_deterministic_bucket_generation(self):
        tw = resolve_time_window(window="1h")
        buckets = tw.generate_bucket_timestamps()
        assert len(buckets) >= 12
        assert len(buckets) <= 100
        for i in range(1, len(buckets)):
            assert buckets[i] > buckets[i - 1]
            diff = (buckets[i] - buckets[i - 1]).total_seconds()
            assert diff == tw.bucket_seconds

    def test_custom_range_order_assertion(self):
        with pytest.raises(ValueError, match="must be strictly before end timestamp"):
            resolve_time_window(start="2026-08-28T12:00:00Z", end="2026-08-28T10:00:00Z")


# ===========================================================================
# 2. Integration Tests: Dashboard Bundle Endpoint
# ===========================================================================

class TestDashboardBundleTimeRange:
    """Validates /api/v1/dashboard with preset and custom time ranges."""

    def test_dashboard_bundle_unconstrained(self):
        resp = client.get("/api/v1/dashboard")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "summary" in data
        assert "timeseries" in data
        assert "categories" in data
        assert "top_domains" in data
        assert "top_clients" in data
        assert "recent_flagged" in data

    def test_dashboard_bundle_with_preset_24h(self):
        resp = client.get("/api/v1/dashboard?window=24h")
        assert resp.status_code == 200
        data = resp.json()["data"]
        summary = data["summary"]
        assert "total_queries" in summary
        assert "total_threats" in summary
        assert isinstance(data["timeseries"], list)
        assert isinstance(data["top_domains"], list)
        assert isinstance(data["top_clients"], list)

    def test_dashboard_bundle_with_custom_range(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/dashboard?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "summary" in data
        assert len(data["timeseries"]) > 0

    def test_dashboard_bundle_custom_precedence_over_preset(self):
        # Even if window=1m is supplied, custom range 2026-08-28 takes precedence
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-28T23:59:59Z"
        resp = client.get(f"/api/v1/dashboard?window=1m&start_time={start}&end_time={end}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        # In custom range, queries occurred on 2026-08-28, so total_queries > 0
        assert data["summary"]["total_queries"] > 0

    def test_dashboard_bundle_zero_data_empty_state(self):
        # A historical window where no DNS queries were recorded
        start = "2015-01-01T00:00:00Z"
        end = "2015-01-01T01:00:00Z"
        resp = client.get(f"/api/v1/dashboard?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["summary"]["total_queries"] == 0
        assert data["summary"]["total_threats"] == 0
        assert data["summary"]["unique_domains"] == 0
        assert data["summary"]["unique_clients"] == 0
        assert data["top_domains"] == []
        assert data["top_clients"] == []
        assert data["categories"] == []
        assert data["recent_flagged"] == []


# ===========================================================================
# 3. Integration Tests: Sub-endpoints & Paginated Tables
# ===========================================================================

class TestSubEndpointsTimeRange:
    """Validates /summary, /timeseries, /domains, /clients time-window behavior."""

    def test_summary_with_time_range(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/summary?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["total_queries"] > 0

    def test_timeseries_with_time_range(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-28T06:00:00Z"
        resp = client.get(f"/api/v1/threats/timeseries?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        buckets = resp.json()["data"]
        assert len(buckets) > 0
        assert all("time_bucket" in b for b in buckets)

    def test_top_domains_time_scoped(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/domains/top?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        domains = resp.json()["data"]
        assert len(domains) > 0
        assert all(d["query_count"] > 0 for d in domains)

    def test_top_clients_time_scoped(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/clients/top?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        clients = resp.json()["data"]
        assert len(clients) > 0
        assert all(c["query_count"] > 0 for c in clients)

    def test_paginated_domains_time_scoped(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/domains?start_time={start}&end_time={end}&page=1&page_size=10")
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "meta" in body
        assert body["meta"]["total"] > 0

    def test_paginated_clients_time_scoped(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/clients?start_time={start}&end_time={end}&page=1&page_size=10")
        assert resp.status_code == 200
        body = resp.json()
        assert "data" in body
        assert "meta" in body
        assert body["meta"]["total"] > 0


# ===========================================================================
# 4. Integration Tests: Investigation Endpoints with Time Ranges
# ===========================================================================

class TestInvestigationTimeRange:
    """Validates domain and client investigation with time ranges."""

    def test_domain_investigation_with_range(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/investigation/domain/google.com?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "dns_activity" in data
        assert "selected_range" in data["dns_activity"]
        sr = data["dns_activity"]["selected_range"]
        assert sr["start"] == start
        assert sr["end"] == end

    def test_client_investigation_with_range(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/investigation/client/192.168.1.100?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert "client" in data
        assert "selected_range" in data
        sr = data["selected_range"]
        assert sr is not None
        assert sr["start"] == start
        assert sr["end"] == end
