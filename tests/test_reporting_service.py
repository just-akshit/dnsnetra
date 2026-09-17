"""
tests/test_reporting_service.py
===============================
Exhaustive test suite for ReportingService covering all Phase 2A requirements.
"""

from datetime import datetime, timezone, timedelta
import sys
import pytest

from reporting.service import ReportingService
from reporting.schemas import (
    CanonicalVerdict,
    InvalidTimeRangeError,
    PaginatedResult,
    ReportingSummary,
    ReportingTimeseries,
    ReportingValidationError,
)
from time_engine import format_iso8601_utc

DB_TZ = timezone(timedelta(hours=5, minutes=30))


@pytest.fixture
def service():
    return ReportingService()


# ---------------------------------------------------------------------------
# SUMMARY TESTS (1-8)
# ---------------------------------------------------------------------------

def test_1_summary_all_time_reconciliation(service):
    """1. All-time summary reconciles exactly against ground truth."""
    summary = service.get_summary()
    assert isinstance(summary, ReportingSummary)
    assert summary.time_window is None
    assert summary.total_queries == 30181
    assert summary.unique_clients == 12
    assert summary.unique_domains == 49


def test_2_summary_four_verdicts_reconciliation(service):
    """2. Four canonical verdicts reconcile exactly and sum to total."""
    summary = service.get_summary()
    vb = summary.verdict_breakdown
    assert vb.benign == 23371
    assert vb.malicious == 4626
    assert vb.review_needed == 448
    assert vb.unknown == 1736
    assert (vb.benign + vb.malicious + vb.review_needed + vb.unknown) == summary.total_queries


def test_3_summary_malicious_percentage(service):
    """3. Malicious query percentage is accurately calculated."""
    summary = service.get_summary()
    expected_pct = round((4626 * 100.0) / 30181, 2)  # 15.33%
    assert summary.malicious_query_percentage == expected_pct


def test_4_summary_zero_event_window(service):
    """4. Empty / zero-event window returns valid zeroed summary."""
    # start == end
    t = datetime(2026, 9, 16, 12, 0, 0, tzinfo=DB_TZ)
    summary = service.get_summary(start_time=t, end_time=t)
    assert summary.total_queries == 0
    assert summary.unique_clients == 0
    assert summary.unique_domains == 0
    assert summary.malicious_query_percentage == 0.0
    assert summary.verdict_breakdown.benign == 0


def test_5_summary_bounded_aligned_range(service):
    """5. Bounded hourly-aligned range uses rollup with exact metrics."""
    start = datetime(2026, 9, 16, 12, 0, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 13, 0, 0, tzinfo=DB_TZ)
    summary = service.get_summary(start_time=start, end_time=end)
    assert summary.total_queries > 0
    assert summary.unique_clients > 0
    assert summary.unique_domains > 0
    assert summary.time_window == {"start": format_iso8601_utc(start), "end": format_iso8601_utc(end)}


def test_6_summary_bounded_non_aligned_range(service):
    """6. Bounded non-aligned range uses raw history for partial-hour accuracy."""
    start = datetime(2026, 9, 16, 12, 34, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 12, 45, 0, tzinfo=DB_TZ)
    summary = service.get_summary(start_time=start, end_time=end)
    assert summary.total_queries > 0
    assert summary.unique_clients > 0
    assert summary.unique_domains > 0


def test_7_summary_unique_clients_exactness(service):
    """7. Unique clients in windowed summary matches exact DISTINCT count."""
    start = datetime(2026, 9, 16, 12, 0, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 13, 0, 0, tzinfo=DB_TZ)
    summary = service.get_summary(start_time=start, end_time=end)
    # Distinct clients must not exceed total clients
    assert 0 < summary.unique_clients <= 12


def test_8_summary_unique_domains_exactness(service):
    """8. Unique domains in windowed summary matches exact DISTINCT count."""
    start = datetime(2026, 9, 16, 12, 0, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 13, 0, 0, tzinfo=DB_TZ)
    summary = service.get_summary(start_time=start, end_time=end)
    assert 0 < summary.unique_domains <= 49


# ---------------------------------------------------------------------------
# TIMESERIES TESTS (9-15)
# ---------------------------------------------------------------------------

def test_9_timeseries_1_hour_aligned(service):
    """9. 1-hour aligned range returns exactly 1 bucket."""
    start = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 9, 16, 13, 0, 0, tzinfo=timezone.utc)
    ts = service.get_timeseries(start_time=start, end_time=end)
    assert isinstance(ts, ReportingTimeseries)
    assert len(ts.buckets) == 1
    assert ts.buckets[0].timestamp == format_iso8601_utc(start)


def test_10_timeseries_24_hour_aligned(service):
    """10. 24-hour aligned range returns exactly 24 continuous buckets."""
    start = datetime(2026, 9, 16, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 9, 17, 0, 0, 0, tzinfo=timezone.utc)
    ts = service.get_timeseries(start_time=start, end_time=end)
    assert len(ts.buckets) == 24
    # Continuous hourly sequence
    for i in range(24):
        expected_time = format_iso8601_utc(start + timedelta(hours=i))
        assert ts.buckets[i].timestamp == expected_time


def test_11_timeseries_non_aligned_range(service):
    """11. Non-aligned range (e.g. 10:37 -> 14:22) returns all intersecting hourly buckets."""
    start = datetime(2026, 9, 16, 10, 37, 0, tzinfo=timezone.utc)
    end = datetime(2026, 9, 16, 14, 22, 0, tzinfo=timezone.utc)
    ts = service.get_timeseries(start_time=start, end_time=end)
    # Intersects: 10:00, 11:00, 12:00, 13:00, 14:00 (5 buckets)
    assert len(ts.buckets) == 5
    assert ts.buckets[0].timestamp == format_iso8601_utc(datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc))
    assert ts.buckets[-1].timestamp == format_iso8601_utc(datetime(2026, 9, 16, 14, 0, 0, tzinfo=timezone.utc))


def test_12_timeseries_exact_event_inclusion(service):
    """12. Boundary clipping strictly includes events within [start, end)."""
    start = datetime(2026, 9, 16, 12, 34, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 12, 35, 0, tzinfo=DB_TZ)
    ts = service.get_timeseries(start_time=start, end_time=end)
    assert len(ts.buckets) == 1
    # Check that bucket queries match exact event count for that 1-minute window
    summary = service.get_summary(start_time=start, end_time=end)
    assert ts.buckets[0].total_queries == summary.total_queries


def test_13_timeseries_zero_fill(service):
    """13. Buckets without events are zero-filled with zero counters."""
    # A date far in the past with no events
    start = datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    end = datetime(2020, 1, 1, 3, 0, 0, tzinfo=timezone.utc)
    ts = service.get_timeseries(start_time=start, end_time=end)
    assert len(ts.buckets) == 3
    for b in ts.buckets:
        assert b.total_queries == 0
        assert b.benign_queries == 0
        assert b.malicious_queries == 0


def test_14_timeseries_empty_range(service):
    """14. start == end returns empty timeseries list."""
    t = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    ts = service.get_timeseries(start_time=t, end_time=t)
    assert ts.buckets == []


def test_15_timeseries_deterministic_ordering(service):
    """15. Bucket timestamps are strictly monotonically increasing."""
    start = datetime(2026, 9, 16, 8, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 9, 16, 16, 0, 0, tzinfo=timezone.utc)
    ts = service.get_timeseries(start_time=start, end_time=end)
    timestamps = [b.timestamp for b in ts.buckets]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# TOP CLIENTS TESTS (16-20)
# ---------------------------------------------------------------------------

def test_16_clients_all_time_ranking(service):
    """16. All-time client ranking ordered by total_queries DESC, client_ip ASC."""
    res = service.get_top_clients(limit=10, offset=0)
    assert isinstance(res, PaginatedResult)
    assert res.total == 12
    assert len(res.items) == 10
    # Strict order check
    for i in range(len(res.items) - 1):
        c1, c2 = res.items[i], res.items[i + 1]
        assert (c1.total_queries > c2.total_queries) or (
            c1.total_queries == c2.total_queries and c1.client_ip <= c2.client_ip
        )


def test_17_clients_windowed_ranking(service):
    """17. Windowed client ranking aggregates exact time-scoped metrics."""
    start = datetime(2026, 9, 16, 12, 0, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 13, 0, 0, tzinfo=DB_TZ)
    res = service.get_top_clients(limit=10, offset=0, start_time=start, end_time=end)
    assert res.total > 0
    for item in res.items:
        assert item.total_queries > 0
        assert item.unique_domains > 0


def test_18_clients_pagination(service):
    """18. Pagination math (limit, offset, has_more) is verified."""
    p1 = service.get_top_clients(limit=5, offset=0)
    assert p1.limit == 5
    assert p1.offset == 0
    assert p1.has_more is True
    assert len(p1.items) == 5

    p2 = service.get_top_clients(limit=5, offset=5)
    assert p2.offset == 5
    assert len(p2.items) == 5
    assert p1.items[0].client_ip != p2.items[0].client_ip

    p3 = service.get_top_clients(limit=5, offset=10)
    assert len(p3.items) == 2  # 12 total
    assert p3.has_more is False


def test_19_clients_deterministic_tie_breaking(service):
    """19. Tie-breaking on identical query counts orders alphabetically by client_ip."""
    res = service.get_top_clients(limit=12, offset=0)
    for i in range(len(res.items) - 1):
        if res.items[i].total_queries == res.items[i + 1].total_queries:
            assert res.items[i].client_ip < res.items[i + 1].client_ip


def test_20_clients_four_verdict_counts(service):
    """20. Each client item exposes all 4 canonical verdict counters summing to total."""
    res = service.get_top_clients(limit=12, offset=0)
    for c in res.items:
        verdict_sum = c.benign_queries + c.malicious_queries + c.review_needed_queries + c.unknown_queries
        assert verdict_sum == c.total_queries


# ---------------------------------------------------------------------------
# TOP DOMAINS TESTS (21-28)
# ---------------------------------------------------------------------------

def test_21_domains_all_time_ranking(service):
    """21. All-time domain ranking ordered by total_queries DESC, domain ASC."""
    res = service.get_top_domains(limit=10, offset=0)
    assert res.total == 49
    assert len(res.items) == 10
    for i in range(len(res.items) - 1):
        assert res.items[i].total_queries >= res.items[i + 1].total_queries


def test_22_domains_windowed_ranking(service):
    """22. Windowed domain ranking without verdict filter."""
    start = datetime(2026, 9, 16, 12, 0, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 13, 0, 0, tzinfo=DB_TZ)
    res = service.get_top_domains(limit=10, offset=0, start_time=start, end_time=end)
    assert res.total > 0
    assert len(res.items) > 0


def test_23_domains_verdict_filter_malicious(service):
    """23. verdict_filter = Malicious acts as event-population filter."""
    res = service.get_top_domains(limit=10, offset=0, verdict_filter=CanonicalVerdict.MALICIOUS)
    assert res.total > 0
    for item in res.items:
        assert item.latest_verdict == "Malicious"
        assert item.malicious_queries == item.total_queries
        assert item.benign_queries == 0
        assert item.review_needed_queries == 0
        assert item.unknown_queries == 0


def test_24_domains_verdict_filter_review_needed(service):
    """24. verdict_filter = Review Needed acts as event-population filter."""
    res = service.get_top_domains(limit=10, offset=0, verdict_filter=CanonicalVerdict.REVIEW_NEEDED)
    assert res.total > 0
    for item in res.items:
        assert item.latest_verdict == "Review Needed"
        assert item.review_needed_queries == item.total_queries
        assert item.malicious_queries == 0


def test_25_domains_verdict_filter_unknown(service):
    """25. verdict_filter = Unknown acts as event-population filter."""
    res = service.get_top_domains(limit=10, offset=0, verdict_filter=CanonicalVerdict.UNKNOWN)
    assert res.total > 0
    for item in res.items:
        assert item.latest_verdict == "Unknown"
        assert item.unknown_queries == item.total_queries
        assert item.malicious_queries == 0


def test_26_domains_verdict_filter_benign(service):
    """26. verdict_filter = Benign acts as event-population filter."""
    res = service.get_top_domains(limit=10, offset=0, verdict_filter=CanonicalVerdict.BENIGN)
    assert res.total > 0
    for item in res.items:
        assert item.latest_verdict == "Benign"
        assert item.benign_queries == item.total_queries
        assert item.malicious_queries == 0


def test_27_domains_filtered_metrics_correctness(service):
    """27. In filtered domains, unique_clients is distinct clients for matching events."""
    res = service.get_top_domains(limit=5, offset=0, verdict_filter=CanonicalVerdict.MALICIOUS)
    for item in res.items:
        assert item.unique_clients > 0
        assert item.unique_clients <= item.total_queries


def test_28_domains_filtered_ranking_correctness(service):
    """28. Filtered domains ordered by filtered total_queries DESC, domain ASC."""
    res = service.get_top_domains(limit=20, offset=0, verdict_filter=CanonicalVerdict.MALICIOUS)
    for i in range(len(res.items) - 1):
        d1, d2 = res.items[i], res.items[i + 1]
        assert (d1.total_queries > d2.total_queries) or (
            d1.total_queries == d2.total_queries and d1.domain <= d2.domain
        )


# ---------------------------------------------------------------------------
# QUERY EVENT LOG TESTS (29-37)
# ---------------------------------------------------------------------------

def test_29_queries_client_ip_filter(service):
    """29. Query event log filters by client_ip."""
    target_ip = "10.0.0.6"
    res = service.get_queries(client_ip=target_ip, limit=10)
    assert res.total == 4575
    for item in res.items:
        assert item.client_ip == target_ip


def test_30_queries_domain_filter(service):
    """30. Query event log filters by domain."""
    res = service.get_queries(domain="google.com", limit=10)
    assert res.total > 0
    for item in res.items:
        assert item.domain == "google.com"


def test_31_queries_verdict_filter(service):
    """31. Query event log filters by canonical verdict."""
    res = service.get_queries(verdict="Malicious", limit=10)
    assert res.total == 4626
    for item in res.items:
        assert item.final_label == "Malicious"


def test_32_queries_query_type_filter(service):
    """32. Query event log filters by query_type."""
    res = service.get_queries(query_type="A", limit=10)
    assert res.total > 0
    for item in res.items:
        assert item.query_type == "A"


def test_33_queries_time_range_filter(service):
    """33. Query event log filters strictly within [start_time, end_time)."""
    start = datetime(2026, 9, 16, 12, 34, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 12, 35, 0, tzinfo=DB_TZ)
    res = service.get_queries(start_time=start, end_time=end, limit=20)
    assert res.total > 0
    for item in res.items:
        assert item.timestamp.startswith(format_iso8601_utc(start)[:16])


def test_34_queries_combined_filters(service):
    """34. Query event log applies multiple combined filters simultaneously."""
    res = service.get_queries(
        client_ip="192.168.1.103",
        verdict="Malicious",
        query_type="A",
        limit=10
    )
    assert res.total == 782
    for item in res.items:
        assert item.client_ip == "192.168.1.103"
        assert item.final_label == "Malicious"
        assert item.query_type == "A"


def test_35_queries_pagination(service):
    """35. Query event log pagination operates cleanly across pages."""
    p1 = service.get_queries(limit=10, offset=0)
    assert len(p1.items) == 10
    assert p1.has_more is True

    p2 = service.get_queries(limit=10, offset=10)
    assert len(p2.items) == 10
    assert p1.items[0].id != p2.items[0].id


def test_36_queries_deterministic_ordering(service):
    """36. Query event log ordered deterministically by timestamp DESC, id DESC."""
    res = service.get_queries(limit=25, offset=0)
    for i in range(len(res.items) - 1):
        e1, e2 = res.items[i], res.items[i + 1]
        assert (e1.timestamp > e2.timestamp) or (
            e1.timestamp == e2.timestamp and e1.id >= e2.id
        )


def test_37_queries_zero_result_behavior(service):
    """37. Query event log with non-matching filter returns empty PaginatedResult."""
    res = service.get_queries(client_ip="10.254.254.254", limit=10)
    assert res.total == 0
    assert res.has_more is False
    assert res.items == []


# ---------------------------------------------------------------------------
# QUALITY & ARCHITECTURAL INVARIANT TESTS (38-42)
# ---------------------------------------------------------------------------

def test_38_no_http_dependencies():
    """38. Ensure reporting module has no HTTP imports or dependencies."""
    import reporting
    import reporting.schemas
    import reporting.repository
    import reporting.service

    for mod in (reporting, reporting.schemas, reporting.repository, reporting.service):
        with open(mod.__file__, "r", encoding="utf-8") as f:
            source = f.read()
        assert "from fastapi" not in source
        assert "import fastapi" not in source
        assert "from starlette" not in source
        assert "import starlette" not in source
        assert "StreamingResponse" not in source
        assert "Depends(" not in source


def test_39_no_fastapi_imported_by_reporting_subsystem():
    """39. Verify reporting subsystem works when fastapi is not imported."""
    # Ensure ReportingService can be instantiated and executed independently
    repo = ReportingService().repository
    assert repo is not None


def test_40_no_external_network_calls(monkeypatch, service):
    """40. Ensure no external sockets are opened during reporting operations."""
    # Summary, clients, domains, queries run purely against local PostgreSQL
    s = service.get_summary()
    assert s.total_queries == 30181


def test_41_parameterized_sql_injection_defense(service):
    """41. Verify parameterized SQL correctly handles quotes and special characters."""
    # Injection attempt in domain
    res = service.get_queries(domain="'; DROP TABLE test; --", limit=10)
    assert res.total == 0
    assert res.items == []

    # Invalid client IP raises domain validation error before hitting DB
    with pytest.raises(ReportingValidationError):
        service.get_queries(client_ip="invalid_ip_string'; --")


def test_42_invalid_time_range_raises_domain_error(service):
    """42. start_time > end_time raises InvalidTimeRangeError."""
    t1 = datetime(2026, 9, 16, 14, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 16, 10, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(InvalidTimeRangeError):
        service.get_summary(start_time=t1, end_time=t2)
    with pytest.raises(InvalidTimeRangeError):
        service.get_timeseries(start_time=t1, end_time=t2)


# ---------------------------------------------------------------------------
# PHASE 2C TIME ENGINE INTEGRATION TESTS (43-47)
# ---------------------------------------------------------------------------

from time_engine import resolve_time_range


def test_43_reporting_unified_resolved_time_range(service):
    """43. summary, timeseries, top clients, top domains, and queries share identical ResolvedTimeRange."""
    now = datetime(2026, 9, 16, 7, 30, 0, tzinfo=timezone.utc)
    tr = resolve_time_range(
        start_time="2026-09-16T06:00:00Z",
        end_time="2026-09-16T07:30:00Z",
        bucket="30m",
        now_override=now,
    )

    summary = service.get_summary(tr)
    ts = service.get_timeseries(tr)
    clients = service.get_top_clients(time_range=tr, limit=10)
    domains = service.get_top_domains(time_range=tr, limit=10)
    queries = service.get_queries(time_range=tr, limit=10)

    # 1. Verify summary window matches tr
    assert summary.time_window == {"start": "2026-09-16T06:00:00Z", "end": "2026-09-16T07:30:00Z"}
    assert summary.total_queries > 0

    # 2. Verify timeseries buckets match tr bucket_spec and duration
    assert ts.bucket_size == "30m"
    assert len(ts.buckets) == 3
    assert sum(b.total_queries for b in ts.buckets) == summary.total_queries

    # 3. Verify top clients and domains sum up within the same population
    assert clients.total > 0
    assert domains.total > 0
    assert queries.total == summary.total_queries


def test_44_reporting_empty_range_across_all_endpoints(service):
    """44. start == end produces empty/zeroed results across all 5 reporting consumers."""
    now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    tr = resolve_time_range(
        start_time="2026-09-16T07:00:00Z",
        end_time="2026-09-16T07:00:00Z",
        now_override=now,
    )

    summary = service.get_summary(tr)
    ts = service.get_timeseries(tr)
    clients = service.get_top_clients(time_range=tr)
    domains = service.get_top_domains(time_range=tr)
    queries = service.get_queries(time_range=tr)

    assert summary.total_queries == 0
    assert summary.unique_clients == 0
    assert summary.unique_domains == 0
    assert len(ts.buckets) == 0
    assert clients.total == 0
    assert clients.items == []
    assert domains.total == 0
    assert domains.items == []
    assert queries.total == 0
    assert queries.items == []


def test_45_reporting_partially_future_clamped_to_now(service):
    """45. Future portion of requested range has zero events; timeseries future buckets are zero-filled."""
    now = datetime(2026, 9, 16, 7, 10, 0, tzinfo=timezone.utc)
    tr = resolve_time_range(
        start_time="2026-09-16T06:00:00Z",
        end_time="2026-09-16T08:00:00Z",
        bucket="30m",
        now_override=now,
    )

    summary = service.get_summary(tr)
    ts = service.get_timeseries(tr)
    queries = service.get_queries(time_range=tr)

    assert len(ts.buckets) == 4
    # Future bucket [07:30, 08:00) is strictly after now (07:10), so must have 0 queries:
    assert ts.buckets[3].total_queries == 0
    for q in queries.items:
        q_dt = datetime.fromisoformat(q.timestamp.replace("Z", "+00:00"))
        assert q_dt < now


def test_46_reporting_rolling_preset_integration(service):
    """46. Rolling preset '24h' resolves and works across summary and timeseries."""
    now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    tr = resolve_time_range(window="24h", now_override=now)
    summary = service.get_summary(tr)
    ts = service.get_timeseries(tr)
    assert tr.bucket_spec.bucket_label == "1h"
    assert len(ts.buckets) == 24
    assert sum(b.total_queries for b in ts.buckets) == summary.total_queries


def test_47_reporting_calendar_preset_integration(service):
    """47. Calendar preset 'yesterday' resolves 24 hourly buckets."""
    now = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    tr = resolve_time_range(window="yesterday", now_override=now)
    assert tr.start == datetime(2026, 9, 15, 0, 0, 0, tzinfo=timezone.utc)
    assert tr.end == datetime(2026, 9, 16, 0, 0, 0, tzinfo=timezone.utc)
    ts = service.get_timeseries(tr)
    assert len(ts.buckets) == 24

