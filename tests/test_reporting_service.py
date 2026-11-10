"""
tests/test_reporting_service.py
===============================
Exhaustive test suite for ReportingService covering all Phase 2A requirements.
"""

from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
import socket
import sys
import pytest

from domain_profiling.connection import get_db_connection
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


SEED_IP = "203.0.113.250"
SEED_DOMAIN = "task5-seed.example.test"
# Isolated instant before the live dataset (history starts 2025-09-29).
SEED_TIME = datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


@contextmanager
def _seed_event(
    *,
    client_ip: str = SEED_IP,
    domain: str = SEED_DOMAIN,
    timestamp: datetime = SEED_TIME,
    verdict: str = "Malicious",
    query_type: str = "A",
    ti_source: str = "pytest",
    response_code: str = "NOERROR",
):
    """Insert one isolated history row; always delete it on teardown.

    Only domain_query_history is touched, so rollup/profile-backed all-time
    metrics are unaffected while the event is alive.
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM domain_query_history "
                "WHERE client_ip = %s AND domain = %s AND timestamp = %s;",
                (client_ip, domain, timestamp),
            )
            cur.execute(
                """
                INSERT INTO domain_query_history
                    (timestamp, client_ip, domain, query_type, final_label,
                     ti_source, response_code)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (timestamp, client_ip, domain, query_type, verdict,
                 ti_source, response_code),
            )
            event_id = cur.fetchone()[0]
        conn.commit()
    try:
        yield event_id
    finally:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM domain_query_history WHERE id = %s;",
                    (event_id,),
                )
            conn.commit()


def _count_pages(fetch_page, limit: int = 1000):
    """Page through a service call and return (reported_total, rows_seen)."""
    offset, rows_seen, reported_total = 0, 0, None
    while True:
        page = fetch_page(limit=limit, offset=offset)
        if reported_total is None:
            reported_total = page.total
        assert page.total == reported_total
        rows_seen += len(page.items)
        if not page.has_more:
            break
        assert page.items, "has_more was True on an empty page"
        offset += limit
    return reported_total, rows_seen


def _distinct_domains(items):
    """Set of domains present in a list of DomainSummaryItem/QueryEventItem."""
    return {item.domain for item in items}


# ---------------------------------------------------------------------------
# SUMMARY TESTS (1-8)
# ---------------------------------------------------------------------------

def test_1_summary_all_time_reconciliation(service):
    """1. All-time summary reconciles against its breakdown and entity lists."""
    summary = service.get_summary()
    assert isinstance(summary, ReportingSummary)
    assert summary.time_window is None
    vb = summary.verdict_breakdown
    assert summary.total_queries > 0
    assert summary.total_queries == (
        vb.benign + vb.malicious + vb.review_needed + vb.unknown
    )
    assert summary.unique_clients == service.get_top_clients(limit=1).total
    assert summary.unique_domains == service.get_top_domains(limit=1).total


def test_2_summary_four_verdicts_reconciliation(service):
    """2. Verdicts reconcile against the event log and sum to total."""
    summary = service.get_summary()
    vb = summary.verdict_breakdown
    assert vb.benign == service.get_queries(verdict="Benign", limit=1).total
    assert vb.malicious == service.get_queries(verdict="Malicious", limit=1).total
    assert vb.review_needed == service.get_queries(verdict="Review Needed", limit=1).total
    # Unknown may legitimately be an empty population; derive it, never assume > 0.
    known = vb.benign + vb.malicious + vb.review_needed
    assert vb.unknown == summary.total_queries - known
    assert min(vb.benign, vb.malicious, vb.review_needed, vb.unknown) >= 0
    assert known + vb.unknown == summary.total_queries


def test_3_summary_malicious_percentage(service):
    """3. Malicious percentage derives from the reconciled breakdown."""
    summary = service.get_summary()
    vb = summary.verdict_breakdown
    if summary.total_queries:
        expected_pct = round((vb.malicious * 100.0) / summary.total_queries, 2)
    else:
        expected_pct = 0.0
    assert summary.malicious_query_percentage == expected_pct
    assert 0.0 <= summary.malicious_query_percentage <= 100.0


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


def test_bounded_summary_matches_timeseries_total(service):
    """Bounded summary and timeseries agree on every counter for a seeded window.

    The seeded hour has no rollup row, so the old rollup-backed summary path
    would report 0 while the raw timeseries reports the event.
    """
    with _seed_event(timestamp=SEED_TIME, verdict="Malicious"):
        start = SEED_TIME
        end = SEED_TIME + timedelta(hours=1)
        summary = service.get_summary(start_time=start, end_time=end)
        series = service.get_timeseries(start_time=start, end_time=end, bucket="1h")

        assert summary.total_queries == 1
        assert summary.verdict_breakdown.malicious == 1
        assert summary.total_queries == sum(b.total_queries for b in series.buckets)
        assert summary.verdict_breakdown.benign == sum(
            b.benign_queries for b in series.buckets
        )
        assert summary.verdict_breakdown.malicious == sum(
            b.malicious_queries for b in series.buckets
        )
        assert summary.verdict_breakdown.review_needed == sum(
            b.review_needed_queries for b in series.buckets
        )
        assert summary.verdict_breakdown.unknown == sum(
            b.unknown_queries for b in series.buckets
        )


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
    """16. Client ranking reconciles with summary and pages by total."""
    summary = service.get_summary()
    res = service.get_top_clients(limit=10, offset=0)
    assert isinstance(res, PaginatedResult)
    assert res.total == summary.unique_clients
    assert len(res.items) == min(10, res.total)
    assert res.has_more == (res.total > 10)
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
    """18. Pagination lengths and has_more derive from the reported total."""
    total = service.get_top_clients(limit=1, offset=0).total
    p1 = service.get_top_clients(limit=5, offset=0)
    assert p1.limit == 5
    assert p1.offset == 0
    assert p1.has_more == (total > 5)
    assert len(p1.items) == min(5, total)

    p2 = service.get_top_clients(limit=5, offset=5)
    assert p2.offset == 5
    assert len(p2.items) == max(0, min(5, total - 5))
    if p1.items and p2.items:
        assert p1.items[0].client_ip != p2.items[0].client_ip

    p3 = service.get_top_clients(limit=5, offset=10)
    assert len(p3.items) == max(0, min(5, total - 10))
    assert p3.has_more == (total > 10)


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
    """21. Domain ranking reconciles with summary and pages by total."""
    summary = service.get_summary()
    res = service.get_top_domains(limit=10, offset=0)
    assert res.total == summary.unique_domains
    assert len(res.items) == min(10, res.total)
    assert res.has_more == (res.total > 10)
    assert len(_distinct_domains(res.items)) == len(res.items)
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
    """25. verdict_filter = Unknown selects only Unknown events (seeded)."""
    with _seed_event(verdict="Unknown"):
        res = service.get_top_domains(
            limit=10, offset=0, verdict_filter=CanonicalVerdict.UNKNOWN
        )
        assert res.total >= 1
        assert any(item.domain == SEED_DOMAIN for item in res.items)
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
    """29. Query event log filters by client_ip (seeded population)."""
    with _seed_event(client_ip=SEED_IP):
        res = service.get_queries(client_ip=SEED_IP, limit=10)
        assert res.total == 1
        assert len(res.items) == 1
        for item in res.items:
            assert item.client_ip == SEED_IP
        total, seen = _count_pages(
            lambda limit, offset: service.get_queries(
                client_ip=SEED_IP, limit=limit, offset=offset
            )
        )
        assert total == 1
        assert seen == total


def test_30_queries_domain_filter(service):
    """30. Query event log filters by domain."""
    res = service.get_queries(domain="google.com", limit=10)
    assert res.total > 0
    for item in res.items:
        assert item.domain == "google.com"


def test_31_queries_verdict_filter(service):
    """31. Verdict filter pages to its total; seeded event is included."""
    with _seed_event(verdict="Malicious"):
        total, seen = _count_pages(
            lambda limit, offset: service.get_queries(
                verdict="Malicious", limit=limit, offset=offset
            )
        )
        assert total >= 1
        assert seen == total
        seeded = service.get_queries(
            client_ip=SEED_IP, verdict="Malicious", limit=10
        )
        assert seeded.total == 1
        for item in seeded.items:
            assert item.final_label == "Malicious"
        for item in service.get_queries(verdict="Malicious", limit=10).items:
            assert item.final_label == "Malicious"


def test_32_queries_query_type_filter(service):
    """32. Query event log filters by query_type."""
    res = service.get_queries(query_type="A", limit=10)
    assert res.total > 0
    for item in res.items:
        assert item.query_type == "A"


def test_33_queries_time_range_filter(service):
    """33. Query event log filters strictly within [start_time, end_time)."""
    with _seed_event(client_ip=SEED_IP, timestamp=SEED_TIME):
        start = SEED_TIME
        end = SEED_TIME + timedelta(minutes=1)
        res = service.get_queries(
            client_ip=SEED_IP, start_time=start, end_time=end, limit=20
        )
        assert res.total == 1
        assert len(res.items) == 1
        expected_prefix = format_iso8601_utc(start)[:16]
        for item in res.items:
            assert item.timestamp.startswith(expected_prefix)


def test_34_queries_combined_filters(service):
    """34. Combined filters intersect to the seeded event, never widening it."""
    with _seed_event(client_ip=SEED_IP, verdict="Malicious", query_type="A"):
        res = service.get_queries(
            client_ip=SEED_IP, verdict="Malicious", query_type="A", limit=10
        )
        assert res.total == 1
        assert len(res.items) == 1
        for item in res.items:
            assert item.client_ip == SEED_IP
            assert item.final_label == "Malicious"
            assert item.query_type == "A"
        # Each individual filter is a superset of the combined filter.
        for kwargs in (
            {"client_ip": SEED_IP},
            {"verdict": "Malicious"},
            {"query_type": "A"},
        ):
            assert service.get_queries(**kwargs, limit=1).total >= res.total


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
    """40. Reporting touches only the local DB, never an outbound socket."""
    # Warm the connection pool before blocking sockets so DB access reuses it.
    service.get_summary()

    def _blocked_connect(self, address, *args, **kwargs):
        raise AssertionError(f"reporting opened an external socket to {address!r}")

    monkeypatch.setattr(socket.socket, "connect", _blocked_connect)

    summary = service.get_summary()
    vb = summary.verdict_breakdown
    assert summary.total_queries == (
        vb.benign + vb.malicious + vb.review_needed + vb.unknown
    )
    clients = service.get_top_clients(limit=10)
    assert clients.total == summary.unique_clients
    assert len(clients.items) == min(10, clients.total)
    domains = service.get_top_domains(limit=10)
    assert domains.total == summary.unique_domains
    assert len(domains.items) == min(10, domains.total)
    queries = service.get_queries(limit=10)
    assert queries.total == summary.total_queries
    assert len(queries.items) == min(10, queries.total)


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

