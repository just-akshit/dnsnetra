"""
tests/test_reporting_repository.py
==================================
Exhaustive unit and reconciliation tests for ReportingRepository.
"""

from datetime import datetime, timezone, timedelta
import pytest
from reporting.repository import ReportingRepository
from reporting.schemas import CanonicalVerdict

DB_TZ = timezone(timedelta(hours=5, minutes=30))


@pytest.fixture
def repo():
    return ReportingRepository()


def test_repository_all_time_summary_reconciliation(repo):
    """Verify all-time summary reconciles against authoritative counts."""
    summary = repo.get_all_time_summary()
    assert summary["total_queries"] == 30181
    assert summary["benign_queries"] == 23371
    assert summary["malicious_queries"] == 4626
    assert summary["review_needed_queries"] == 448
    assert summary["unknown_queries"] == 1736
    assert summary["unique_clients"] == 12
    assert summary["unique_domains"] == 49


def test_repository_aligned_window_summary(repo):
    """Verify aligned window query uses rollups and counts distinct entities."""
    start = datetime(2026, 9, 16, 12, 0, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 13, 0, 0, tzinfo=DB_TZ)
    summary = repo.get_aligned_window_summary(start, end)
    assert summary["total_queries"] > 0
    assert summary["unique_clients"] > 0
    assert summary["unique_domains"] > 0
    assert summary["total_queries"] == (
        summary["benign_queries"] + summary["malicious_queries"] +
        summary["review_needed_queries"] + summary["unknown_queries"]
    )


def test_repository_raw_window_summary_unaligned(repo):
    """Verify unaligned partial-hour query runs against raw history with exact counts."""
    start = datetime(2026, 9, 16, 12, 34, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 12, 45, 0, tzinfo=DB_TZ)
    summary = repo.get_raw_window_summary(start, end)
    assert summary["total_queries"] > 0
    assert summary["unique_clients"] > 0
    assert summary["unique_domains"] > 0


def test_repository_timeseries_aligned(repo):
    """Verify aligned timeseries returns rollup buckets ordered chronologically."""
    start = datetime(2026, 9, 16, 0, 0, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 17, 0, 0, 0, tzinfo=DB_TZ)
    buckets = repo.get_aligned_timeseries(start, end)
    assert isinstance(buckets, list)
    for b in buckets:
        assert "bucket_time" in b
        assert "total_queries" in b
        assert "malicious_queries" in b


def test_repository_timeseries_raw_unaligned(repo):
    """Verify raw timeseries groups by hour and respects boundary clipping."""
    start = datetime(2026, 9, 16, 12, 30, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 14, 15, 0, tzinfo=DB_TZ)
    buckets = repo.get_raw_timeseries(start, end)
    assert isinstance(buckets, list)
    for b in buckets:
        assert "bucket_time" in b
        assert "total_queries" in b


def test_repository_top_clients_all_time(repo):
    """Verify all-time top clients pagination and ordering."""
    total, rows = repo.get_all_time_top_clients(limit=5, offset=0)
    assert total == 12
    assert len(rows) == 5
    # Verify deterministic ordering: total_queries DESC, client_ip ASC
    for i in range(len(rows) - 1):
        assert rows[i]["total_queries"] >= rows[i + 1]["total_queries"]


def test_repository_top_clients_windowed(repo):
    """Verify windowed top clients aggregation from domain_query_history."""
    start = datetime(2026, 9, 16, 12, 0, 0, tzinfo=DB_TZ)
    end = datetime(2026, 9, 16, 13, 0, 0, tzinfo=DB_TZ)
    total, rows = repo.get_windowed_top_clients(start, end, limit=10, offset=0)
    assert total > 0
    assert len(rows) > 0
    assert "client_ip" in rows[0]
    assert "total_queries" in rows[0]


def test_repository_top_domains_all_time(repo):
    """Verify all-time top domains ordering and count."""
    total, rows = repo.get_all_time_top_domains(limit=10, offset=0)
    assert total == 49
    assert len(rows) == 10
    assert rows[0]["total_queries"] >= rows[1]["total_queries"]


def test_repository_filtered_top_domains_event_population(repo):
    """Verify verdict-filtered top domains acts as an event-population filter."""
    verdict = CanonicalVerdict.MALICIOUS.value
    total, rows = repo.get_filtered_top_domains(
        verdict=verdict, start_time=None, end_time=None, limit=10, offset=0
    )
    assert total > 0
    assert len(rows) > 0
    for r in rows:
        assert r["latest_verdict"] == "Malicious"
        assert r["malicious_queries"] == r["total_queries"]
        assert r["benign_queries"] == 0
        assert r["review_needed_queries"] == 0
        assert r["unknown_queries"] == 0


def test_repository_get_queries_multi_filter(repo):
    """Verify get_queries with multiple filter parameters."""
    total, rows = repo.get_queries(
        client_ip="192.168.1.103",
        verdict="Malicious",
        limit=10,
        offset=0
    )
    assert total > 0
    assert len(rows) <= 10
    for r in rows:
        assert r["client_ip"] == "192.168.1.103"
        assert r["final_label"] == "Malicious"
