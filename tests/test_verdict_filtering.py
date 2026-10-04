"""
tests/test_verdict_filtering.py
===============================
Integration and unit tests for SQL-level verdict filtering,
free-text search, and multi-criteria sorting across reporting endpoints.
"""

import pytest
from datetime import datetime, timezone
from reporting.repository import ReportingRepository
from reporting.service import ReportingService
from reporting.schemas import CanonicalVerdict


@pytest.fixture
def repo():
    return ReportingRepository()


@pytest.fixture
def service():
    return ReportingService()


class TestVerdictFilteringSQL:
    """Verify ReportingRepository SQL-level verdict filtering."""

    def test_get_filtered_top_domains_malicious(self, repo):
        total, rows = repo.get_filtered_top_domains(
            verdict="Malicious",
            start_time=None,
            end_time=None,
            limit=10,
            offset=0,
        )
        assert isinstance(total, int)
        assert total > 0
        assert len(rows) <= 10
        for r in rows:
            assert r["latest_verdict"] == "Malicious"
            assert r["malicious_queries"] > 0

    def test_get_filtered_top_domains_benign(self, repo):
        total, rows = repo.get_filtered_top_domains(
            verdict="Benign",
            start_time=None,
            end_time=None,
            limit=10,
            offset=0,
        )
        assert isinstance(total, int)
        assert total > 0
        assert len(rows) <= 10
        for r in rows:
            assert r["latest_verdict"] == "Benign"

    def test_get_filtered_top_domains_with_search(self, repo):
        # First retrieve a domain from malicious list
        _, initial_rows = repo.get_filtered_top_domains(
            verdict="Malicious",
            start_time=None,
            end_time=None,
            limit=1,
            offset=0,
        )
        if initial_rows:
            sample_dom = initial_rows[0]["domain"]
            prefix = sample_dom[:4]
            total, rows = repo.get_filtered_top_domains(
                verdict="Malicious",
                start_time=None,
                end_time=None,
                search=prefix,
                limit=10,
                offset=0,
            )
            assert total > 0
            for r in rows:
                assert prefix.lower() in r["domain"].lower()
                assert r["latest_verdict"] == "Malicious"

    def test_get_queries_verdict_and_search(self, repo):
        total, rows = repo.get_queries(
            verdict="Malicious",
            search=None,
            limit=5,
            offset=0,
        )
        assert total > 0
        for r in rows:
            assert r["final_label"] == "Malicious"

    def test_get_queries_sorting(self, repo):
        _, rows_desc = repo.get_queries(
            verdict="Malicious",
            sort_by="timestamp",
            sort_order="desc",
            limit=5,
            offset=0,
        )
        _, rows_asc = repo.get_queries(
            verdict="Malicious",
            sort_by="timestamp",
            sort_order="asc",
            limit=5,
            offset=0,
        )
        if len(rows_desc) > 1 and len(rows_asc) > 1:
            assert rows_desc[0]["timestamp"] >= rows_desc[1]["timestamp"]
            assert rows_asc[0]["timestamp"] <= rows_asc[1]["timestamp"]


class TestReportingServiceVerdictComposition:
    """Verify ReportingService parameter normalization and delegation."""

    def test_service_get_top_domains_canonical_verdict(self, service):
        res = service.get_top_domains(
            limit=10,
            offset=0,
            verdict_filter="malicious",  # lowercase should normalize to "Malicious"
        )
        assert res.total > 0
        assert len(res.items) <= 10
        for d in res.items:
            assert d.latest_verdict == "Malicious"

    def test_service_get_queries_case_insensitive_verdict(self, service):
        res = service.get_queries(
            limit=10,
            offset=0,
            verdict="review needed",  # case-insensitive
        )
        assert res.total > 0
        for q in res.items:
            assert q.final_label == "Review Needed"
