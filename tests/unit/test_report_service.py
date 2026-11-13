"""Snapshot composition without network or database."""

from types import SimpleNamespace

import pytest

from dnsnetra.domains.reporting.report_service import ReportService
from dnsnetra.time_engine import InvalidTimeRangeError, format_iso8601_utc


class _FakeInvestigation:
    def get_domain_dossier(self, domain, refresh_live=False):
        return SimpleNamespace(
            model_dump=lambda mode="json": {
                "domain": domain,
                "observed_in_network": False,
                "profile": None,
                "recent_queries": [],
                "live_intel": {"checked_at": "2026-11-10T00:00:00Z"},
            }
        )

    def get_client_dossier(self, client_ip, refresh_live=False):
        return SimpleNamespace(
            model_dump=lambda mode="json": {
                "client_ip": client_ip,
                "observed_in_network": True,
                "profile": None,
                "recent_queries": [],
                "live_intel": None,
            }
        )


class _FakeReporting:
    def get_summary(self, **kwargs):
        return SimpleNamespace(
            model_dump=lambda mode="json": {"total_queries": 0}
        )

    def get_entity_summary(self, entity_type, value, **kwargs):
        return SimpleNamespace(
            total_queries=0,
            model_dump=lambda mode="json": {"total_queries": 0},
        )

    def get_timeseries(self, **kwargs):
        return SimpleNamespace(buckets=[])

    def get_entity_timeseries(self, entity_type, value, **kwargs):
        return SimpleNamespace(buckets=[])

    def get_queries(self, **kwargs):
        return SimpleNamespace(
            total=2,
            items=[SimpleNamespace(model_dump=lambda mode="json": {"id": 1})],
        )


def test_domain_snapshot_keeps_provenance_and_caps_rows():
    service = ReportService(
        investigation_service=_FakeInvestigation(),
        reporting_service=_FakeReporting(),
    )
    snapshot = service.build_snapshot(
        kind="entity_domain",
        entity="example.com",
        window=None,
        start_time=None,
        end_time=None,
        filters={},
    )

    assert snapshot["schema_version"] == 1
    assert snapshot["kind"] == "entity_domain"
    assert snapshot["entity"] == {"type": "domain", "value": "example.com"}
    assert snapshot["observed_in_network"] is False
    assert "live_intel" in snapshot["dossier"]
    assert snapshot["provenance"]["live_intel_checked_at"] == "2026-11-10T00:00:00Z"


def test_query_set_snapshot_records_filters_and_preview():
    service = ReportService(reporting_service=_FakeReporting())
    snapshot = service.build_snapshot(
        kind="query_set",
        entity=None,
        window="24h",
        start_time=None,
        end_time=None,
        filters={"verdict": "Malicious"},
    )

    assert snapshot["kind"] == "query_set"
    assert snapshot["filters"] == {"verdict": "Malicious"}
    assert snapshot["summary"]["total_queries"] == 0
    assert len(snapshot["preview_queries"]) == 1


class _RecordingReporting(_FakeReporting):
    def __init__(self):
        self.timeseries_kwargs = {}

    def get_entity_timeseries(self, entity_type, value, **kwargs):
        self.timeseries_kwargs = kwargs
        return SimpleNamespace(
            buckets=[SimpleNamespace(model_dump=lambda mode="json": {"timestamp": "b1"})]
        )


class _AllTimeRaisingReporting(_FakeReporting):
    def get_entity_timeseries(self, entity_type, value, **kwargs):
        raise InvalidTimeRangeError("All-time timeseries is not permitted.")


class _FakeRepository:
    def __init__(self):
        self.created = None

    def create(self, **kwargs):
        self.created = kwargs
        return SimpleNamespace(**kwargs)


def test_7d_entity_snapshot_uses_preset_bucket_and_keeps_buckets():
    reporting = _RecordingReporting()
    service = ReportService(
        investigation_service=_FakeInvestigation(),
        reporting_service=reporting,
    )
    snapshot = service.build_snapshot(
        kind="entity_domain",
        entity="example.com",
        window="7d",
        start_time=None,
        end_time=None,
        filters={},
    )

    assert "bucket" not in reporting.timeseries_kwargs
    assert "time_range" in reporting.timeseries_kwargs
    assert len(snapshot["timeline"]) == 1
    assert snapshot["provenance"]["timeline_available"] is True


def test_all_time_entity_snapshot_records_missing_timeline():
    service = ReportService(
        investigation_service=_FakeInvestigation(),
        reporting_service=_AllTimeRaisingReporting(),
    )
    snapshot = service.build_snapshot(
        kind="entity_client",
        entity="192.0.2.1",
        window=None,
        start_time=None,
        end_time=None,
        filters=None,
    )

    assert snapshot["timeline"] == []
    assert snapshot["provenance"]["timeline_available"] is False


def test_none_filters_normalize_to_empty_dict():
    service = ReportService(reporting_service=_FakeReporting())
    snapshot = service.build_snapshot(
        kind="query_set",
        entity=None,
        window="24h",
        start_time=None,
        end_time=None,
        filters=None,
    )

    assert snapshot["filters"] == {}


def test_create_normalizes_filters_and_reuses_one_resolved_window():
    repository = _FakeRepository()
    service = ReportService(
        repository=repository,
        reporting_service=_FakeReporting(),
    )
    service.create(
        kind="query_set",
        entity=None,
        window="24h",
        start_time=None,
        end_time=None,
        filters=None,
        title="",
        user_id=1,
    )

    assert repository.created["filters"] == {}
    assert repository.created["snapshot"]["filters"] == {}
    assert repository.created["snapshot"]["window"]["start"] == format_iso8601_utc(
        repository.created["window_start"]
    )
    assert repository.created["snapshot"]["window"]["end"] == format_iso8601_utc(
        repository.created["window_end"]
    )



class _ManyQueriesReporting(_FakeReporting):
    """Return more events than the dossier's 25-row preview would."""

    def __init__(self, count=600):
        self.count = count
        self.query_kwargs = None

    def get_queries(self, **kwargs):
        self.query_kwargs = kwargs
        limit = kwargs.get("limit", self.count)
        items = [
            SimpleNamespace(
                model_dump=lambda mode="json", i=i: {"id": i, "domain": "example.com"}
            )
            for i in range(min(self.count, limit))
        ]
        return SimpleNamespace(total=self.count, items=items)


def test_entity_snapshot_captures_up_to_500_recent_queries():
    reporting = _ManyQueriesReporting(count=600)
    service = ReportService(
        investigation_service=_FakeInvestigation(),
        reporting_service=reporting,
    )

    snapshot = service.build_snapshot(
        kind="entity_domain", entity="example.com", window="7d",
        start_time=None, end_time=None, filters={},
    )

    assert reporting.query_kwargs["domain_exact"] == "example.com"
    assert "domain" not in reporting.query_kwargs
    assert reporting.query_kwargs["limit"] == 500
    assert reporting.query_kwargs["offset"] == 0
    assert len(snapshot["dossier"]["recent_queries"]) == 500


class _EntityScopedReporting(_FakeReporting):
    def __init__(self, total=7, raise_timeseries=False):
        self.total = total
        self.raise_timeseries = raise_timeseries
        self.summary_args = None
        self.timeseries_args = None

    def get_summary(self, **kwargs):
        raise AssertionError("network-wide summary must not be used")

    def get_entity_summary(self, entity_type, value, **kwargs):
        self.summary_args = (entity_type, value, kwargs)
        return SimpleNamespace(
            total_queries=self.total,
            model_dump=lambda mode="json": {"total_queries": self.total},
        )

    def get_entity_timeseries(self, entity_type, value, **kwargs):
        self.timeseries_args = (entity_type, value, kwargs)
        if self.raise_timeseries:
            raise InvalidTimeRangeError("All-time timeseries is not permitted.")
        return SimpleNamespace(
            buckets=[SimpleNamespace(model_dump=lambda mode="json": {"total_queries": self.total})]
        )


def test_entity_snapshot_uses_entity_scoped_summary_and_timeline():
    reporting = _EntityScopedReporting(total=7)
    service = ReportService(
        investigation_service=_FakeInvestigation(),
        reporting_service=reporting,
    )

    snapshot = service.build_snapshot(
        kind="entity_domain", entity="example.com", window="7d",
        start_time=None, end_time=None, filters={},
    )

    assert snapshot["row_count"] == 7
    assert snapshot["summary"]["total_queries"] == 7
    assert len(snapshot["timeline"]) == 1
    assert reporting.summary_args[0:2] == ("domain", "example.com")
    assert reporting.timeseries_args[0:2] == ("domain", "example.com")


def test_all_time_entity_snapshot_stays_entity_scoped_without_timeline():
    reporting = _EntityScopedReporting(total=5, raise_timeseries=True)
    service = ReportService(
        investigation_service=_FakeInvestigation(),
        reporting_service=reporting,
    )

    snapshot = service.build_snapshot(
        kind="entity_client", entity="192.0.2.1", window=None,
        start_time=None, end_time=None, filters={},
    )

    assert snapshot["row_count"] == 5
    assert snapshot["summary"]["total_queries"] == 5
    assert snapshot["timeline"] == []
    assert snapshot["provenance"]["timeline_available"] is False
    assert reporting.summary_args[0:2] == ("client", "192.0.2.1")


def test_query_set_create_requires_a_window_or_filter():
    service = ReportService(
        repository=_FakeRepository(), reporting_service=_FakeReporting(),
    )

    with pytest.raises(ValueError):
        service.create(
            kind="query_set", entity=None, window=None, start_time=None,
            end_time=None, filters={}, title=None, user_id=1,
        )


@pytest.mark.parametrize("filters", [{"search": "   "}, {"bogus": "x"}])
def test_query_set_create_rejects_blank_or_unknown_filters(filters):
    service = ReportService(
        repository=_FakeRepository(), reporting_service=_FakeReporting(),
    )

    with pytest.raises(ValueError):
        service.create(
            kind="query_set", entity=None, window=None, start_time=None,
            end_time=None, filters=filters, title=None, user_id=1,
        )


def test_query_set_create_accepts_a_trimmed_known_filter():
    repository = _FakeRepository()
    service = ReportService(
        repository=repository, reporting_service=_FakeReporting(),
    )

    service.create(
        kind="query_set", entity=None, window=None, start_time=None,
        end_time=None, filters={"search": "  beacon  "}, title=None, user_id=1,
    )

    assert repository.created["filters"] == {"search": "  beacon  "}


def test_create_canonicalizes_domain_entity():
    repository = _FakeRepository()
    service = ReportService(
        repository=repository,
        investigation_service=_FakeInvestigation(),
        reporting_service=_FakeReporting(),
    )

    service.create(
        kind="entity_domain", entity="EXAMPLE.COM.", window="24h",
        start_time=None, end_time=None, filters={}, title=None, user_id=1,
    )

    assert repository.created["entity_value"] == "example.com"
    assert repository.created["snapshot"]["entity"]["value"] == "example.com"


def test_create_canonicalizes_client_ip_entity():
    repository = _FakeRepository()
    service = ReportService(
        repository=repository,
        investigation_service=_FakeInvestigation(),
        reporting_service=_FakeReporting(),
    )

    service.create(
        kind="entity_client", entity="2001:0db8::0001", window="24h",
        start_time=None, end_time=None, filters={}, title=None, user_id=1,
    )

    assert repository.created["entity_value"] == "2001:db8::1"
    assert repository.created["snapshot"]["entity"]["value"] == "2001:db8::1"
