"""Snapshot composition without network or database."""

from types import SimpleNamespace

from reporting.report_service import ReportService
from time_engine import InvalidTimeRangeError, format_iso8601_utc


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

    def get_timeseries(self, **kwargs):
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

    def get_timeseries(self, **kwargs):
        self.timeseries_kwargs = kwargs
        return SimpleNamespace(
            buckets=[SimpleNamespace(model_dump=lambda mode="json": {"timestamp": "b1"})]
        )


class _AllTimeRaisingReporting(_FakeReporting):
    def get_timeseries(self, **kwargs):
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

