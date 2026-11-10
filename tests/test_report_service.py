"""Snapshot composition without network or database."""

from types import SimpleNamespace

from reporting.report_service import ReportService


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
