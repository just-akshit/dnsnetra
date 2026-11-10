"""Entity reporting for unseen indicators and role gates."""

from fastapi.testclient import TestClient

from api.main import app
from investigation.live.models import IndicatorVerdict, LiveIntelReport

client = TestClient(app)


class _FakeLive:
    def lookup_domain(self, value, refresh=False):
        return LiveIntelReport(
            indicator=value,
            kind="domain",
            verdict=IndicatorVerdict(state="unknown", reasons=["no data"]),
            checked_at="2026-11-10T00:00:00Z",
        )

    def lookup_ip(self, value, refresh=False):
        return None


def test_unseen_domain_returns_a_live_dossier(monkeypatch, analyst_headers):
    from api.routes import reports as report_routes
    from investigation.service import InvestigationService

    monkeypatch.setattr(
        report_routes,
        "InvestigationService",
        lambda: InvestigationService(live_intel_service=_FakeLive()),
    )

    res = client.get(
        "/api/v1/reports/entity",
        headers=analyst_headers,
        params={"entity": "never-seen-report.example"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["entity_type"] == "domain"
    assert body["domain_dossier"]["observed_in_network"] is False


def test_support_cannot_read_entity_dossiers(support_headers):
    res = client.get(
        "/api/v1/reports/entity",
        headers=support_headers,
        params={"entity": "example.com", "entity_type": "domain"},
    )
    assert res.status_code == 403
