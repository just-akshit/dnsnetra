"""Dossier behavior for entities with no local telemetry (no network, no DB)."""

import pytest

from dnsnetra.domains.investigations.live.models import IndicatorVerdict, LiveIntelReport
from dnsnetra.domains.investigations.schemas import InvalidEntityError
from dnsnetra.domains.investigations.service import InvestigationService


def live_report(indicator: str, kind: str) -> LiveIntelReport:
    return LiveIntelReport(
        indicator=indicator,
        kind=kind,
        verdict=IndicatorVerdict(state="unknown", reasons=["no data"]),
        checked_at="2026-11-08T00:00:00Z",
    )


class FakeLiveIntel:
    def __init__(self):
        self.refresh_calls: list[bool] = []

    def lookup_domain(self, domain: str, refresh: bool = False) -> LiveIntelReport:
        self.refresh_calls.append(refresh)
        return live_report(domain, "domain")

    def lookup_ip(self, ip: str, refresh: bool = False) -> LiveIntelReport:
        self.refresh_calls.append(refresh)
        return live_report(ip, "ip")


class FakeRepo:
    def __init__(self, domain_profile=None, client_profile=None):
        self._domain_profile = domain_profile
        self._client_profile = client_profile

    def get_domain_profile(self, domain):
        return self._domain_profile

    def get_domain_querying_clients(self, domain, limit):
        return []

    def get_domain_threat_intel(self, domain):
        return {}

    def get_client_profile(self, client_ip):
        return self._client_profile

    def get_client_relationships(self, client_ip, limit):
        return []

    def get_client_threat_activity(self, client_ip, limit):
        return []


class FakeReporting:
    def get_queries(self, **kwargs):
        return 0, []


DOMAIN_PROFILE = {
    "domain": "example.com",
    "first_seen": "2026-01-01T00:00:00Z",
    "last_seen": "2026-01-02T00:00:00Z",
    "total_queries": 5,
    "unique_clients": 1,
    "benign_queries": 5,
    "malicious_queries": 0,
    "review_needed_queries": 0,
    "unknown_queries": 0,
}

CLIENT_PROFILE = {
    "client_ip": "10.0.0.5",
    "first_seen": "2026-01-01T00:00:00Z",
    "last_seen": "2026-01-02T00:00:00Z",
    "total_queries": 5,
    "unique_domains": 1,
    "benign_queries": 5,
    "malicious_queries": 0,
    "review_needed_queries": 0,
    "unknown_queries": 0,
}


def service(repo: FakeRepo) -> InvestigationService:
    return InvestigationService(
        investigation_repository=repo,
        reporting_repository=FakeReporting(),
        live_intel_service=FakeLiveIntel(),
    )


def test_unseen_domain_returns_live_report_instead_of_404():
    dossier = service(FakeRepo()).get_domain_dossier("never-seen.example")

    assert dossier.profile is None
    assert dossier.observed_in_network is False
    assert dossier.live_intel is not None
    assert dossier.threat_intel.reputation is None


def test_unseen_client_returns_live_report_instead_of_404():
    dossier = service(FakeRepo()).get_client_dossier("203.0.113.10")

    assert dossier.profile is None
    assert dossier.observed_in_network is False
    assert dossier.live_intel is not None
    assert dossier.top_domains == []


def test_known_domain_keeps_local_profile():
    dossier = service(FakeRepo(domain_profile=DOMAIN_PROFILE)).get_domain_dossier("example.com")

    assert dossier.profile is not None
    assert dossier.observed_in_network is True
    assert dossier.live_intel is not None


def test_known_client_keeps_local_profile():
    dossier = service(FakeRepo(client_profile=CLIENT_PROFILE)).get_client_dossier("10.0.0.5")

    assert dossier.profile is not None
    assert dossier.observed_in_network is True
    assert dossier.live_intel is not None


def test_malformed_input_is_still_rejected():
    svc = service(FakeRepo())

    with pytest.raises(InvalidEntityError):
        svc.get_domain_dossier("not a domain")
    with pytest.raises(InvalidEntityError):
        svc.get_client_dossier("192.168.1.999")


def test_refresh_flag_reaches_live_lookup():
    live = FakeLiveIntel()
    svc = InvestigationService(
        investigation_repository=FakeRepo(),
        reporting_repository=FakeReporting(),
        live_intel_service=live,
    )

    svc.get_domain_dossier("never-seen.example", refresh_live=True)
    svc.get_domain_dossier("never-seen.example")

    assert live.refresh_calls == [True, False]
