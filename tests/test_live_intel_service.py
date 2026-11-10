"""Unit tests for LiveIntelService with fake providers (no network, no database)."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from investigation.enrichment.models import DNSResolutionResult, DomainRegistrationResult
from investigation.live.service import LiveIntelService, reset_live_intel_cache
from labeler.intel.correlation.models import ThreatProviderResult


class FakeProvider:
    def __init__(self, name: str, result: ThreatProviderResult):
        self.provider_name = name
        self.result = result
        self.calls = 0

    def lookup(self, value: str) -> ThreatProviderResult:
        self.calls += 1
        return self.result

    def lookup_ip(self, value: str) -> ThreatProviderResult:
        self.calls += 1
        return self.result


class ExplodingProvider:
    provider_name = "VirusTotal"

    def lookup(self, value: str) -> ThreatProviderResult:
        raise RuntimeError("provider is down")


class SlowProvider:
    provider_name = "VirusTotal"

    def lookup(self, value: str) -> ThreatProviderResult:
        time.sleep(0.3)
        return vt_result()


class FakeDNS:
    def resolve(self, domain: str, deadline=None) -> DNSResolutionResult:
        return DNSResolutionResult(status="AVAILABLE", a=["93.184.216.34"])


class FakeRDAP:
    def enrich(self, domain: str, deadline=None) -> DomainRegistrationResult:
        return DomainRegistrationResult(
            status="AVAILABLE",
            registrar="Example Registrar",
            created_at="1997-09-15T04:00:00Z",
        )


def vt_result(malicious: int = 12, total: int = 90) -> ThreatProviderResult:
    return ThreatProviderResult(
        provider="VirusTotal",
        malicious=malicious > 0,
        confidence=malicious / total if total else 0.0,
        malicious_count=malicious,
        harmless_count=max(total - malicious, 0),
        raw_data={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "harmless": max(total - malicious, 0),
                        "suspicious": 0,
                        "undetected": 0,
                    },
                    "categories": {"engine": "malware"},
                    "reputation": -42,
                }
            }
        },
    )


def otx_result(pulses: int = 0) -> ThreatProviderResult:
    pulse_items = [{"name": f"pulse-{index}"} for index in range(pulses)]
    return ThreatProviderResult(
        provider="AlienVault OTX",
        malicious=pulses >= 3,
        malicious_count=pulses,
        found=pulses > 0,
        raw_data={"general": {"pulse_info": {"count": pulses, "pulses": pulse_items}}},
    )


def vt_ip_result() -> ThreatProviderResult:
    return ThreatProviderResult(
        provider="VirusTotal",
        malicious=False,
        malicious_count=0,
        harmless_count=70,
        raw_data={
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "harmless": 70,
                        "suspicious": 0,
                        "undetected": 10,
                    },
                    "asn": 15169,
                    "as_owner": "Google LLC",
                    "country": "US",
                    "network": "8.8.8.0/24",
                    "reputation": 100,
                }
            }
        },
    )


@pytest.fixture(autouse=True)
def clear_cache():
    reset_live_intel_cache()
    yield
    reset_live_intel_cache()


def service(vt: FakeProvider, otx: FakeProvider) -> LiveIntelService:
    return LiveIntelService(
        providers=[vt, otx],
        dns_resolver=FakeDNS(),
        rdap_enricher=FakeRDAP(),
    )


def test_unseen_domain_gets_live_verdict_and_enrichment():
    vt = FakeProvider("VirusTotal", vt_result())
    otx = FakeProvider("AlienVault OTX", otx_result(0))

    report = service(vt, otx).lookup_domain("never-seen.example")

    assert report.kind == "domain"
    assert report.verdict.state == "malicious"
    assert report.dns_records is not None
    assert report.registration is not None
    assert len(report.providers) == 2


def test_cache_prevents_duplicate_provider_calls():
    vt = FakeProvider("VirusTotal", vt_result())
    otx = FakeProvider("AlienVault OTX", otx_result(0))
    live = service(vt, otx)

    first = live.lookup_domain("cached.example")
    second = live.lookup_domain("cached.example")

    assert first.verdict.state == "malicious"
    assert second is first
    assert vt.calls == 1
    assert otx.calls == 1


def test_concurrent_lookups_for_the_same_indicator_make_one_provider_call():
    """Two analysts opening the same unseen domain must share one upstream lookup.

    Each request builds its own LiveIntelService, so single-flight has to live
    at module scope alongside the cache, not on the instance.
    """
    entered = threading.Event()
    release = threading.Event()
    calls = 0
    lock = threading.Lock()

    class BlockingProvider(FakeProvider):
        def lookup(self, value: str) -> ThreatProviderResult:
            nonlocal calls
            with lock:
                calls += 1
            entered.set()
            assert release.wait(2), "provider was never released"
            return self.result

    vt = BlockingProvider("VirusTotal", vt_result())
    otx = FakeProvider("AlienVault OTX", otx_result(0))
    barrier = threading.Barrier(6)

    def lookup() -> object:
        barrier.wait()
        return LiveIntelService(
            providers=[vt, otx],
            dns_resolver=FakeDNS(),
            rdap_enricher=FakeRDAP(),
        ).lookup_domain("concurrent.example")

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(lookup) for _ in range(6)]
        assert entered.wait(2), "provider was never called"
        # All six are now inside _cached; the leader is blocked upstream.
        time.sleep(0.1)
        assert calls == 1, "concurrent lookups must collapse into one upstream call"
        release.set()
        reports = [future.result() for future in futures]

    assert len({id(report) for report in reports}) == 1


def test_failed_build_wakes_waiters_and_clears_the_flight():
    """A raising leader must not poison the slot or strand its followers."""
    entered = threading.Event()
    release = threading.Event()
    calls = 0
    lock = threading.Lock()

    def failing_builder() -> object:
        nonlocal calls
        with lock:
            calls += 1
        entered.set()
        assert release.wait(2), "builder was never released"
        raise RuntimeError("provider is down")

    live = service(FakeProvider("VirusTotal", vt_result()), FakeProvider("AlienVault OTX", otx_result(0)))
    barrier = threading.Barrier(3)
    outcomes: list[str] = []

    def worker() -> None:
        barrier.wait()
        try:
            live._cached("domain:fail.example", failing_builder)
        except RuntimeError as exc:
            outcomes.append(str(exc))

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(worker) for _ in range(3)]
        assert entered.wait(2)
        time.sleep(0.1)
        assert calls == 1
        release.set()
        for future in futures:
            future.result()

    assert outcomes == ["provider is down"] * 3

    # The slot is reusable: this would hang for the inflight timeout if the
    # failed flight had been left behind.
    assert live._cached("domain:fail.example", lambda: "recovered") == "recovered"


def test_refresh_bypasses_the_cache():
    vt = FakeProvider("VirusTotal", vt_result())
    otx = FakeProvider("AlienVault OTX", otx_result(0))
    live = service(vt, otx)

    live.lookup_domain("refreshed.example")
    live.lookup_domain("refreshed.example", refresh=True)

    assert vt.calls == 2
    assert otx.calls == 2


def test_private_ip_skips_external_providers():
    vt = FakeProvider("VirusTotal", vt_ip_result())
    otx = FakeProvider("AlienVault OTX", otx_result(0))

    report = service(vt, otx).lookup_ip("192.168.1.10")

    assert report.verdict.state == "unknown"
    assert report.providers == []
    assert vt.calls == 0
    assert otx.calls == 0


def test_public_ip_includes_network_context():
    vt = FakeProvider("VirusTotal", vt_ip_result())
    otx = FakeProvider("AlienVault OTX", otx_result(0))

    report = service(vt, otx).lookup_ip("8.8.8.8")

    assert report.verdict.state == "clean"
    assert report.ip_context is not None
    assert report.ip_context.asn == 15169
    assert report.ip_context.as_owner == "Google LLC"
    assert vt.calls == 1


def test_provider_failure_degrades_to_unknown():
    live = LiveIntelService(
        providers=[ExplodingProvider()],
        dns_resolver=FakeDNS(),
        rdap_enricher=FakeRDAP(),
    )

    report = live.lookup_domain("broken.example")

    assert report.verdict.state == "unknown"
    assert report.providers[0].status == "unavailable"
    assert "provider is down" in (report.providers[0].error or "")


def test_slow_provider_is_cut_off_at_the_deadline(monkeypatch):
    from investigation.live import service as live_service

    monkeypatch.setattr(live_service, "DEFAULT_PROVIDER_DEADLINE_SECONDS", 0.05)

    live = LiveIntelService(
        providers=[SlowProvider()],
        dns_resolver=FakeDNS(),
        rdap_enricher=FakeRDAP(),
    )

    report = live.lookup_domain("slow.example")

    assert report.verdict.state == "unknown"
    assert report.providers[0].status == "unavailable"
    assert "timed out" in (report.providers[0].error or "")
