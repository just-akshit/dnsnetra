"""Unit tests for the live four-state verdict (no network, no database)."""

from dnsnetra.domains.investigations.enrichment.models import DomainRegistrationResult
from dnsnetra.domains.investigations.live.models import ProviderEvidence
from dnsnetra.domains.investigations.live.verdict import evaluate_verdict


def ev(provider: str, status: str = "ok", **kwargs) -> ProviderEvidence:
    return ProviderEvidence(provider=provider, status=status, **kwargs)


def vt(malicious: int, total: int, suspicious: int = 0) -> ProviderEvidence:
    return ev(
        "VirusTotal",
        malicious=malicious,
        suspicious=suspicious,
        harmless=max(total - malicious - suspicious, 0),
        total=total,
    )


def otx(pulses: int) -> ProviderEvidence:
    return ev("AlienVault OTX", pulse_count=pulses)


def test_no_data_is_unknown_not_clean():
    verdict = evaluate_verdict([])
    assert verdict.state == "unknown"


def test_unavailable_providers_are_unknown():
    verdict = evaluate_verdict(
        [ev("VirusTotal", status="unavailable"), ev("AlienVault OTX", status="unavailable")]
    )
    assert verdict.state == "unknown"
    assert verdict.sources_with_data == 0


def test_single_engine_outlier_is_not_malicious():
    verdict = evaluate_verdict([vt(malicious=1, total=92)])
    assert verdict.state == "clean"
    assert any("low-signal outlier" in reason for reason in verdict.reasons)


def test_two_engine_detections_are_suspicious():
    assert evaluate_verdict([vt(malicious=2, total=92)]).state == "suspicious"


def test_one_detection_in_small_sample_is_suspicious():
    assert evaluate_verdict([vt(malicious=1, total=10)]).state == "suspicious"


def test_ten_percent_ratio_is_malicious():
    verdict = evaluate_verdict([vt(malicious=12, total=90)])
    assert verdict.state == "malicious"
    assert verdict.confidence >= 0.5


def test_zero_detections_with_coverage_is_clean():
    verdict = evaluate_verdict([vt(malicious=0, total=60), otx(0)])
    assert verdict.state == "clean"


def test_zero_detections_with_low_coverage_is_unknown():
    verdict = evaluate_verdict([vt(malicious=0, total=5)])
    assert verdict.state == "unknown"


def test_otx_pulses_alone_are_suspicious_not_malicious():
    assert evaluate_verdict([otx(5)]).state == "suspicious"
    assert evaluate_verdict([otx(1)]).state == "suspicious"


def test_strong_vt_clean_scan_overrides_noisy_otx_pulses():
    # apple.com-style false positive: 0/92 engines, but many unrelated pulses.
    verdict = evaluate_verdict([vt(malicious=0, total=92), otx(50)])
    assert verdict.state == "clean"
    assert any("takes precedence" in reason for reason in verdict.reasons)


def test_otx_pulses_with_thin_vt_coverage_are_suspicious():
    verdict = evaluate_verdict([vt(malicious=0, total=12), otx(5)])
    assert verdict.state == "suspicious"


def test_fresh_domain_with_thin_history_is_not_clean():
    registration = DomainRegistrationResult(
        status="AVAILABLE",
        created_at="2026-11-05T00:00:00Z",  # 3 days before 2026-11-08
    )
    verdict = evaluate_verdict([vt(malicious=0, total=12), otx(0)], registration)
    assert verdict.state == "unknown"
    assert any("not enough evidence" in reason for reason in verdict.reasons)


def test_old_domain_with_coverage_can_be_clean():
    registration = DomainRegistrationResult(
        status="AVAILABLE",
        created_at="1997-09-15T04:00:00Z",
    )
    verdict = evaluate_verdict([vt(malicious=0, total=60), otx(0)], registration)
    assert verdict.state == "clean"


def test_sources_with_data_counts_only_real_data():
    verdict = evaluate_verdict(
        [
            vt(malicious=0, total=0),
            ev("AlienVault OTX", status="no_data"),
            ev("VirusTotal", status="unavailable"),
        ]
    )
    assert verdict.sources_with_data == 0
    assert verdict.sources_queried == 3
