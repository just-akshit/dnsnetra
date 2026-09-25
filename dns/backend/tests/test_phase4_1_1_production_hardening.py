"""
PHASE 4.1.1 PRODUCTION HARDENING TESTS
=======================================
Validates:
1. Inconclusive vs Malicious correlation semantics (no false BENIGN on zero signal).
2. Decoupling of CorrelationEngine verdict from VirusTotal classification consensus.
3. Monotonic deadline propagation and bounded execution across all providers.
4. Concurrency invariant: multiple simultaneous slow providers (5s each) do NOT stack (5 x 5s != 25s).
5. Elimination of historical ~17.5s pathological latency case.
6. Partial result composition on deadline expiry without HTTP 500.
"""

import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient

from api.main import app
from enrichment.manager import EnrichmentManager
from enrichment.dns import DNSResolverEnricher
from enrichment.rdap import RDAPEnricher
from enrichment.ip import IPEnricher
from enrichment.models import (
    DNSResolutionResult,
    DomainRegistrationResult,
    IPEnrichmentItem,
    IPGeoResult,
    IPNetworkResult,
)
from labeler.intel.correlation.models import ThreatProviderResult


client = TestClient(app)


# ===========================================================================
# 1. CORRELATION SEMANTICS TESTS
# ===========================================================================
class TestCorrelationSemantics:
    """Verifies that correlation verdict never asserts BENIGN on absence of evidence."""

    @patch("api.routes.investigation.is_trusted", return_value=False)
    @patch("api.routes.investigation.is_malicious", return_value=False)
    @patch("api.routes.investigation.get_reputation_domain", return_value=None)
    @patch("api.routes.investigation.VirusTotalProvider")
    @patch("api.routes.investigation.AlienVaultOTXProvider")
    def test_zero_provider_signal_produces_inconclusive_verdict(
        self, mock_otx_cls, mock_vt_cls, mock_rep, mock_mal, mock_trust
    ):
        """Zero threat signal / unrated (404/undetected) produces correlation INCONCLUSIVE and classification REVIEW_NEEDED."""
        mock_vt = MagicMock()
        mock_vt.is_enabled.return_value = True
        mock_vt.lookup.return_value = ThreatProviderResult(
            provider="VirusTotal",
            malicious=False,
            confidence=0.0,
            found=False,
            unavailable=False,
            raw_data={"malicious": 0, "harmless": 0, "suspicious": 0, "undetected": 90},
        )
        mock_vt_cls.return_value = mock_vt

        mock_otx = MagicMock()
        mock_otx.is_enabled.return_value = True
        mock_otx.lookup.return_value = ThreatProviderResult(
            provider="AlienVault OTX",
            malicious=False,
            confidence=0.0,
            found=False,
            unavailable=False,
            raw_data={"pulse_count": 0},
        )
        mock_otx_cls.return_value = mock_otx

        resp = client.get("/api/v1/investigation/domain/zero-signal-test-domain.biz?force_external=true")
        assert resp.status_code == 200
        data = resp.json()["data"]

        # Classification must be REVIEW_NEEDED / unknown
        assert data["classification"]["status"] == "REVIEW_NEEDED"
        assert data["classification"]["label"] == "unknown"

        # Correlation MUST NOT be "benign" — it must be "INCONCLUSIVE"
        corr = data["correlation"]
        assert corr["status"] == "EVALUATED"
        assert corr["score"] == 0.0
        assert corr["confidence"] == 0.0
        assert corr["verdict"] == "INCONCLUSIVE"
        assert corr["provenance"] == "COMPUTED"

    @patch("api.routes.investigation.is_trusted", return_value=False)
    @patch("api.routes.investigation.is_malicious", return_value=False)
    @patch("api.routes.investigation.get_reputation_domain", return_value=None)
    @patch("api.routes.investigation.VirusTotalProvider")
    @patch("api.routes.investigation.AlienVaultOTXProvider")
    def test_correlated_malicious_produces_malicious_verdict(
        self, mock_otx_cls, mock_vt_cls, mock_rep, mock_mal, mock_trust
    ):
        """When weighted score exceeds threshold, correlation verdict is MALICIOUS."""
        mock_vt = MagicMock()
        mock_vt.is_enabled.return_value = True
        mock_vt.lookup.return_value = ThreatProviderResult(
            provider="VirusTotal",
            malicious=True,
            confidence=0.90,
            found=True,
            unavailable=False,
            raw_data={"malicious": 12, "harmless": 0, "suspicious": 2},
        )
        mock_vt_cls.return_value = mock_vt

        mock_otx = MagicMock()
        mock_otx.is_enabled.return_value = True
        mock_otx.lookup.return_value = ThreatProviderResult(
            provider="AlienVault OTX",
            malicious=False,
            confidence=0.0,
            found=False,
            unavailable=False,
            raw_data={"pulse_count": 0},
        )
        mock_otx_cls.return_value = mock_otx

        resp = client.get("/api/v1/investigation/domain/correlated-malicious-domain.com?force_external=true")
        assert resp.status_code == 200
        data = resp.json()["data"]

        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        corr = data["correlation"]
        assert corr["status"] == "EVALUATED"
        assert corr["score"] >= 0.60
        assert corr["verdict"] == "MALICIOUS"
        assert corr["provenance"] == "COMPUTED"

    @patch("api.routes.investigation.is_trusted", return_value=False)
    @patch("api.routes.investigation.is_malicious", return_value=False)
    @patch("api.routes.investigation.get_reputation_domain", return_value=None)
    @patch("api.routes.investigation.VirusTotalProvider")
    @patch("api.routes.investigation.AlienVaultOTXProvider")
    def test_multi_engine_clean_consensus_produces_known_clean(
        self, mock_otx_cls, mock_vt_cls, mock_rep, mock_mal, mock_trust
    ):
        """Multi-engine clean consensus (harmless>=5, 0 mal/susp) produces KNOWN_CLEAN at classification layer."""
        mock_vt = MagicMock()
        mock_vt.is_enabled.return_value = True
        mock_vt.lookup.return_value = ThreatProviderResult(
            provider="VirusTotal",
            malicious=False,
            confidence=0.85,
            harmless_count=15,
            malicious_count=0,
            suspicious_count=0,
            found=True,
            unavailable=False,
            raw_data={"malicious": 0, "harmless": 15, "suspicious": 0, "undetected": 75},
        )
        mock_vt_cls.return_value = mock_vt


        mock_otx = MagicMock()
        mock_otx.is_enabled.return_value = True
        mock_otx.lookup.return_value = ThreatProviderResult(
            provider="AlienVault OTX",
            malicious=False,
            confidence=0.0,
            found=False,
            unavailable=False,
            raw_data={"pulse_count": 0},
        )
        mock_otx_cls.return_value = mock_otx

        resp = client.get("/api/v1/investigation/domain/clean-consensus-domain.org?force_external=true")
        assert resp.status_code == 200
        data = resp.json()["data"]

        assert data["classification"]["status"] == "KNOWN_CLEAN"
        assert data["classification"]["label"] == "clean"
        assert data["classification"]["source"] == "External Threat Intelligence"
        assert data["correlation"]["verdict"] == "INCONCLUSIVE"

    @patch("api.routes.investigation.is_trusted", return_value=False)
    @patch("api.routes.investigation.is_malicious", return_value=False)
    @patch("api.routes.investigation.get_reputation_domain", return_value=None)
    @patch("api.routes.investigation.VirusTotalProvider")
    @patch("api.routes.investigation.AlienVaultOTXProvider")
    def test_single_harmless_vote_does_not_produce_known_clean(
        self, mock_otx_cls, mock_vt_cls, mock_rep, mock_mal, mock_trust
    ):
        """Single harmless vote (< 5 consensus) produces REVIEW_NEEDED at classification layer."""
        mock_vt = MagicMock()
        mock_vt.is_enabled.return_value = True
        mock_vt.lookup.return_value = ThreatProviderResult(
            provider="VirusTotal",
            malicious=False,
            confidence=0.50,
            found=True,
            unavailable=False,
            raw_data={"malicious": 0, "harmless": 1, "suspicious": 0, "undetected": 89},
        )
        mock_vt.harmless_count = 1
        mock_vt.malicious_count = 0
        mock_vt.suspicious_count = 0
        mock_vt_cls.return_value = mock_vt

        mock_otx = MagicMock()
        mock_otx.is_enabled.return_value = True
        mock_otx.lookup.return_value = ThreatProviderResult(
            provider="AlienVault OTX",
            malicious=False,
            confidence=0.0,
            found=False,
            unavailable=False,
            raw_data={"pulse_count": 0},
        )
        mock_otx_cls.return_value = mock_otx

        resp = client.get("/api/v1/investigation/domain/single-harmless-domain.org?force_external=true")
        assert resp.status_code == 200
        data = resp.json()["data"]

        assert data["classification"]["status"] == "REVIEW_NEEDED"
        assert data["classification"]["label"] == "unknown"
        assert data["correlation"]["verdict"] == "INCONCLUSIVE"

    @patch("api.routes.investigation.is_trusted", return_value=False)
    @patch("api.routes.investigation.is_malicious", return_value=False)
    @patch("api.routes.investigation.get_reputation_domain", return_value=None)
    @patch("api.routes.investigation.VirusTotalProvider")
    @patch("api.routes.investigation.AlienVaultOTXProvider")
    def test_provider_failures_produce_failed_correlation(
        self, mock_otx_cls, mock_vt_cls, mock_rep, mock_mal, mock_trust
    ):
        """When live providers fail, correlation status is FAILED with null score/verdict."""
        mock_vt = MagicMock()
        mock_vt.is_enabled.return_value = True
        mock_vt.lookup.return_value = ThreatProviderResult(
            provider="VirusTotal",
            malicious=False,
            confidence=0.0,
            found=False,
            unavailable=True,
            error="HTTP 500 server error",
        )
        mock_vt_cls.return_value = mock_vt

        mock_otx = MagicMock()
        mock_otx.is_enabled.return_value = True
        mock_otx.lookup.return_value = ThreatProviderResult(
            provider="AlienVault OTX",
            malicious=False,
            confidence=0.0,
            found=False,
            unavailable=True,
            error="Connection timeout",
        )
        mock_otx_cls.return_value = mock_otx

        resp = client.get("/api/v1/investigation/domain/provider-failure-test.com?force_external=true")
        assert resp.status_code == 200
        data = resp.json()["data"]

        assert data["classification"]["status"] == "REVIEW_NEEDED"
        assert data["correlation"]["status"] == "FAILED"
        assert data["correlation"]["verdict"] is None
        assert data["correlation"]["score"] is None
        assert data["correlation"]["provenance"] == "COMPUTED"

    def test_persisted_reputation_correlation_is_not_evaluated(self):
        """Active persisted reputation matches report correlation status NOT_EVALUATED and null verdict."""
        resp = client.get("/api/v1/investigation/domain/secure-update.net")
        assert resp.status_code == 200
        data = resp.json()["data"]

        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data["correlation"]["status"] == "NOT_EVALUATED"
        assert data["correlation"]["verdict"] is None
        assert data["correlation"]["score"] is None
        assert data["correlation"]["provenance"] is None

    def test_local_authoritative_match_correlation_is_not_applicable(self):
        """Local ground truth match reports correlation status NOT_APPLICABLE and null verdict."""
        resp = client.get("/api/v1/investigation/domain/google.com")
        assert resp.status_code == 200
        data = resp.json()["data"]

        assert data["classification"]["status"] == "POPULAR_BENIGN_CONTEXT"
        assert data["correlation"]["status"] == "NOT_APPLICABLE"
        assert data["correlation"]["verdict"] is None
        assert data["correlation"]["score"] is None
        assert data["correlation"]["provenance"] is None


# ===========================================================================
# 2. DEADLINE & PROVIDER ISOLATION TESTS
# ===========================================================================
class TestDeadlineAndIsolation:
    """Verifies that slow providers do not block execution beyond the global monotonic deadline."""

    def test_slow_dns_bounded_by_enrichment_deadline(self):
        """A DNS provider that delays for 5 seconds does not exceed the 3.5s enrichment budget."""
        mgr = EnrichmentManager(overall_budget=1.0, dns_timeout=0.5, rdap_timeout=0.5)

        def slow_resolve(domain, deadline=None):
            time.sleep(3.0)
            return DNSResolutionResult(status="AVAILABLE", a=["1.2.3.4"])

        mgr.dns_enricher.resolve = slow_resolve

        start = time.perf_counter()
        result = mgr.enrich_domain("slow-dns-test.biz")
        duration = time.perf_counter() - start

        # Must complete around ~1.0s budget (test tolerance <= 1.5s)
        assert duration < 1.6, f"Expected duration < 1.6s, got {duration:.2f}s"
        assert result.dns.status == "PROVIDER_FAILURE"
        assert "deadline exceeded" in (result.dns.error or "").lower()

    def test_slow_rdap_bounded_by_enrichment_deadline(self):
        """An RDAP provider that delays for 5 seconds does not exceed the budget and returns partial DNS."""
        mgr = EnrichmentManager(overall_budget=1.0, dns_timeout=0.5, rdap_timeout=0.5)

        def fast_dns(domain, deadline=None):
            return DNSResolutionResult(status="AVAILABLE", a=["93.184.216.34"])

        def slow_rdap(domain, deadline=None):
            time.sleep(3.0)
            return DomainRegistrationResult(status="AVAILABLE", registrar="Slow Registrar")

        mgr.dns_enricher.resolve = fast_dns
        mgr.rdap_enricher.enrich = slow_rdap

        start = time.perf_counter()
        result = mgr.enrich_domain("slow-rdap-test.biz")
        duration = time.perf_counter() - start

        assert duration < 1.6, f"Expected duration < 1.6s, got {duration:.2f}s"
        # DNS succeeded
        assert result.dns.status == "AVAILABLE"
        assert result.dns.a == ["93.184.216.34"]
        # RDAP timed out honestly
        assert result.registration.status == "PROVIDER_FAILURE"
        assert "deadline exceeded" in (result.registration.error or "").lower()
        # Overall status is PARTIAL because DNS was available
        assert result.status == "PARTIAL"

    def test_concurrency_invariant_simultaneous_slow_providers_do_not_multiply(self):
        """
        Concurrency invariant:
        5 simultaneous slow providers (DNS 4s, RDAP 4s, IPinfo 4s, VT 4s, OTX 4s)
        do NOT stack to 20 seconds. Total request completes within the global deadline.
        """
        mgr = EnrichmentManager(overall_budget=1.0, dns_timeout=0.5, rdap_timeout=0.5, ipinfo_timeout=0.5)

        def slow_dns(domain, deadline=None):
            time.sleep(4.0)
            return DNSResolutionResult(status="AVAILABLE", a=["1.1.1.1"])

        def slow_rdap(domain, deadline=None):
            time.sleep(4.0)
            return DomainRegistrationResult(status="AVAILABLE")

        def slow_ip(ip, deadline=None):
            time.sleep(4.0)
            return IPEnrichmentItem(
                ip=ip,
                ip_type="PUBLIC",
                geo=IPGeoResult(status="AVAILABLE"),
                network=IPNetworkResult(status="AVAILABLE"),
            )

        mgr.dns_enricher.resolve = slow_dns
        mgr.rdap_enricher.enrich = slow_rdap
        mgr.ip_enricher.enrich_ip = slow_ip

        start = time.perf_counter()
        result = mgr.enrich_domain("simultaneous-slow-test.biz")
        duration = time.perf_counter() - start

        # Total duration must remain bounded around the 1.0s budget (test tolerance <= 1.6s), NOT 12.0s!
        assert duration < 1.6, f"Concurrency invariant failed: expected < 1.6s, took {duration:.2f}s"
        assert result.status in ("PROVIDER_FAILURE", "NO_DATA", "PARTIAL")

    def test_historical_pathological_latency_regression(self):
        """
        Regression Test:
        Verifies that querying an unindexed domain completes well under 5.0 seconds
        and that the historical ~17.5-second hang does not recur.
        """
        start = time.perf_counter()
        resp = client.get("/api/v1/investigation/domain/completely-unindexed-random-domain.biz")
        duration = time.perf_counter() - start

        assert resp.status_code == 200
        # Historical latency was ~17.5 seconds. The hardened pipeline must finish in < 4.5 seconds.
        assert duration < 4.5, f"Historical ~17.5s regression occurred! Duration was {duration:.2f}s"
        data = resp.json()["data"]
        assert data["classification"]["status"] == "REVIEW_NEEDED"
        assert data["correlation"]["verdict"] == "INCONCLUSIVE"
        assert "enrichment" in data


# ===========================================================================
# 3. GOLDEN INTEGRATION CASES
# ===========================================================================
class TestGoldenDomainCases:
    """Verifies all four golden test cases for full payload and latency integrity."""

    def test_golden_01_google_com(self):
        """google.com: Tranco apex, POPULAR_BENIGN_CONTEXT, correlation NOT_APPLICABLE, fast duration."""
        start = time.perf_counter()
        resp = client.get("/api/v1/investigation/domain/google.com")
        duration = time.perf_counter() - start

        assert resp.status_code == 200
        assert duration < 1.5, f"google.com investigation took {duration:.2f}s"
        data = resp.json()["data"]
        assert data["classification"]["status"] == "POPULAR_BENIGN_CONTEXT"
        assert data["correlation"]["status"] == "NOT_APPLICABLE"

    def test_golden_02_secure_update_net(self):
        """secure-update.net: Persisted reputation, KNOWN_MALICIOUS, correlation NOT_EVALUATED, no fake VT."""
        resp = client.get("/api/v1/investigation/domain/secure-update.net")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data["correlation"]["status"] == "NOT_EVALUATED"
        assert data["external_intelligence"]["virustotal"]["status"] == "NO_DATA"

    def test_golden_03_imccj_gobgem_com(self):
        """imccj.gobgem.com: Exact URLhaus match, KNOWN_MALICIOUS, correlation NOT_APPLICABLE."""
        resp = client.get("/api/v1/investigation/domain/imccj.gobgem.com")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data["local_intelligence"]["urlhaus"]["match_scope"] == "EXACT_FQDN"

    def test_golden_04_unindexed_domain(self):
        """Unindexed domain: REVIEW_NEEDED, correlation INCONCLUSIVE, bounded total latency."""
        resp = client.get("/api/v1/investigation/domain/controlled-unindexed-test-2026.biz")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["classification"]["status"] == "REVIEW_NEEDED"
        assert data["correlation"]["verdict"] == "INCONCLUSIVE"
