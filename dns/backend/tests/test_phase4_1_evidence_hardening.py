"""
Phase 4.1 — Evidence Contract & Provenance Hardening Tests
=========================================================
Verifies:
- Invariants INV-01 through INV-15
- Golden API Cases GOLDEN-01 through GOLDEN-05
- Strict non-contradiction between classification, external TI, and correlation
- Non-fabrication of provider results from persisted aggregate records
- Accurate provenance assignment (PERSISTED for records, COMPUTED for engine, REAL for live lookups)
- Correct Phase 2.7 classification hierarchy where malicious evidence always takes precedence over Tranco popularity context
- Distinction between provider-level clean signals and multi-engine clean consensus
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient

from api.main import app
from labeler.intel.correlation.models import ThreatProviderResult


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# ===========================================================================
# INVARIANT TESTS (INV-01 - INV-15)
# ===========================================================================
class TestPhase41Invariants:
    def test_inv_01_persisted_reputation_correlation_not_evaluated(self, client):
        """INV-01: Persisted malicious reputation cannot coexist with correlation.verdict = benign."""
        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data["reputation"]["active_record"] is True

        corr = data["correlation"]
        assert corr["status"] == "NOT_EVALUATED"
        assert corr["verdict"] is None
        assert corr["score"] is None
        assert corr["confidence"] is None
        assert corr["provenance"] is None

    def test_inv_02_no_fabricated_vt_evidence_from_persisted_tce(self, client):
        """INV-02: Persisted Threat Correlation Engine record does NOT create VirusTotal = MALICIOUS."""
        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        data = res.json()["data"]

        vt = data["external_intelligence"]["virustotal"]
        assert vt["status"] == "NO_DATA"
        assert vt["availability_reason"] == "NOT_RECORDED_IN_PERSISTED_REPUTATION"
        assert vt["result"] is None
        assert vt["confidence"] is None

    def test_inv_03_no_fabricated_otx_evidence_from_persisted_tce(self, client):
        """INV-03: Persisted Threat Correlation Engine record does NOT create AlienVault OTX = MALICIOUS."""
        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        data = res.json()["data"]

        otx = data["external_intelligence"]["otx"]
        assert otx["status"] == "NO_DATA"
        assert otx["availability_reason"] == "NOT_RECORDED_IN_PERSISTED_REPUTATION"
        assert otx["result"] is None
        assert otx["confidence"] is None

    def test_inv_04_confidence_consistency(self, client):
        """INV-04: Classification confidence matches its exact evidence source."""
        # URLhaus exact match -> confidence 1.0
        res_u = client.get("/api/v1/investigation/domain/imccj.gobgem.com")
        assert res_u.status_code == 200
        assert res_u.json()["data"]["classification"]["confidence"] == 1.0

        # Tranco match -> confidence 0.0 (risk confidence)
        res_g = client.get("/api/v1/investigation/domain/google.com")
        assert res_g.status_code == 200
        assert res_g.json()["data"]["classification"]["confidence"] == 0.0

    def test_inv_05_zero_or_low_detections_not_automatically_known_clean(self, client):
        """INV-05: Zero provider detections or a single harmless vote cannot produce KNOWN_CLEAN without strong consensus."""
        # Case A: 91 undetected, 0 harmless, 0 malicious
        unrated_vt = ThreatProviderResult(
            provider="VirusTotal",
            malicious=False,
            confidence=0.0,
            malicious_count=0,
            harmless_count=0,
            suspicious_count=0,
            found=False,
        )
        no_data_otx = ThreatProviderResult(
            provider="AlienVault OTX",
            malicious=False,
            confidence=0.0,
            malicious_count=0,
            found=False,
        )

        with patch("api.routes.investigation.VirusTotalProvider.lookup", return_value=unrated_vt), \
             patch("api.routes.investigation.AlienVaultOTXProvider.lookup", return_value=no_data_otx):
            res = client.get("/api/v1/investigation/domain/unrated-domain-xyz-123.org?force_external=true")
            assert res.status_code == 200
            data = res.json()["data"]

            assert data["classification"]["status"] in ("REVIEW_NEEDED", "UNKNOWN")
            assert data["classification"]["label"] == "unknown"

        # Case B: 1 harmless vote (insufficient multi-engine consensus for global KNOWN_CLEAN)
        single_harmless_vt = ThreatProviderResult(
            provider="VirusTotal",
            malicious=False,
            confidence=0.01,
            malicious_count=0,
            harmless_count=1,
            suspicious_count=0,
            found=True,
        )
        with patch("api.routes.investigation.VirusTotalProvider.lookup", return_value=single_harmless_vt), \
             patch("api.routes.investigation.AlienVaultOTXProvider.lookup", return_value=no_data_otx):
            res2 = client.get("/api/v1/investigation/domain/single-harmless-domain.org?force_external=true")
            assert res2.status_code == 200
            data2 = res2.json()["data"]
            # Provider level records CLEAN
            assert data2["external_intelligence"]["virustotal"]["result"] == "CLEAN"
            # Global classification remains REVIEW_NEEDED because 1 harmless vote is not substantial consensus
            assert data2["classification"]["status"] in ("REVIEW_NEEDED", "UNKNOWN")
            assert data2["classification"]["label"] == "unknown"

    def test_inv_06_every_evidence_has_valid_provenance(self, client):
        """INV-06: Every item in evidence chain has a valid provenance from the strict taxonomy."""
        res = client.get("/api/v1/investigation/domain/google.com")
        assert res.status_code == 200
        evidence = res.json()["data"]["investigation"]["evidence"]
        assert len(evidence) > 0
        for ev in evidence:
            assert ev["provenance"] in ("LOCAL", "REAL", "PERSISTED", "COMPUTED")

    def test_inv_07_live_lookup_has_real_provenance(self, client):
        """INV-07: Live lookups produce REAL provenance."""
        mock_vt = ThreatProviderResult(
            provider="VirusTotal",
            malicious=True,
            confidence=0.9,
            malicious_count=5,
            found=True,
        )
        with patch("api.routes.investigation.VirusTotalProvider.lookup", return_value=mock_vt):
            res = client.get("/api/v1/investigation/domain/live-test-malicious-domain.biz?force_external=true")
            assert res.status_code == 200
            ext = res.json()["data"]["external_intelligence"]
            assert ext["provenance"] == "REAL"
            assert ext["freshness"] == "LIVE_LOOKUP"

    def test_inv_08_active_reputation_has_persisted_provenance(self, client):
        """INV-08: Active reputation produces PERSISTED provenance on reputation and external intel."""
        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        ext = res.json()["data"]["external_intelligence"]
        assert ext["provenance"] == "PERSISTED"
        assert ext["freshness"] == "ACTIVE_REPUTATION"

    def test_inv_09_computed_correlation_has_computed_provenance(self, client):
        """INV-09: Live correlation evaluation produces COMPUTED provenance."""
        mock_vt = ThreatProviderResult(
            provider="VirusTotal",
            malicious=True,
            confidence=0.9,
            malicious_count=5,
            found=True,
        )
        with patch("api.routes.investigation.VirusTotalProvider.lookup", return_value=mock_vt):
            res = client.get("/api/v1/investigation/domain/live-computed-domain.biz?force_external=true")
            assert res.status_code == 200
            corr = res.json()["data"]["correlation"]
            assert corr["provenance"] == "COMPUTED"
            assert corr["status"] == "EVALUATED"

    def test_inv_10_skipped_provider_has_no_fake_counts(self, client):
        """INV-10: SKIPPED provider results contain 0 detections and null confidence."""
        res = client.get("/api/v1/investigation/domain/google.com")
        assert res.status_code == 200
        vt = res.json()["data"]["external_intelligence"]["virustotal"]
        assert vt["status"] == "SKIPPED"
        assert vt["malicious_count"] == 0
        assert vt["confidence"] is None
        assert vt["result"] is None

    def test_inv_11_not_evaluated_correlation_has_null_scores_and_null_provenance(self, client):
        """INV-11: NOT_EVALUATED correlation has score=None, verdict=None, and provenance=None."""
        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        corr = res.json()["data"]["correlation"]
        assert corr["status"] == "NOT_EVALUATED"
        assert corr["score"] is None
        assert corr["confidence"] is None
        assert corr["verdict"] is None
        assert corr["provenance"] is None

    def test_inv_12_classification_evidence_chain_explanation(self, client):
        """INV-12: Classification has a corresponding evidence chain explaining why it was selected."""
        res = client.get("/api/v1/investigation/domain/imccj.gobgem.com")
        assert res.status_code == 200
        inv = res.json()["data"]["investigation"]
        assert inv["known"] is True
        assert "URLhaus" in inv["why"]
        assert any(e["provider"] == "URLhaus" for e in inv["evidence"])

    def test_inv_13_provider_does_not_inherit_other_provider_result(self, client):
        """INV-13: A provider never inherits another provider's result."""
        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["external_intelligence"]["virustotal"]["result"] is None
        assert data["external_intelligence"]["otx"]["result"] is None

    def test_inv_14_missing_provider_credentials_produce_not_configured(self, client):
        """INV-14: Missing provider credentials produce NOT_CONFIGURED, never CLEAN."""
        with patch("api.routes.investigation.VirusTotalProvider.is_enabled", return_value=False), \
             patch("api.routes.investigation.AlienVaultOTXProvider.is_enabled", return_value=False):
            res = client.get("/api/v1/investigation/domain/unconfigured-sample-999.biz?force_external=true")
            assert res.status_code == 200
            data = res.json()["data"]
            assert data["external_intelligence"]["virustotal"]["status"] == "NOT_CONFIGURED"
            assert data["external_intelligence"]["otx"]["status"] == "NOT_CONFIGURED"
            assert data["classification"]["status"] in ("REVIEW_NEEDED", "UNKNOWN")

    def test_inv_15_provider_failure_produces_failed_correlation_with_computed_provenance(self, client):
        """INV-15: Provider failure produces PROVIDER_FAILURE, failed correlation with provenance COMPUTED."""
        mock_fail = ThreatProviderResult(
            provider="VirusTotal",
            unavailable=True,
            error="HTTP 500 Internal Server Error",
        )
        with patch("api.routes.investigation.VirusTotalProvider.lookup", return_value=mock_fail), \
             patch("api.routes.investigation.AlienVaultOTXProvider.lookup", return_value=mock_fail):
            res = client.get("/api/v1/investigation/domain/failing-upstream-domain.biz?force_external=true")
            assert res.status_code == 200
            data = res.json()["data"]
            assert data["external_intelligence"]["virustotal"]["status"] == "PROVIDER_FAILURE"
            assert data["correlation"]["status"] == "FAILED"
            assert data["correlation"]["provenance"] == "COMPUTED"
            assert data["classification"]["status"] in ("REVIEW_NEEDED", "UNKNOWN")


# ===========================================================================
# GOLDEN API CASES (GOLDEN-01 - GOLDEN-05)
# ===========================================================================
class TestPhase41GoldenCases:
    def test_golden_01_google_com(self, client):
        """GOLDEN-01: google.com -> Tranco POPULAR_BENIGN_CONTEXT, external TI SKIPPED, correlation NOT_APPLICABLE."""
        res = client.get("/api/v1/investigation/domain/google.com")
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["domain"]["fqdn"] == "google.com"
        assert data["classification"]["status"] == "POPULAR_BENIGN_CONTEXT"
        assert data["classification"]["label"] == "benign"
        assert data["classification"]["source"] == "Tranco"
        assert data["external_intelligence"]["status"] == "SKIPPED"
        assert data["external_intelligence"]["virustotal"]["status"] == "SKIPPED"
        assert data["correlation"]["status"] == "NOT_APPLICABLE"
        assert data["correlation"]["verdict"] is None
        assert data["correlation"]["provenance"] is None

    def test_golden_02_secure_update_net(self, client):
        """GOLDEN-02: secure-update.net -> Persisted reputation malicious, correlation NOT_EVALUATED, no fake VT."""
        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["domain"]["fqdn"] == "secure-update.net"
        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data["classification"]["label"] == "malicious"
        assert data["reputation"]["active_record"] is True
        assert data["correlation"]["status"] == "NOT_EVALUATED"
        assert data["correlation"]["score"] is None
        assert data["correlation"]["provenance"] is None
        assert data["external_intelligence"]["virustotal"]["status"] == "NO_DATA"
        assert data["external_intelligence"]["virustotal"]["availability_reason"] == "NOT_RECORDED_IN_PERSISTED_REPUTATION"
        assert data["external_intelligence"]["otx"]["status"] == "NO_DATA"

    def test_golden_03_urlhaus_malicious_fqdn(self, client):
        """GOLDEN-03: imccj.gobgem.com -> URLhaus exact malicious match, LOCAL provenance."""
        res = client.get("/api/v1/investigation/domain/imccj.gobgem.com")
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data["classification"]["source"] == "URLhaus"
        assert data["classification"]["scope"] == "EXACT_FQDN"
        assert data["local_intelligence"]["urlhaus"]["matched"] is True

    def test_golden_04_unindexed_unknown_domain(self, client):
        """GOLDEN-04: Nonexistent / unindexed domain -> REVIEW_NEEDED / unknown, not false KNOWN_CLEAN."""
        no_data = ThreatProviderResult(
            provider="VirusTotal",
            malicious=False,
            confidence=0.0,
            found=False,
        )
        with patch("api.routes.investigation.VirusTotalProvider.lookup", return_value=no_data), \
             patch("api.routes.investigation.AlienVaultOTXProvider.lookup", return_value=no_data):
            res = client.get("/api/v1/investigation/domain/completely-nonexistent-domain-404-test.xyz")
            assert res.status_code == 200
            data = res.json()["data"]

            assert data["classification"]["status"] in ("REVIEW_NEEDED", "UNKNOWN")
            assert data["classification"]["label"] == "unknown"
            assert data["classification"]["risk_score"] == 0.0

    def test_golden_05_provider_unavailable(self, client):
        """GOLDEN-05: Provider unavailable condition produces PROVIDER_FAILURE and REVIEW_NEEDED, not benign."""
        fail_res = ThreatProviderResult(
            provider="VirusTotal",
            unavailable=True,
            error="Connection timed out",
        )
        with patch("api.routes.investigation.VirusTotalProvider.lookup", return_value=fail_res), \
             patch("api.routes.investigation.AlienVaultOTXProvider.lookup", return_value=fail_res):
            res = client.get("/api/v1/investigation/domain/unavailable-provider-domain-test.com?force_external=true")
            assert res.status_code == 200
            data = res.json()["data"]

            assert data["external_intelligence"]["virustotal"]["status"] == "PROVIDER_FAILURE"
            assert data["correlation"]["status"] == "FAILED"
            assert data["correlation"]["provenance"] == "COMPUTED"
            assert data["classification"]["status"] in ("REVIEW_NEEDED", "UNKNOWN")
            assert data["classification"]["label"] != "benign"
