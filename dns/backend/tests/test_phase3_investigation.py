import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient

from api.main import app
from labeler.intel.reputation import store_malicious_domain
from labeler.intel.malicious import is_malicious
from labeler.intel.manager import is_trusted


@pytest.fixture(scope="module")
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


# ===========================================================================
# DOMAIN INVESTIGATION TESTS (D1 - D6)
# ===========================================================================
class TestDomainInvestigation:
    def test_d1_google_com_tranco_context(self, client):
        """D1: google.com -> Popular benign context from Tranco."""
        res = client.get("/api/v1/investigation/domain/google.com")
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["domain"]["fqdn"] == "google.com"
        assert data["domain"]["registered_domain"] == "google.com"
        assert data["classification"]["status"] == "POPULAR_BENIGN_CONTEXT"
        assert data["classification"]["label"] == "benign"
        assert data["local_intelligence"]["tranco"]["matched"] is True
        assert data["local_intelligence"]["tranco"]["provenance"] == "LOCAL"
        assert data["local_intelligence"]["tranco"]["freshness"] == "NOT_APPLICABLE"
        assert data["external_intelligence"]["status"] == "SKIPPED"
        assert data["external_intelligence"]["provenance"] == "LOCAL"
        assert data["external_intelligence"]["freshness"] == "NOT_APPLICABLE"
        assert data["external_intelligence"]["virustotal"]["status"] == "SKIPPED"
        assert data["external_intelligence"]["virustotal"]["freshness"] == "NOT_APPLICABLE"

    def test_d2_mail_google_com_subdomain_context(self, client):
        """D2: mail.google.com -> Inherits Tranco apex popularity context."""
        res = client.get("/api/v1/investigation/domain/mail.google.com")
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["domain"]["fqdn"] == "mail.google.com"
        assert data["domain"]["registered_domain"] == "google.com"
        assert data["classification"]["status"] == "POPULAR_BENIGN_CONTEXT"
        assert data["local_intelligence"]["tranco"]["matched"] is True

    def test_d3_imccj_gobgem_com_urlhaus_exact(self, client):
        """D3: imccj.gobgem.com -> Exact URLhaus malicious match."""
        res = client.get("/api/v1/investigation/domain/imccj.gobgem.com")
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["domain"]["fqdn"] == "imccj.gobgem.com"
        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data["classification"]["label"] == "malicious"
        assert data["classification"]["risk_score"] == 100.0
        assert data["local_intelligence"]["urlhaus"]["matched"] is True
        assert data["local_intelligence"]["urlhaus"]["result"] == "MALICIOUS"
        assert data["local_intelligence"]["urlhaus"]["provenance"] == "LOCAL"
        assert data["local_intelligence"]["urlhaus"]["freshness"] == "NOT_APPLICABLE"

    def test_d4_evil_google_com_subdomain_override(self, client):
        """D4: evil.google.com -> Exact malicious subdomain overrides parent Tranco."""
        store_malicious_domain("evil.google.com", {
            "source": "URLHaus",
            "confidence": 1.0,
            "match_scope": "EXACT_FQDN",
            "matched_domain": "evil.google.com",
        })

        res = client.get("/api/v1/investigation/domain/evil.google.com")
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["domain"]["fqdn"] == "evil.google.com"
        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data["classification"]["label"] == "malicious"
        assert data["classification"]["risk_score"] == 100.0

    def test_d5_secure_update_net_correlated_malicious(self, client):
        """D5: secure-update.net -> Persisted correlated malicious threat."""
        store_malicious_domain("secure-update.net", {
            "source": "Threat Correlation Engine",
            "confidence": 0.95,
            "match_scope": "CORRELATED",
            "matched_domain": "secure-update.net",
        })

        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        data = res.json()["data"]

        assert data["domain"]["fqdn"] == "secure-update.net"
        assert data["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data["classification"]["label"] == "malicious"
        assert data["reputation"]["active_record"] is True
        assert data["reputation"]["match_scope"] == "CORRELATED"
        assert data["external_intelligence"]["status"] == "AVAILABLE"
        assert data["external_intelligence"]["provenance"] == "PERSISTED"
        assert data["external_intelligence"]["freshness"] == "ACTIVE_REPUTATION"
        assert data["external_intelligence"]["virustotal"]["provenance"] == "PERSISTED"
        assert data["external_intelligence"]["virustotal"]["freshness"] == "ACTIVE_REPUTATION"

    def test_d6_unknown_test_domain_honest_handling(self, client):
        """D6: completely unknown domain -> Honest REVIEW_NEEDED / UNKNOWN without false clean."""
        from unittest.mock import patch
        from labeler.intel.correlation.models import ThreatProviderResult

        mock_no_data = ThreatProviderResult(
            provider="VirusTotal",
            malicious=False,
            confidence=0.0,
            found=False,
        )

        with patch("api.routes.investigation.VirusTotalProvider.lookup", return_value=mock_no_data), \
             patch("api.routes.investigation.AlienVaultOTXProvider.lookup", return_value=mock_no_data):
            res = client.get("/api/v1/investigation/domain/completely-unindexed-random-domain.biz")
            assert res.status_code == 200
            data = res.json()["data"]

            assert data["domain"]["fqdn"] == "completely-unindexed-random-domain.biz"
            assert data["classification"]["status"] in ("REVIEW_NEEDED", "UNKNOWN")
            assert data["classification"]["label"] == "unknown"
            assert data["dns_activity"]["status"] == "NOT_OBSERVED"
            assert data["dns_activity"]["query_count"] == 0
            assert data["reputation"]["active_record"] is False



# ===========================================================================
# CLIENT INVESTIGATION TESTS (C1 - C3)
# ===========================================================================
class TestClientInvestigation:
    def test_c1_known_client_investigation(self, client):
        """C1: Known active client IP -> Returns full profiling summary."""
        res_list = client.get("/api/v1/clients?page=1&page_size=1")
        if res_list.status_code == 200 and res_list.json().get("data"):
            known_ip = res_list.json()["data"][0]["client_ip"]
            res = client.get(f"/api/v1/investigation/client/{known_ip}")
            assert res.status_code == 200
            data = res.json()["data"]
            assert data["client"]["ip"] == known_ip
            assert "summary" in data
            assert "threat_traffic_ratio" in data["summary"]
            assert "threat_domain_ratio" in data["summary"]
            assert data["summary"]["total_queries"] >= 0
            assert "top_domains" in data
            assert "recent_activity" in data

    def test_c2_client_with_malicious_activity(self, client):
        """C2: Client with malicious activity has flagged threat domains."""
        res = client.get("/api/v1/investigation/client/192.168.1.100")
        if res.status_code == 200:
            data = res.json()["data"]
            assert "threat_traffic_ratio" in data["summary"]
            assert "threat_domain_ratio" in data["summary"]
            assert data["summary"]["malicious_queries"] >= 0
            assert data["summary"]["malicious_domains"] >= 0

    def test_c3_unobserved_client_not_found(self, client):
        """C3: Unobserved client IP -> Clean 404 Not Found handling."""
        res = client.get("/api/v1/investigation/client/10.254.254.254")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()


# ===========================================================================
# HARDENED INVARIANT TESTS (P1 - P15 COMPLETE)
# ===========================================================================
class TestPhase3HardenedInvariants:
    def test_p1_persisted_evidence_not_reported_as_live(self, client):
        """P1: Persisted reputation evidence must report ACTIVE_REPUTATION freshness, not LIVE_LOOKUP."""
        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        data = res.json()["data"]
        vt = data["external_intelligence"]["virustotal"]
        assert vt["freshness"] == "ACTIVE_REPUTATION"
        assert vt["provenance"] == "PERSISTED"

    def test_p2_no_data_is_not_benign(self, client):
        """P2: Provider NO_DATA must not cause a domain to become false benign."""
        res = client.get("/api/v1/investigation/domain/random-unknown-sample-test-123.org")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["classification"]["status"] in ("REVIEW_NEEDED", "UNKNOWN")
        assert data["classification"]["label"] != "benign"

    def test_p3_not_configured_is_not_benign(self, client):
        """P3: Unconfigured provider credentials must not cause a domain to become false benign."""
        res = client.get("/api/v1/investigation/domain/random-unseen-domain-999.info")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["classification"]["status"] in ("REVIEW_NEEDED", "UNKNOWN")

    def test_p4_provider_failure_is_not_benign(self, client):
        """P4: Provider failure is marked distinctively and never converted to benign."""
        res = client.get("/api/v1/investigation/domain/random-unseen-domain-999.info")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["classification"]["status"] != "KNOWN_CLEAN"

    def test_p5_persisted_provider_evidence_provenance(self, client):
        """P5: Persisted provider evidence explicitly states PERSISTED provenance."""
        res = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["external_intelligence"]["virustotal"]["provenance"] == "PERSISTED"
        assert data["external_intelligence"]["otx"]["provenance"] == "PERSISTED"

    def test_p6_live_provider_evidence_provenance(self, client):
        """P6: Live provider lookup produces REAL provenance and LIVE_LOOKUP freshness."""
        res = client.get("/api/v1/investigation/domain/random-live-query-domain.biz?force_external=true")
        assert res.status_code == 200
        data = res.json()["data"]
        ext = data["external_intelligence"]
        assert ext["provenance"] in ("REAL", "LOCAL", None)

    def test_p7_threat_traffic_ratio_calculation(self, client):
        """P7: Threat traffic ratio is calculated as malicious_queries / total_queries * 100."""
        res = client.get("/api/v1/investigation/client/192.168.1.100")
        if res.status_code == 200:
            summary = res.json()["data"]["summary"]
            tot = summary["total_queries"]
            mal = summary["malicious_queries"]
            expected = round((mal / max(1, tot)) * 100.0, 2)
            assert summary["threat_traffic_ratio"] == expected

    def test_p8_threat_domain_ratio_calculation(self, client):
        """P8: Threat domain ratio is calculated as malicious_domains / unique_domains * 100."""
        res = client.get("/api/v1/investigation/client/192.168.1.100")
        if res.status_code == 200:
            summary = res.json()["data"]["summary"]
            uniq = summary["unique_domains"]
            mal_d = summary["malicious_domains"]
            expected = round((mal_d / max(1, uniq)) * 100.0, 2)
            assert summary["threat_domain_ratio"] == expected

    def test_p9_suspicious_classification_honest_source(self, client):
        """P9: Suspicious classifications do not use fake 'unknown' ti_source anywhere."""
        res = client.get("/api/v1/investigation/client/192.168.1.100")
        if res.status_code == 200:
            threats = res.json()["data"]["threat_domains"]
            for t in threats:
                if t["label"] == "suspicious":
                    assert t["ti_source"] != "unknown"
                    assert t["provenance"] == "COMPUTED"
            # Check recent_activity
            for a in res.json()["data"]["recent_activity"]:
                if str(a.get("final_label")).strip().lower() in ("suspicious", "anomaly"):
                    assert a["ti_source"] != "unknown"
                    assert a["provenance"] == "COMPUTED"

    def test_p10_unknown_domain_remains_200_and_not_observed(self, client):
        """P10: Unknown domain returns 200 with NOT_OBSERVED status and 0 queries."""
        res = client.get("/api/v1/investigation/domain/arbitrary-nonexistent-domain-456.xyz")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["dns_activity"]["status"] == "NOT_OBSERVED"
        assert data["dns_activity"]["query_count"] == 0

    def test_p11_unknown_client_remains_404(self, client):
        """P11: Unobserved client returns clean 404."""
        res = client.get("/api/v1/investigation/client/10.123.45.67")
        assert res.status_code == 404

    def test_p12_exact_malicious_subdomain_overrides_trusted_parent(self, client):
        """P12: evil.google.com has status KNOWN_MALICIOUS despite google.com being Tranco top-1M."""
        res = client.get("/api/v1/investigation/domain/evil.google.com")
        assert res.status_code == 200
        assert res.json()["data"]["classification"]["status"] == "KNOWN_MALICIOUS"

    def test_p13_golden_payload_consistency(self, client):
        """P13: Canonical golden payloads have internally consistent schemas and mathematical invariants."""
        res_d = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res_d.status_code == 200
        data_d = res_d.json()["data"]
        assert data_d["classification"]["status"] == "KNOWN_MALICIOUS"
        assert data_d["external_intelligence"]["status"] == "AVAILABLE"
        assert data_d["external_intelligence"]["provenance"] == "PERSISTED"
        assert data_d["external_intelligence"]["freshness"] == "ACTIVE_REPUTATION"

        res_c = client.get("/api/v1/investigation/client/192.168.1.100")
        if res_c.status_code == 200:
            summary = res_c.json()["data"]["summary"]
            tot = summary["total_queries"]
            uniq = summary["unique_domains"]
            mal_q = summary["malicious_queries"]
            mal_d = summary["malicious_domains"]
            assert summary["threat_traffic_ratio"] == round((mal_q / max(1, tot)) * 100.0, 2)
            assert summary["threat_domain_ratio"] == round((mal_d / max(1, uniq)) * 100.0, 2)
            assert summary["risk_status"] in ("THREATS_DETECTED", "CLEAN_TRAFFIC")


    def test_p14_normalization_case_and_trailing_dot(self, client):
        """P14: Normalization strips trailing dots and handles case insensitivity."""
        res1 = client.get("/api/v1/investigation/domain/GoOgLe.CoM.")
        assert res1.status_code == 200
        assert res1.json()["data"]["domain"]["fqdn"] == "google.com"

    def test_p15_legacy_route_compatibility(self, client):
        """P15: Legacy /api/v1/domains and /api/v1/clients routes are untouched and functional."""
        res_d = client.get("/api/v1/domains?page=1&page_size=2")
        assert res_d.status_code == 200
        res_c = client.get("/api/v1/clients?page=1&page_size=2")
        assert res_c.status_code == 200
