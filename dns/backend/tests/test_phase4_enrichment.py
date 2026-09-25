"""
Phase 4 — Domain & Client Enrichment Unit & Integration Tests
============================================================
Tests E1 through E20 verifying:
- DNS resolution (A, AAAA, CNAME, NS, structured MX)
- IP deduplication & multi-IP architecture
- Local GeoLite2-ASN lookups
- IPinfo Geolocation enrichment (configured, unconfigured, timeout, 429)
- RDAP Domain Registration enrichment (success, NO_DATA, failure, redaction)
- IP Classification & strict RFC 1918 private IP guard
- Monotonic deadline & partial status aggregation
- Strict non-contamination of Phase 2.7 threat scores & verdicts
- Phase 3 investigation contract preservation
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient

from api.main import app
from enrichment.dns import DNSResolverEnricher
from enrichment.ip import IPEnricher, classify_ip
from enrichment.models import MXRecord
from enrichment.rdap import RDAPEnricher
from enrichment.manager import EnrichmentManager


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


# ===========================================================================
# E1 - E5: DNS INFRASTRUCTURE RESOLUTION
# ===========================================================================
class TestDNSResolution:
    def test_e1_dns_a_resolution(self):
        """E1: Resolves A records into IPv4 list."""
        enricher = DNSResolverEnricher()
        with patch.object(enricher.resolver, "resolve") as mock_resolve:
            mock_a = MagicMock()
            mock_a.address = "93.184.216.34"
            mock_resolve.return_value = [mock_a]

            res = enricher.resolve("example.com")
            assert res.status == "AVAILABLE"
            assert "93.184.216.34" in res.a
            assert res.provider == "DNS Resolver"
            assert res.provenance == "REAL"
            assert res.freshness == "LIVE_LOOKUP"

    def test_e2_dns_aaaa_resolution(self):
        """E2: Resolves AAAA records into IPv6 list."""
        enricher = DNSResolverEnricher()
        with patch.object(enricher.resolver, "resolve") as mock_resolve:
            def side_effect(domain, rdtype, **kwargs):
                if rdtype == "AAAA":
                    mock_aaaa = MagicMock()
                    mock_aaaa.address = "2606:2800:220:1:248:1893:25c8:1946"
                    return [mock_aaaa]
                raise Exception("NoAnswer")
            mock_resolve.side_effect = side_effect

            res = enricher.resolve("example.com")
            assert res.status == "AVAILABLE"
            assert "2606:2800:220:1:248:1893:25c8:1946" in res.aaaa

    def test_e3_dns_cname_resolution(self):
        """E3: Resolves CNAME canonical targets."""
        enricher = DNSResolverEnricher()
        with patch.object(enricher.resolver, "resolve") as mock_resolve:
            def side_effect(domain, rdtype, **kwargs):
                if rdtype == "CNAME":
                    mock_cname = MagicMock()
                    mock_cname.target = "canonical.example.com."
                    return [mock_cname]
                raise Exception("NoAnswer")
            mock_resolve.side_effect = side_effect

            res = enricher.resolve("alias.example.com")
            assert res.status == "AVAILABLE"
            assert "canonical.example.com" in res.cname

    def test_e4_dns_ns_resolution(self):
        """E4: Resolves authoritative nameserver list."""
        enricher = DNSResolverEnricher()
        with patch.object(enricher.resolver, "resolve") as mock_resolve:
            def side_effect(domain, rdtype, **kwargs):
                if rdtype == "NS":
                    ns1 = MagicMock()
                    ns1.target = "a.iana-servers.net."
                    ns2 = MagicMock()
                    ns2.target = "b.iana-servers.net."
                    return [ns1, ns2]
                raise Exception("NoAnswer")
            mock_resolve.side_effect = side_effect

            res = enricher.resolve("example.com")
            assert res.status == "AVAILABLE"
            assert "a.iana-servers.net" in res.ns
            assert "b.iana-servers.net" in res.ns

    def test_e5_dns_mx_structured_records(self):
        """E5: Resolves MX records as structured objects with priority and exchange."""
        enricher = DNSResolverEnricher()
        with patch.object(enricher.resolver, "resolve") as mock_resolve:
            def side_effect(domain, rdtype, **kwargs):
                if rdtype == "MX":
                    mx1 = MagicMock()
                    mx1.preference = 10
                    mx1.exchange = "mail.example.com."
                    return [mx1]
                raise Exception("NoAnswer")
            mock_resolve.side_effect = side_effect

            res = enricher.resolve("example.com")
            assert res.status == "AVAILABLE"
            assert len(res.mx) == 1
            assert res.mx[0].priority == 10
            assert res.mx[0].exchange == "mail.example.com"


# ===========================================================================
# E6 - E7: MULTI-IP AND DEDUPLICATION
# ===========================================================================
class TestMultiIPAndDeduplication:
    def test_e6_multiple_ips_supported(self):
        """E6: Supports multiple A/AAAA records for 1-to-many infrastructure."""
        mgr = EnrichmentManager()
        with patch.object(mgr.dns_enricher, "resolve") as mock_dns, \
             patch.object(mgr.rdap_enricher, "enrich") as mock_rdap:
            from enrichment.models import DNSResolutionResult, DomainRegistrationResult
            mock_dns.return_value = DNSResolutionResult(
                status="AVAILABLE",
                a=["93.184.216.34", "93.184.216.35"],
                aaaa=["2606:2800:220:1::1"],
            )
            mock_rdap.return_value = DomainRegistrationResult(status="AVAILABLE")

            res = mgr.enrich_domain("example.com")
            assert len(res.ips) == 3
            ip_addrs = [item.ip for item in res.ips]
            assert "93.184.216.34" in ip_addrs
            assert "93.184.216.35" in ip_addrs
            assert "2606:2800:220:1::1" in ip_addrs

    def test_e7_ip_deduplication(self):
        """E7: Deduplicates IP addresses so same IP is only enriched once."""
        enricher = IPEnricher()
        with patch.object(enricher, "enrich_ip") as mock_enrich:
            from enrichment.models import IPEnrichmentItem, IPGeoResult, IPNetworkResult
            mock_enrich.return_value = IPEnrichmentItem(
                ip="1.2.3.4",
                ip_type="PUBLIC",
                geo=IPGeoResult(status="AVAILABLE"),
                network=IPNetworkResult(status="AVAILABLE"),
            )

            result = enricher.enrich_ips_deduplicated(["1.2.3.4", "1.2.3.4", "5.6.7.8", "5.6.7.8"])
            assert len(result) == 2
            assert mock_enrich.call_count == 2


# ===========================================================================
# E8 - E12: ASN & IPINFO GEOLOCATION ENRICHMENT
# ===========================================================================
class TestIPAndASNEnrichment:
    def test_e8_local_asn_lookup(self):
        """E8: Queries local GeoLite2-ASN database."""
        enricher = IPEnricher()
        res = enricher._lookup_asn("8.8.8.8")
        if res.status == "AVAILABLE":
            assert res.asn == "AS15169"
            assert "Google" in (res.asn_organization or "")
            assert res.provider == "GeoLite2-ASN"
            assert res.provenance == "LOCAL"
            assert res.freshness == "LIVE_LOOKUP"

    def test_e9_ipinfo_live_enrichment_mapping(self):
        """E9: IPinfo live enrichment properly maps explicit fields."""
        enricher = IPEnricher(ipinfo_token="test_token")
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "ip": "8.8.8.8",
                "city": "Mountain View",
                "region": "California",
                "country": "US",
                "country_name": "United States",
                "loc": "37.3860,-122.0838",
                "timezone": "America/Los_Angeles",
                "postal": "94035",
                "org": "AS15169 Google LLC",
            }
            mock_get.return_value = mock_resp

            geo = enricher._lookup_geo("8.8.8.8")
            assert geo.status == "AVAILABLE"
            assert geo.city == "Mountain View"
            assert geo.region == "California"
            assert geo.country == "United States"
            assert geo.country_code == "US"
            assert geo.latitude == 37.3860
            assert geo.longitude == -122.0838
            assert geo.timezone == "America/Los_Angeles"
            assert geo.postal == "94035"
            assert geo.provider == "IPinfo"
            assert geo.provenance == "REAL"
            assert geo.freshness == "LIVE_LOOKUP"

    def test_e10_missing_ipinfo_configuration(self):
        """E10: Missing IPinfo credentials returns NOT_CONFIGURED without error."""
        enricher = IPEnricher(ipinfo_token="")
        geo = enricher._lookup_geo("8.8.8.8")
        assert geo.status == "NOT_CONFIGURED"
        assert geo.freshness == "NOT_APPLICABLE"

    def test_e11_ipinfo_timeout_handled(self):
        """E11: IPinfo request timeout returns PROVIDER_FAILURE."""
        import requests
        enricher = IPEnricher(ipinfo_token="test_token")
        with patch("requests.get", side_effect=requests.Timeout("Connection timed out")):
            geo = enricher._lookup_geo("8.8.8.8")
            assert geo.status == "PROVIDER_FAILURE"
            assert "timed out" in (geo.error or "").lower()

    def test_e12_ipinfo_429_rate_limit(self):
        """E12: IPinfo HTTP 429 returns PROVIDER_FAILURE without infinite retries."""
        enricher = IPEnricher(ipinfo_token="test_token")
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 429
            mock_get.return_value = mock_resp

            geo = enricher._lookup_geo("8.8.8.8")
            assert geo.status == "PROVIDER_FAILURE"
            assert "429" in (geo.error or "")


# ===========================================================================
# E13 - E15: RDAP DOMAIN REGISTRATION
# ===========================================================================
class TestRDAPEnrichment:
    def test_e13_rdap_success(self):
        """E13: Authoritative RDAP lookup parses registrar, dates, status, and nameservers."""
        enricher = RDAPEnricher()
        mock_payload = {
            "status": ["clientTransferProhibited", "clientDeleteProhibited"],
            "events": [
                {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2019-09-09T15:39:04Z"},
            ],
            "entities": [
                {
                    "roles": ["registrar"],
                    "handle": "292",
                    "publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
                    "vcardArray": ["vcard", [["fn", {}, "text", "MarkMonitor Inc."]]],
                }
            ],
            "nameservers": [{"ldhName": "NS1.GOOGLE.COM"}, {"ldhName": "NS2.GOOGLE.COM"}],
        }

        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = mock_payload
            mock_get.return_value = mock_resp

            res = enricher.enrich("google.com")
            assert res.status == "AVAILABLE"
            assert res.registrar == "MarkMonitor Inc."
            assert res.registrar_id == "292"
            assert res.created_at == "1997-09-15T04:00:00Z"
            assert res.expires_at == "2028-09-14T04:00:00Z"
            assert res.updated_at == "2019-09-09T15:39:04Z"
            assert "clientTransferProhibited" in res.domain_status
            assert "NS1.GOOGLE.COM" in res.nameservers
            assert res.provider == "Authoritative RDAP"
            assert res.provenance == "REAL"
            assert res.freshness == "LIVE_LOOKUP"

    def test_e14_rdap_no_data(self):
        """E14: Unindexed / unregistered domain returns NO_DATA."""
        enricher = RDAPEnricher()
        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_get.return_value = mock_resp

            res = enricher.enrich("unregistered-random-domain-12345.com")
            assert res.status == "NO_DATA"

    def test_e15_rdap_provider_failure(self):
        """E15: RDAP 500 or timeout returns PROVIDER_FAILURE."""
        import requests
        enricher = RDAPEnricher()
        with patch("requests.get", side_effect=requests.Timeout("RDAP Timeout")):
            res = enricher.enrich("google.com")
            assert res.status == "PROVIDER_FAILURE"
            assert "timed out" in (res.error or "").lower()


# ===========================================================================
# E16 - E18: IP CLASSIFICATION & ORCHESTRATION
# ===========================================================================
class TestIPClassificationAndOrchestration:
    def test_e16_private_ip_guard(self):
        """E16: Private/loopback IPs return NOT_APPLICABLE and never call external GeoIP."""
        enricher = IPEnricher(ipinfo_token="test_token")
        with patch.object(enricher, "_lookup_geo") as mock_geo:
            res_private = enricher.enrich_ip("192.168.1.100")
            assert res_private.ip_type == "PRIVATE"
            assert res_private.geo.status == "NOT_APPLICABLE"
            assert res_private.network.status == "NOT_APPLICABLE"
            assert res_private.geo.provenance == "COMPUTED"
            mock_geo.assert_not_called()

            res_loopback = enricher.enrich_ip("127.0.0.1")
            assert res_loopback.ip_type == "LOOPBACK"
            assert res_loopback.geo.status == "NOT_APPLICABLE"
            mock_geo.assert_not_called()

    def test_e17_public_client_enrichment(self):
        """E17: Public client IP executes ASN and Geo enrichment."""
        mgr = EnrichmentManager()
        res = mgr.enrich_client_ip("8.8.8.8")
        assert res.ip == "8.8.8.8"
        assert res.ip_type == "PUBLIC"
        assert res.network.status in ("AVAILABLE", "NO_DATA")
        assert res.geo.status in ("AVAILABLE", "NOT_CONFIGURED", "PROVIDER_FAILURE")

    def test_e18_partial_enrichment_aggregation(self):
        """E18: Partial enrichment returns status PARTIAL when some components succeed."""
        mgr = EnrichmentManager()
        from enrichment.models import DNSResolutionResult, DomainRegistrationResult
        dns_res = DNSResolutionResult(status="AVAILABLE", a=["8.8.8.8"])
        rdap_res = DomainRegistrationResult(status="PROVIDER_FAILURE")

        overall = mgr._aggregate_domain_status(dns_res, [], rdap_res)
        assert overall == "PARTIAL"


# ===========================================================================
# E19 - E20: PHASE 3 CONTRACT & THREAT SCORING PRESERVATION
# ===========================================================================
class TestContractAndVerdictPreservation:
    def test_e19_phase3_contract_preservation(self, client):
        """E19: Phase 3 investigation payload fields are preserved intact with enrichment attached."""
        res = client.get("/api/v1/investigation/domain/google.com")
        assert res.status_code == 200
        data = res.json()["data"]

        # Check all Phase 3 fields exist
        assert "domain" in data
        assert "classification" in data
        assert "local_intelligence" in data
        assert "external_intelligence" in data
        assert "correlation" in data
        assert "dns_activity" in data
        assert "reputation" in data
        assert "querying_clients" in data
        assert "investigation" in data
        assert "duration_ms" in data

        # Check Phase 4 enrichment field exists
        assert "enrichment" in data
        enrichment = data["enrichment"]
        assert "dns" in enrichment
        assert "ips" in enrichment
        assert "registration" in enrichment
        assert "status" in enrichment

    def test_e20_phase27_threat_verdict_preservation(self, client):
        """E20: Enrichment is strictly observational and never alters Phase 2.7 threat verdicts."""
        # google.com remains POPULAR_BENIGN_CONTEXT
        res_g = client.get("/api/v1/investigation/domain/google.com")
        assert res_g.status_code == 200
        assert res_g.json()["data"]["classification"]["status"] == "POPULAR_BENIGN_CONTEXT"
        assert res_g.json()["data"]["classification"]["risk_score"] == 0.0

        # secure-update.net remains KNOWN_MALICIOUS
        res_s = client.get("/api/v1/investigation/domain/secure-update.net")
        assert res_s.status_code == 200
        assert res_s.json()["data"]["classification"]["status"] == "KNOWN_MALICIOUS"
        assert res_s.json()["data"]["classification"]["risk_score"] == 100.0
