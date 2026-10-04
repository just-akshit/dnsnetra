"""
tests/test_rdap_enrichment.py
=============================
Unit and mock tests for Authoritative RDAP and live DNS enrichment.
"""

import pytest
import time
from unittest.mock import patch, MagicMock
from investigation.enrichment.rdap import RDAPEnricher
from investigation.enrichment.dns_resolver import DNSResolver
from investigation.enrichment.models import DomainRegistrationResult, DNSResolutionResult, MXRecord
from investigation.schemas import DomainDossier, DomainProfileSummary, PersistedThreatIntel


MOCK_RDAP_RESPONSE = {
    "status": ["clientTransferProhibited", "active"],
    "events": [
        {"eventAction": "registration", "eventDate": "1997-09-15T04:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2028-09-14T04:00:00Z"},
        {"eventAction": "last changed", "eventDate": "2024-08-01T12:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "handle": "292",
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "MarkMonitor, Inc."],
                ],
            ],
        }
    ],
    "nameservers": [
        {"ldhName": "ns1.google.com"},
        {"ldhName": "ns2.google.com"},
    ],
}


class TestRDAPEnrichment:
    """Verify RDAP enricher behavior and parsing."""

    def test_enrich_empty_domain(self):
        enricher = RDAPEnricher(timeout=1.0)
        res = enricher.enrich("")
        assert res.status == "NO_DATA"

    def test_enrich_deadline_exceeded(self):
        enricher = RDAPEnricher(timeout=1.0)
        past_deadline = time.monotonic() - 1.0
        res = enricher.enrich("example.com", deadline=past_deadline)
        assert res.status == "PROVIDER_FAILURE"
        assert "deadline" in (res.error or "").lower()

    @patch("requests.get")
    def test_enrich_successful_rdap_parse(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = MOCK_RDAP_RESPONSE
        mock_get.return_value = mock_resp

        enricher = RDAPEnricher(timeout=2.0)
        res = enricher.enrich("google.com")

        assert res.status == "AVAILABLE"
        assert res.registrar == "MarkMonitor, Inc."
        assert res.registrar_id == "292"
        assert res.created_at == "1997-09-15T04:00:00Z"
        assert res.expires_at == "2028-09-14T04:00:00Z"
        assert "NS1.GOOGLE.COM" in res.nameservers
        assert "NS2.GOOGLE.COM" in res.nameservers
        assert "clientTransferProhibited" in res.domain_status

    @patch("requests.get")
    def test_enrich_404_no_data(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        enricher = RDAPEnricher(timeout=2.0)
        res = enricher.enrich("nonexistent-unregistered-domain-999.com")
        assert res.status == "NO_DATA"


class TestDNSResolver:
    """Verify live DNS resolver behavior."""

    def test_resolve_empty_domain(self):
        resolver = DNSResolver(timeout=1.0)
        res = resolver.resolve("")
        assert res.status == "NO_DATA"

    def test_resolve_deadline_exceeded(self):
        resolver = DNSResolver(timeout=1.0)
        past_deadline = time.monotonic() - 1.0
        res = resolver.resolve("google.com", deadline=past_deadline)
        assert res.status == "PROVIDER_FAILURE"
