"""
Phase 4 — Enrichment Module
===========================
Exports core orchestrator, enrichers, and Pydantic models.
"""

from enrichment.models import (
    MXRecord,
    DNSResolutionResult,
    IPGeoResult,
    IPNetworkResult,
    IPEnrichmentItem,
    DomainRegistrationResult,
    DomainEnrichmentResult,
    ClientIPEnrichmentResult,
)
from enrichment.dns import DNSResolverEnricher
from enrichment.ip import IPEnricher, classify_ip
from enrichment.rdap import RDAPEnricher
from enrichment.manager import EnrichmentManager

__all__ = [
    "MXRecord",
    "DNSResolutionResult",
    "IPGeoResult",
    "IPNetworkResult",
    "IPEnrichmentItem",
    "DomainRegistrationResult",
    "DomainEnrichmentResult",
    "ClientIPEnrichmentResult",
    "DNSResolverEnricher",
    "IPEnricher",
    "classify_ip",
    "RDAPEnricher",
    "EnrichmentManager",
]
