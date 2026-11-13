"""
investigation/enrichment
========================
Live domain registration (RDAP) and DNS resolution enrichment for DNSNetra.
"""

from .models import DomainRegistrationResult, DNSResolutionResult, MXRecord
from .rdap import RDAPEnricher
from .dns_resolver import DNSResolver

__all__ = [
    "DomainRegistrationResult",
    "DNSResolutionResult",
    "MXRecord",
    "RDAPEnricher",
    "DNSResolver",
]
