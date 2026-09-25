"""
Phase 4 — Enrichment Pydantic Models
=====================================
Explicit schemas for:
- Live DNS Resolution (A, AAAA, CNAME, NS, structured MX)
- IP Geolocation (IPinfo)
- IP ASN / Network (GeoLite2-ASN)
- Domain Registration (Authoritative RDAP)
- Unified Domain Enrichment Result
- Client IP Endpoint Enrichment Result
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# DNS Models
# ---------------------------------------------------------------------------
class MXRecord(BaseModel):
    priority: int
    exchange: str


class DNSResolutionResult(BaseModel):
    status: str = "NO_DATA"  # AVAILABLE | NO_DATA | PROVIDER_FAILURE
    a: List[str] = Field(default_factory=list)
    aaaa: List[str] = Field(default_factory=list)
    cname: List[str] = Field(default_factory=list)
    ns: List[str] = Field(default_factory=list)
    mx: List[MXRecord] = Field(default_factory=list)
    provider: str = "DNS Resolver"
    provenance: str = "REAL"
    freshness: str = "LIVE_LOOKUP"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# IP Geolocation & Network Models
# ---------------------------------------------------------------------------
class IPGeoResult(BaseModel):
    status: str = "NO_DATA"  # AVAILABLE | NO_DATA | PROVIDER_FAILURE | NOT_CONFIGURED | NOT_APPLICABLE
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    postal: Optional[str] = None
    accuracy_radius: Optional[int] = None
    provider: str = "IPinfo"
    provenance: str = "REAL"
    freshness: str = "LIVE_LOOKUP"
    error: Optional[str] = None


class IPNetworkResult(BaseModel):
    status: str = "NO_DATA"  # AVAILABLE | NO_DATA | PROVIDER_FAILURE | NOT_APPLICABLE
    asn: Optional[str] = None  # e.g. "AS15169"
    asn_organization: Optional[str] = None
    isp: Optional[str] = None
    organization: Optional[str] = None
    connection_type: Optional[str] = None
    provider: str = "GeoLite2-ASN"
    provenance: str = "LOCAL"
    freshness: str = "LIVE_LOOKUP"
    error: Optional[str] = None


class IPEnrichmentItem(BaseModel):
    ip: str
    ip_type: str = "PUBLIC"  # PUBLIC | PRIVATE | LOOPBACK | LINK_LOCAL | MULTICAST | UNSPECIFIED | RESERVED
    geo: IPGeoResult
    network: IPNetworkResult


# ---------------------------------------------------------------------------
# Domain Registration (RDAP) Models
# ---------------------------------------------------------------------------
class DomainRegistrationResult(BaseModel):
    status: str = "NO_DATA"  # AVAILABLE | NO_DATA | PROVIDER_FAILURE
    source: str = "Authoritative RDAP"
    registrar: Optional[str] = None
    registrar_id: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    expires_at: Optional[str] = None
    domain_status: List[str] = Field(default_factory=list)
    nameservers: List[str] = Field(default_factory=list)
    provider: str = "Authoritative RDAP"
    provenance: str = "REAL"
    freshness: str = "LIVE_LOOKUP"
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Top-Level Aggregated Enrichment Results
# ---------------------------------------------------------------------------
class DomainEnrichmentResult(BaseModel):
    status: str = "NO_DATA"  # AVAILABLE | PARTIAL | NO_DATA | PROVIDER_FAILURE | NOT_CONFIGURED
    dns: DNSResolutionResult
    ips: List[IPEnrichmentItem] = Field(default_factory=list)
    registration: DomainRegistrationResult
    duration_ms: float = 0.0


class ClientIPEnrichmentResult(BaseModel):
    ip: str
    ip_type: str = "PUBLIC"
    status: str = "NO_DATA"  # AVAILABLE | PARTIAL | NO_DATA | PROVIDER_FAILURE | NOT_CONFIGURED | NOT_APPLICABLE
    geo: IPGeoResult
    network: IPNetworkResult
    duration_ms: float = 0.0
