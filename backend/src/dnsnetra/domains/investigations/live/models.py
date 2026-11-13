"""
investigation/live/models.py
============================
Contracts for live external reputation (VirusTotal + AlienVault OTX) and
infrastructure enrichment (DNS + RDAP) for an arbitrary domain or IP.

These models intentionally contain only bounded, whitelisted evidence. Raw
provider payloads stay in the provider result and never reach the API.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from dnsnetra.domains.investigations.enrichment.models import DNSResolutionResult, DomainRegistrationResult


class ProviderEvidence(BaseModel):
    """Bounded, display-ready evidence from a single external provider."""

    model_config = ConfigDict(frozen=True)

    provider: str
    status: str  # "ok" | "no_data" | "unavailable"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    total: int = 0
    pulse_count: int = 0
    confidence: float = 0.0
    error: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class IndicatorVerdict(BaseModel):
    """Four-state verdict. Absence of data is ``unknown``, never ``clean``."""

    model_config = ConfigDict(frozen=True)

    state: str  # "malicious" | "suspicious" | "clean" | "unknown"
    confidence: float = 0.0
    reasons: List[str] = Field(default_factory=list)
    sources_with_data: int = 0
    sources_queried: int = 0


class IPContext(BaseModel):
    """Network ownership context for a public IP address."""

    model_config = ConfigDict(frozen=True)

    asn: Optional[int] = None
    as_owner: Optional[str] = None
    country: Optional[str] = None
    network: Optional[str] = None
    reputation: Optional[int] = None


class LiveIntelReport(BaseModel):
    """Live external dossier for a domain or IP address."""

    model_config = ConfigDict(frozen=True)

    indicator: str
    kind: str  # "domain" | "ip"
    verdict: IndicatorVerdict
    providers: List[ProviderEvidence] = Field(default_factory=list)
    registration: Optional[DomainRegistrationResult] = None
    dns_records: Optional[DNSResolutionResult] = None
    ip_context: Optional[IPContext] = None
    checked_at: str
