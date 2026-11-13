"""
investigation/enrichment/models.py
==================================
Pydantic contracts for live domain registration (RDAP) and DNS resolution.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field


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
