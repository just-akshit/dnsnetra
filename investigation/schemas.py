"""
investigation/schemas.py
========================
Domain contracts, typed models, and exceptions for DNSNetra Investigation Engine.
Pure Python Pydantic models with ZERO HTTP or FastAPI dependencies.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Domain Exceptions
# ---------------------------------------------------------------------------

class InvestigationError(Exception):
    """Base exception for investigation subsystem."""
    pass


class EntityNotFoundError(InvestigationError):
    """Raised when an authoritative client or domain profile is not found."""
    pass


class InvalidEntityError(InvestigationError):
    """Raised when input client IP or domain validation fails."""
    pass


class InvariantViolationError(InvestigationError):
    """Raised when an internal data integrity invariant is violated."""
    pass


# ---------------------------------------------------------------------------
# Common Query Event Preview
# ---------------------------------------------------------------------------

class QueryEventSummary(BaseModel):
    """Bounded recent query event record for forensic preview."""
    model_config = ConfigDict(frozen=True)

    id: int
    timestamp: str  # ISO-8601 UTC string
    client_ip: str
    domain: str
    query_type: str
    response_code: Optional[str] = None
    final_label: str  # Canonical verdict string
    ti_source: Optional[str] = None


# ---------------------------------------------------------------------------
# Client Dossier Contracts
# ---------------------------------------------------------------------------

class ClientProfileSummary(BaseModel):
    """Authoritative lifetime summary of an individual client entity."""
    model_config = ConfigDict(frozen=True)

    client_ip: str
    first_seen: str
    last_seen: str
    total_queries: int
    unique_domains: int
    benign_queries: int
    malicious_queries: int
    review_needed_queries: int
    unknown_queries: int
    last_domain: Optional[str] = None
    last_query_type: Optional[str] = None


class ClientRelationshipItem(BaseModel):
    """Bounded client-to-domain lifetime interaction record."""
    model_config = ConfigDict(frozen=True)

    domain: str
    visit_count: int
    benign_visits: int
    malicious_visits: int
    review_needed_visits: int
    unknown_visits: int
    first_seen: str
    last_seen: str


class ClientThreatActivityItem(BaseModel):
    """Suspect or non-benign relationship item with deterministic activity category."""
    model_config = ConfigDict(frozen=True)

    domain: str
    visit_count: int
    benign_visits: int
    malicious_visits: int
    review_needed_visits: int
    unknown_visits: int
    activity_category: str  # "MALICIOUS", "REVIEW_NEEDED", "UNKNOWN", "MIXED"
    last_seen: str


class ClientDossier(BaseModel):
    """360-degree forensic dossier for an individual client entity."""
    model_config = ConfigDict(frozen=True)

    client_ip: str
    profile: ClientProfileSummary
    top_domains: List[ClientRelationshipItem] = Field(default_factory=list)
    threat_activity: List[ClientThreatActivityItem] = Field(default_factory=list)
    recent_queries: List[QueryEventSummary] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Domain Dossier Contracts
# ---------------------------------------------------------------------------

class DomainProfileSummary(BaseModel):
    """Authoritative lifetime summary of an individual domain entity."""
    model_config = ConfigDict(frozen=True)

    domain: str
    first_seen: str
    last_seen: str
    total_queries: int
    unique_clients: int
    benign_queries: int  # Mapped from domain_profiles.clean_queries
    malicious_queries: int
    review_needed_queries: int
    unknown_queries: int
    query_type_distribution: Dict[str, int] = Field(default_factory=dict)
    last_client_ip: Optional[str] = None
    last_label: Optional[str] = None
    last_ti_source: Optional[str] = None


class DomainQueryingClientItem(BaseModel):
    """Bounded domain-to-client reverse interaction record."""
    model_config = ConfigDict(frozen=True)

    client_ip: str
    visit_count: int
    benign_visits: int
    malicious_visits: int
    review_needed_visits: int
    unknown_visits: int
    first_seen: str
    last_seen: str


class ReputationContext(BaseModel):
    """Persisted malicious reputation evidence from reputation_domains."""
    model_config = ConfigDict(frozen=True)

    status: str
    source: str
    confidence: Optional[float] = None
    match_scope: Optional[str] = None
    matched_domain: Optional[str] = None
    times_seen: int = 1
    query_count: int = 1
    first_seen: str
    last_seen: str
    last_verified_at: Optional[str] = None
    verification_count: Optional[int] = 1


class DailyReviewContext(BaseModel):
    """Persisted review-queue state from daily_review_domains."""
    model_config = ConfigDict(frozen=True)

    status: str
    review_reason: Optional[str] = None
    review_count: int = 1
    first_seen_at: str
    last_seen_at: str
    last_checked_at: Optional[str] = None
    next_check_at: str
    evidence_summary: Optional[Dict[str, Any]] = None


class ReviewedCleanContext(BaseModel):
    """Persisted clean triage verification from reviewed_clean_domains."""
    model_config = ConfigDict(frozen=True)

    status: str
    verification_source: str
    verified_at: str
    review_count: int = 1
    evidence_summary: Optional[Dict[str, Any]] = None


class PersistedThreatIntel(BaseModel):
    """Composite container preserving all active local threat intelligence contexts."""
    model_config = ConfigDict(frozen=True)

    reputation: Optional[ReputationContext] = None
    daily_review: Optional[DailyReviewContext] = None
    reviewed_clean: Optional[ReviewedCleanContext] = None


class DomainDossier(BaseModel):
    """360-degree forensic dossier for an individual domain entity."""
    model_config = ConfigDict(frozen=True)

    domain: str
    profile: DomainProfileSummary
    top_querying_clients: List[DomainQueryingClientItem] = Field(default_factory=list)
    threat_intel: PersistedThreatIntel
    recent_queries: List[QueryEventSummary] = Field(default_factory=list)
