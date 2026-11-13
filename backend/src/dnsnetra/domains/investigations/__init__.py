"""
investigation
=============
Investigation Engine for DNSNetra.
Provides read-only, on-demand 360-degree analyst dossiers for Client IPs and Domains.
"""

from .schemas import (
    InvestigationError,
    EntityNotFoundError,
    InvalidEntityError,
    InvariantViolationError,
    QueryEventSummary,
    ClientProfileSummary,
    ClientRelationshipItem,
    ClientThreatActivityItem,
    ClientDossier,
    DomainProfileSummary,
    DomainQueryingClientItem,
    ReputationContext,
    DailyReviewContext,
    ReviewedCleanContext,
    PersistedThreatIntel,
    DomainDossier,
)
from .repository import InvestigationRepository
from .service import InvestigationService

__all__ = [
    "InvestigationError",
    "EntityNotFoundError",
    "InvalidEntityError",
    "InvariantViolationError",
    "QueryEventSummary",
    "ClientProfileSummary",
    "ClientRelationshipItem",
    "ClientThreatActivityItem",
    "ClientDossier",
    "DomainProfileSummary",
    "DomainQueryingClientItem",
    "ReputationContext",
    "DailyReviewContext",
    "ReviewedCleanContext",
    "PersistedThreatIntel",
    "DomainDossier",
    "InvestigationRepository",
    "InvestigationService",
]
