"""
investigation/service.py
========================
Orchestration and business logic layer for DNSNetra Investigation Engine.
Composes profile, relationship, threat intelligence, and event preview data.
Pure Python with ZERO HTTP or web framework dependencies.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, List, Optional

from labeler.intel.database import normalize_domain
from reporting.repository import ReportingRepository
from .repository import InvestigationRepository
from .schemas import (
    ClientDossier,
    ClientProfileSummary,
    ClientRelationshipItem,
    ClientThreatActivityItem,
    DailyReviewContext,
    DomainDossier,
    DomainProfileSummary,
    DomainQueryingClientItem,
    EntityNotFoundError,
    InvalidEntityError,
    InvariantViolationError,
    PersistedThreatIntel,
    QueryEventSummary,
    ReputationContext,
    ReviewedCleanContext,
)

logger = logging.getLogger(__name__)

# Bounded limit constraints
DEFAULT_RELATIONSHIPS_LIMIT = 20
MAX_RELATIONSHIPS_LIMIT = 100

DEFAULT_RECENT_QUERIES_LIMIT = 25
MAX_RECENT_QUERIES_LIMIT = 50


def classify_activity_category(
    benign_visits: int,
    malicious_visits: int,
    review_needed_visits: int,
    unknown_visits: int,
) -> str:
    """
    Deterministically classify non-benign relationships into an activity category.
    Factual historical classification; never infers causal or intent conclusions.
    """
    non_zero_count = sum(
        1 for c in (benign_visits, malicious_visits, review_needed_visits, unknown_visits) if c > 0
    )
    if non_zero_count > 1:
        return "MIXED"
    if malicious_visits > 0:
        return "MALICIOUS"
    if review_needed_visits > 0:
        return "REVIEW_NEEDED"
    if unknown_visits > 0:
        return "UNKNOWN"
    return "BENIGN"


class InvestigationService:
    """
    Orchestration service assembling read-only 360-degree dossiers for analysts.
    """

    def __init__(
        self,
        investigation_repository: Optional[InvestigationRepository] = None,
        reporting_repository: Optional[ReportingRepository] = None,
    ) -> None:
        self._investigation_repo = investigation_repository or InvestigationRepository()
        self._reporting_repo = reporting_repository or ReportingRepository()

    # -----------------------------------------------------------------------
    # Input Validation Helpers
    # -----------------------------------------------------------------------

    @staticmethod
    def validate_client_ip(client_ip: str) -> str:
        """
        Validates client IP string using Python standard library ipaddress.
        Rejects CIDRs, hostnames, empty strings, and malformed characters.
        """
        if not client_ip or not isinstance(client_ip, str) or not client_ip.strip():
            raise InvalidEntityError(f"Client IP must be a non-empty string. Received: {client_ip!r}")

        clean = client_ip.strip()
        if "/" in clean:
            raise InvalidEntityError(f"CIDR ranges are not valid single client IPs: '{clean}'")

        try:
            parsed = ipaddress.ip_address(clean)
            return str(parsed)
        except ValueError as exc:
            raise InvalidEntityError(f"Malformed IP address: '{clean}'") from exc

    @staticmethod
    def validate_domain(domain: str) -> str:
        """
        Normalizes and validates domain string using authoritative project validator.
        Strips whitespace, converts to lowercase, strips trailing dots, and enforces RFC constraints.
        """
        if not domain or not isinstance(domain, str) or not domain.strip():
            raise InvalidEntityError(f"Domain must be a non-empty string. Received: {domain!r}")

        clean = domain.strip()
        if len(clean) > 253:
            raise InvalidEntityError(f"Domain exceeds RFC 1035 limit of 253 characters (length: {len(clean)})")

        normalized = normalize_domain(clean)
        if not normalized:
            raise InvalidEntityError(f"Invalid domain name format: '{clean}'")

        return normalized

    # -----------------------------------------------------------------------
    # Client Investigation Dossier
    # -----------------------------------------------------------------------

    def get_client_dossier(
        self,
        client_ip: str,
        limit_recent: int = DEFAULT_RECENT_QUERIES_LIMIT,
        limit_relationships: int = DEFAULT_RELATIONSHIPS_LIMIT,
    ) -> ClientDossier:
        """
        Assembles 360-degree forensic dossier for an individual client IP.
        """
        clean_ip = self.validate_client_ip(client_ip)
        recent_limit = max(1, min(limit_recent, MAX_RECENT_QUERIES_LIMIT))
        rel_limit = max(1, min(limit_relationships, MAX_RELATIONSHIPS_LIMIT))

        # 1. Authoritative profile lookup
        profile_raw = self._investigation_repo.get_client_profile(clean_ip)
        if not profile_raw:
            raise EntityNotFoundError(f"Client IP '{clean_ip}' not found in client profiles.")

        # Invariant verification: sum of 4 verdicts == total_queries
        v_sum = (
            profile_raw["benign_queries"]
            + profile_raw["malicious_queries"]
            + profile_raw["review_needed_queries"]
            + profile_raw["unknown_queries"]
        )
        if v_sum != profile_raw["total_queries"]:
            raise InvariantViolationError(
                f"Client '{clean_ip}' profile verdict invariant violated: "
                f"sum({v_sum}) != total_queries({profile_raw['total_queries']})"
            )

        profile = ClientProfileSummary(**profile_raw)

        # 2. Bounded top domain relationships
        rel_raw = self._investigation_repo.get_client_relationships(clean_ip, limit=rel_limit)
        top_domains: List[ClientRelationshipItem] = []
        for r in rel_raw:
            r_sum = r["benign_visits"] + r["malicious_visits"] + r["review_needed_visits"] + r["unknown_visits"]
            if r_sum != r["visit_count"]:
                raise InvariantViolationError(
                    f"Relationship invariant violated for client {clean_ip} -> {r['domain']}: "
                    f"sum({r_sum}) != visit_count({r['visit_count']})"
                )
            top_domains.append(ClientRelationshipItem(**r))

        # 3. Bounded threat activity
        threat_raw = self._investigation_repo.get_client_threat_activity(clean_ip, limit=rel_limit)
        threat_activity: List[ClientThreatActivityItem] = []
        for t in threat_raw:
            category = classify_activity_category(
                t["benign_visits"],
                t["malicious_visits"],
                t["review_needed_visits"],
                t["unknown_visits"],
            )
            item_data = dict(t)
            item_data["activity_category"] = category
            threat_activity.append(ClientThreatActivityItem(**item_data))

        # 4. Bounded recent query events via ReportingRepository
        _, raw_events = self._reporting_repo.get_queries(client_ip=clean_ip, limit=recent_limit)
        recent_queries = [
            QueryEventSummary(
                id=ev["id"],
                timestamp=ev["timestamp"],
                client_ip=ev["client_ip"],
                domain=ev["domain"],
                query_type=ev["query_type"],
                response_code=ev.get("response_code"),
                final_label=ev["final_label"],
                ti_source=ev.get("ti_source"),
            )
            for ev in raw_events
        ]

        return ClientDossier(
            client_ip=clean_ip,
            profile=profile,
            top_domains=top_domains,
            threat_activity=threat_activity,
            recent_queries=recent_queries,
        )

    # -----------------------------------------------------------------------
    # Domain Investigation Dossier
    # -----------------------------------------------------------------------

    def get_domain_dossier(
        self,
        domain: str,
        limit_recent: int = DEFAULT_RECENT_QUERIES_LIMIT,
        limit_relationships: int = DEFAULT_RELATIONSHIPS_LIMIT,
    ) -> DomainDossier:
        """
        Assembles 360-degree forensic dossier for an individual domain entity.
        """
        clean_domain = self.validate_domain(domain)
        recent_limit = max(1, min(limit_recent, MAX_RECENT_QUERIES_LIMIT))
        rel_limit = max(1, min(limit_relationships, MAX_RELATIONSHIPS_LIMIT))

        # 1. Authoritative profile lookup
        profile_raw = self._investigation_repo.get_domain_profile(clean_domain)
        if not profile_raw:
            raise EntityNotFoundError(f"Domain '{clean_domain}' not found in domain profiles.")

        # Invariant verification: sum of 4 verdicts == total_queries
        v_sum = (
            profile_raw["benign_queries"]
            + profile_raw["malicious_queries"]
            + profile_raw["review_needed_queries"]
            + profile_raw["unknown_queries"]
        )
        if v_sum != profile_raw["total_queries"]:
            raise InvariantViolationError(
                f"Domain '{clean_domain}' profile verdict invariant violated: "
                f"sum({v_sum}) != total_queries({profile_raw['total_queries']})"
            )

        profile = DomainProfileSummary(**profile_raw)

        # 2. Bounded top querying clients
        clients_raw = self._investigation_repo.get_domain_querying_clients(clean_domain, limit=rel_limit)
        top_querying_clients: List[DomainQueryingClientItem] = []
        for c in clients_raw:
            c_sum = c["benign_visits"] + c["malicious_visits"] + c["review_needed_visits"] + c["unknown_visits"]
            if c_sum != c["visit_count"]:
                raise InvariantViolationError(
                    f"Relationship invariant violated for domain {clean_domain} <- {c['client_ip']}: "
                    f"sum({c_sum}) != visit_count({c['visit_count']})"
                )
            top_querying_clients.append(DomainQueryingClientItem(**c))

        # 3. Persisted threat intelligence context
        ti_raw = self._investigation_repo.get_domain_threat_intel(clean_domain)
        reputation_ctx = ReputationContext(**ti_raw["reputation"]) if ti_raw.get("reputation") else None
        daily_review_ctx = DailyReviewContext(**ti_raw["daily_review"]) if ti_raw.get("daily_review") else None
        reviewed_clean_ctx = ReviewedCleanContext(**ti_raw["reviewed_clean"]) if ti_raw.get("reviewed_clean") else None

        threat_intel = PersistedThreatIntel(
            reputation=reputation_ctx,
            daily_review=daily_review_ctx,
            reviewed_clean=reviewed_clean_ctx,
        )

        # 4. Bounded recent query events via ReportingRepository
        _, raw_events = self._reporting_repo.get_queries(domain=clean_domain, limit=recent_limit)
        recent_queries = [
            QueryEventSummary(
                id=ev["id"],
                timestamp=ev["timestamp"],
                client_ip=ev["client_ip"],
                domain=ev["domain"],
                query_type=ev["query_type"],
                response_code=ev.get("response_code"),
                final_label=ev["final_label"],
                ti_source=ev.get("ti_source"),
            )
            for ev in raw_events
        ]

        return DomainDossier(
            domain=clean_domain,
            profile=profile,
            top_querying_clients=top_querying_clients,
            threat_intel=threat_intel,
            recent_queries=recent_queries,
        )
