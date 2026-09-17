"""
tests/test_investigation_service.py
===================================
Comprehensive unit & integration tests for InvestigationService.
Covers threat classification, existence semantics, validation, bounded limits,
verdict invariants, TI contracts, and architectural boundaries.
"""

import sys
import pytest
from unittest.mock import MagicMock

from investigation.service import InvestigationService, classify_activity_category
from investigation.schemas import (
    ClientDossier,
    DomainDossier,
    EntityNotFoundError,
    InvalidEntityError,
    InvariantViolationError,
)
from reporting.repository import ReportingRepository


@pytest.fixture
def service():
    return InvestigationService()


# ---------------------------------------------------------------------------
# 1. Threat Classification Tests (Factual Classification)
# ---------------------------------------------------------------------------

def test_threat_activity_classification_pure_malicious():
    assert classify_activity_category(benign_visits=0, malicious_visits=5, review_needed_visits=0, unknown_visits=0) == "MALICIOUS"


def test_threat_activity_classification_pure_review_needed():
    assert classify_activity_category(benign_visits=0, malicious_visits=0, review_needed_visits=3, unknown_visits=0) == "REVIEW_NEEDED"


def test_threat_activity_classification_pure_unknown():
    assert classify_activity_category(benign_visits=0, malicious_visits=0, review_needed_visits=0, unknown_visits=7) == "UNKNOWN"


def test_threat_activity_classification_mixed_benign_and_malicious():
    assert classify_activity_category(benign_visits=10, malicious_visits=2, review_needed_visits=0, unknown_visits=0) == "MIXED"


def test_threat_activity_classification_mixed_benign_and_unknown():
    assert classify_activity_category(benign_visits=10, malicious_visits=0, review_needed_visits=0, unknown_visits=3) == "MIXED"


def test_threat_activity_classification_mixed_malicious_and_review():
    assert classify_activity_category(benign_visits=0, malicious_visits=1, review_needed_visits=1, unknown_visits=0) == "MIXED"


def test_threat_activity_classification_mixed_review_and_unknown():
    assert classify_activity_category(benign_visits=0, malicious_visits=0, review_needed_visits=2, unknown_visits=4) == "MIXED"


def test_threat_activity_classification_mixed_all_four():
    assert classify_activity_category(benign_visits=1, malicious_visits=1, review_needed_visits=1, unknown_visits=1) == "MIXED"


def test_threat_activity_classification_benign_only():
    # If a relationship has only benign visits, it is classified as BENIGN (and excluded from threat_activity)
    assert classify_activity_category(benign_visits=100, malicious_visits=0, review_needed_visits=0, unknown_visits=0) == "BENIGN"


def test_client_threat_activity_excludes_benign_only(service):
    # Retrieve real dossier for 10.0.0.5; any item in threat_activity must have a non-benign visit
    dossier = service.get_client_dossier("10.0.0.5")
    for item in dossier.threat_activity:
        assert item.activity_category in ("MALICIOUS", "REVIEW_NEEDED", "UNKNOWN", "MIXED")
        non_benign = item.malicious_visits + item.review_needed_visits + item.unknown_visits
        assert non_benign > 0


# ---------------------------------------------------------------------------
# 2. Domain Relationships & Querying Clients
# ---------------------------------------------------------------------------

def test_domain_querying_clients_preserves_benign_clients(service):
    # google.com has benign clients
    dossier = service.get_domain_dossier("google.com")
    assert isinstance(dossier.top_querying_clients, list)
    assert len(dossier.top_querying_clients) > 0
    for c in dossier.top_querying_clients:
        assert c.visit_count > 0
        v_sum = c.benign_visits + c.malicious_visits + c.review_needed_visits + c.unknown_visits
        assert v_sum == c.visit_count


def test_domain_querying_clients_bounded_limit(service):
    dossier = service.get_domain_dossier("google.com", limit_relationships=5)
    assert len(dossier.top_querying_clients) <= 5


# ---------------------------------------------------------------------------
# 3. Persisted Threat Intelligence Tests
# ---------------------------------------------------------------------------

def test_persisted_ti_daily_review(service):
    dossier = service.get_domain_dossier("log-collector.net")
    assert dossier.threat_intel.daily_review is not None
    assert dossier.threat_intel.daily_review.status == "review_needed"
    assert dossier.threat_intel.daily_review.review_count >= 1


def test_persisted_ti_reviewed_clean(service):
    dossier = service.get_domain_dossier("amazoncompte.fr")
    assert dossier.threat_intel.reviewed_clean is not None
    assert dossier.threat_intel.reviewed_clean.status == "clean"
    assert dossier.threat_intel.reviewed_clean.verification_source == "online_correlation"


def test_persisted_ti_none_present(service):
    dossier = service.get_domain_dossier("google.com")
    # google.com is clean/trusted and not in daily review or clean promotion table
    assert dossier.threat_intel.daily_review is None
    assert dossier.threat_intel.reviewed_clean is None


def test_persisted_ti_multiple_contexts_coexistence():
    # Mock repository returning both reputation and daily review
    mock_inv_repo = MagicMock()
    mock_inv_repo.get_domain_profile.return_value = {
        "domain": "test-multi.com",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
        "total_queries": 10,
        "unique_clients": 1,
        "benign_queries": 0,
        "malicious_queries": 10,
        "review_needed_queries": 0,
        "unknown_queries": 0,
        "query_type_distribution": {"A": 10},
    }
    mock_inv_repo.get_domain_querying_clients.return_value = []
    mock_inv_repo.get_domain_threat_intel.return_value = {
        "reputation": {
            "status": "malicious",
            "source": "URLhaus",
            "confidence": 1.0,
            "match_scope": "EXACT",
            "first_seen": "2026-01-01T00:00:00Z",
            "last_seen": "2026-01-02T00:00:00Z",
            "verification_count": 1,
        },
        "daily_review": {
            "status": "review_needed",
            "review_count": 1,
            "first_seen_at": "2026-01-01T00:00:00Z",
            "last_seen_at": "2026-01-02T00:00:00Z",
            "next_check_at": "2026-07-01T00:00:00Z",
        },
        "reviewed_clean": None,
    }
    mock_rep_repo = MagicMock()
    mock_rep_repo.get_queries.return_value = (0, [])

    svc = InvestigationService(mock_inv_repo, mock_rep_repo)
    dossier = svc.get_domain_dossier("test-multi.com")
    assert dossier.threat_intel.reputation is not None
    assert dossier.threat_intel.daily_review is not None
    assert dossier.threat_intel.reputation.source == "URLhaus"
    assert dossier.threat_intel.daily_review.status == "review_needed"


# ---------------------------------------------------------------------------
# 4. Existence & Empty State Tests
# ---------------------------------------------------------------------------

def test_client_not_found_raises_404(service):
    with pytest.raises(EntityNotFoundError) as exc:
        service.get_client_dossier("192.0.2.254")
    assert "not found" in str(exc.value)


def test_domain_not_found_raises_404(service):
    with pytest.raises(EntityNotFoundError) as exc:
        service.get_domain_dossier("totally-unobserved-test-123456.org")
    assert "not found" in str(exc.value)


def test_client_clean_returns_valid_dossier_with_empty_threat_activity():
    mock_inv_repo = MagicMock()
    mock_inv_repo.get_client_profile.return_value = {
        "client_ip": "10.1.1.1",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
        "total_queries": 50,
        "unique_domains": 1,
        "benign_queries": 50,
        "malicious_queries": 0,
        "review_needed_queries": 0,
        "unknown_queries": 0,
        "last_domain": "google.com",
        "last_query_type": "A",
    }
    mock_inv_repo.get_client_relationships.return_value = [{
        "domain": "google.com",
        "visit_count": 50,
        "benign_visits": 50,
        "malicious_visits": 0,
        "review_needed_visits": 0,
        "unknown_visits": 0,
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
    }]
    mock_inv_repo.get_client_threat_activity.return_value = []
    mock_rep_repo = MagicMock()
    mock_rep_repo.get_queries.return_value = (0, [])

    svc = InvestigationService(mock_inv_repo, mock_rep_repo)
    dossier = svc.get_client_dossier("10.1.1.1")
    assert isinstance(dossier, ClientDossier)
    assert dossier.threat_activity == []
    assert len(dossier.top_domains) == 1


# ---------------------------------------------------------------------------
# 5. Recent Events & Bounded Limits
# ---------------------------------------------------------------------------

def test_recent_events_default_limit(service):
    dossier = service.get_client_dossier("10.0.0.5")
    assert len(dossier.recent_queries) <= 25


def test_recent_events_clamped_to_max_50(service):
    dossier = service.get_client_dossier("10.0.0.5", limit_recent=100)
    assert len(dossier.recent_queries) <= 50


def test_recent_events_deterministic_order(service):
    dossier = service.get_domain_dossier("google.com", limit_recent=10)
    timestamps = [q.timestamp for q in dossier.recent_queries]
    assert timestamps == sorted(timestamps, reverse=True)


# ---------------------------------------------------------------------------
# 6. Input Validation Tests
# ---------------------------------------------------------------------------

def test_validation_valid_ipv4(service):
    assert service.validate_client_ip("192.168.1.1") == "192.168.1.1"


def test_validation_valid_ipv6(service):
    assert service.validate_client_ip("2001:db8::1") == "2001:db8::1"


def test_validation_rejects_cidr(service):
    with pytest.raises(InvalidEntityError) as exc:
        service.validate_client_ip("192.168.1.0/24")
    assert "CIDR" in str(exc.value)


def test_validation_rejects_malformed_ip(service):
    with pytest.raises(InvalidEntityError):
        service.validate_client_ip("999.999.1.1")


def test_validation_rejects_empty_ip(service):
    with pytest.raises(InvalidEntityError):
        service.validate_client_ip("   ")


def test_validation_domain_normalization(service):
    assert service.validate_domain("  GOOGLE.COM.  ") == "google.com"


def test_validation_rejects_empty_domain(service):
    with pytest.raises(InvalidEntityError):
        service.validate_domain("   ")


def test_validation_rejects_oversized_domain(service):
    oversized = "a" * 250 + ".org"
    with pytest.raises(InvalidEntityError):
        service.validate_domain(oversized)


def test_validation_rejects_malformed_domain(service):
    with pytest.raises(InvalidEntityError):
        service.validate_domain("invalid..domain.com")


# ---------------------------------------------------------------------------
# 7. Invariant Reconciliation Tests
# ---------------------------------------------------------------------------

def test_client_profile_verdict_reconciliation(service):
    dossier = service.get_client_dossier("10.0.0.5")
    p = dossier.profile
    v_sum = p.benign_queries + p.malicious_queries + p.review_needed_queries + p.unknown_queries
    assert v_sum == p.total_queries


def test_domain_profile_verdict_reconciliation(service):
    dossier = service.get_domain_dossier("google.com")
    p = dossier.profile
    v_sum = p.benign_queries + p.malicious_queries + p.review_needed_queries + p.unknown_queries
    assert v_sum == p.total_queries


def test_client_profile_invariant_violation_raises():
    mock_inv_repo = MagicMock()
    # Inconsistent sum: 10 + 0 + 0 + 0 != 20
    mock_inv_repo.get_client_profile.return_value = {
        "client_ip": "10.0.0.1",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
        "total_queries": 20,
        "unique_domains": 1,
        "benign_queries": 10,
        "malicious_queries": 0,
        "review_needed_queries": 0,
        "unknown_queries": 0,
    }
    svc = InvestigationService(mock_inv_repo, MagicMock())
    with pytest.raises(InvariantViolationError) as exc:
        svc.get_client_dossier("10.0.0.1")
    assert "invariant violated" in str(exc.value)


def test_domain_profile_invariant_violation_raises():
    mock_inv_repo = MagicMock()
    # Inconsistent sum: 10 + 0 + 0 + 0 != 20
    mock_inv_repo.get_domain_profile.return_value = {
        "domain": "broken.com",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
        "total_queries": 20,
        "unique_clients": 1,
        "benign_queries": 10,
        "malicious_queries": 0,
        "review_needed_queries": 0,
        "unknown_queries": 0,
        "query_type_distribution": {"A": 10},
    }
    svc = InvestigationService(mock_inv_repo, MagicMock())
    with pytest.raises(InvariantViolationError) as exc:
        svc.get_domain_dossier("broken.com")
    assert "invariant violated" in str(exc.value)


# ---------------------------------------------------------------------------
# 8. Architecture & Decoupling Boundaries
# ---------------------------------------------------------------------------

def test_no_fastapi_imported_by_investigation_subsystem():
    for mod_name in list(sys.modules.keys()):
        if mod_name.startswith("investigation"):
            mod = sys.modules[mod_name]
            for val in vars(mod).values():
                assert "fastapi" not in str(type(val)).lower()


def test_no_reporting_service_dependency_in_investigation():
    from investigation import service
    # Assert ReportingService is not imported or instantiated in investigation.service
    assert not hasattr(service, "ReportingService")


def test_no_external_network_modules_imported():
    forbidden_modules = ["requests", "urllib.request", "httpx", "aiohttp"]
    from investigation import service, repository
    for f in forbidden_modules:
        assert f not in sys.modules or (f not in vars(service) and f not in vars(repository))


def test_no_reporting_imports_investigation():
    import reporting.repository
    import reporting.service
    import reporting.schemas
    for mod in (reporting.repository, reporting.service, reporting.schemas):
        assert not hasattr(mod, "investigation")
        for val in vars(mod).values():
            assert "investigation" not in str(type(val)).lower()


# ---------------------------------------------------------------------------
# 9. Model Immutability Tests (Frozen Verification)
# ---------------------------------------------------------------------------

def test_model_immutability_client_profile_summary():
    from pydantic import ValidationError
    from investigation.schemas import ClientProfileSummary
    p = ClientProfileSummary(
        client_ip="10.0.0.1",
        first_seen="2026-01-01T00:00:00Z",
        last_seen="2026-01-02T00:00:00Z",
        total_queries=10,
        unique_domains=1,
        benign_queries=10,
        malicious_queries=0,
        review_needed_queries=0,
        unknown_queries=0,
    )
    with pytest.raises(ValidationError):
        p.client_ip = "10.0.0.2"


def test_model_immutability_persisted_threat_intel():
    from pydantic import ValidationError
    from investigation.schemas import PersistedThreatIntel, ReputationContext
    ti = PersistedThreatIntel(
        reputation=ReputationContext(
            status="malicious",
            source="URLhaus",
            confidence=1.0,
            match_scope="EXACT",
            first_seen="2026-01-01T00:00:00Z",
            last_seen="2026-01-02T00:00:00Z",
        )
    )
    with pytest.raises(ValidationError):
        ti.reputation = None


def test_model_immutability_client_dossier(service):
    from pydantic import ValidationError
    dossier = service.get_client_dossier("10.0.0.5")
    with pytest.raises(ValidationError):
        dossier.client_ip = "10.0.0.99"


def test_model_immutability_domain_dossier(service):
    from pydantic import ValidationError
    dossier = service.get_domain_dossier("google.com")
    with pytest.raises(ValidationError):
        dossier.domain = "other.org"


# ---------------------------------------------------------------------------
# 10. Relationship Invariant & Edge Cases
# ---------------------------------------------------------------------------

def test_client_relationship_invariant_violation_raises():
    mock_inv_repo = MagicMock()
    mock_inv_repo.get_client_profile.return_value = {
        "client_ip": "10.0.0.1",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
        "total_queries": 10,
        "unique_domains": 1,
        "benign_queries": 10,
        "malicious_queries": 0,
        "review_needed_queries": 0,
        "unknown_queries": 0,
    }
    # Inconsistent sum: 5 + 0 + 0 + 0 != 10
    mock_inv_repo.get_client_relationships.return_value = [{
        "domain": "test.com",
        "visit_count": 10,
        "benign_visits": 5,
        "malicious_visits": 0,
        "review_needed_visits": 0,
        "unknown_visits": 0,
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
    }]
    svc = InvestigationService(mock_inv_repo, MagicMock())
    with pytest.raises(InvariantViolationError) as exc:
        svc.get_client_dossier("10.0.0.1")
    assert "invariant violated" in str(exc.value)


def test_domain_relationship_invariant_violation_raises():
    mock_inv_repo = MagicMock()
    mock_inv_repo.get_domain_profile.return_value = {
        "domain": "test.com",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
        "total_queries": 10,
        "unique_clients": 1,
        "benign_queries": 10,
        "malicious_queries": 0,
        "review_needed_queries": 0,
        "unknown_queries": 0,
        "query_type_distribution": {"A": 10},
    }
    # Inconsistent sum: 5 + 0 + 0 + 0 != 10
    mock_inv_repo.get_domain_querying_clients.return_value = [{
        "client_ip": "10.0.0.1",
        "visit_count": 10,
        "benign_visits": 5,
        "malicious_visits": 0,
        "review_needed_visits": 0,
        "unknown_visits": 0,
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
    }]
    svc = InvestigationService(mock_inv_repo, MagicMock())
    with pytest.raises(InvariantViolationError) as exc:
        svc.get_domain_dossier("test.com")
    assert "invariant violated" in str(exc.value)


def test_existing_entity_with_zero_recent_events():
    mock_inv_repo = MagicMock()
    mock_inv_repo.get_client_profile.return_value = {
        "client_ip": "10.0.0.1",
        "first_seen": "2026-01-01T00:00:00Z",
        "last_seen": "2026-01-02T00:00:00Z",
        "total_queries": 5,
        "unique_domains": 1,
        "benign_queries": 5,
        "malicious_queries": 0,
        "review_needed_queries": 0,
        "unknown_queries": 0,
    }
    mock_inv_repo.get_client_relationships.return_value = []
    mock_inv_repo.get_client_threat_activity.return_value = []
    mock_rep_repo = MagicMock()
    mock_rep_repo.get_queries.return_value = (0, [])

    svc = InvestigationService(mock_inv_repo, mock_rep_repo)
    dossier = svc.get_client_dossier("10.0.0.1")
    assert dossier.recent_queries == []
    assert dossier.top_domains == []
    assert dossier.threat_activity == []

