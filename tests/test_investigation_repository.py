"""
tests/test_investigation_repository.py
======================================
Tests for InvestigationRepository: SQL queries, parameterized safety,
boundary limits, reverse lookups, and persisted threat intel.
"""

import pytest
from investigation.repository import InvestigationRepository, _sanitize_evidence_summary


@pytest.fixture
def repo():
    return InvestigationRepository()


# ---------------------------------------------------------------------------
# Client Repository Tests
# ---------------------------------------------------------------------------

def test_repo_client_profile_existing(repo):
    # '10.0.0.5' is an existing client in the database
    profile = repo.get_client_profile("10.0.0.5")
    assert profile is not None
    assert profile["client_ip"] == "10.0.0.5"
    assert profile["total_queries"] > 0
    assert "benign_queries" in profile
    assert "malicious_queries" in profile
    assert "review_needed_queries" in profile
    assert "unknown_queries" in profile
    # Verify sum invariant in DB
    v_sum = (
        profile["benign_queries"]
        + profile["malicious_queries"]
        + profile["review_needed_queries"]
        + profile["unknown_queries"]
    )
    assert v_sum == profile["total_queries"]


def test_repo_client_profile_non_existent(repo):
    profile = repo.get_client_profile("192.0.2.254")
    assert profile is None


def test_repo_client_relationships_bounded(repo):
    rels = repo.get_client_relationships("10.0.0.5", limit=5)
    assert isinstance(rels, list)
    assert len(rels) <= 5
    for r in rels:
        assert "domain" in r
        assert "visit_count" in r
        assert r["visit_count"] > 0
        v_sum = r["benign_visits"] + r["malicious_visits"] + r["review_needed_visits"] + r["unknown_visits"]
        assert v_sum == r["visit_count"]


def test_repo_client_threat_activity_filter(repo):
    threats = repo.get_client_threat_activity("10.0.0.5", limit=20)
    assert isinstance(threats, list)
    for t in threats:
        # Must have at least one non-benign visit
        non_benign = t["malicious_visits"] + t["review_needed_visits"] + t["unknown_visits"]
        assert non_benign > 0


# ---------------------------------------------------------------------------
# Domain Repository Tests
# ---------------------------------------------------------------------------

def test_repo_domain_profile_existing(repo):
    # 'google.com' is an existing domain in the database
    profile = repo.get_domain_profile("google.com")
    assert profile is not None
    assert profile["domain"] == "google.com"
    assert profile["total_queries"] > 0
    assert "benign_queries" in profile
    assert "malicious_queries" in profile
    assert "review_needed_queries" in profile
    assert "unknown_queries" in profile
    assert "query_type_distribution" in profile
    dist = profile["query_type_distribution"]
    assert "A" in dist
    assert "AAAA" in dist
    # Verify sum invariant
    v_sum = (
        profile["benign_queries"]
        + profile["malicious_queries"]
        + profile["review_needed_queries"]
        + profile["unknown_queries"]
    )
    assert v_sum == profile["total_queries"]


def test_repo_domain_profile_non_existent(repo):
    profile = repo.get_domain_profile("nonexistent-domain-test-xyz.org")
    assert profile is None


def test_repo_domain_querying_clients_reverse_lookup(repo):
    clients = repo.get_domain_querying_clients("google.com", limit=10)
    assert isinstance(clients, list)
    for c in clients:
        assert "client_ip" in c
        assert "visit_count" in c
        assert c["visit_count"] > 0
        v_sum = c["benign_visits"] + c["malicious_visits"] + c["review_needed_visits"] + c["unknown_visits"]
        assert v_sum == c["visit_count"]


def test_repo_domain_threat_intel_reputation(repo):
    # Query known reputation domain if present or test structure
    ti = repo.get_domain_threat_intel("google.com")
    assert isinstance(ti, dict)
    assert "reputation" in ti
    assert "daily_review" in ti
    assert "reviewed_clean" in ti


def test_repo_domain_threat_intel_daily_review(repo):
    # 'log-collector.net' is known in daily_review_domains
    ti = repo.get_domain_threat_intel("log-collector.net")
    assert ti["daily_review"] is not None
    assert ti["daily_review"]["status"] == "review_needed"
    assert ti["daily_review"]["review_count"] >= 1


def test_repo_domain_threat_intel_reviewed_clean(repo):
    # 'amazoncompte.fr' is known in reviewed_clean_domains
    ti = repo.get_domain_threat_intel("amazoncompte.fr")
    assert ti["reviewed_clean"] is not None
    assert ti["reviewed_clean"]["status"] == "clean"
    assert ti["reviewed_clean"]["verification_source"] == "online_correlation"


# ---------------------------------------------------------------------------
# Evidence Whitelist Sanitization Tests (Strict Isolation)
# ---------------------------------------------------------------------------

def test_evidence_summary_null():
    # 4. NULL payload returns None
    assert _sanitize_evidence_summary(None, None) is None


def test_evidence_summary_empty():
    # 3. Empty payload returns None
    assert _sanitize_evidence_summary({}, {}) is None


def test_evidence_summary_known_virustotal():
    # 1. Known VirusTotal summary
    vt_payload = {"status": "AVAILABLE", "malicious_count": 0, "harmless_count": 72, "suspicious_count": 1}
    summary = _sanitize_evidence_summary(vt_payload, None)
    assert summary is not None
    assert "virustotal" in summary
    assert summary["virustotal"] == {
        "provider": "VirusTotal",
        "malicious_count": 0,
        "harmless_count": 72,
        "suspicious_count": 1,
    }


def test_evidence_summary_known_otx():
    # 2. Known OTX summary
    otx_payload = {"pulse_info": {"count": 7, "pulses": [1, 2, 3]}}
    summary = _sanitize_evidence_summary(None, otx_payload)
    assert summary is not None
    assert "alienvault_otx" in summary
    assert summary["alienvault_otx"] == {
        "provider": "AlienVault OTX",
        "pulse_count": 7,
    }


def test_evidence_summary_unexpected_keys():
    # 5. Unexpected keys ignored and returns None
    vt_unexpected = {"unknown_vendor_key": "some_data", "another_unknown": 123}
    otx_unexpected = {"custom_tag": "test"}
    assert _sanitize_evidence_summary(vt_unexpected, otx_unexpected) is None


def test_evidence_summary_nested_arbitrary_payload():
    # 6. Nested arbitrary payload ignored and returns None
    vt_nested = {"data": {"nested_unknown": {"foo": "bar"}}}
    otx_nested = {"general": {"unrelated_list": [1, 2, 3]}}
    assert _sanitize_evidence_summary(vt_nested, otx_nested) is None


def test_evidence_summary_malformed_payload():
    # 7. Malformed payload returns None
    assert _sanitize_evidence_summary("not a dict", 12345) is None
    assert _sanitize_evidence_summary({"malicious_count": "invalid_int"}, None) is None


def test_evidence_summary_guarantee_no_arbitrary_keys_leaked():
    # 8. Guarantee that arbitrary provider fields are not leaked
    vt_payload = {
        "malicious_count": 2,
        "harmless_count": 50,
        "secret_token": "leak_me",
        "raw_json_dump": {"nested": "value"},
    }
    otx_payload = {
        "pulse_info": {"count": 4},
        "internal_ip": "10.10.10.10",
        "raw_pulses": [{"id": 1, "description": "do not leak"}],
    }
    summary = _sanitize_evidence_summary(vt_payload, otx_payload)
    assert summary is not None
    # VT check: only allowed keys
    vt_res = summary["virustotal"]
    assert set(vt_res.keys()) <= {"provider", "malicious_count", "harmless_count", "suspicious_count"}
    assert "secret_token" not in vt_res
    assert "raw_json_dump" not in vt_res

    # OTX check: only allowed keys
    otx_res = summary["alienvault_otx"]
    assert set(otx_res.keys()) <= {"provider", "pulse_count"}
    assert "internal_ip" not in otx_res
    assert "raw_pulses" not in otx_res


# ---------------------------------------------------------------------------
# Client History All-Row Reconciliation Test
# ---------------------------------------------------------------------------

def test_repo_all_client_history_rows_reconciliation(repo):
    """
    CRITICAL INVARIANT TEST:
    Examines EVERY row in client_history and verifies:
    benign_visits + malicious_visits + review_needed_visits + unknown_visits == visit_count.
    Fails loudly if any row violates the 4-state verdict invariant.
    """
    import psycopg2.extras
    with repo._get_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("""
                SELECT 
                    host(client_ip) AS client_ip,
                    domain,
                    visit_count,
                    benign_visits,
                    malicious_visits,
                    review_needed_visits,
                    unknown_visits
                FROM client_history;
            """)
            rows = cur.fetchall()
            assert len(rows) > 0, "client_history must not be empty"

            violations = []
            for r in rows:
                v_sum = (
                    r["benign_visits"]
                    + r["malicious_visits"]
                    + r["review_needed_visits"]
                    + r["unknown_visits"]
                )
                if v_sum != r["visit_count"]:
                    violations.append(
                        f"Client {r['client_ip']} -> {r['domain']}: "
                        f"sum({v_sum}) != visit_count({r['visit_count']}) "
                        f"(benign={r['benign_visits']}, mal={r['malicious_visits']}, "
                        f"rev={r['review_needed_visits']}, unk={r['unknown_visits']})"
                    )

            assert len(violations) == 0, f"Found {len(violations)} client_history invariant violations:\n" + "\n".join(violations)


# ---------------------------------------------------------------------------
# Security & Parameterized Query Safety
# ---------------------------------------------------------------------------

def test_repo_sql_injection_defense_domain(repo):
    injection_domain = "google.com'; DROP TABLE domain_profiles; --"
    res = repo.get_domain_profile(injection_domain)
    assert res is None


def test_repo_read_only_guarantee(repo):
    forbidden = ["insert", "update", "delete", "drop", "create", "alter", "write"]
    for attr in dir(repo):
        if not attr.startswith("_"):
            for f in forbidden:
                assert not attr.startswith(f), f"Repository must be read-only; found {attr}"
