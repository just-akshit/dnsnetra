"""
tests/test_client_profiling.py
==============================
Focused test suite for Phase 1: Client Profiling Repair & Data Contract.

Verifies:
- Complete client_profiles schema contract & counters
- Canonical four-state verdicts (Benign, Malicious, Review Needed, Unknown)
- Event metadata propagation (event timestamp, query_type, final_label)
- Event timestamp preservation (not datetime.now())
- Out-of-order event timestamp handling (LEAST/GREATEST & last_domain)
- Client history visit counters and unique constraint integrity
- Transaction atomicity & rollback safety
- Restored client 192.168.10.51 existence and accuracy
- Reconciliation against domain_query_history (DELTA = 0)
- Domain repository Review Needed statistics & label filtering
"""

from datetime import datetime, timezone, timedelta
import pytest
import psycopg2
import psycopg2.extras

from client_profiling.manager import process_query, get_client_profile, get_client_history
from client_profiling.db import get_pool
from domain_profiling.repository import DomainProfilingRepository
from aggregator.config import DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD


TEST_IP_1 = "198.51.100.10"
TEST_IP_2 = "198.51.100.20"
TEST_IP_3 = "198.51.100.30"
ALL_TEST_IPS = [TEST_IP_1, TEST_IP_2, TEST_IP_3]


@pytest.fixture(autouse=True)
def cleanup_test_clients():
    """Ensure test IPs are cleaned up before and after each test."""
    def _cleanup():
        pool = get_pool()
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM client_history WHERE client_ip = ANY(%s::inet[]);",
                    (ALL_TEST_IPS,)
                )
                cur.execute(
                    "DELETE FROM client_profiles WHERE client_ip = ANY(%s::inet[]);",
                    (ALL_TEST_IPS,)
                )
            conn.commit()

    _cleanup()
    yield
    _cleanup()


def test_new_client_creation():
    """Verify new client row is created with all initial contract fields."""
    event_ts = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    process_query(
        client_ip=TEST_IP_1,
        domain="example.com",
        timestamp=event_ts,
        query_type="A",
        final_label="Benign"
    )

    profile = get_client_profile(TEST_IP_1)
    assert profile is not None
    assert profile["client_ip"] == TEST_IP_1
    assert profile["first_seen"] == event_ts
    assert profile["last_seen"] == event_ts
    assert profile["total_queries"] == 1
    assert profile["unique_domains"] == 1
    assert profile["benign_queries"] == 1
    assert profile["malicious_queries"] == 0
    assert profile["review_needed_queries"] == 0
    assert profile["unknown_queries"] == 0
    assert profile["last_domain"] == "example.com"
    assert profile["last_query_type"] == "A"

    history = get_client_history(TEST_IP_1)
    assert len(history) == 1
    assert history[0]["domain"] == "example.com"
    assert history[0]["visit_count"] == 1
    assert history[0]["benign_visits"] == 1
    assert history[0]["malicious_visits"] == 0
    assert history[0]["review_needed_visits"] == 0
    assert history[0]["unknown_visits"] == 0
    assert history[0]["first_seen"] == event_ts
    assert history[0]["last_seen"] == event_ts


def test_existing_client_update_and_multiple_verdicts():
    """Verify client counters aggregate across multiple events and domains."""
    t1 = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 8, 20, 10, 5, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 8, 20, 10, 10, 0, tzinfo=timezone.utc)
    t4 = datetime(2026, 8, 20, 10, 15, 0, tzinfo=timezone.utc)

    # 4 queries: 2 domains, all 4 verdicts
    process_query(TEST_IP_1, "domain-a.org", t1, "A", "Benign")
    process_query(TEST_IP_1, "domain-b.net", t2, "AAAA", "Malicious")
    process_query(TEST_IP_1, "domain-a.org", t3, "MX", "Review Needed")
    process_query(TEST_IP_1, "domain-b.net", t4, "TXT", "Unknown")

    profile = get_client_profile(TEST_IP_1)
    assert profile is not None
    assert profile["total_queries"] == 4
    assert profile["unique_domains"] == 2
    assert profile["benign_queries"] == 1
    assert profile["malicious_queries"] == 1
    assert profile["review_needed_queries"] == 1
    assert profile["unknown_queries"] == 1
    assert profile["first_seen"] == t1
    assert profile["last_seen"] == t4
    assert profile["last_domain"] == "domain-b.net"
    assert profile["last_query_type"] == "TXT"

    history = get_client_history(TEST_IP_1)
    assert len(history) == 2
    h_map = {h["domain"]: h for h in history}

    assert h_map["domain-a.org"]["visit_count"] == 2
    assert h_map["domain-a.org"]["benign_visits"] == 1
    assert h_map["domain-a.org"]["review_needed_visits"] == 1
    assert h_map["domain-a.org"]["first_seen"] == t1
    assert h_map["domain-a.org"]["last_seen"] == t3

    assert h_map["domain-b.net"]["visit_count"] == 2
    assert h_map["domain-b.net"]["malicious_visits"] == 1
    assert h_map["domain-b.net"]["unknown_visits"] == 1
    assert h_map["domain-b.net"]["first_seen"] == t2
    assert h_map["domain-b.net"]["last_seen"] == t4


def test_out_of_order_timestamps():
    """
    Test events arriving out of chronological order.
    Event A: 10:00
    Event B: 10:05
    Event C: 09:55 (arrives last)
    Verify first_seen is 09:55, last_seen is 10:05, and last_domain remains B.
    """
    ts_mid = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    ts_latest = datetime(2026, 8, 20, 10, 5, 0, tzinfo=timezone.utc)
    ts_earliest = datetime(2026, 8, 20, 9, 55, 0, tzinfo=timezone.utc)

    # Ingestion order: mid -> latest -> earliest
    process_query(TEST_IP_2, "mid.com", ts_mid, "A", "Benign")
    process_query(TEST_IP_2, "latest.com", ts_latest, "AAAA", "Malicious")
    process_query(TEST_IP_2, "earliest.com", ts_earliest, "TXT", "Unknown")

    profile = get_client_profile(TEST_IP_2)
    assert profile is not None
    assert profile["total_queries"] == 3
    assert profile["unique_domains"] == 3
    assert profile["first_seen"] == ts_earliest
    assert profile["last_seen"] == ts_latest
    assert profile["last_domain"] == "latest.com"
    assert profile["last_query_type"] == "AAAA"


def test_event_timestamp_preservation_not_datetime_now():
    """Verify that event timestamps in the past are preserved without wall-clock drift."""
    historical_ts = datetime(2025, 1, 15, 8, 30, 0, tzinfo=timezone.utc)
    process_query(TEST_IP_3, "archive.org", historical_ts, "A", "Benign")

    profile = get_client_profile(TEST_IP_3)
    assert profile is not None
    assert profile["first_seen"] == historical_ts
    assert profile["last_seen"] == historical_ts
    assert (datetime.now(timezone.utc) - profile["last_seen"]).days > 30


def test_unique_domains_not_incremented_on_repeat():
    """Verify unique_domains does not increase when visiting existing domains."""
    t1 = datetime(2026, 8, 20, 11, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 8, 20, 11, 1, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 8, 20, 11, 2, 0, tzinfo=timezone.utc)

    process_query(TEST_IP_1, "repeat.com", t1, "A", "Benign")
    process_query(TEST_IP_1, "repeat.com", t2, "A", "Benign")
    process_query(TEST_IP_1, "repeat.com", t3, "A", "Benign")

    profile = get_client_profile(TEST_IP_1)
    assert profile["total_queries"] == 3
    assert profile["unique_domains"] == 1

    history = get_client_history(TEST_IP_1)
    assert len(history) == 1
    assert history[0]["visit_count"] == 3
    assert history[0]["benign_visits"] == 3


def test_missing_client_192_168_10_51_reconciled():
    """Verify client 192.168.10.51 is present in client_profiles and reconciled."""
    target_ip = "192.168.10.51"
    profile = get_client_profile(target_ip)
    assert profile is not None, f"Client {target_ip} missing from client_profiles!"
    assert profile["client_ip"] == target_ip
    assert profile["total_queries"] > 0
    assert profile["unique_domains"] > 0

    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT 
                    COUNT(*) AS raw_count,
                    COUNT(DISTINCT domain) AS raw_domains,
                    MIN(timestamp) AS raw_first,
                    MAX(timestamp) AS raw_last
                FROM domain_query_history
                WHERE client_ip = %s;
                """,
                (target_ip,)
            )
            raw = cur.fetchone()
            assert raw is not None
            assert profile["total_queries"] == raw[0]
            assert profile["unique_domains"] == raw[1]
            assert profile["first_seen"] == raw[2]
            assert profile["last_seen"] == raw[3]


def test_full_reconciliation_zero_delta():
    """
    Reconcile all client profiling counters against domain_query_history.
    Every delta must be 0.
    """
    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # 1. Total event count vs sum(client_profiles.total_queries)
            cur.execute("SELECT COUNT(*) FROM domain_query_history;")
            raw_total = cur.fetchone()[0]

            cur.execute("SELECT SUM(total_queries) FROM client_profiles;")
            profile_total = cur.fetchone()[0]
            assert raw_total == profile_total, f"Total queries delta: {raw_total} vs {profile_total}"

            # 2. Verdict counters
            cur.execute("""
                SELECT 
                    COUNT(*) FILTER (WHERE final_label = 'Benign') AS b,
                    COUNT(*) FILTER (WHERE final_label = 'Malicious') AS m,
                    COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS r,
                    COUNT(*) FILTER (WHERE final_label = 'Unknown') AS u
                FROM domain_query_history;
            """)
            raw_b, raw_m, raw_r, raw_u = cur.fetchone()

            cur.execute("""
                SELECT 
                    SUM(benign_queries),
                    SUM(malicious_queries),
                    SUM(review_needed_queries),
                    SUM(unknown_queries)
                FROM client_profiles;
            """)
            p_b, p_m, p_r, p_u = cur.fetchone()

            assert raw_b == p_b, f"Benign queries delta: {raw_b} vs {p_b}"
            assert raw_m == p_m, f"Malicious queries delta: {raw_m} vs {p_m}"
            assert raw_r == p_r, f"Review Needed queries delta: {raw_r} vs {p_r}"
            assert raw_u == p_u, f"Unknown queries delta: {raw_u} vs {p_u}"
            assert (p_b + p_m + p_r + p_u) == profile_total

            # 3. Client history sum(visit_count) == raw_total
            cur.execute("SELECT SUM(visit_count) FROM client_history;")
            history_total = cur.fetchone()[0]
            assert raw_total == history_total, f"History visits delta: {raw_total} vs {history_total}"

            # 4. Client history verdict sum == visit_count
            cur.execute("""
                SELECT COUNT(*) 
                FROM client_history 
                WHERE visit_count != (benign_visits + malicious_visits + review_needed_visits + unknown_visits);
            """)
            mismatched_history = cur.fetchone()[0]
            assert mismatched_history == 0, f"Found {mismatched_history} client_history rows with mismatched verdict sum"

            # 5. Distinct client count
            cur.execute("SELECT COUNT(DISTINCT client_ip) FROM domain_query_history;")
            raw_clients = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM client_profiles;")
            profile_clients = cur.fetchone()[0]
            assert raw_clients == profile_clients, f"Clients delta: {raw_clients} vs {profile_clients}"


def test_domain_repo_database_statistics_includes_review_needed():
    """Verify DomainRepository.get_database_statistics returns correct review_needed counts."""
    repo = DomainProfilingRepository()
    stats = repo.get_database_statistics()

    assert "total_review_needed_queries_logged" in stats
    assert stats["total_review_needed_queries_logged"] == 448
    assert stats["total_malicious_queries_logged"] == 4626
    assert stats["total_clean_queries_logged"] == 23371
    assert stats["total_unknown_queries_logged"] == 1736


def test_domain_repo_get_most_queried_by_label_all_verdicts():
    """Verify DomainRepository.get_most_queried_by_label correctly handles all 4 canonical verdicts."""
    repo = DomainProfilingRepository()

    # Test Review Needed
    review_res = repo.get_most_queried_by_label("Review Needed", limit=5)
    assert isinstance(review_res, list)
    assert len(review_res) > 0
    for item in review_res:
        assert "label_query_count" in item
        assert "domain" in item

    # Test Malicious
    mal_res = repo.get_most_queried_by_label("Malicious", limit=5)
    assert isinstance(mal_res, list)
    assert len(mal_res) > 0

    # Test Benign
    benign_res = repo.get_most_queried_by_label("Benign", limit=5)
    assert isinstance(benign_res, list)
    assert len(benign_res) > 0

    # Test Unknown
    unknown_res = repo.get_most_queried_by_label("Unknown", limit=5)
    assert isinstance(unknown_res, list)
    assert len(unknown_res) > 0


def test_transaction_rollback_safety():
    """Verify that an invalid event does not commit partial updates."""
    # Attempt to process an invalid IP to trigger validation failure
    with pytest.raises(ValueError):
        process_query(
            client_ip="",
            domain="fail.com",
            timestamp=datetime.now(timezone.utc),
            query_type="A",
            final_label="Benign"
        )

    # Ensure no empty client was created
    profile = get_client_profile("")
    assert profile is None


def test_top_clients_query_contract_and_ordering():
    """Verify aggregator.queries.get_top_clients runs against client_profiles directly."""
    from aggregator.queries import get_top_clients
    top = get_top_clients(limit=5)
    assert isinstance(top, list)
    assert len(top) > 0
    # Verify ordering by query_count DESC
    counts = [item["query_count"] for item in top]
    assert counts == sorted(counts, reverse=True)
    # Verify keys
    for item in top:
        assert "client_ip" in item
        assert "query_count" in item
        assert "malicious_queries" in item
        assert "last_seen" in item


def test_redundant_index_removal_and_constraints():
    """Verify idx_client_history_client_domain is removed and unique_client_domain constraint exists."""
    pool = get_pool()
    with pool.connection() as conn:
        with conn.cursor() as cur:
            # Verify redundant index is gone
            cur.execute("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename = 'client_history' AND indexname = 'idx_client_history_client_domain';
            """)
            assert cur.fetchone() is None

            # Verify unique constraint / index exists
            cur.execute("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename = 'client_history' AND indexname = 'unique_client_domain';
            """)
            assert cur.fetchone() is not None

            # Verify client_profiles indexes exist
            cur.execute("""
                SELECT indexname 
                FROM pg_indexes 
                WHERE tablename = 'client_profiles' AND indexname IN (
                    'idx_client_profiles_last_seen',
                    'idx_client_profiles_total_queries'
                );
            """)
            indexes = {r[0] for r in cur.fetchall()}
            assert "idx_client_profiles_last_seen" in indexes
            assert "idx_client_profiles_total_queries" in indexes

