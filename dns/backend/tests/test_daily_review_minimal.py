"""
test_daily_review_minimal.py
============================
Focused test suite verifying the minimal Daily Review schema and data model for MVP:
  1. NEW DOMAIN: Injected DNS timestamp -> query_count=1, first_seen=timestamp, last_seen=timestamp.
  2. REPEATED QUERY: Second DNS query -> 1 row, query_count=2, first_seen=T1, last_seen=T2.
  3. THIRD QUERY: Third query -> query_count=3.
  4. OUT-OF-ORDER QUERY: Older query timestamp preserves first_seen=earliest, last_seen=latest.
  5. EXTERNAL REVIEW: last_checked updates while first_seen, last_seen, query_count remain unchanged.
  6. STATUS TRANSITION: REVIEW_NEEDED -> CLEAN -> MALICIOUS, verifying previous_status tracking.
  7. NORMAL DNS QUERY AFTER STATUS CHANGE: query_count increments, last_seen updates, status & previous_status & last_checked unchanged.
  8. QUERY_COUNT MIGRATION: metadata.query_count values safely migrate to query_count column.
  9. SYNCHRONOUS LOCAL INTELLIGENCE INTEGRATION: ThreatIntelligence.evaluate() Step 5 HIT.
  10. REPUTATION DB PROMOTION: Recheck to MALICIOUS populates reputation_db.

All test domains use synthetic names ('mvp-daily-review-test-*.example') and are cleaned up after execution.
"""

from __future__ import annotations

import os
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
import psycopg2
import pytest
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

from labeler.config import LabelingConfig
from labeler.threat_intelligence import ThreatIntelligence
from labeler.intel.daily_review import get_daily_review_verdict, close_connection_pool
from labeler.intel.reputation import get_domain, remove_malicious_domain, close_connection as close_rep_conn
from unknown_domain_repository.unknown_domain_repository.constants import DomainStatus, DomainSource
from unknown_domain_repository.unknown_domain_repository.database import DatabaseManager, DatabaseConfig
from unknown_domain_repository.unknown_domain_repository.config import load_config as load_udr_config
from unknown_domain_repository.unknown_domain_repository.logger import initialize_logger
from unknown_domain_repository.unknown_domain_repository.models import UnknownDomain
from unknown_domain_repository.unknown_domain_repository.repository import UnknownDomainRepository
from scripts.daily_recheck import run_recheck


@pytest.fixture(scope="module")
def repo():
    udr_config = load_udr_config()
    try:
        initialize_logger(udr_config.logging)
    except Exception:
        pass
    db_mgr = DatabaseManager(udr_config)
    db_mgr.initialize()
    repository = UnknownDomainRepository(db_mgr)
    yield repository
    db_mgr.close()
    close_connection_pool()
    close_rep_conn()


@pytest.fixture
def cleanup_test_domains():
    created_domains = []

    def _track(domain: str) -> str:
        created_domains.append(domain)
        return domain

    yield _track

    # Cleanup afterwards
    host = os.getenv("DAILY_REVIEW_DB_HOST", os.getenv("DB_HOST", "localhost"))
    port = int(os.getenv("DAILY_REVIEW_DB_PORT", os.getenv("DB_PORT", "5432")))
    user = os.getenv("DAILY_REVIEW_DB_USERNAME", os.getenv("DB_USER", "postgres"))
    password = os.getenv("DAILY_REVIEW_DB_PASSWORD", os.getenv("DB_PASSWORD", ""))
    database = os.getenv("DAILY_REVIEW_DB_DATABASE", "daily_review_db")

    conn = psycopg2.connect(host=host, port=port, user=user, password=password, dbname=database)
    cur = conn.cursor()
    for d in created_domains:
        cur.execute("DELETE FROM unknown_domains WHERE domain = %s;", (d,))
        remove_malicious_domain(d)
    conn.commit()
    cur.close()
    conn.close()


def test_1_new_domain(repo, cleanup_test_domains):
    """
    TEST 1. NEW DOMAIN
    Insert domain with query timestamp = 2026-08-20 09:15:32 UTC.
    Verify: query_count = 1, first_seen = query timestamp, last_seen = query timestamp.
    """
    domain_name = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime(2026, 8, 20, 9, 15, 32, tzinfo=timezone.utc)

    domain_entity = UnknownDomain.create_new(
        domain=domain_name,
        first_seen=t1,
        last_seen=t1,
        query_count=1,
    )
    inserted, was_inserted = repo.upsert_domain(domain_entity)

    assert was_inserted is True
    assert inserted.domain == domain_name
    assert inserted.query_count == 1
    assert inserted.first_seen == t1
    assert inserted.last_seen == t1
    assert inserted.status == DomainStatus.NEW
    assert inserted.last_checked is None
    assert inserted.previous_status is None


def test_2_repeated_query(repo, cleanup_test_domains):
    """
    TEST 2. REPEATED QUERY
    Send the same domain again at 2026-08-21 10:20:00 UTC.
    Verify: exactly one row exists, query_count = 2, first_seen = T1, last_seen = T2.
    """
    domain_name = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime(2026, 8, 20, 9, 15, 32, tzinfo=timezone.utc)
    t2 = datetime(2026, 8, 21, 10, 20, 0, tzinfo=timezone.utc)

    # First observation
    repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t1, last_seen=t1))

    # Second observation
    domain_q2 = UnknownDomain.create_new(domain=domain_name, first_seen=t2, last_seen=t2)
    updated, was_inserted = repo.upsert_domain(domain_q2, update_last_seen=True)

    assert was_inserted is False
    assert updated.domain == domain_name
    assert updated.query_count == 2
    assert updated.first_seen == t1
    assert updated.last_seen == t2

    # Verify exactly one row in DB
    fetched = repo.get_domain_by_name(domain_name)
    assert fetched is not None
    assert fetched.query_count == 2
    assert fetched.first_seen == t1
    assert fetched.last_seen == t2


def test_3_third_query(repo, cleanup_test_domains):
    """
    TEST 3. THIRD QUERY
    Send another query at 2026-08-25 14:00:00 UTC.
    Verify: query_count = 3.
    """
    domain_name = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime(2026, 8, 20, 9, 15, 32, tzinfo=timezone.utc)
    t2 = datetime(2026, 8, 21, 10, 20, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 8, 25, 14, 0, 0, tzinfo=timezone.utc)

    repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t1, last_seen=t1))
    repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t2, last_seen=t2))
    updated, was_inserted = repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t3, last_seen=t3))

    assert was_inserted is False
    assert updated.query_count == 3
    assert updated.first_seen == t1
    assert updated.last_seen == t3


def test_4_out_of_order_query(repo, cleanup_test_domains):
    """
    TEST 4. OUT-OF-ORDER QUERY
    Send an older timestamp after a newer timestamp.
    Verify: first_seen remains the earliest timestamp, last_seen remains the latest timestamp.
    """
    domain_name = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t_normal = datetime(2026, 8, 20, 12, 0, 0, tzinfo=timezone.utc)
    t_older = datetime(2026, 8, 19, 8, 0, 0, tzinfo=timezone.utc)

    repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t_normal, last_seen=t_normal))

    # Send out-of-order query with older timestamp
    updated, _ = repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t_older, last_seen=t_older))

    assert updated.query_count == 2
    assert updated.first_seen == t_older
    assert updated.last_seen == t_normal


def test_5_external_review(repo, cleanup_test_domains):
    """
    TEST 5. EXTERNAL REVIEW
    Run an external review.
    Verify: last_checked changes, but first_seen, last_seen, query_count do not change.
    """
    domain_name = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime(2026, 8, 20, 9, 15, 32, tzinfo=timezone.utc)
    repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t1, last_seen=t1))

    # Run external review
    review_time = datetime(2026, 8, 20, 10, 30, 0, tzinfo=timezone.utc)
    repo.update_external_review(
        domain_name=domain_name,
        new_status=DomainStatus.REVIEW_NEEDED,
        review_time=review_time,
    )

    domain = repo.get_domain_by_name(domain_name)
    assert domain.last_checked == review_time
    assert domain.first_seen == t1
    assert domain.last_seen == t1
    assert domain.query_count == 1


def test_6_status_transition(repo, cleanup_test_domains):
    """
    TEST 6. STATUS TRANSITION
    Test: REVIEW_NEEDED -> CLEAN
    Verify: previous_status = REVIEW_NEEDED, status = CLEAN
    Then: CLEAN -> MALICIOUS
    Verify: previous_status = CLEAN, status = MALICIOUS
    """
    domain_name = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime(2026, 8, 20, 9, 0, 0, tzinfo=timezone.utc)
    repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t1, last_seen=t1))

    # 1. External review sets REVIEW_NEEDED
    r1_time = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    repo.update_external_review(domain_name, DomainStatus.REVIEW_NEEDED, review_time=r1_time)

    # 2. Recheck transitions REVIEW_NEEDED -> CLEAN
    r2_time = datetime(2026, 8, 21, 10, 0, 0, tzinfo=timezone.utc)
    repo.update_external_review(domain_name, DomainStatus.CLEAN, review_time=r2_time)

    d1 = repo.get_domain_by_name(domain_name)
    assert d1.previous_status == DomainStatus.REVIEW_NEEDED
    assert d1.status == DomainStatus.CLEAN
    assert d1.last_checked == r2_time

    # 3. Later recheck transitions CLEAN -> MALICIOUS
    r3_time = datetime(2026, 8, 22, 10, 0, 0, tzinfo=timezone.utc)
    repo.update_external_review(domain_name, DomainStatus.MALICIOUS, review_time=r3_time)

    d2 = repo.get_domain_by_name(domain_name)
    assert d2.previous_status == DomainStatus.CLEAN
    assert d2.status == DomainStatus.MALICIOUS
    assert d2.last_checked == r3_time


def test_7_normal_dns_query_after_status_change(repo, cleanup_test_domains):
    """
    TEST 7. NORMAL DNS QUERY AFTER STATUS CHANGE
    Send another DNS query.
    Verify: query_count increments, last_seen changes,
    but: status remains MALICIOUS, previous_status remains CLEAN, last_checked does not change.
    """
    domain_name = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime(2026, 8, 20, 9, 0, 0, tzinfo=timezone.utc)
    repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t1, last_seen=t1))

    r1_time = datetime(2026, 8, 20, 10, 0, 0, tzinfo=timezone.utc)
    repo.update_external_review(domain_name, DomainStatus.CLEAN, review_time=r1_time)

    r2_time = datetime(2026, 8, 21, 10, 0, 0, tzinfo=timezone.utc)
    repo.update_external_review(domain_name, DomainStatus.MALICIOUS, review_time=r2_time)

    # Now a normal DNS query arrives at 2026-08-22 15:00:00 UTC
    t_dns = datetime(2026, 8, 22, 15, 0, 0, tzinfo=timezone.utc)
    updated, was_inserted = repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t_dns, last_seen=t_dns))

    assert was_inserted is False
    assert updated.query_count == 2
    assert updated.last_seen == t_dns
    assert updated.status == DomainStatus.MALICIOUS
    assert updated.previous_status == DomainStatus.CLEAN
    assert updated.last_checked == r2_time


def test_8_query_count_migration(repo, cleanup_test_domains):
    """
    TEST 8. QUERY_COUNT MIGRATION
    Verify existing metadata.query_count values are preserved when migrating into the real query_count column.
    """
    from scripts.migrate_daily_review_schema import run_migration

    domain_name = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime(2026, 8, 20, 9, 0, 0, tzinfo=timezone.utc)

    # Insert raw row with metadata.query_count = 27
    with repo.db_manager.transaction() as conn:
        conn.execute(
            """
            INSERT INTO unknown_domains (domain, first_seen, last_seen, source, status, metadata, query_count)
            VALUES (%s, %s, %s, 'dns_query_log', 'new', '{"query_count": 27}'::jsonb, 1);
            """,
            (domain_name, t1, t1),
        )

    # Run migration function
    res = run_migration()
    assert res["success"] is True

    # Verify query_count column is now 27
    row = repo.get_domain_by_name(domain_name)
    assert row.query_count == 27
    assert row.metadata.get("query_count") == 27


def test_9_synchronous_local_intelligence_hit(repo, cleanup_test_domains):
    """
    TEST 9. SYNCHRONOUS LOCAL INTELLIGENCE INTEGRATION
    Verify that ThreatIntelligence.evaluate() recognizes domains in Daily Review as Step 5 HIT.
    """
    domain_clean = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    domain_malicious = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime.now(timezone.utc)

    repo.upsert_domain(UnknownDomain.create_new(domain=domain_clean, first_seen=t1, last_seen=t1))
    repo.update_external_review(domain_clean, DomainStatus.CLEAN)

    repo.upsert_domain(UnknownDomain.create_new(domain=domain_malicious, first_seen=t1, last_seen=t1))
    repo.update_external_review(domain_malicious, DomainStatus.MALICIOUS)

    ti = ThreatIntelligence(LabelingConfig())

    # Check clean domain
    score_c, reasons_c = ti.evaluate(domain_clean)
    assert any("Daily Review Match (clean)" in r for r in reasons_c)

    # Check malicious domain
    score_m, reasons_m = ti.evaluate(domain_malicious)
    assert score_m == 100
    assert any("Daily Review Match (malicious)" in r for r in reasons_m)


def test_10_recheck_process_reputation_promotion(repo, cleanup_test_domains):
    """
    TEST 10. RECHECK PROMOTION TO REPUTATION DB
    Verify that rechecking a domain and finding it MALICIOUS writes to reputation_db.
    """
    domain_name = cleanup_test_domains(f"mvp-daily-review-test-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime.now(timezone.utc) - timedelta(days=365)

    repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t1, last_seen=t1))
    repo.update_external_review(domain_name, DomainStatus.REVIEW_NEEDED, review_time=t1)

    # Custom mock evaluator that marks this domain malicious
    class MockMaliciousDecision:
        malicious = True
        has_intelligence = True

    mock_evaluator = lambda d: MockMaliciousDecision()

    stats = run_recheck(batch_size=500, recheck_hours=24, override_evaluator=mock_evaluator)
    assert stats["transitioned_malicious"] >= 1

    # Verify Daily Review updated
    d = repo.get_domain_by_name(domain_name)
    assert d.status == DomainStatus.MALICIOUS
    assert d.previous_status == DomainStatus.REVIEW_NEEDED

    # Verify Reputation DB received the domain
    rep = get_domain(domain_name)
    assert rep is not None
    assert rep["domain"] == domain_name
    assert rep["status"] == "malicious"


def test_11_clean_to_malicious_recheck_transition(repo, cleanup_test_domains):
    """
    TEST 11. CLEAN -> MALICIOUS VIA DAILY RECHECK & IMMEDIATE LOCAL INTEL HIT
    Verify:
    1. T1: external result = CLEAN (status = CLEAN, last_checked = T1)
    2. T2: next recheck evaluates domain, finds it MALICIOUS
    3. Daily Review updates: previous_status = CLEAN, status = MALICIOUS
    4. Reputation DB receives domain
    5. Next DNS Query evaluates via Local Intelligence -> immediately returns MALICIOUS!
    """
    domain_name = cleanup_test_domains(f"clean-to-malicious-{uuid.uuid4().hex[:8]}.example")
    t1 = datetime.now(timezone.utc) - timedelta(days=365)

    # 1. Domain initially observed and externally evaluated as CLEAN at T1
    repo.upsert_domain(UnknownDomain.create_new(domain=domain_name, first_seen=t1, last_seen=t1))
    repo.update_external_review(domain_name, DomainStatus.CLEAN, review_time=t1)

    initial_rec = repo.get_domain_by_name(domain_name)
    assert initial_rec.status == DomainStatus.CLEAN
    assert initial_rec.last_checked is not None

    # Verify CLEAN domain IS returned as eligible by get_domains_for_recheck
    eligible = repo.get_domains_for_recheck(batch_size=500, older_than_hours=24)
    eligible_names = [d.domain for d in eligible]
    assert domain_name in eligible_names, "CLEAN domain must be eligible for periodic recheck"

    # 2. T2: Daily recheck runs with evaluator finding domain MALICIOUS
    class MockBecameMaliciousDecision:
        malicious = True
        has_intelligence = True

    mock_eval = lambda d: MockBecameMaliciousDecision()
    stats = run_recheck(batch_size=500, recheck_hours=24, override_evaluator=mock_eval)
    assert stats["transitioned_malicious"] >= 1

    # 3. Verify Daily Review record
    updated_rec = repo.get_domain_by_name(domain_name)
    assert updated_rec.status == DomainStatus.MALICIOUS
    assert updated_rec.previous_status == DomainStatus.CLEAN

    # 4. Verify Reputation DB promotion
    rep_entry = get_domain(domain_name)
    assert rep_entry is not None
    assert rep_entry["domain"] == domain_name
    assert rep_entry["status"] == "malicious"

    # 5. Verify immediate Local Intelligence evaluation on incoming DNS query
    ti = ThreatIntelligence(LabelingConfig())
    score, reasons = ti.evaluate(domain_name)
    assert score == 100
    assert any("Reputation Cache Match" in r or "Daily Review Match (malicious)" in r for r in reasons)

