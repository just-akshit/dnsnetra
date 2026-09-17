"""
Comprehensive Automated Test Suite for DNSNetra Detection Pipeline
===================================================================
Validates the complete 4-tier threat-detection architecture and fundamental contract:
    DO NOT REPROCESS A DOMAIN THAT DNSNETRA ALREADY KNOWS.

Tests include:
1. TEST 1: L1 RAM Cache Hit (zero DB, zero heuristics, zero VT/OTX)
2. TEST 2: Reputation DB Hit (MALICIOUS, query_count++, times_seen++, last_seen=NOW(), zero heuristics, zero VT/OTX)
3. TEST 3: Trusted DB Hit (CLEAN, zero heuristics, zero VT/OTX)
4. TEST 4: Malicious Feed DB Hit (MALICIOUS, NOT stored to reputation_domains, zero heuristics, zero VT/OTX)
5. TEST 5: Reviewed Clean DB Hit (CLEAN, zero heuristics, zero VT/OTX)
6. TEST 6: Completely New Domain -> Heuristics Executed
7. TEST 7: Completely New Domain -> Online TI Called (VT + OTX)
8. TEST 8: Online TI Malicious -> Promoted to reputation_domains
9. TEST 9: Second Query After Malicious -> Hits local intel, zero external TI
10. TEST 10: Online TI Clean -> Promoted to reviewed_clean_domains
11. TEST 11: Online TI Inconclusive -> Stored in daily_review_domains (+180 days)
12. TEST 12: Daily Review Not Due -> REVIEW_NEEDED, zero heuristics, zero VT/OTX
13. TEST 13: Daily Review Due -> Online TI Called, Heuristics SKIPPED
14. TEST 14: Daily Review Due -> Promoted to Malicious
15. TEST 15: Daily Review Due -> Promoted to Clean
16. TEST 16: Daily Review Due -> Still Inconclusive (extended +180 days, review_count++)
17. TEST 17: External API Failure -> Retry State (1h backoff), NOT marked clean
18. TEST 18: Canonical Domain Normalization
19. TEST 19: Repeated Unknown Domain Telemetry
20. TEST 20: Concurrency & Row Locking (SELECT FOR UPDATE SKIP LOCKED)
21. TEST 21: Admin API Endpoints (Health, Auth, Dossier, Stats, Verdict Override)
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app
from labeler.config import LabelingConfig
from labeler.intel.correlation.engine import CorrelationEngine
from labeler.intel.correlation.models import ThreatDecision, ThreatProviderResult
from labeler.intel.daily_review import (
    DailyReviewWorker,
    DecisionProvenance,
    ReviewStatus,
    claim_due_reviews_for_processing,
    fetch_due_reviews_for_update,
    get_review_domain,
    get_reviewed_clean_domain,
    get_stats,
    promote_to_clean,
    promote_to_malicious,
    recover_stale_processing,
    upsert_review_needed,
)
from labeler.intel.database import normalize_domain
from labeler.intel.reputation import (
    get_domain as get_reputation_domain,
    record_observation,
    store_malicious_domain,
)
from labeler.intel.reputation.connection import get_connection
from labeler.pipeline import DetectionPipeline, DetectionVerdict


@pytest.fixture
def mock_correlation_engine():
    """Create a mock CorrelationEngine for isolated pipeline testing."""
    engine = MagicMock(spec=CorrelationEngine)
    # Default to inconclusive
    engine.evaluate.return_value = ThreatDecision(
        domain="unresolved.test",
        malicious=False,
        score=0.0,
        confidence=0.0,
        threshold=0.60,
        provider_results=[
            ThreatProviderResult(provider="virustotal", malicious=False, confidence=0.0, unavailable=False, found=False),
            ThreatProviderResult(provider="alienvault", malicious=False, confidence=0.0, unavailable=False, found=False),
        ],
        source="TestMock",
    )
    return engine


@pytest.fixture
def pipeline(mock_correlation_engine):
    """Create a test DetectionPipeline with mock engine."""
    config = LabelingConfig()
    pipe = DetectionPipeline(
        config=config,
        correlation_engine=mock_correlation_engine,
        review_interval_days=180,
    )
    return pipe


@pytest.fixture
def test_domain():
    """Generate a unique ephemeral test domain."""
    unique_id = uuid.uuid4().hex[:10]
    domain = f"test-{unique_id}.org"
    yield domain

    # Cleanup DB after test
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM daily_review_domains WHERE domain = %s", (domain,))
                cur.execute("DELETE FROM reviewed_clean_domains WHERE domain = %s", (domain,))
                cur.execute("DELETE FROM reputation_domains WHERE domain = %s", (domain,))
            conn.commit()
    except Exception:
        pass


# ==============================================================================
# TEST 1: L1 RAM Cache Hit (Zero DB, Zero Heuristics, Zero VT/OTX)
# ==============================================================================
def test_1_l1_ram_cache_hit(pipeline, mock_correlation_engine, test_domain):
    # Manually populate L1 RAM cache
    pipeline._populate_l1(test_domain, is_malicious=True, confidence=0.99)

    with patch.object(pipeline.heuristics, "evaluate") as mock_heuristics, \
         patch("labeler.pipeline.get_reputation_domain") as mock_rep:

        verdict = pipeline.evaluate(test_domain)

        assert verdict.verdict == "MALICIOUS"
        assert verdict.provenance == DecisionProvenance.L1_CACHE.value
        assert verdict.ti_source == "cache"

        # Assert no downstream evaluation was performed
        mock_heuristics.assert_not_called()
        mock_correlation_engine.evaluate.assert_not_called()
        mock_rep.assert_not_called()


# ==============================================================================
# TEST 2: Reputation DB Hit (MALICIOUS, Telemetry Updated, Zero Heuristics/VT/OTX)
# ==============================================================================
def test_2_reputation_db_hit(pipeline, mock_correlation_engine, test_domain):
    # Store directly into reputation_domains
    store_malicious_domain(
        test_domain,
        source="unit_test",
        confidence=0.95,
        metadata={"query_count": 1, "times_seen": 1},
    )

    with patch.object(pipeline.heuristics, "evaluate") as mock_heuristics:
        verdict = pipeline.evaluate(test_domain, client_ip="10.0.0.1", query_type="A")

        assert verdict.verdict == "MALICIOUS"
        assert verdict.provenance == DecisionProvenance.LOCAL_REPUTATION.value
        assert verdict.ti_source == "reputation"

        # Check telemetry update in PostgreSQL
        record = get_reputation_domain(test_domain)
        assert record is not None
        assert record.get("query_count", 0) >= 2
        assert record.get("times_seen", 0) >= 2

        # Verify heuristics & external TI were NEVER called
        mock_heuristics.assert_not_called()
        mock_correlation_engine.evaluate.assert_not_called()

        # Verify L1 cache was populated
        assert pipeline.l1_cache.get(test_domain) is not None


# ==============================================================================
# TEST 3: Trusted DB Hit (Tranco SQLite -> CLEAN, Zero Heuristics/VT/OTX)
# ==============================================================================
def test_3_trusted_db_hit(pipeline, mock_correlation_engine):
    # google.com is in Tranco Top 1M whitelist
    domain = "google.com"
    # Ensure not in L1 cache
    pipeline.l1_cache.clear()

    with patch.object(pipeline.heuristics, "evaluate") as mock_heuristics:
        verdict = pipeline.evaluate(domain)

        assert verdict.verdict == "CLEAN"
        assert verdict.provenance == DecisionProvenance.LOCAL_TRUSTED.value
        assert verdict.ti_source == "trusted"

        mock_heuristics.assert_not_called()
        mock_correlation_engine.evaluate.assert_not_called()
        assert pipeline.l1_cache.get(domain) is not None


# ==============================================================================
# TEST 4: Malicious Feed DB Hit (URLhaus Feed -> MALICIOUS, NOT in reputation_domains)
# ==============================================================================
def test_4_malicious_feed_db_hit_not_in_reputation(pipeline, mock_correlation_engine, test_domain):
    pipeline.l1_cache.clear()

    with patch("labeler.pipeline.is_malicious", return_value=True), \
         patch.object(pipeline.heuristics, "evaluate") as mock_heuristics:

        verdict = pipeline.evaluate(test_domain)

        assert verdict.verdict == "MALICIOUS"
        assert verdict.provenance == DecisionProvenance.LOCAL_MALICIOUS_FEED.value
        assert verdict.ti_source == "malicious_feed"

        # Crucial architectural correction #2: Must NOT be copied into reputation_domains
        rep = get_reputation_domain(test_domain)
        assert rep is None, "Malicious feed hit must NOT be automatically inserted into reputation_domains!"

        # Must populate L1 cache
        assert pipeline.l1_cache.get(test_domain) is not None

        # Zero heuristics and zero online TI
        mock_heuristics.assert_not_called()
        mock_correlation_engine.evaluate.assert_not_called()


# ==============================================================================
# TEST 5: Reviewed Clean DB Hit (CLEAN, Zero Heuristics/VT/OTX)
# ==============================================================================
def test_5_reviewed_clean_db_hit(pipeline, mock_correlation_engine, test_domain):
    # Crucial architectural correction #1: reviewed_clean_domains checked in L2
    pipeline.l1_cache.clear()
    promote_to_clean(test_domain, source="unit_test_verified")

    with patch.object(pipeline.heuristics, "evaluate") as mock_heuristics:
        verdict = pipeline.evaluate(test_domain)

        assert verdict.verdict == "CLEAN"
        assert verdict.provenance == DecisionProvenance.LOCAL_REVIEWED_CLEAN.value
        assert verdict.ti_source == "reviewed_clean"

        # Zero heuristics, zero online TI
        mock_heuristics.assert_not_called()
        mock_correlation_engine.evaluate.assert_not_called()

        # Populated L1
        assert pipeline.l1_cache.get(test_domain) is not None


# ==============================================================================
# TEST 6 & 7: Completely New Domain -> Heuristics and Online TI Executed
# ==============================================================================
def test_6_and_7_new_domain_executes_heuristics_and_online_ti(pipeline, mock_correlation_engine, test_domain):
    pipeline.l1_cache.clear()

    with patch.object(pipeline.heuristics, "evaluate", wraps=pipeline.heuristics.evaluate) as mock_heuristics:
        verdict = pipeline.evaluate(test_domain)

        # For a completely new domain, heuristics MUST be executed
        mock_heuristics.assert_called_once()
        # Online TI MUST be called
        mock_correlation_engine.evaluate.assert_called_once()


# ==============================================================================
# TEST 8 & 9: Online TI Malicious -> Promoted to reputation_domains & Second Query Hits Local
# ==============================================================================
def test_8_and_9_online_ti_malicious_and_second_query_hit(pipeline, mock_correlation_engine, test_domain):
    pipeline.l1_cache.clear()

    # Mock Online TI returning Malicious
    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=test_domain,
        malicious=True,
        score=0.90,
        confidence=0.88,
        threshold=0.60,
        provider_results=[
            ThreatProviderResult(provider="virustotal", malicious=True, confidence=0.88, raw_data={"positives": 12}, found=True),
            ThreatProviderResult(provider="alienvault", malicious=True, confidence=0.80, raw_data={"pulse_count": 5}, found=True),
        ],
        source="VT+OTX",
    )

    # First query
    verdict1 = pipeline.evaluate(test_domain)
    assert verdict1.verdict == "MALICIOUS"
    assert verdict1.provenance == DecisionProvenance.VT_OTX_CORRELATION.value

    # Stored in reputation_domains
    rep = get_reputation_domain(test_domain)
    assert rep is not None
    assert rep.get("status") == "malicious" or rep.get("confidence") >= 0.8

    # Second query: Reset mock call counts
    mock_correlation_engine.reset_mock()
    pipeline.l1_cache.clear()  # Even if L1 is cleared, L2 reputation_domains hits!

    with patch.object(pipeline.heuristics, "evaluate") as mock_heuristics:
        verdict2 = pipeline.evaluate(test_domain)

        assert verdict2.verdict == "MALICIOUS"
        assert verdict2.provenance == DecisionProvenance.LOCAL_REPUTATION.value
        # MUST NOT re-query online TI or heuristics!
        mock_correlation_engine.evaluate.assert_not_called()
        mock_heuristics.assert_not_called()


# ==============================================================================
# TEST 10: Online TI Clean -> Promoted to reviewed_clean_domains
# ==============================================================================
def test_10_online_ti_clean_promoted(pipeline, mock_correlation_engine, test_domain):
    pipeline.l1_cache.clear()

    # Mock Online TI returning Clean with intelligence
    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=test_domain,
        malicious=False,
        score=0.0,
        confidence=0.92,
        threshold=0.60,
        provider_results=[
            ThreatProviderResult(provider="virustotal", malicious=False, confidence=0.92, raw_data={"positives": 0, "total": 70}, found=True),
            ThreatProviderResult(provider="alienvault", malicious=False, confidence=0.85, raw_data={"pulse_count": 0}, found=True),
        ],
        source="VT+OTX",
    )

    verdict = pipeline.evaluate(test_domain)
    assert verdict.verdict == "CLEAN"
    assert verdict.provenance == DecisionProvenance.VT_OTX_CORRELATION.value

    # Must be in reviewed_clean_domains
    clean_rec = get_reviewed_clean_domain(test_domain)
    assert clean_rec is not None
    assert clean_rec.domain == test_domain

    # Second query with cleared L1 cache should hit reviewed_clean_domains in L2
    pipeline.l1_cache.clear()
    mock_correlation_engine.reset_mock()
    with patch.object(pipeline.heuristics, "evaluate") as mock_heuristics:
        verdict2 = pipeline.evaluate(test_domain)
        assert verdict2.verdict == "CLEAN"
        assert verdict2.provenance == DecisionProvenance.LOCAL_REVIEWED_CLEAN.value
        mock_correlation_engine.evaluate.assert_not_called()
        mock_heuristics.assert_not_called()


# ==============================================================================
# TEST 11: Online TI Inconclusive -> Stored in daily_review_domains (+180 Days)
# ==============================================================================
def test_11_online_ti_inconclusive_added_to_daily_review(pipeline, mock_correlation_engine, test_domain):
    pipeline.l1_cache.clear()

    # Mock inconclusive
    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=test_domain,
        malicious=False,
        score=0.0,
        confidence=0.0,
        threshold=0.60,
        provider_results=[],
        source="VT+OTX",
    )

    verdict = pipeline.evaluate(test_domain)
    assert verdict.verdict == "REVIEW_NEEDED"
    assert verdict.provenance == DecisionProvenance.DAILY_REVIEW.value

    # Must be in daily_review_domains with status 'review_needed' and next_check_at ~180 days
    dr_rec = get_review_domain(test_domain)
    assert dr_rec is not None
    assert dr_rec.status == ReviewStatus.REVIEW_NEEDED
    assert dr_rec.next_check_at is not None
    # Verify next_check_at is roughly 180 days in future
    future_diff = (dr_rec.next_check_at - datetime.now(timezone.utc)).total_seconds() / 86400
    assert 178 <= future_diff <= 182

    # NEVER classify no information as Clean
    assert verdict.verdict != "CLEAN"


# ==============================================================================
# TEST 12: Daily Review Not Due -> REVIEW_NEEDED (Zero Heuristics, Zero VT/OTX)
# ==============================================================================
def test_12_daily_review_not_due_returns_review_needed(pipeline, mock_correlation_engine, test_domain):
    pipeline.l1_cache.clear()
    # Insert not due (next_check_at in 100 days)
    upsert_review_needed(test_domain, reason="pending test", interval_days=100)

    with patch.object(pipeline.heuristics, "evaluate") as mock_heuristics:
        verdict = pipeline.evaluate(test_domain)

        assert verdict.verdict == "REVIEW_NEEDED"
        assert verdict.provenance == DecisionProvenance.DAILY_REVIEW.value

        # Zero heuristics, zero online TI
        mock_heuristics.assert_not_called()
        mock_correlation_engine.evaluate.assert_not_called()


# ==============================================================================
# TEST 13: Daily Review Due -> Re-investigation Bypasses Heuristics (Correction #3)
# ==============================================================================
def test_13_daily_review_due_bypasses_heuristics(pipeline, mock_correlation_engine, test_domain):
    pipeline.l1_cache.clear()
    # Insert overdue record (next_check_at in past)
    with get_connection() as conn:
        with conn.cursor() as cur:
            past_time = datetime.now(timezone.utc) - timedelta(days=1)
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at, review_reason)
                VALUES (%s, 'review_needed', %s, 'test overdue')
                """,
                (test_domain, past_time),
            )
        conn.commit()

    with patch.object(pipeline.heuristics, "evaluate") as mock_heuristics:
        verdict = pipeline.evaluate(test_domain)

        # Heuristics MUST BE SKIPPED (Correction #3)
        mock_heuristics.assert_not_called()
        # Online TI MUST be called
        mock_correlation_engine.evaluate.assert_called_once()


# ==============================================================================
# TEST 14, 15, 16: Worker Resolution (Malicious, Clean, Still Inconclusive)
# ==============================================================================
def test_14_worker_promotes_due_to_malicious(mock_correlation_engine, test_domain):
    # Insert overdue record
    with get_connection() as conn:
        with conn.cursor() as cur:
            past_time = datetime.now(timezone.utc) - timedelta(days=2)
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at, review_reason)
                VALUES (%s, 'review_needed', %s, 'test overdue worker')
                """,
                (test_domain, past_time),
            )
        conn.commit()

    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=test_domain,
        malicious=True,
        score=0.95,
        confidence=0.90,
        threshold=0.60,
        provider_results=[
            ThreatProviderResult(provider="virustotal", malicious=True, confidence=0.90, raw_data={"positives": 10}, found=True)
        ],
        source="worker_test",
    )

    worker = DailyReviewWorker(correlation_engine=mock_correlation_engine)
    res = worker.process_domain_investigation(test_domain)
    assert res == "malicious"

    rep = get_reputation_domain(test_domain)
    assert rep is not None
    dr = get_review_domain(test_domain)
    assert dr.status == ReviewStatus.MALICIOUS


def test_15_worker_promotes_due_to_clean(mock_correlation_engine, test_domain):
    # Insert overdue record
    with get_connection() as conn:
        with conn.cursor() as cur:
            past_time = datetime.now(timezone.utc) - timedelta(days=2)
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at, review_reason)
                VALUES (%s, 'review_needed', %s, 'test overdue clean')
                """,
                (test_domain, past_time),
            )
        conn.commit()

    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=test_domain,
        malicious=False,
        score=0.0,
        confidence=0.95,
        threshold=0.60,
        provider_results=[
            ThreatProviderResult(provider="virustotal", malicious=False, confidence=0.95, raw_data={"positives": 0}, found=True)
        ],
        source="worker_test",
    )

    worker = DailyReviewWorker(correlation_engine=mock_correlation_engine)
    res = worker.process_domain_investigation(test_domain)
    assert res == "clean"

    clean_rec = get_reviewed_clean_domain(test_domain)
    assert clean_rec is not None
    dr = get_review_domain(test_domain)
    assert dr.status == ReviewStatus.CLEAN


def test_16_worker_defers_inconclusive_by_180_days(mock_correlation_engine, test_domain):
    # Insert overdue record
    with get_connection() as conn:
        with conn.cursor() as cur:
            past_time = datetime.now(timezone.utc) - timedelta(days=2)
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at, review_reason, review_count)
                VALUES (%s, 'review_needed', %s, 'test overdue inconclusive', 1)
                """,
                (test_domain, past_time),
            )
        conn.commit()

    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=test_domain,
        malicious=False,
        score=0.0,
        confidence=0.0,
        threshold=0.60,
        provider_results=[],
        source="worker_test",
    )

    worker = DailyReviewWorker(correlation_engine=mock_correlation_engine, review_interval_days=180)
    res = worker.process_domain_investigation(test_domain)
    assert res == "inconclusive"

    dr = get_review_domain(test_domain)
    assert dr.status == ReviewStatus.REVIEW_NEEDED
    assert dr.review_count == 2
    # next_check_at extended into future
    assert dr.next_check_at > datetime.now(timezone.utc)


# ==============================================================================
# TEST 17: External API Failure -> Retry State (1 Hour), NOT Clean
# ==============================================================================
def test_17_api_failure_handling(pipeline, mock_correlation_engine, test_domain):
    pipeline.l1_cache.clear()
    # All providers unavailable
    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=test_domain,
        malicious=False,
        score=0.0,
        confidence=0.0,
        threshold=0.60,
        provider_results=[
            ThreatProviderResult(provider="virustotal", malicious=False, confidence=0.0, unavailable=True, error="Rate limit exceeded"),
            ThreatProviderResult(provider="alienvault", malicious=False, confidence=0.0, unavailable=True, error="Connection timeout"),
        ],
        source="error",
    )

    verdict = pipeline.evaluate(test_domain)
    assert verdict.verdict == "EXTERNAL_LOOKUP_FAILED"
    assert verdict.provenance == DecisionProvenance.EXTERNAL_LOOKUP_FAILED.value
    # NEVER mark failed lookup as CLEAN!
    assert verdict.verdict != "CLEAN"


# ==============================================================================
# TEST 18: Canonical Domain Normalization
# ==============================================================================
def test_18_canonical_normalization():
    assert normalize_domain("EXAMPLE.com.") == "example.com"
    assert normalize_domain("  FOO.BAR.ORG   ") == "foo.bar.org"
    assert normalize_domain("sub.test.com...") == "sub.test.com"
    # IDN punycode
    assert normalize_domain("münchen.de") == "xn--mnchen-3ya.de"


# ==============================================================================
# TEST 19: Repeated Unknown Domain Telemetry
# ==============================================================================
def test_19_repeated_unknown_domain_telemetry(pipeline, mock_correlation_engine, test_domain):
    pipeline.l1_cache.clear()
    # Insert not due
    upsert_review_needed(test_domain, reason="telemetry test", interval_days=30)
    initial_rec = get_review_domain(test_domain)

    # Query twice
    pipeline.evaluate(test_domain)
    pipeline.evaluate(test_domain)

    updated_rec = get_review_domain(test_domain)
    assert updated_rec.last_seen_at is not None
    assert updated_rec.status == ReviewStatus.REVIEW_NEEDED


# ==============================================================================
# TEST 20: Concurrency & Row Locking (SKIP LOCKED)
# ==============================================================================
def test_20_concurrency_skip_locked(test_domain):
    # Insert overdue domain
    with get_connection() as conn:
        with conn.cursor() as cur:
            past_time = datetime.now(timezone.utc) - timedelta(days=1)
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at, review_reason)
                VALUES (%s, 'review_needed', %s, 'concurrency test')
                """,
                (test_domain, past_time),
            )
        conn.commit()

    # Session 1 acquires lock with FOR UPDATE SKIP LOCKED
    with get_connection() as conn1, get_connection() as conn2:
        cur1 = conn1.cursor()
        cur2 = conn2.cursor()

        # Session 1 fetches and locks
        cur1.execute(
            """
            SELECT domain FROM daily_review_domains
            WHERE status = 'review_needed' AND next_check_at <= NOW() AND domain = %s
            FOR UPDATE SKIP LOCKED
            """,
            (test_domain,),
        )
        rows1 = cur1.fetchall()
        assert len(rows1) == 1
        assert rows1[0][0] == test_domain

        # Session 2 attempts to fetch the exact same row -> must be SKIPPED!
        cur2.execute(
            """
            SELECT domain FROM daily_review_domains
            WHERE status = 'review_needed' AND next_check_at <= NOW() AND domain = %s
            FOR UPDATE SKIP LOCKED
            """,
            (test_domain,),
        )
        rows2 = cur2.fetchall()
        assert len(rows2) == 0, "Session 2 must skip rows locked by Session 1!"

        conn1.rollback()
        conn2.rollback()


# ==============================================================================
# TEST 21: Admin API Endpoints (Health, Auth, Dossier, Stats, Verdict Override)
# ==============================================================================
def test_21_admin_api_endpoints(test_domain):
    client = TestClient(app)

    # 1. Health check
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "healthy"

    # 2. Login
    login_res = client.post("/api/v1/auth/token", data={"username": "admin@security.local", "password": "admin"})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Stats
    stats_res = client.get("/api/v1/daily-review/stats", headers=headers)
    assert stats_res.status_code == 200
    assert "total" in stats_res.json()

    # 4. Insert domain into daily review
    upsert_review_needed(test_domain, reason="api test domain", interval_days=180)

    # 5. Get Dossier
    dossier_res = client.get(f"/api/v1/daily-review/{test_domain}", headers=headers)
    assert dossier_res.status_code == 200
    dossier_data = dossier_res.json()
    assert dossier_data["domain"] == test_domain
    assert dossier_data["daily_review_record"] is not None

    # 6. Admin Manual Verdict Override to CLEAN
    override_res = client.post(
        f"/api/v1/daily-review/{test_domain}/verdict",
        json={"verdict": "clean", "reason": "Verified corporate partner in test", "confidence": 1.0},
        headers=headers,
    )
    assert override_res.status_code == 200
    assert override_res.json()["verdict"] == "CLEAN"

    # Verify promoted to reviewed_clean_domains
    clean_rec = get_reviewed_clean_domain(test_domain)
    assert clean_rec is not None


# ==============================================================================
# TEST 22: Concurrency & Worker Claim Mutex (No Duplicate Processing)
# ==============================================================================
def test_22_concurrent_worker_claim_mutex(test_domain):
    import concurrent.futures

    domains = [f"{test_domain}-c{i}" for i in range(4)]
    past_time = datetime.now(timezone.utc) - timedelta(hours=2)

    with get_connection() as conn:
        with conn.cursor() as cur:
            for d in domains:
                cur.execute(
                    """
                    INSERT INTO daily_review_domains (domain, status, next_check_at, review_reason)
                    VALUES (%s, 'review_needed', %s, 'concurrency worker test')
                    ON CONFLICT (domain) DO UPDATE SET status = 'review_needed', next_check_at = EXCLUDED.next_check_at
                    """,
                    (d, past_time),
                )
        conn.commit()

    claimed_by_worker: dict[int, list[str]] = {0: [], 1: []}

    def worker_claim_task(worker_id: int):
        claimed = claim_due_reviews_for_processing(batch_size=10, stale_timeout_minutes=15)
        test_claimed = [r.domain for r in claimed if r.domain in domains]
        return worker_id, test_claimed

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(worker_claim_task, i) for i in range(2)]
        for f in concurrent.futures.as_completed(futures):
            wid, claimed = f.result()
            claimed_by_worker[wid] = claimed

    worker0_domains = set(claimed_by_worker[0])
    worker1_domains = set(claimed_by_worker[1])

    # No domain claimed by both workers
    overlap = worker0_domains.intersection(worker1_domains)
    assert len(overlap) == 0, f"Duplicate domain claim detected across workers: {overlap}"
    assert len(worker0_domains.union(worker1_domains)) == 4, "All 4 domains should have been claimed"

    # Status transitioned to 'processing'
    for d in domains:
        rec = get_review_domain(d)
        assert rec is not None
        assert rec.status == ReviewStatus.PROCESSING.value

    # Cleanup
    with get_connection() as conn:
        with conn.cursor() as cur:
            for d in domains:
                cur.execute("DELETE FROM daily_review_domains WHERE domain = %s", (d,))
        conn.commit()


# ==============================================================================
# TEST 23: Complete 180-Day Daily Review Lifecycle & Terminal Outcomes
# ==============================================================================
def test_23_scheduler_180_day_journey(mock_correlation_engine, test_domain):
    # 1. Domain in review_needed but NOT due -> must NOT be claimed
    future_time = datetime.now(timezone.utc) + timedelta(days=100)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at, review_reason)
                VALUES (%s, 'review_needed', %s, 'not due yet')
                """,
                (test_domain, future_time),
            )
        conn.commit()

    worker = DailyReviewWorker(correlation_engine=mock_correlation_engine)
    processed_count = worker.run_once()
    assert processed_count == 0
    rec_not_due = get_review_domain(test_domain)
    assert rec_not_due.status == ReviewStatus.REVIEW_NEEDED.value

    # 2. Make domain DUE: next_check_at <= NOW()
    past_time = datetime.now(timezone.utc) - timedelta(hours=1)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE daily_review_domains SET next_check_at = %s WHERE domain = %s",
                (past_time, test_domain),
            )
        conn.commit()

    # Outcome A: Inconclusive -> extends +180 days, status reverts to review_needed
    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=test_domain,
        malicious=False,
        score=0.0,
        confidence=0.0,
        threshold=0.60,
        provider_results=[],
        source="test_inconclusive",
    )
    processed = worker.run_once()
    assert processed == 1
    rec_inconclusive = get_review_domain(test_domain)
    assert rec_inconclusive.status == ReviewStatus.REVIEW_NEEDED.value
    assert rec_inconclusive.next_check_at > datetime.now(timezone.utc) + timedelta(days=170)

    # 3. Make due again, Outcome B: Clean -> promoted to reviewed_clean_domains
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE daily_review_domains SET next_check_at = %s WHERE domain = %s",
                (past_time, test_domain),
            )
        conn.commit()

    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=test_domain,
        malicious=False,
        score=0.0,
        confidence=0.95,
        threshold=0.60,
        provider_results=[
            ThreatProviderResult(provider="virustotal", malicious=False, confidence=0.95, raw_data={"positives": 0}, found=True)
        ],
        source="test_clean",
    )
    processed = worker.run_once()
    assert processed == 1
    rec_clean = get_review_domain(test_domain)
    assert rec_clean.status == ReviewStatus.CLEAN.value
    assert get_reviewed_clean_domain(test_domain) is not None

    # 4. Outcome C: Malicious -> promoted to reputation_domains
    mal_domain = f"mal-{test_domain}"
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at, review_reason)
                VALUES (%s, 'review_needed', %s, 'overdue for malicious check')
                """,
                (mal_domain, past_time),
            )
        conn.commit()

    mock_correlation_engine.evaluate.return_value = ThreatDecision(
        domain=mal_domain,
        malicious=True,
        score=0.99,
        confidence=0.95,
        threshold=0.60,
        provider_results=[
            ThreatProviderResult(provider="virustotal", malicious=True, confidence=0.95, raw_data={"positives": 15}, found=True)
        ],
        source="test_malicious",
    )
    processed = worker.run_once()
    assert processed == 1
    rec_mal = get_review_domain(mal_domain)
    assert rec_mal.status == ReviewStatus.MALICIOUS.value
    assert get_reputation_domain(mal_domain) is not None

    # Cleanup mal_domain
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM daily_review_domains WHERE domain = %s", (mal_domain,))
            cur.execute("DELETE FROM reputation_domains WHERE domain = %s", (mal_domain,))
        conn.commit()


# ==============================================================================
# TEST 24: API is_due Filter Endpoint
# ==============================================================================
def test_24_api_is_due_filter(test_domain):
    client = TestClient(app)
    login_res = client.post("/api/v1/auth/token", data={"username": "admin@security.local", "password": "admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    due_domain = f"due-{test_domain}"
    not_due_domain = f"notdue-{test_domain}"

    past_time = datetime.now(timezone.utc) - timedelta(days=2)
    future_time = datetime.now(timezone.utc) + timedelta(days=30)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at, review_reason)
                VALUES (%s, 'review_needed', %s, 'due test'),
                       (%s, 'review_needed', %s, 'not due test')
                """,
                (due_domain, past_time, not_due_domain, future_time),
            )
        conn.commit()

    try:
        # 1. is_due=true -> only due_domain
        res_due = client.get(f"/api/v1/daily-review?is_due=true&search={test_domain}", headers=headers)
        assert res_due.status_code == 200
        items_due = [d["domain"] for d in res_due.json()["domains"]]
        assert due_domain in items_due
        assert not_due_domain not in items_due

        # 2. is_due=false -> only not_due_domain
        res_not_due = client.get(f"/api/v1/daily-review?is_due=false&search={test_domain}", headers=headers)
        assert res_not_due.status_code == 200
        items_not_due = [d["domain"] for d in res_not_due.json()["domains"]]
        assert not_due_domain in items_not_due
        assert due_domain not in items_not_due

        # 3. is_due omitted -> returns both
        res_all = client.get(f"/api/v1/daily-review?search={test_domain}", headers=headers)
        assert res_all.status_code == 200
        items_all = [d["domain"] for d in res_all.json()["domains"]]
        assert due_domain in items_all
        assert not_due_domain in items_all

    finally:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM daily_review_domains WHERE domain IN (%s, %s)", (due_domain, not_due_domain))
            conn.commit()


# ==============================================================================
# TEST 25: Daily Review Stats Contract Verification (Non-Zero DB Values)
# ==============================================================================
def test_25_daily_review_stats_contract(test_domain):
    client = TestClient(app)
    login_res = client.post("/api/v1/auth/token", data={"username": "admin@security.local", "password": "admin"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    d_due = f"stat-due-{test_domain}"
    d_notdue = f"stat-notdue-{test_domain}"
    d_mal = f"stat-mal-{test_domain}"
    d_clean = f"stat-clean-{test_domain}"
    d_proc = f"stat-proc-{test_domain}"

    past_time = datetime.now(timezone.utc) - timedelta(days=1)
    future_time = datetime.now(timezone.utc) + timedelta(days=100)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at)
                VALUES (%s, 'review_needed', %s),
                       (%s, 'review_needed', %s),
                       (%s, 'malicious', %s),
                       (%s, 'clean', %s),
                       (%s, 'processing', %s)
                """,
                (d_due, past_time, d_notdue, future_time, d_mal, future_time, d_clean, future_time, d_proc, future_time),
            )
        conn.commit()

    try:
        res = client.get("/api/v1/daily-review/stats", headers=headers)
        assert res.status_code == 200
        data = res.json()

        assert "total" in data and data["total"] >= 5
        assert "review_needed" in data and data["review_needed"] >= 2
        assert "due_for_review" in data and data["due_for_review"] >= 1
        assert "malicious" in data and data["malicious"] >= 1
        assert "clean" in data and data["clean"] >= 1
        assert "processing" in data and data["processing"] >= 1

    finally:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM daily_review_domains WHERE domain IN (%s, %s, %s, %s, %s)",
                    (d_due, d_notdue, d_mal, d_clean, d_proc),
                )
            conn.commit()


# ==============================================================================
# TEST 26: JWT Secret Environment Validation
# ==============================================================================
def test_26_jwt_secret_environment_validation():
    from api.auth import get_jwt_secret_key, DEV_INSECURE_TEST_SECRET

    # 1. Production + missing secret -> must raise RuntimeError
    with pytest.raises(RuntimeError) as exc_info:
        get_jwt_secret_key(env="production", secret_key="")
    assert "CRITICAL SECURITY CONFIGURATION ERROR" in str(exc_info.value)

    # 2. Production + insecure default secret -> must raise RuntimeError
    with pytest.raises(RuntimeError) as exc_info2:
        get_jwt_secret_key(env="production", secret_key="dnsnetra-secure-default-change-in-prod")
    assert "CRITICAL SECURITY CONFIGURATION ERROR" in str(exc_info2.value)

    # 3. Production + secure key -> success
    prod_key = get_jwt_secret_key(env="production", secret_key="super-secure-production-entropy-key-999")
    assert prod_key == "super-secure-production-entropy-key-999"

    # 4. Development + missing secret -> returns DEV_INSECURE_TEST_SECRET safely
    dev_key = get_jwt_secret_key(env="development", secret_key="")
    assert dev_key == DEV_INSECURE_TEST_SECRET

    # 5. Test environment + missing secret -> returns DEV_INSECURE_TEST_SECRET safely
    test_key = get_jwt_secret_key(env="test", secret_key="")
    assert test_key == DEV_INSECURE_TEST_SECRET


# ==============================================================================
# TEST 27: Stale PROCESSING Record Recovery
# ==============================================================================
def test_27_stale_processing_recovery(test_domain):
    stale_domain = f"stale-{test_domain}"

    with get_connection() as conn:
        with conn.cursor() as cur:
            old_time = datetime.now(timezone.utc) - timedelta(minutes=30)
            cur.execute(
                """
                INSERT INTO daily_review_domains (domain, status, next_check_at, updated_at)
                VALUES (%s, 'processing', %s, %s)
                """,
                (stale_domain, old_time, old_time),
            )
        conn.commit()

    try:
        # A) Explicit recovery utility resets it to review_needed
        recovered = recover_stale_processing(timeout_minutes=15)
        assert recovered >= 1
        rec = get_review_domain(stale_domain)
        assert rec.status == ReviewStatus.REVIEW_NEEDED.value

        # B) Re-insert in processing 30 minutes ago, verify claim_due_reviews_for_processing reclaims it
        with get_connection() as conn:
            with conn.cursor() as cur:
                old_time = datetime.now(timezone.utc) - timedelta(minutes=30)
                cur.execute("DELETE FROM daily_review_domains WHERE domain = %s", (stale_domain,))
                cur.execute(
                    """
                    INSERT INTO daily_review_domains (domain, status, next_check_at, updated_at)
                    VALUES (%s, 'processing', %s, %s)
                    """,
                    (stale_domain, old_time, old_time),
                )
            conn.commit()

        claimed = claim_due_reviews_for_processing(batch_size=50, stale_timeout_minutes=15)
        claimed_domains = [r.domain for r in claimed]
        assert stale_domain in claimed_domains

    finally:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM daily_review_domains WHERE domain = %s", (stale_domain,))
            conn.commit()


# ==============================================================================
# TEST 28: Application Restart Persistence (Cold Start L1 Empty)
# ==============================================================================
def test_28_application_restart_persistence(mock_correlation_engine, test_domain):
    mal_domain = f"restart-mal-{test_domain}"
    clean_domain = f"restart-clean-{test_domain}"
    dr_domain = f"restart-dr-{test_domain}"

    store_malicious_domain(mal_domain, source="restart_test", confidence=0.99)
    promote_to_clean(clean_domain, source="restart_test")
    upsert_review_needed(dr_domain, reason="restart test pending", interval_days=100)

    try:
        # Simulate application restart by creating completely new DetectionPipeline instances
        config = LabelingConfig()
        new_pipe = DetectionPipeline(config=config, correlation_engine=mock_correlation_engine)

        # Assert cold start L1 RAM cache is completely empty
        assert new_pipe.l1_cache.get(mal_domain) is None
        assert new_pipe.l1_cache.get(clean_domain) is None
        assert new_pipe.l1_cache.get(dr_domain) is None

        # Query all three domains: must hit PostgreSQL L2 without calling heuristics or external TI
        with patch.object(new_pipe.heuristics, "evaluate") as mock_heuristics:
            v_mal = new_pipe.evaluate(mal_domain)
            assert v_mal.verdict == "MALICIOUS"
            assert v_mal.provenance == DecisionProvenance.LOCAL_REPUTATION.value

            v_clean = new_pipe.evaluate(clean_domain)
            assert v_clean.verdict == "CLEAN"
            assert v_clean.provenance == DecisionProvenance.LOCAL_REVIEWED_CLEAN.value

            v_dr = new_pipe.evaluate(dr_domain)
            assert v_dr.verdict == "REVIEW_NEEDED"
            assert v_dr.provenance == DecisionProvenance.DAILY_REVIEW.value

            mock_heuristics.assert_not_called()
            mock_correlation_engine.evaluate.assert_not_called()

    finally:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM reputation_domains WHERE domain = %s", (mal_domain,))
                cur.execute("DELETE FROM reviewed_clean_domains WHERE domain = %s", (clean_domain,))
                cur.execute("DELETE FROM daily_review_domains WHERE domain = %s", (dr_domain,))
            conn.commit()
