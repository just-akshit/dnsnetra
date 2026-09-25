#!/usr/bin/env python3
"""
test_four_db_lookups.py
=======================
Verifies the four PostgreSQL threat-intelligence databases and measures exact-lookup latency:
  1. trusted_db (is_trusted)
  2. malicious_db (is_malicious)
  3. reputation_db (reputation_domains store/get)
  4. daily_review_db (unknown_domains store/status lifecycle)
  5. ThreatIntelligence end-to-end evaluation
  6. Exact-lookup latency benchmark on malicious_db
"""

from __future__ import annotations

import os
import sys
import time
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import psycopg2
import numpy as np
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("test_four_db_lookups")

from labeler.intel.manager import is_trusted
from labeler.intel.malicious import is_malicious
from labeler.intel.reputation import get_domain, store_malicious_domain
from labeler.threat_intelligence import ThreatIntelligence
from labeler.config import LabelingConfig
from unknown_domain_repository.unknown_domain_repository.repository import UnknownDomainRepository
from unknown_domain_repository.unknown_domain_repository.models import UnknownDomain
from unknown_domain_repository.unknown_domain_repository.constants import DomainSource, DomainStatus
from unknown_domain_repository.unknown_domain_repository.config import load_config as load_udr_config
from unknown_domain_repository.unknown_domain_repository.logger import initialize_logger

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
MALICIOUS_DB = os.getenv("MALICIOUS_DB_DATABASE", "malicious_db")


def test_trusted_db() -> bool:
    logger.info("--- 1. Testing trusted_db (PostgreSQL) ---")
    test_cases = [
        ("google.com", True),
        ("cloudflare.com", True),
        ("microsoft.com", True),
        ("apple.com", True),
        ("github.com", True),
        ("this-domain-does-not-exist-at-all-xyz-123.test", False),
    ]

    all_passed = True
    for domain, expected in test_cases:
        res = is_trusted(domain)
        status = "PASS" if res == expected else "FAIL"
        if res != expected:
            all_passed = False
        logger.info("  [%s] is_trusted('%s') -> %s (expected %s)", status, domain, res, expected)

    return all_passed


def test_malicious_db() -> tuple[bool, str]:
    logger.info("--- 2. Testing malicious_db (PostgreSQL) ---")
    
    # Retrieve a known domain from the actual migrated malicious_db
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=MALICIOUS_DB,
        user=DB_USER,
        password=DB_PASSWORD,
    )
    cur = conn.cursor()
    cur.execute("SELECT domain FROM malicious_domains WHERE domain != 'google.com' LIMIT 1;")
    known_malicious = cur.fetchone()[0]
    cur.close()
    conn.close()

    test_cases = [
        (known_malicious, True),
        ("wikipedia.org", False),
        ("python.org", False),
        ("random-clean-test-domain-987654.org", False),
    ]

    all_passed = True
    for domain, expected in test_cases:
        res = is_malicious(domain)
        status = "PASS" if res == expected else "FAIL"
        if res != expected:
            all_passed = False
        logger.info("  [%s] is_malicious('%s') -> %s (expected %s)", status, domain, res, expected)

    return all_passed, known_malicious


def test_reputation_db() -> bool:
    logger.info("--- 3. Testing reputation_db (PostgreSQL) ---")
    
    # 1. Test existing reputation record
    known_rep_domain = "secure-update.net"
    rec = get_domain(known_rep_domain)
    logger.info("  get_domain('%s') -> %s", known_rep_domain, rec)
    has_known = rec is not None

    # 2. Test upsert
    test_dom = "test-reputation-migration-verify.net"
    store_malicious_domain(test_dom, {
        "source": "UnitTest",
        "confidence": 0.95,
        "match_scope": "EXACT_FQDN",
        "matched_domain": test_dom,
    })
    stored_rec = get_domain(test_dom)
    logger.info("  store & get_domain('%s') -> %s", test_dom, stored_rec)
    upsert_ok = stored_rec is not None and stored_rec.get("domain") == test_dom

    passed = has_known and upsert_ok
    logger.info("  [%s] reputation_db verification", "PASS" if passed else "FAIL")
    return passed


def test_daily_review_db() -> bool:
    logger.info("--- 4. Testing daily_review_db (PostgreSQL) ---")
    from unknown_domain_repository.unknown_domain_repository.database import DatabaseManager
    udr_config = load_udr_config()
    initialize_logger(udr_config.logging)
    db_manager = DatabaseManager(udr_config)
    db_manager.initialize()
    repo = UnknownDomainRepository(db_manager)

    test_domain = f"test-unknown-{int(time.time())}.xyz"
    record = UnknownDomain(
        domain=test_domain,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        source=DomainSource.DNS_QUERY_LOG,
        status=DomainStatus.REVIEW_NEEDED,
        metadata={"reason": "integration_test"},
    )

    inserted = repo.insert_domain(record, allow_duplicates=True)
    fetched = repo.get_domain_by_name(test_domain)
    
    passed = (inserted is not None) and (fetched is not None) and (fetched.status == DomainStatus.REVIEW_NEEDED)
    logger.info("  [%s] daily_review_db insert & retrieve -> status=%s", "PASS" if passed else "FAIL", fetched.status if fetched else None)
    return passed


def test_threat_intelligence_pipeline(known_malicious: str) -> bool:
    logger.info("--- 5. Testing ThreatIntelligence Evaluation Precedence ---")
    cfg = LabelingConfig()
    ti = ThreatIntelligence(cfg)

    # 1. Trusted domain (Tranco context)
    t_score, t_reasons = ti.evaluate("google.com", "google.com", "com", "NOERROR")
    logger.info("  google.com -> score=%d, reasons=%s", t_score, t_reasons)
    t_pass = t_score == cfg.WHITELIST_SCORE

    # 2. Known Malicious domain (URLhaus)
    m_score, m_reasons = ti.evaluate(known_malicious, known_malicious, "com", "NOERROR")
    logger.info("  %s -> score=%d, reasons=%s", known_malicious, m_score, m_reasons)
    m_pass = m_score == cfg.MAX_THREAT_SCORE

    # 3. Clean untrusted domain
    u_score, u_reasons = ti.evaluate("clean-unknown-domain-test.org", "clean-unknown-domain-test.org", "org", "NOERROR")
    logger.info("  clean-unknown-domain-test.org -> score=%d, reasons=%s", u_score, u_reasons)
    u_pass = u_score == 0

    all_passed = t_pass and m_pass and u_pass
    logger.info("  [%s] ThreatIntelligence evaluation flow", "PASS" if all_passed else "FAIL")
    return all_passed


def benchmark_malicious_lookup(n_iterations: int = 1000) -> dict[str, float]:
    logger.info("--- 6. Benchmarking Exact Lookup on malicious_db (%d iterations) ---", n_iterations)
    
    # Select a sample of 100 real domains to query repeatedly
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=MALICIOUS_DB,
        user=DB_USER,
        password=DB_PASSWORD,
    )
    cur = conn.cursor()
    cur.execute("SELECT domain FROM malicious_domains LIMIT 100;")
    domains = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()

    latencies_ms: List[float] = []
    
    # Warmup
    for _ in range(20):
        is_malicious(domains[0])

    for i in range(n_iterations):
        target = domains[i % len(domains)]
        start = time.perf_counter()
        is_malicious(target)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        latencies_ms.append(elapsed_ms)

    latencies = np.array(latencies_ms)
    median_lat = float(np.median(latencies))
    p95_lat = float(np.percentile(latencies, 95))
    p99_lat = float(np.percentile(latencies, 99))
    min_lat = float(np.min(latencies))
    max_lat = float(np.max(latencies))

    logger.info("  Lookup Latency Benchmark Results:")
    logger.info("    Iterations: %d", n_iterations)
    logger.info("    Median:     %.3f ms", median_lat)
    logger.info("    p95:        %.3f ms", p95_lat)
    logger.info("    p99:        %.3f ms", p99_lat)
    logger.info("    Min:        %.3f ms", min_lat)
    logger.info("    Max:        %.3f ms", max_lat)

    return {
        "iterations": n_iterations,
        "median_ms": median_lat,
        "p95_ms": p95_lat,
        "p99_ms": p99_lat,
        "min_ms": min_lat,
        "max_ms": max_lat,
    }


def main() -> int:
    try:
        t_ok = test_trusted_db()
        m_ok, known_malicious = test_malicious_db()
        r_ok = test_reputation_db()
        d_ok = test_daily_review_db()
        ti_ok = test_threat_intelligence_pipeline(known_malicious)
        bench = benchmark_malicious_lookup(1000)

        all_ok = t_ok and m_ok and r_ok and d_ok and ti_ok
        print("\n" + "=" * 80)
        print(f"{'INTELLIGENCE DATABASES VERIFICATION & BENCHMARK SUMMARY':^80}")
        print("=" * 80)
        print(f"  trusted_db (is_trusted):                     {'PASS' if t_ok else 'FAIL'}")
        print(f"  malicious_db (is_malicious):                 {'PASS' if m_ok else 'FAIL'}")
        print(f"  reputation_db (reputation_domains):          {'PASS' if r_ok else 'FAIL'}")
        print(f"  daily_review_db (unknown_domains):           {'PASS' if d_ok else 'FAIL'}")
        print(f"  ThreatIntelligence End-to-End Evaluation:    {'PASS' if ti_ok else 'FAIL'}")
        print("-" * 80)
        print("  Exact-Lookup Benchmark on PostgreSQL malicious_db (1,000 queries):")
        print(f"    - Median Latency: {bench['median_ms']:.3f} ms")
        print(f"    - p95 Latency:    {bench['p95_ms']:.3f} ms")
        print(f"    - p99 Latency:    {bench['p99_ms']:.3f} ms")
        print(f"    - Min / Max:      {bench['min_ms']:.3f} ms / {bench['max_ms']:.3f} ms")
        print("=" * 80 + "\n")

        return 0 if all_ok else 1
    except Exception as exc:
        logger.exception("Test execution failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
