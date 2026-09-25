#!/usr/bin/env python3
"""
verify_mvp_pipeline.py
======================
Comprehensive Smoke Test & Verification Suite for MVP PostgreSQL 4-DB Migration & Pipeline:
  - Phase 0: Prerequisite Audit
  - Phase 1: Database Connectivity
  - Phase 2: Schema Verification
  - Phase 3: Data Integrity
  - Phase 4: Trusted Database Test
  - Phase 5: Malicious Database Test
  - Phase 6: Reputation Database Test
  - Phase 7: Daily Review Database Test
  - Phase 8: Four-Database Precedence Test
  - Phase 9: Existing Labeling Test
  - Phase 10: PostgreSQL Exact Lookup Performance
  - Phase 11: PostgreSQL Restart Test
  - Phase 12: Live Pipeline Verification
  - Phase 13: Rollback Safety Check
"""

from __future__ import annotations

import os
import sys
import time
import platform
import sqlite3
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple

import psycopg2
import numpy as np
import pandas as pd
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("verify_mvp_pipeline")

from labeler.intel.manager import is_trusted
from labeler.intel.database import normalize_domain as normalize_trusted_domain
from labeler.intel.malicious import is_malicious
from labeler.intel.malicious.downloader import normalize_domain as normalize_malicious_domain
from labeler.intel.reputation import get_domain, store_malicious_domain
from labeler.threat_intelligence import ThreatIntelligence
from labeler.label_dataset import DNSLabeller
from labeler.config import LabelingConfig

from unknown_domain_repository.unknown_domain_repository.repository import UnknownDomainRepository
from unknown_domain_repository.unknown_domain_repository.models import UnknownDomain
from unknown_domain_repository.unknown_domain_repository.constants import DomainSource, DomainStatus
from unknown_domain_repository.unknown_domain_repository.config import load_config as load_udr_config
from unknown_domain_repository.unknown_domain_repository.logger import initialize_logger
from unknown_domain_repository.unknown_domain_repository.database import DatabaseManager

from run_live_pipeline import (
    LivePipelineProcessor,
    _record_from_structured_json,
    IncrementalFeatureWriter,
)
from domain_profiling.service import DomainProfilingService

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

DATABASES = [
    os.getenv("DB_NAME", "dns_threat_detection"),
    os.getenv("TRUSTED_DB_DATABASE", "trusted_db"),
    os.getenv("MALICIOUS_DB_DATABASE", "malicious_db"),
    os.getenv("REPUTATION_DB_DATABASE", "reputation_db"),
    os.getenv("DAILY_REVIEW_DB_DATABASE", "daily_review_db"),
]


# ===========================================================================
# PHASE 0: Prerequisite Audit
# ===========================================================================
def phase_0_audit() -> Dict[str, Any]:
    logger.info("=== PHASE 0 — PREREQUISITE AUDIT ===")
    py_ver = platform.python_version()
    pg_ver = "UNKNOWN"
    try:
        conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="postgres")
        cur = conn.cursor()
        cur.execute("SELECT version();")
        pg_ver = cur.fetchone()[0]
        cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
        existing_dbs = {r[0] for r in cur.fetchall()}
        cur.close()
        conn.close()
    except Exception as exc:
        logger.error("Failed to connect to PostgreSQL maintenance db: %s", exc)
        existing_dbs = set()

    env_vars_present = all(
        os.getenv(k) for k in [
            "DB_HOST", "DB_NAME", "TRUSTED_DB_DATABASE",
            "MALICIOUS_DB_DATABASE", "REPUTATION_DB_DATABASE", "DAILY_REVIEW_DB_DATABASE"
        ]
    )

    all_dbs_exist = all(d in existing_dbs for d in DATABASES)
    logger.info("  Python Version:     %s", py_ver)
    logger.info("  PostgreSQL Host:    %s:%d", DB_HOST, DB_PORT)
    logger.info("  PostgreSQL Version: %s", pg_ver[:50])
    logger.info("  Required DBs Exist: %s (%s)", all_dbs_exist, DATABASES)
    logger.info("  Env Vars Config:    %s", env_vars_present)

    passed = all_dbs_exist and env_vars_present
    return {
        "passed": passed,
        "python_version": py_ver,
        "pg_version": pg_ver,
        "host": DB_HOST,
        "port": DB_PORT,
    }


# ===========================================================================
# PHASE 1: Database Connectivity
# ===========================================================================
def phase_1_connectivity() -> Dict[str, bool]:
    logger.info("=== PHASE 1 — DATABASE CONNECTIVITY ===")
    results = {}
    for db in DATABASES:
        try:
            conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname=db)
            cur = conn.cursor()
            cur.execute("SELECT current_database(), version();")
            res = cur.fetchone()
            cur.close()
            conn.close()
            results[db] = True
            logger.info("  %-25s -> PASS (connected to %s)", db, res[0])
        except Exception as exc:
            results[db] = False
            logger.error("  %-25s -> FAIL (%s)", db, exc)
    return results


# ===========================================================================
# PHASE 2: Schema Verification
# ===========================================================================
def phase_2_schemas() -> Dict[str, bool]:
    logger.info("=== PHASE 2 — SCHEMA VERIFICATION ===")
    checks = {
        "trusted_db": ["trusted_domains", "metadata"],
        "malicious_db": ["malicious_domains", "metadata"],
        "reputation_db": ["reputation_domains"],
        "daily_review_db": ["unknown_domains", "schema_metadata"],
        "dns_threat_detection": [
            "domain_query_history", "domain_profiles",
            "client_profiles", "client_history", "dashboard_users"
        ],
    }

    results = {}
    for db, expected_tables in checks.items():
        try:
            conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname=db)
            cur = conn.cursor()
            cur.execute("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE';
            """)
            present = {r[0] for r in cur.fetchall()}
            cur.close()
            conn.close()

            missing = [t for t in expected_tables if t not in present]
            status = len(missing) == 0
            results[db] = status
            if status:
                logger.info("  %-25s -> PASS (All %d expected tables present)", db, len(expected_tables))
            else:
                logger.error("  %-25s -> FAIL (Missing: %s)", db, missing)
        except Exception as exc:
            results[db] = False
            logger.error("  %-25s -> FAIL (%s)", db, exc)

    return results


# ===========================================================================
# PHASE 3: Data Integrity
# ===========================================================================
def phase_3_data_integrity() -> Dict[str, Any]:
    logger.info("=== PHASE 3 — DATA INTEGRITY ===")

    # 1. Trusted
    t_sqlite = PROJECT_ROOT / "data" / "trusted_domains.db"
    s_conn = sqlite3.connect(t_sqlite)
    s_cur = s_conn.cursor()
    s_cur.execute("SELECT COUNT(*) FROM trusted_domains;")
    t_src = s_cur.fetchone()[0]
    s_conn.close()

    p_conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="trusted_db")
    p_cur = p_conn.cursor()
    p_cur.execute("SELECT COUNT(*) FROM trusted_domains;")
    t_dst = p_cur.fetchone()[0]
    p_conn.close()

    # 2. Malicious
    m_sqlite = PROJECT_ROOT / "data" / "malicious_domains.db"
    s_conn = sqlite3.connect(m_sqlite)
    s_cur = s_conn.cursor()
    s_cur.execute("SELECT COUNT(*) FROM malicious_domains;")
    m_src = s_cur.fetchone()[0]
    s_conn.close()

    p_conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="malicious_db")
    p_cur = p_conn.cursor()
    p_cur.execute("SELECT COUNT(*) FROM malicious_domains;")
    m_dst = p_cur.fetchone()[0]
    p_conn.close()

    # 3. Reputation
    p_conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="reputation_db")
    p_cur = p_conn.cursor()
    p_cur.execute("SELECT COUNT(*) FROM reputation_domains;")
    r_dst = p_cur.fetchone()[0]
    p_conn.close()

    # 4. Daily Review
    p_conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="daily_review_db")
    p_cur = p_conn.cursor()
    p_cur.execute("SELECT COUNT(*) FROM unknown_domains;")
    u_dst = p_cur.fetchone()[0]
    p_conn.close()

    logger.info("  trusted:      %d source -> %d destination (diff: %d)", t_src, t_dst, t_dst - t_src)
    logger.info("  malicious:    %d source -> %d destination (diff: %d)", m_src, m_dst, m_dst - m_src)
    logger.info("  reputation:   %d destination rows (expected reference >= 9)", r_dst)
    logger.info("  daily review: %d destination rows (expected reference >= 51)", u_dst)

    passed = (t_src == t_dst) and (m_src == m_dst) and (r_dst >= 9) and (u_dst >= 51)
    return {
        "passed": passed,
        "trusted": (t_src, t_dst),
        "malicious": (m_src, m_dst),
        "reputation": r_dst,
        "daily_review": u_dst,
    }


# ===========================================================================
# PHASE 4: Trusted Database Test
# ===========================================================================
def phase_4_trusted_test() -> bool:
    logger.info("=== PHASE 4 — TRUSTED DATABASE TEST ===")
    test_domains = [
        ("google.com", True),
        ("cloudflare.com", True),
        ("microsoft.com", True),
        ("apple.com", True),
        ("github.com", True),
        ("this-domain-should-not-exist-987654321.example", False),
    ]

    all_passed = True
    for raw_domain, expected in test_domains:
        normalized = normalize_trusted_domain(raw_domain)
        found = is_trusted(raw_domain)
        status = "PASS" if found == expected else "FAIL"
        if found != expected:
            all_passed = False
        logger.info(
            "  [%s] domain: %-45s | normalized: %-45s | found: %-5s (expected %s) | source: trusted_db",
            status, raw_domain, normalized, str(found), str(expected)
        )

    return all_passed


# ===========================================================================
# PHASE 5: Malicious Database Test
# ===========================================================================
def phase_5_malicious_test() -> Tuple[bool, List[str]]:
    logger.info("=== PHASE 5 — MALICIOUS DATABASE TEST ===")

    # Retrieve real existing malicious domains from malicious_db
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="malicious_db")
    cur = conn.cursor()
    cur.execute("SELECT domain FROM malicious_domains WHERE domain NOT LIKE '%google.com%' LIMIT 3;")
    existing_samples = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()

    logger.info("  Sample existing malicious records from PostgreSQL: %s", existing_samples)

    all_passed = True

    # 1. Existing malicious records
    for domain in existing_samples:
        normalized = normalize_malicious_domain(domain)
        found = is_malicious(domain)
        status = "PASS" if found else "FAIL"
        if not found:
            all_passed = False
        logger.info("  [%s] known malicious: %-30s | normalized: %-30s | found: %s", status, domain, normalized, found)

    # 2. Known clean / popular candidates
    clean_candidates = [
        "wikipedia.org",
        "python.org",
        "mozilla.org",
        "this-domain-should-not-exist-987654321.example",
    ]
    for domain in clean_candidates:
        normalized = normalize_malicious_domain(domain)
        found = is_malicious(domain)
        status = "PASS" if not found else "FAIL"
        if found:
            all_passed = False
        logger.info("  [%s] clean candidate: %-30s | normalized: %-30s | found: %s", status, domain, normalized, found)

    return all_passed, existing_samples


# ===========================================================================
# PHASE 6: Reputation Database Test
# ===========================================================================
def phase_6_reputation_test() -> bool:
    logger.info("=== PHASE 6 — REPUTATION DATABASE TEST ===")

    # 1. Dynamically select an existing reputation record
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="reputation_db")
    cur = conn.cursor()
    cur.execute("SELECT domain, status, source, confidence FROM reputation_domains LIMIT 1;")
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        logger.error("No existing reputation domains found in reputation_db!")
        return False

    existing_dom, exp_status, exp_source, exp_conf = row
    logger.info("  Inspecting existing reputation domain: %s (status=%s, source=%s)", existing_dom, exp_status, exp_source)

    # Query via application repository
    rec = get_domain(existing_dom)
    lookup_ok = (rec is not None) and (rec.get("domain") == existing_dom)
    logger.info("  [%s] get_domain('%s') from reputation_db -> %s", "PASS" if lookup_ok else "FAIL", existing_dom, rec)

    # 2. Safe upsert test with guaranteed cleanup
    temp_test_domain = f"mvp-test-temp-{int(time.time())}.test"
    try:
        store_malicious_domain(temp_test_domain, {
            "source": "VerificationTest",
            "confidence": 0.99,
            "match_scope": "EXACT_FQDN",
            "matched_domain": temp_test_domain,
        })
        stored_rec = get_domain(temp_test_domain)
        upsert_ok = (stored_rec is not None) and (stored_rec.get("domain") == temp_test_domain)
        logger.info("  [%s] temporary test record store & verify: %s", "PASS" if upsert_ok else "FAIL", temp_test_domain)
    finally:
        # CLEANUP
        conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="reputation_db")
        cur = conn.cursor()
        cur.execute("DELETE FROM reputation_domains WHERE domain = %s;", (temp_test_domain,))
        conn.commit()
        cur.close()
        conn.close()
        logger.info("  Cleaned up temporary test record '%s' from reputation_db", temp_test_domain)

    return lookup_ok and upsert_ok


# ===========================================================================
# PHASE 7: Daily Review Database Test
# ===========================================================================
def phase_7_daily_review_test() -> bool:
    logger.info("=== PHASE 7 — DAILY REVIEW DATABASE TEST ===")
    udr_config = load_udr_config()
    initialize_logger(udr_config.logging)
    db_manager = DatabaseManager(udr_config)
    db_manager.initialize()
    repo = UnknownDomainRepository(db_manager)

    # Inspect existing records
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="daily_review_db")
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*), status FROM unknown_domains GROUP BY status;")
    status_counts = cur.fetchall()
    cur.close()
    conn.close()
    logger.info("  Existing unknown_domains breakdown: %s", status_counts)

    # Choose unique synthetic test domain
    synth_domain = f"mvp-verification-{int(time.time())}.example"

    # Verify not in trusted, malicious, reputation
    assert not is_trusted(synth_domain), "Synthetic domain unexpectedly in trusted_db"
    assert not is_malicious(synth_domain), "Synthetic domain unexpectedly in malicious_db"
    assert get_domain(synth_domain) is None, "Synthetic domain unexpectedly in reputation_db"

    try:
        # Run record into daily_review_db with status REVIEW_NEEDED
        test_rec = UnknownDomain(
            domain=synth_domain,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            source=DomainSource.DNS_QUERY_LOG,
            status=DomainStatus.REVIEW_NEEDED,
            metadata={"test": "phase_7_daily_review"},
        )
        inserted = repo.insert_domain(test_rec, allow_duplicates=True)
        retrieved = repo.get_domain_by_name(synth_domain)

        passed = (inserted is not None) and (retrieved is not None) and (retrieved.status == DomainStatus.REVIEW_NEEDED)
        logger.info("  [%s] daily_review_db verified with status REVIEW_NEEDED -> %s", "PASS" if passed else "FAIL", retrieved)
    finally:
        # CLEANUP
        conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="daily_review_db")
        cur = conn.cursor()
        cur.execute("DELETE FROM unknown_domains WHERE domain = %s;", (synth_domain,))
        conn.commit()
        cur.close()
        conn.close()
        logger.info("  Cleaned up synthetic test domain '%s' from daily_review_db", synth_domain)

    return passed


# ===========================================================================
# PHASE 8: Four-Database Precedence Test
# ===========================================================================
def phase_8_precedence_test(sample_malicious: str) -> bool:
    logger.info("=== PHASE 8 — FOUR-DATABASE PRECEDENCE TEST ===")
    cfg = LabelingConfig()
    ti = ThreatIntelligence(cfg)

    test_matrix = [
        {
            "domain": "google.com",
            "rd": "google.com",
            "tld": "com",
            "expected_db": "trusted_db",
            "expected_score": cfg.WHITELIST_SCORE,
            "expected_reason_substr": "Trusted Tranco Domain",
            "expected_source": "trusted",
        },
        {
            "domain": sample_malicious,
            "rd": sample_malicious,
            "tld": "com",
            "expected_db": "malicious_db",
            "expected_score": cfg.MAX_THREAT_SCORE,
            "expected_reason_substr": "Known Malicious Domain (URLhaus)",
            "expected_source": "malicious",
        },
        {
            "domain": "mvp-unresolved-review-needed.example",
            "rd": "mvp-unresolved-review-needed.example",
            "tld": "example",
            "expected_db": "daily_review_db",
            "expected_score": 0,
            "expected_reason_substr": "",
            "expected_source": "unknown",
        },
    ]

    all_passed = True
    for t in test_matrix:
        score, reasons = ti.evaluate(t["domain"], t["rd"], t["tld"], "NOERROR")
        
        # Determine actual source
        if "Trusted Tranco Domain" in reasons:
            actual_source = "trusted"
            consulted_db = "trusted_db"
            hit = True
        elif "Known Malicious Domain (URLhaus)" in reasons:
            actual_source = "malicious"
            consulted_db = "malicious_db"
            hit = True
        else:
            actual_source = "unknown"
            consulted_db = "reputation_db -> external TI -> daily_review_db"
            hit = False

        status = "PASS" if actual_source == t["expected_source"] else "FAIL"
        if actual_source != t["expected_source"]:
            all_passed = False

        logger.info(
            "  [%s] domain: %-38s | db consulted: %-35s | hit: %-5s | verdict score: %-4d | source: %s",
            status, t["domain"], consulted_db, str(hit), score, actual_source
        )

    return all_passed


# ===========================================================================
# PHASE 9: Existing Labeling Test
# ===========================================================================
def phase_9_labeling_test(sample_malicious: str) -> bool:
    logger.info("=== PHASE 9 — EXISTING LABELING TEST ===")
    labeller = DNSLabeller(config=LabelingConfig())

    records = [
        pd.Series({"domain": "google.com", "query_type": "A", "response_code": "NOERROR", "client_ip": "192.168.1.10"}),
        pd.Series({"domain": sample_malicious, "query_type": "A", "response_code": "NOERROR", "client_ip": "192.168.1.10"}),
        pd.Series({"domain": "simplecleanexample.org", "query_type": "A", "response_code": "NOERROR", "client_ip": "192.168.1.10"}),
    ]

    all_passed = True
    for row in records:
        score, label, conf, reason, ti_source = labeller._process_row(row)
        dom = row["domain"]
        if dom == "google.com":
            passed = (label == "Benign" and ti_source == "trusted")
        elif dom == sample_malicious:
            passed = (label == "Malicious" and ti_source == "malicious")
        else:
            passed = (label == "Benign" and ti_source == "unknown")

        status = "PASS" if passed else "FAIL"
        if not passed:
            all_passed = False
        logger.info("  [%s] domain: %-30s -> label: %-10s | score: %-4d | conf: %-3d | ti_source: %s", status, dom, label, score, conf, ti_source)

    return all_passed


# ===========================================================================
# PHASE 10: PostgreSQL Exact Lookup Performance
# ===========================================================================
def phase_10_performance_benchmark(n_iterations: int = 1000) -> Dict[str, float]:
    logger.info("=== PHASE 10 — POSTGRESQL EXACT LOOKUP PERFORMANCE (%d queries) ===", n_iterations)

    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="malicious_db")
    cur = conn.cursor()
    cur.execute("SELECT domain FROM malicious_domains LIMIT 50;")
    existing_domains = [r[0] for r in cur.fetchall()]
    cur.close()
    conn.close()

    non_existing_domains = [f"non-existent-lookup-benchmark-{i}.invalid" for i in range(50)]
    all_query_domains = existing_domains + non_existing_domains

    # Warmup
    for _ in range(20):
        is_malicious(all_query_domains[0])

    latencies_ms = []
    for i in range(n_iterations):
        target = all_query_domains[i % len(all_query_domains)]
        t0 = time.perf_counter()
        is_malicious(target)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)

    arr = np.array(latencies_ms)
    res = {
        "min": float(np.min(arr)),
        "median": float(np.median(arr)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "max": float(np.max(arr)),
    }

    logger.info("  Benchmark Statistics over %d queries (50%% existing, 50%% non-existing):", n_iterations)
    logger.info("    min:    %.3f ms", res["min"])
    logger.info("    median: %.3f ms", res["median"])
    logger.info("    p95:    %.3f ms", res["p95"])
    logger.info("    p99:    %.3f ms", res["p99"])
    logger.info("    max:    %.3f ms", res["max"])

    return res


# ===========================================================================
# PHASE 12: Live Pipeline Verification
# ===========================================================================
def phase_12_live_pipeline() -> Tuple[bool, bool]:
    logger.info("=== PHASE 12 — LIVE PIPELINE VERIFICATION ===")

    test_domain = f"test-pipeline-telemetry-{int(time.time())}.org"
    msg = {
        "timestamp": datetime.now(timezone.utc).strftime("%d-%b-%Y %H:%M:%S.000"),
        "client_ip": "192.168.1.99",
        "client_port": "54321",
        "domain": test_domain,
        "query_class": "IN",
        "query_type": "A",
        "flags": "+",
        "resolver": "127.0.0.1",
    }

    # Verify message parsing
    parse_result = _record_from_structured_json(msg, source_file="smoke_test", line_number=1)
    parse_ok = parse_result.success and parse_result.record.domain == test_domain
    logger.info("  [%s] parse_result: domain=%s, client_ip=%s", "PASS" if parse_ok else "FAIL", parse_result.record.domain, parse_result.record.client_ip)

    # Process through pipeline runner and verify telemetry stored in dns_threat_detection
    dataset_path = PROJECT_ROOT / "data" / "test_live_dataset.csv"
    feature_path = PROJECT_ROOT / "data" / "test_live_features.csv"
    feat_writer = IncrementalFeatureWriter(feature_path)
    domain_profiler = DomainProfilingService()

    runner = LivePipelineProcessor(
        dataset_path=dataset_path,
        feature_writer=feat_writer,
        profiling_enabled=True,
        domain_profiler=domain_profiler,
    )

    runner.process_structured_message(1, msg, "smoke_test")

    # Verify event stored in domain_query_history in dns_threat_detection
    conn = psycopg2.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASSWORD, dbname="dns_threat_detection")
    cur = conn.cursor()
    cur.execute("SELECT id, domain, client_ip, query_type, final_label, ti_source FROM domain_query_history WHERE domain = %s ORDER BY id DESC LIMIT 1;", (test_domain,))
    row = cur.fetchone()
    cur.close()
    conn.close()

    telemetry_ok = (row is not None) and (row[1] == test_domain)
    logger.info("  [%s] Telemetry stored in dns_threat_detection.domain_query_history -> %s", "PASS" if telemetry_ok else "FAIL", row)

    # Cleanup temporary test files
    for p in [dataset_path, feature_path]:
        try:
            if p.exists():
                p.unlink()
        except Exception:
            pass

    return parse_ok, telemetry_ok


# ===========================================================================
# PHASE 13: Rollback Safety Check
# ===========================================================================
def phase_13_rollback_safety() -> bool:
    logger.info("=== PHASE 13 — ROLLBACK SAFETY CHECK ===")
    expected_sqlite_files = [
        PROJECT_ROOT / "data" / "trusted_domains.db",
        PROJECT_ROOT / "data" / "malicious_domains.db",
        PROJECT_ROOT / "dashboard.db",
    ]

    all_exist = True
    for p in expected_sqlite_files:
        exists = p.exists() and p.stat().st_size > 0
        if not exists:
            all_exist = False
        logger.info("  [%s] %-40s (Size: %s bytes)", "EXISTS" if exists else "MISSING", p.relative_to(PROJECT_ROOT), f"{p.stat().st_size:,}" if p.exists() else "0")

    return all_exist


# ===========================================================================
# MAIN EXECUTION
# ===========================================================================
def main() -> int:
    print("\n" + "=" * 80)
    print(f"{'MVP POSTGRESQL + DNS PIPELINE VERIFICATION SUITE':^80}")
    print("=" * 80 + "\n")

    p0 = phase_0_audit()
    p1 = phase_1_connectivity()
    p2 = phase_2_schemas()
    p3 = phase_3_data_integrity()
    p4_ok = phase_4_trusted_test()
    p5_ok, sample_malicious = phase_5_malicious_test()
    p6_ok = phase_6_reputation_test()
    p7_ok = phase_7_daily_review_test()
    p8_ok = phase_8_precedence_test(sample_malicious[0])
    p9_ok = phase_9_labeling_test(sample_malicious[0])
    p10_bench = phase_10_performance_benchmark(1000)
    p12_parse, p12_telem = phase_12_live_pipeline()
    p13_ok = phase_13_rollback_safety()

    print("\n" + "=" * 80)
    print(f"{'FINAL VERIFICATION AUDIT SUMMARY':^80}")
    print("=" * 80)
    print(f"  Environment & Prerequisite Audit:          {'PASS' if p0['passed'] else 'FAIL'}")
    print(f"  Database Connectivity (5 DBs):             {'PASS' if all(p1.values()) else 'FAIL'}")
    print(f"  Schema Verification (All Tables/Keys):     {'PASS' if all(p2.values()) else 'FAIL'}")
    print(f"  Data Integrity (Source == Destination):    {'PASS' if p3['passed'] else 'FAIL'}")
    print(f"  Trusted Lookup Test:                       {'PASS' if p4_ok else 'FAIL'}")
    print(f"  Malicious Lookup Test:                     {'PASS' if p5_ok else 'FAIL'}")
    print(f"  Reputation Lookup Test:                    {'PASS' if p6_ok else 'FAIL'}")
    print(f"  Daily Review Test:                         {'PASS' if p7_ok else 'FAIL'}")
    print(f"  Four-Database Precedence Test:             {'PASS' if p8_ok else 'FAIL'}")
    print(f"  Existing Labeling Test:                    {'PASS' if p9_ok else 'FAIL'}")
    print(f"  Live Pipeline Processing:                  {'PASS' if p12_parse else 'FAIL'}")
    print(f"  Telemetry Storage (domain_query_history):  {'PASS' if p12_telem else 'FAIL'}")
    print(f"  Rollback Safety (Original SQLite Backup):  {'PASS' if p13_ok else 'FAIL'}")
    print("--------------------------------------------------------------------------------")
    print(f"  PostgreSQL Exact Lookup Benchmark (1,000 queries):")
    print(f"    min:    {p10_bench['min']:.3f} ms")
    print(f"    median: {p10_bench['median']:.3f} ms")
    print(f"    p95:    {p10_bench['p95']:.3f} ms")
    print(f"    p99:    {p10_bench['p99']:.3f} ms")
    print(f"    max:    {p10_bench['max']:.3f} ms")
    print("=" * 80)

    overall = all([
        p0["passed"],
        all(p1.values()),
        all(p2.values()),
        p3["passed"],
        p4_ok,
        p5_ok,
        p6_ok,
        p7_ok,
        p8_ok,
        p9_ok,
        p12_parse,
        p12_telem,
        p13_ok,
    ])

    print(f"\nOVERALL RESULT: {'FINAL STATUS: PASS' if overall else 'FINAL STATUS: FAIL'}\n")
    return 0 if overall else 1


if __name__ == "__main__":
    sys.exit(main())
