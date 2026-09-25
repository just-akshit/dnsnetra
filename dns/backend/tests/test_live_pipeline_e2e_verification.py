#!/usr/bin/env python3
"""
backend/tests/test_live_pipeline_e2e_verification.py
===================================================
End-to-End Live Pipeline Verification & Timestamp/Repeated Query Test
"""

import os
import sys
import time
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

from run_live_pipeline import LivePipelineProcessor, IncrementalFeatureWriter
import client_profiling
from domain_profiling.service import DomainProfilingService

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASS = os.getenv("DB_PASSWORD", "")

def get_conn(dbname):
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS, dbname=dbname
    )

def test_pipeline_e2e():
    print("\n" + "=" * 70)
    print("STARTING LIVE PIPELINE E2E VERIFICATION TEST")
    print("=" * 70)

    # Initialize client profiling pool
    client_profiling.initialize_pool()

    # Synthetic test domain names
    TRUSTED_DOMAIN = "google.com"
    MALICIOUS_DOMAIN = "test-synthetic-malicious-e2e.biz"
    REPUTATION_DOMAIN = "test-synthetic-reputation-e2e.org"
    UNKNOWN_DOMAIN = "test-synthetic-unknown-e2e.info"

    # Pre-clean any leftover synthetic test data
    def cleanup():
        print("[Cleanup] Removing synthetic test domains...")
        with get_conn("malicious_db") as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM malicious_domains WHERE domain = %s;", (MALICIOUS_DOMAIN,))
        with get_conn("reputation_db") as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM reputation_domains WHERE domain IN (%s, %s, %s);", 
                            (MALICIOUS_DOMAIN, REPUTATION_DOMAIN, UNKNOWN_DOMAIN))
        with get_conn("daily_review_db") as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM unknown_domains WHERE domain IN (%s, %s);", 
                            (UNKNOWN_DOMAIN, MALICIOUS_DOMAIN))
        with get_conn("dns_threat_detection") as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM domain_query_history WHERE domain IN (%s, %s, %s);",
                            (MALICIOUS_DOMAIN, REPUTATION_DOMAIN, UNKNOWN_DOMAIN))
                cur.execute("DELETE FROM domain_profiles WHERE domain IN (%s, %s, %s);",
                            (MALICIOUS_DOMAIN, REPUTATION_DOMAIN, UNKNOWN_DOMAIN))
                cur.execute("DELETE FROM client_history WHERE domain IN (%s, %s, %s);",
                            (MALICIOUS_DOMAIN, REPUTATION_DOMAIN, UNKNOWN_DOMAIN))
                cur.execute("DELETE FROM client_profiles WHERE client_ip IN ('192.168.10.51', '192.168.10.52', '192.168.10.53', '192.168.10.54', '192.168.10.55');")

    cleanup()

    # Setup pre-conditions
    # 1. Add MALICIOUS_DOMAIN to malicious_db
    with get_conn("malicious_db") as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO malicious_domains (domain, source) VALUES (%s, 'urlhaus') ON CONFLICT DO NOTHING;", (MALICIOUS_DOMAIN,))
    
    # 2. Add REPUTATION_DOMAIN to reputation_db
    with get_conn("reputation_db") as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO reputation_domains (domain, status, source, confidence, match_scope, matched_domain)
                VALUES (%s, 'malicious', 'URLHaus', 1.0, 'EXACT_FQDN', %s)
                ON CONFLICT DO NOTHING;
            """, (REPUTATION_DOMAIN, REPUTATION_DOMAIN))

    # Initialize live pipeline components
    dataset_path = Path("/tmp/test_live_dataset.csv")
    features_path = Path("/tmp/test_live_features.csv")
    if dataset_path.exists():
        dataset_path.unlink()
    if features_path.exists():
        features_path.unlink()

    feature_writer = IncrementalFeatureWriter(features_path)
    domain_profiler = DomainProfilingService()

    processor = LivePipelineProcessor(
        dataset_path=dataset_path,
        feature_writer=feature_writer,
        profiling_enabled=True,
        domain_profiler=domain_profiler,
    )

    try:
        # -------------------------------------------------------------
        # TEST 1: TRUSTED DOMAIN
        # -------------------------------------------------------------
        print("\n--- [Test 1] Processing Trusted Domain ---")
        t_trusted = "2026-08-20T09:15:32.000000+00:00"
        msg_trusted = {
            "@timestamp": t_trusted,
            "client_ip": "192.168.10.51",
            "domain": TRUSTED_DOMAIN,
            "query_type": "A",
            "response_code": "NOERROR",
        }
        processor.process_structured_message(1, msg_trusted, "test")

        # Verify in PostgreSQL
        with get_conn("dns_threat_detection") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM domain_query_history WHERE domain = %s ORDER BY id DESC LIMIT 1;", (TRUSTED_DOMAIN,))
                row = cur.fetchone()
                assert row is not None, "Trusted domain not found in domain_query_history!"
                assert row["final_label"] == "Benign", f"Expected Benign label, got {row['final_label']}"
                assert row["ti_source"] == "trusted", f"Expected ti_source=trusted, got {row['ti_source']}"
                expected_dt = datetime.fromisoformat(t_trusted).astimezone(timezone.utc)
                actual_dt = row["timestamp"].astimezone(timezone.utc)
                assert actual_dt == expected_dt, f"Timestamp mismatch: {actual_dt} != {expected_dt}"
                print("  ✓ domain_query_history recorded correctly with exact timestamp & Benign label")

                cur.execute("SELECT * FROM domain_profiles WHERE domain = %s;", (TRUSTED_DOMAIN,))
                dp = cur.fetchone()
                assert dp is not None, "Trusted domain profile not found!"
                print("  ✓ domain_profiles updated")

        # -------------------------------------------------------------
        # TEST 2: MALICIOUS DOMAIN
        # -------------------------------------------------------------
        print("\n--- [Test 2] Processing Malicious Domain ---")
        t_mal = "2026-08-20T10:20:30.000000+00:00"
        msg_mal = {
            "@timestamp": t_mal,
            "client_ip": "192.168.10.52",
            "domain": MALICIOUS_DOMAIN,
            "query_type": "A",
            "response_code": "NOERROR",
        }
        processor.process_structured_message(2, msg_mal, "test")

        # Verify in PostgreSQL
        with get_conn("dns_threat_detection") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM domain_query_history WHERE domain = %s ORDER BY id DESC LIMIT 1;", (MALICIOUS_DOMAIN,))
                row = cur.fetchone()
                assert row is not None, "Malicious domain not found in domain_query_history!"
                assert row["final_label"] == "Malicious", f"Expected Malicious label, got {row['final_label']}"
                assert row["ti_source"] == "malicious", f"Expected ti_source=malicious, got {row['ti_source']}"
                expected_mal_dt = datetime.fromisoformat(t_mal).astimezone(timezone.utc)
                actual_mal_dt = row["timestamp"].astimezone(timezone.utc)
                assert actual_mal_dt == expected_mal_dt, f"Timestamp mismatch: {actual_mal_dt} != {expected_mal_dt}"
                print("  ✓ domain_query_history recorded correctly with exact timestamp & Malicious label")

        with get_conn("reputation_db") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM reputation_domains WHERE domain = %s;", (MALICIOUS_DOMAIN,))
                rep = cur.fetchone()
                assert rep is not None, "Malicious domain not upserted into reputation_domains!"
                assert rep["status"] == "malicious", f"Expected reputation status=malicious, got {rep['status']}"
                print("  ✓ reputation_db.reputation_domains upserted correctly")

        # -------------------------------------------------------------
        # TEST 3: EXISTING REPUTATION DOMAIN
        # -------------------------------------------------------------
        print("\n--- [Test 3] Processing Existing Reputation Domain ---")
        t_rep = "2026-08-20T11:25:40.000000+00:00"
        msg_rep = {
            "@timestamp": t_rep,
            "client_ip": "192.168.10.53",
            "domain": REPUTATION_DOMAIN,
            "query_type": "A",
            "response_code": "NOERROR",
        }
        processor.process_structured_message(3, msg_rep, "test")

        # Verify in PostgreSQL
        with get_conn("dns_threat_detection") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM domain_query_history WHERE domain = %s ORDER BY id DESC LIMIT 1;", (REPUTATION_DOMAIN,))
                row = cur.fetchone()
                assert row is not None, "Reputation domain not found in domain_query_history!"
                assert row["final_label"] == "Malicious", f"Expected Malicious label, got {row['final_label']}"
                expected_rep_dt = datetime.fromisoformat(t_rep).astimezone(timezone.utc)
                actual_rep_dt = row["timestamp"].astimezone(timezone.utc)
                assert actual_rep_dt == expected_rep_dt, f"Timestamp mismatch: {actual_rep_dt} != {expected_rep_dt}"
                print("  ✓ domain_query_history recorded correctly for reputation domain")

        # -------------------------------------------------------------
        # TEST 4: UNKNOWN DOMAIN & REPEAT QUERY TEST
        # -------------------------------------------------------------
        print("\n--- [Test 4] Processing Unknown Domain (First Query T1) ---")
        t_unk_1 = "2026-08-20T12:00:00.000000+00:00"
        msg_unk_1 = {
            "@timestamp": t_unk_1,
            "client_ip": "192.168.10.54",
            "domain": UNKNOWN_DOMAIN,
            "query_type": "A",
            "response_code": "NOERROR",
        }
        processor.process_structured_message(4, msg_unk_1, "test")

        # Check daily_review_db.unknown_domains after T1
        with get_conn("daily_review_db") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM unknown_domains WHERE domain = %s;", (UNKNOWN_DOMAIN,))
                row_t1 = cur.fetchone()
                assert row_t1 is not None, "Unknown domain not found in daily_review_db.unknown_domains!"
                assert row_t1["status"] == "review_needed", f"Expected status=review_needed, got {row_t1['status']}"
                expected_t1 = datetime.fromisoformat(t_unk_1).astimezone(timezone.utc)
                assert row_t1["first_seen"].astimezone(timezone.utc) == expected_t1, f"Expected first_seen={expected_t1}, got {row_t1['first_seen']}"
                assert row_t1["last_seen"].astimezone(timezone.utc) == expected_t1, f"Expected last_seen={expected_t1}, got {row_t1['last_seen']}"
                meta_t1 = row_t1["metadata"] or {}
                assert meta_t1.get("query_count") == 1, f"Expected query_count=1 in metadata, got {meta_t1.get('query_count')}"
                created_at_1 = row_t1["created_at"]
                updated_at_1 = row_t1["updated_at"]
                print(f"  ✓ unknown_domains created: first_seen={row_t1['first_seen']}, last_seen={row_t1['last_seen']}, query_count={meta_t1.get('query_count')}")
                print(f"  ✓ created_at={created_at_1} represents DB creation time (NOT query time)")

        time.sleep(1.0)  # Ensure clock advance for updated_at check

        print("\n--- [Test 4b] Processing Unknown Domain (Repeated Query T2) ---")
        t_unk_2 = "2026-08-20T14:30:00.000000+00:00"
        msg_unk_2 = {
            "@timestamp": t_unk_2,
            "client_ip": "192.168.10.55",
            "domain": UNKNOWN_DOMAIN,
            "query_type": "A",
            "response_code": "NOERROR",
        }
        processor.process_structured_message(5, msg_unk_2, "test")

        # Check daily_review_db.unknown_domains after T2
        with get_conn("daily_review_db") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT COUNT(*) AS cnt FROM unknown_domains WHERE domain = %s;", (UNKNOWN_DOMAIN,))
                cnt = cur.fetchone()["cnt"]
                assert cnt == 1, f"Expected exactly 1 row (no duplicate), found {cnt} rows!"
                
                cur.execute("SELECT * FROM unknown_domains WHERE domain = %s;", (UNKNOWN_DOMAIN,))
                row_t2 = cur.fetchone()
                expected_t2 = datetime.fromisoformat(t_unk_2).astimezone(timezone.utc)
                assert row_t2["first_seen"].astimezone(timezone.utc) == expected_t1, f"first_seen must remain T1! got {row_t2['first_seen']}"
                assert row_t2["last_seen"].astimezone(timezone.utc) == expected_t2, f"last_seen must update to T2! got {row_t2['last_seen']}"
                meta_t2 = row_t2["metadata"] or {}
                actual_query_count = row_t2["query_count"] if "query_count" in row_t2 else meta_t2.get("query_count")
                assert actual_query_count == 2, f"Expected query_count=2, got {actual_query_count}"
                assert row_t2["created_at"] == created_at_1, "created_at must NOT change on repeat query!"
                assert row_t2["updated_at"] >= updated_at_1, "updated_at must update on repeat query!"
                print("  ✓ Repeated query maintained single record:")
                print(f"    first_seen = {row_t2['first_seen']} (preserved initial query time)")
                print(f"    last_seen  = {row_t2['last_seen']} (updated to latest query time)")
                print(f"    query_count = {actual_query_count} (incremented to 2)")
                print(f"    created_at = {row_t2['created_at']} (original DB insert time)")
                print(f"    updated_at = {row_t2['updated_at']} (refreshed DB update time)")

        # Verify domain_query_history has TWO separate events
        with get_conn("dns_threat_detection") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT timestamp, client_ip FROM domain_query_history WHERE domain = %s ORDER BY id ASC;", (UNKNOWN_DOMAIN,))
                events = cur.fetchall()
                assert len(events) == 2, f"Expected 2 raw events in domain_query_history, found {len(events)}"
                assert events[0]["timestamp"].astimezone(timezone.utc) == expected_t1
                assert events[1]["timestamp"].astimezone(timezone.utc) == expected_t2
                print("  ✓ domain_query_history preserved raw event log for both queries (T1 and T2)")

        # -------------------------------------------------------------
        # TEST 5: CLIENT PROFILING & DOMAIN PROFILING
        # -------------------------------------------------------------
        print("\n--- [Test 5] Verifying Profiling Updates ---")
        with get_conn("dns_threat_detection") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Client profiles
                cur.execute("SELECT * FROM client_profiles WHERE client_ip = '192.168.10.54';")
                cp = cur.fetchone()
                assert cp is not None, "Client profile not created for 192.168.10.54!"
                print("  ✓ client_profiles recorded client activity")

                cur.execute("SELECT * FROM client_history WHERE client_ip = '192.168.10.54' AND domain = %s;", (UNKNOWN_DOMAIN,))
                ch = cur.fetchone()
                assert ch is not None, "Client history record not found!"
                print("  ✓ client_history tracked client-domain relationship")

        print("\n" + "=" * 70)
        print("ALL E2E LIVE PIPELINE TESTS PASSED!")
        print("=" * 70)

    finally:
        cleanup()
        client_profiling.close_pool()
        if dataset_path.exists():
            dataset_path.unlink()

if __name__ == "__main__":
    test_pipeline_e2e()
