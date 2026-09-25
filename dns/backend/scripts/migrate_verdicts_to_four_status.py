#!/usr/bin/env python3
"""
migrate_verdicts_to_four_status.py
==================================
Idempotent, transactional, non-destructive migration script to align
PostgreSQL tables (domain_query_history and domain_profiles) with the
Four-Status Classification Model:
  1. Benign
  2. Malicious
  3. Review Needed
  4. Unknown

Rules:
- Suspicious (and case variants) -> 'Review Needed'
- Clean (and case variants)      -> 'Benign'
- Canonical casing applied to 'Benign', 'Malicious', 'Review Needed', 'Unknown'
- Fails if unexpected values exist.
- Does not modify timestamps, query IDs, client IPs, or event rows.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Dict, Any

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

from domain_profiling.connection import get_db_connection


CANONICAL_SET = {"Benign", "Malicious", "Review Needed", "Unknown"}


def get_label_distribution(conn, table: str, col: str) -> Dict[str, int]:
    with conn.cursor() as cur:
        cur.execute(f"SELECT {col}, COUNT(*) FROM {table} GROUP BY {col} ORDER BY COUNT(*) DESC;")
        return {row[0]: row[1] for row in cur.fetchall()}


def run_migration():
    print("=" * 70)
    print("STARTING FOUR-STATUS POSTGRESQL VERDICT MIGRATION")
    print("=" * 70)

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # 1. Inspect before state in domain_query_history
            cur.execute("SELECT COUNT(*) FROM domain_query_history;")
            total_history_before = cur.fetchone()[0]

            history_before = get_label_distribution(conn, "domain_query_history", "final_label")
            print(f"\n[1] domain_query_history BEFORE (Total rows: {total_history_before}):")
            for lbl, count in history_before.items():
                print(f"    - {repr(lbl)}: {count}")

            # Inspect before state in domain_profiles
            cur.execute("SELECT COUNT(*) FROM domain_profiles;")
            total_profiles_before = cur.fetchone()[0]

            profiles_before = get_label_distribution(conn, "domain_profiles", "last_label")
            print(f"\n[2] domain_profiles BEFORE (Total rows: {total_profiles_before}):")
            for lbl, count in profiles_before.items():
                print(f"    - {repr(lbl)}: {count}")

            # 2. Check for unrecognized legacy values
            allowed_legacy = {"suspicious", "clean", "benign", "malicious", "unknown", "review needed", "review_needed"}
            for lbl in history_before.keys():
                norm = (lbl or "").strip().lower()
                if norm not in allowed_legacy:
                    raise ValueError(f"Aborting: Unexpected final_label found in domain_query_history: {repr(lbl)}")
            for lbl in profiles_before.keys():
                norm = (lbl or "").strip().lower()
                if norm not in allowed_legacy:
                    raise ValueError(f"Aborting: Unexpected last_label found in domain_profiles: {repr(lbl)}")

            print("\n[3] Executing transactional migrations...")

            # Migrate domain_query_history
            cur.execute("""
                UPDATE domain_query_history
                SET final_label = 'Review Needed'
                WHERE LOWER(COALESCE(final_label, '')) IN ('suspicious', 'review_needed');
            """)
            history_suspicious_migrated = cur.rowcount

            cur.execute("""
                UPDATE domain_query_history
                SET final_label = 'Benign'
                WHERE LOWER(COALESCE(final_label, '')) = 'clean';
            """)
            history_clean_migrated = cur.rowcount

            cur.execute("""
                UPDATE domain_query_history
                SET final_label = 'Benign'
                WHERE final_label = 'benign';
            """)
            cur.execute("""
                UPDATE domain_query_history
                SET final_label = 'Malicious'
                WHERE final_label = 'malicious';
            """)

            # Migrate domain_profiles
            cur.execute("""
                UPDATE domain_profiles
                SET last_label = 'Review Needed'
                WHERE LOWER(COALESCE(last_label, '')) IN ('suspicious', 'review_needed');
            """)
            profiles_suspicious_migrated = cur.rowcount

            cur.execute("""
                UPDATE domain_profiles
                SET last_label = 'Benign'
                WHERE LOWER(COALESCE(last_label, '')) = 'clean';
            """)
            profiles_clean_migrated = cur.rowcount

            cur.execute("""
                UPDATE domain_profiles
                SET last_label = 'Benign'
                WHERE last_label = 'benign';
            """)
            cur.execute("""
                UPDATE domain_profiles
                SET last_label = 'Malicious'
                WHERE last_label = 'malicious';
            """)

            print(f"    - domain_query_history: {history_suspicious_migrated} 'Suspicious' migrated to 'Review Needed'")
            print(f"    - domain_query_history: {history_clean_migrated} 'Clean' migrated to 'Benign'")
            print(f"    - domain_profiles: {profiles_suspicious_migrated} 'Suspicious' migrated to 'Review Needed'")
            print(f"    - domain_profiles: {profiles_clean_migrated} 'Clean' migrated to 'Benign'")

        conn.commit()

        # 4. Post-migration verification
        history_after = get_label_distribution(conn, "domain_query_history", "final_label")
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM domain_query_history;")
            total_history_after = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM domain_profiles;")
            total_profiles_after = cur.fetchone()[0]

        profiles_after = get_label_distribution(conn, "domain_profiles", "last_label")

        print(f"\n[4] domain_query_history AFTER (Total rows: {total_history_after}):")
        for lbl, count in history_after.items():
            print(f"    - {repr(lbl)}: {count}")

        print(f"\n[5] domain_profiles AFTER (Total rows: {total_profiles_after}):")
        for lbl, count in profiles_after.items():
            print(f"    - {repr(lbl)}: {count}")

        # Assertions
        assert total_history_before == total_history_after, "ROW COUNT MISMATCH in domain_query_history!"
        assert total_profiles_before == total_profiles_after, "ROW COUNT MISMATCH in domain_profiles!"

        for lbl in history_after.keys():
            if lbl not in CANONICAL_SET:
                raise AssertionError(f"Invalid non-canonical status remaining in domain_query_history: {repr(lbl)}")
        for lbl in profiles_after.keys():
            if lbl not in CANONICAL_SET:
                raise AssertionError(f"Invalid non-canonical status remaining in domain_profiles: {repr(lbl)}")

        print("\n" + "=" * 70)
        print("MIGRATION COMPLETED & VERIFIED CLEANLY (0 legacy statuses remain)")
        print("=" * 70)


if __name__ == "__main__":
    run_migration()
