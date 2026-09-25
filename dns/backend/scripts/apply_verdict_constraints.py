#!/usr/bin/env python3
"""
apply_verdict_constraints.py
============================
Enforces PostgreSQL database-level CHECK constraints for the four canonical verdicts:
  - domain_query_history.final_label IN ('Benign', 'Malicious', 'Review Needed', 'Unknown')
  - domain_profiles.last_label IN ('Benign', 'Malicious', 'Review Needed', 'Unknown')
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from domain_profiling.connection import get_db_connection


def apply_constraints():
    print("Enforcing database CHECK constraints for four canonical statuses...")
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # 1. Verify 0 invalid rows in domain_query_history
            cur.execute("""
                SELECT COUNT(*) 
                FROM domain_query_history 
                WHERE final_label NOT IN ('Benign', 'Malicious', 'Review Needed', 'Unknown')
                   OR final_label IS NULL;
            """)
            invalid_history = cur.fetchone()[0]
            if invalid_history > 0:
                raise RuntimeError(f"Cannot apply constraint: {invalid_history} invalid rows in domain_query_history")

            # 2. Verify 0 invalid rows in domain_profiles
            cur.execute("""
                SELECT COUNT(*) 
                FROM domain_profiles 
                WHERE last_label NOT IN ('Benign', 'Malicious', 'Review Needed', 'Unknown')
                   OR last_label IS NULL;
            """)
            invalid_profiles = cur.fetchone()[0]
            if invalid_profiles > 0:
                raise RuntimeError(f"Cannot apply constraint: {invalid_profiles} invalid rows in domain_profiles")

            # 3. Apply constraints idempotently
            cur.execute("""
                ALTER TABLE domain_query_history 
                DROP CONSTRAINT IF EXISTS chk_domain_query_history_final_label;

                ALTER TABLE domain_query_history 
                ADD CONSTRAINT chk_domain_query_history_final_label 
                CHECK (final_label IN ('Benign', 'Malicious', 'Review Needed', 'Unknown'));

                ALTER TABLE domain_profiles 
                DROP CONSTRAINT IF EXISTS chk_domain_profiles_last_label;

                ALTER TABLE domain_profiles 
                ADD CONSTRAINT chk_domain_profiles_last_label 
                CHECK (last_label IN ('Benign', 'Malicious', 'Review Needed', 'Unknown'));
            """)
        conn.commit()

    print("SUCCESS: CHECK constraints successfully enforced on PostgreSQL schema.")


if __name__ == "__main__":
    apply_constraints()
