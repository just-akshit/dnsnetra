#!/usr/bin/env python3
"""
migrate_daily_review_schema.py
==============================
Minimal schema migration for Daily Review subsystem (daily_review_db.unknown_domains):
  1. Adds `query_count` (INTEGER NOT NULL DEFAULT 1).
  2. Adds `last_checked` (TIMESTAMPTZ NULL).
  3. Adds `previous_status` (domain_status NULL).
  4. Migrates existing `metadata.query_count` values into `query_count`.
  5. Adds index on `last_checked`.
  6. Idempotent and preserves all existing rows and metadata.
"""

from __future__ import annotations

import os
import sys
import logging
from pathlib import Path
import psycopg2
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("migrate_daily_review_schema")

DB_HOST = os.getenv("DAILY_REVIEW_DB_HOST", os.getenv("DB_HOST", "localhost"))
DB_PORT = int(os.getenv("DAILY_REVIEW_DB_PORT", os.getenv("DB_PORT", "5432")))
DB_USER = os.getenv("DAILY_REVIEW_DB_USERNAME", os.getenv("DB_USER", "postgres"))
DB_PASSWORD = os.getenv("DAILY_REVIEW_DB_PASSWORD", os.getenv("DB_PASSWORD", ""))
DAILY_REVIEW_DB = os.getenv("DAILY_REVIEW_DB_DATABASE", "daily_review_db")


def run_migration() -> dict:
    logger.info("Connecting to %s at %s:%d as %s", DAILY_REVIEW_DB, DB_HOST, DB_PORT, DB_USER)
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        dbname=DAILY_REVIEW_DB,
    )
    conn.autocommit = False
    cur = conn.cursor()

    try:
        # 1. Add columns if not existing
        logger.info("Adding minimal Daily Review columns if not existing...")
        cur.execute("""
            ALTER TABLE unknown_domains ADD COLUMN IF NOT EXISTS query_count INTEGER NOT NULL DEFAULT 1;
            ALTER TABLE unknown_domains ADD COLUMN IF NOT EXISTS last_checked TIMESTAMPTZ NULL;
            ALTER TABLE unknown_domains ADD COLUMN IF NOT EXISTS previous_status domain_status NULL;
            CREATE INDEX IF NOT EXISTS idx_unknown_domains_last_checked ON unknown_domains (last_checked);
        """)

        # 2. Migrate metadata->>'query_count' to column query_count
        logger.info("Migrating existing metadata.query_count to query_count column...")
        cur.execute("""
            UPDATE unknown_domains
            SET query_count = (metadata->>'query_count')::int
            WHERE metadata ? 'query_count'
              AND (metadata->>'query_count') ~ '^[0-9]+$'
              AND (metadata->>'query_count')::int > 0;
        """)
        migrated_metadata_count = cur.rowcount
        logger.info("Rows updated from metadata.query_count: %d", migrated_metadata_count)

        # Commit transaction
        conn.commit()

        # 3. Validation
        cur.execute("SELECT count(*), count(query_count), count(last_checked), count(previous_status) FROM unknown_domains;")
        total_rows, qc_count, lc_count, ps_count = cur.fetchone()
        logger.info("Validation: Total rows: %d, query_count populated: %d, last_checked: %d, previous_status: %d",
                    total_rows, qc_count, lc_count, ps_count)

        cur.close()
        conn.close()
        return {
            "success": True,
            "total_rows": total_rows,
            "migrated_from_metadata": migrated_metadata_count,
        }

    except Exception as exc:
        conn.rollback()
        cur.close()
        conn.close()
        logger.exception("Migration failed: %s", exc)
        raise


if __name__ == "__main__":
    result = run_migration()
    print("Migration completed successfully:", result)
