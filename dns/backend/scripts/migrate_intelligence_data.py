#!/usr/bin/env python3
"""
migrate_intelligence_data.py
============================
Migrates data from existing sources into the 4 dedicated PostgreSQL databases:
  1. SQLite trusted_domains.db -> trusted_db (trusted_domains & metadata)
  2. SQLite malicious_domains.db -> malicious_db (malicious_domains & metadata)
  3. PostgreSQL dns_threat_detection.reputation_domains -> reputation_db.reputation_domains
  4. PostgreSQL dns_threat_detection.unknown_domains -> daily_review_db.unknown_domains
"""

from __future__ import annotations

import os
import sys
import time
import logging
import sqlite3
from pathlib import Path
from typing import List, Tuple, Any

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("migrate_intelligence_data")

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

PRIMARY_DB = os.getenv("DB_NAME", "dns_threat_detection")
TRUSTED_DB = os.getenv("TRUSTED_DB_DATABASE", "trusted_db")
MALICIOUS_DB = os.getenv("MALICIOUS_DB_DATABASE", "malicious_db")
REPUTATION_DB = os.getenv("REPUTATION_DB_DATABASE", "reputation_db")
DAILY_REVIEW_DB = os.getenv("DAILY_REVIEW_DB_DATABASE", "daily_review_db")

TRUSTED_SQLITE_PATH = PROJECT_ROOT / "data" / "trusted_domains.db"
if not TRUSTED_SQLITE_PATH.exists():
    TRUSTED_SQLITE_PATH = PROJECT_ROOT / "labeler" / "intel" / "trusted_domains.db"

MALICIOUS_SQLITE_PATH = PROJECT_ROOT / "data" / "malicious_domains.db"
if not MALICIOUS_SQLITE_PATH.exists():
    MALICIOUS_SQLITE_PATH = PROJECT_ROOT / "labeler" / "intel" / "malicious" / "malicious_domains.db"


def migrate_trusted_domains() -> dict[str, Any]:
    logger.info("=" * 60)
    logger.info("1. Migrating Trusted Domains from %s to %s", TRUSTED_SQLITE_PATH, TRUSTED_DB)
    logger.info("=" * 60)

    if not TRUSTED_SQLITE_PATH.exists():
        raise FileNotFoundError(f"Trusted SQLite database not found at {TRUSTED_SQLITE_PATH}")

    sqlite_conn = sqlite3.connect(TRUSTED_SQLITE_PATH)
    sqlite_cur = sqlite_conn.cursor()

    sqlite_cur.execute("SELECT COUNT(*) FROM trusted_domains")
    old_count = sqlite_cur.fetchone()[0]
    logger.info("Source SQLite trusted_domains row count: %d", old_count)

    pg_conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=TRUSTED_DB,
        user=DB_USER,
        password=DB_PASSWORD,
    )
    pg_conn.autocommit = False
    pg_cur = pg_conn.cursor()

    # Migrate metadata
    try:
        sqlite_cur.execute("SELECT key, value FROM metadata")
        meta_rows = sqlite_cur.fetchall()
        for k, v in meta_rows:
            pg_cur.execute(
                """
                INSERT INTO metadata (key, value, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
                """,
                (k, v),
            )
        logger.info("Migrated %d metadata rows to %s", len(meta_rows), TRUSTED_DB)
    except Exception as exc:
        logger.warning("Metadata migration warning: %s", exc)

    # Stream trusted_domains in batches
    sqlite_cur.execute("SELECT domain, rank, source, downloaded_at FROM trusted_domains")
    batch_size = 20000
    insert_sql = """
        INSERT INTO trusted_domains (domain, rank, source, downloaded_at, created_at, updated_at)
        VALUES (%s, %s, %s, %s, NOW(), NOW())
        ON CONFLICT (domain) DO UPDATE SET
            rank = EXCLUDED.rank,
            source = EXCLUDED.source,
            downloaded_at = EXCLUDED.downloaded_at,
            updated_at = NOW();
    """

    start_t = time.perf_counter()
    total_migrated = 0
    while True:
        rows = sqlite_cur.fetchmany(batch_size)
        if not rows:
            break
        psycopg2.extras.execute_batch(pg_cur, insert_sql, rows, page_size=1000)
        total_migrated += len(rows)
        logger.info("Migrated %d / %d trusted domains...", total_migrated, old_count)

    pg_conn.commit()
    elapsed = time.perf_counter() - start_t

    pg_cur.execute("SELECT COUNT(*) FROM trusted_domains")
    new_count = pg_cur.fetchone()[0]

    # Fetch sample rows
    pg_cur.execute("SELECT domain, rank, source, downloaded_at FROM trusted_domains LIMIT 3")
    sample_records = pg_cur.fetchall()

    pg_cur.close()
    pg_conn.close()
    sqlite_conn.close()

    logger.info("Finished trusted_domains migration in %.2fs (New count: %d)", elapsed, new_count)
    return {
        "database": TRUSTED_DB,
        "table": "trusted_domains",
        "old_count": old_count,
        "new_count": new_count,
        "difference": new_count - old_count,
        "sample": sample_records,
    }


def migrate_malicious_domains() -> dict[str, Any]:
    logger.info("=" * 60)
    logger.info("2. Migrating Malicious Domains from %s to %s", MALICIOUS_SQLITE_PATH, MALICIOUS_DB)
    logger.info("=" * 60)

    if not MALICIOUS_SQLITE_PATH.exists():
        raise FileNotFoundError(f"Malicious SQLite database not found at {MALICIOUS_SQLITE_PATH}")

    sqlite_conn = sqlite3.connect(MALICIOUS_SQLITE_PATH)
    sqlite_cur = sqlite_conn.cursor()

    sqlite_cur.execute("SELECT COUNT(*) FROM malicious_domains")
    old_count = sqlite_cur.fetchone()[0]
    logger.info("Source SQLite malicious_domains row count: %d", old_count)

    pg_conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=MALICIOUS_DB,
        user=DB_USER,
        password=DB_PASSWORD,
    )
    pg_conn.autocommit = False
    pg_cur = pg_conn.cursor()

    # Migrate metadata
    try:
        sqlite_cur.execute("SELECT key, value FROM metadata")
        meta_rows = sqlite_cur.fetchall()
        for k, v in meta_rows:
            pg_cur.execute(
                """
                INSERT INTO metadata (key, value, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
                """,
                (k, v),
            )
        logger.info("Migrated %d metadata rows to %s", len(meta_rows), MALICIOUS_DB)
    except Exception as exc:
        logger.warning("Metadata migration warning: %s", exc)

    # Stream malicious_domains
    sqlite_cur.execute("SELECT domain, source, downloaded_at FROM malicious_domains")
    batch_size = 10000
    insert_sql = """
        INSERT INTO malicious_domains (domain, source, downloaded_at, created_at, updated_at)
        VALUES (%s, %s, %s, NOW(), NOW())
        ON CONFLICT (domain) DO UPDATE SET
            source = EXCLUDED.source,
            downloaded_at = EXCLUDED.downloaded_at,
            updated_at = NOW();
    """

    start_t = time.perf_counter()
    total_migrated = 0
    while True:
        rows = sqlite_cur.fetchmany(batch_size)
        if not rows:
            break
        psycopg2.extras.execute_batch(pg_cur, insert_sql, rows, page_size=1000)
        total_migrated += len(rows)

    pg_conn.commit()
    elapsed = time.perf_counter() - start_t

    pg_cur.execute("SELECT COUNT(*) FROM malicious_domains")
    new_count = pg_cur.fetchone()[0]

    # Fetch sample rows
    pg_cur.execute("SELECT domain, source, downloaded_at FROM malicious_domains LIMIT 3")
    sample_records = pg_cur.fetchall()

    pg_cur.close()
    pg_conn.close()
    sqlite_conn.close()

    logger.info("Finished malicious_domains migration in %.2fs (New count: %d)", elapsed, new_count)
    return {
        "database": MALICIOUS_DB,
        "table": "malicious_domains",
        "old_count": old_count,
        "new_count": new_count,
        "difference": new_count - old_count,
        "sample": sample_records,
    }


def migrate_reputation_domains() -> dict[str, Any]:
    logger.info("=" * 60)
    logger.info("3. Moving Reputation Domains from %s to %s", PRIMARY_DB, REPUTATION_DB)
    logger.info("=" * 60)

    src_conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=PRIMARY_DB,
        user=DB_USER,
        password=DB_PASSWORD,
    )
    src_cur = src_conn.cursor()

    src_cur.execute("SELECT COUNT(*) FROM reputation_domains")
    old_count = src_cur.fetchone()[0]
    logger.info("Source reputation_domains row count: %d", old_count)

    src_cur.execute(
        """
        SELECT domain, status, source, confidence, match_scope, matched_domain,
               first_seen, last_seen, times_seen, query_count, client_ip, query_type, created_at, updated_at
        FROM reputation_domains
        """
    )
    rows = src_cur.fetchall()

    dst_conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=REPUTATION_DB,
        user=DB_USER,
        password=DB_PASSWORD,
    )
    dst_conn.autocommit = True
    dst_cur = dst_conn.cursor()

    insert_sql = """
        INSERT INTO reputation_domains
            (domain, status, source, confidence, match_scope, matched_domain,
             first_seen, last_seen, times_seen, query_count, client_ip, query_type, created_at, updated_at)
        VALUES
            (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (domain) DO UPDATE SET
            status = EXCLUDED.status,
            source = EXCLUDED.source,
            confidence = EXCLUDED.confidence,
            match_scope = EXCLUDED.match_scope,
            matched_domain = EXCLUDED.matched_domain,
            last_seen = EXCLUDED.last_seen,
            times_seen = EXCLUDED.times_seen,
            query_count = EXCLUDED.query_count,
            client_ip = EXCLUDED.client_ip,
            query_type = EXCLUDED.query_type,
            updated_at = NOW();
    """

    if rows:
        psycopg2.extras.execute_batch(dst_cur, insert_sql, rows)

    dst_cur.execute("SELECT COUNT(*) FROM reputation_domains")
    new_count = dst_cur.fetchone()[0]

    dst_cur.execute("SELECT domain, status, source, confidence, match_scope FROM reputation_domains LIMIT 3")
    sample_records = dst_cur.fetchall()

    dst_cur.close()
    dst_conn.close()
    src_cur.close()
    src_conn.close()

    logger.info("Finished reputation_domains move (New count: %d)", new_count)
    return {
        "database": REPUTATION_DB,
        "table": "reputation_domains",
        "old_count": old_count,
        "new_count": new_count,
        "difference": new_count - old_count,
        "sample": sample_records,
    }


def migrate_daily_review_domains() -> dict[str, Any]:
    logger.info("=" * 60)
    logger.info("4. Moving Unknown Domains from %s to %s", PRIMARY_DB, DAILY_REVIEW_DB)
    logger.info("=" * 60)

    src_conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=PRIMARY_DB,
        user=DB_USER,
        password=DB_PASSWORD,
    )
    src_cur = src_conn.cursor()

    src_cur.execute("SELECT COUNT(*) FROM unknown_domains")
    old_count = src_cur.fetchone()[0]
    logger.info("Source unknown_domains row count: %d", old_count)

    src_cur.execute(
        """
        SELECT domain, first_seen, last_seen, source::text, status::text, metadata, created_at, updated_at, schema_version
        FROM unknown_domains
        """
    )
    rows = src_cur.fetchall()
    adapted_rows = [
        (
            r[0],
            r[1],
            r[2],
            r[3],
            r[4],
            psycopg2.extras.Json(r[5]) if r[5] is not None else None,
            r[6],
            r[7],
            r[8],
        )
        for r in rows
    ]

    dst_conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DAILY_REVIEW_DB,
        user=DB_USER,
        password=DB_PASSWORD,
    )
    dst_conn.autocommit = True
    dst_cur = dst_conn.cursor()

    insert_sql = """
        INSERT INTO unknown_domains
            (domain, first_seen, last_seen, source, status, metadata, created_at, updated_at, schema_version)
        VALUES
            (%s, %s, %s, %s::domain_source, %s::domain_status, %s, %s, %s, %s)
        ON CONFLICT (domain) DO UPDATE SET
            last_seen = EXCLUDED.last_seen,
            source = EXCLUDED.source,
            status = EXCLUDED.status,
            metadata = EXCLUDED.metadata,
            updated_at = NOW(),
            schema_version = EXCLUDED.schema_version;
    """

    if adapted_rows:
        psycopg2.extras.execute_batch(dst_cur, insert_sql, adapted_rows)

    dst_cur.execute("SELECT COUNT(*) FROM unknown_domains")
    new_count = dst_cur.fetchone()[0]

    dst_cur.execute("SELECT domain, source, status, first_seen, last_seen FROM unknown_domains LIMIT 3")
    sample_records = dst_cur.fetchall()

    dst_cur.close()
    dst_conn.close()
    src_cur.close()
    src_conn.close()

    logger.info("Finished unknown_domains move (New count: %d)", new_count)
    return {
        "database": DAILY_REVIEW_DB,
        "table": "unknown_domains",
        "old_count": old_count,
        "new_count": new_count,
        "difference": new_count - old_count,
        "sample": sample_records,
    }


def main() -> int:
    try:
        start_time = time.perf_counter()
        results = [
            migrate_trusted_domains(),
            migrate_malicious_domains(),
            migrate_reputation_domains(),
            migrate_daily_review_domains(),
        ]

        total_elapsed = time.perf_counter() - start_time
        print("\n" + "=" * 80)
        print(f"{'DATABASE MIGRATION AUDIT REPORT':^80}")
        print("=" * 80)
        print(f"{'Database':<18} | {'Table':<20} | {'Old Count':<10} | {'New Count':<10} | {'Diff':<6}")
        print("-" * 80)
        for r in results:
            print(f"{r['database']:<18} | {r['table']:<20} | {r['old_count']:<10} | {r['new_count']:<10} | {r['difference']:<6}")
        print("=" * 80)
        print(f"Total Migration Time: {total_elapsed:.2f} seconds\n")

        print("Sample Migrated Records:")
        for r in results:
            print(f"\n--- {r['database']}.{r['table']} Sample ---")
            for item in r['sample']:
                print(" ", item)

        return 0
    except Exception as exc:
        logger.exception("Migration failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
