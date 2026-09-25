#!/usr/bin/env python3
"""
migrate_sqlite_to_postgres.py
=============================
Phase 3 Migration Script:
Migrates data from existing SQLite databases into dedicated PostgreSQL databases:
  - trusted_domains.db -> trusted_db (trusted_domains & metadata)
  - malicious_domains.db -> malicious_db (malicious_domains & metadata)
"""

from __future__ import annotations

import os
import sys
import time
import logging
import sqlite3
from pathlib import Path
from typing import Any

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
logger = logging.getLogger("migrate_sqlite_to_postgres")

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

TRUSTED_DB = os.getenv("TRUSTED_DB_DATABASE", "trusted_db")
MALICIOUS_DB = os.getenv("MALICIOUS_DB_DATABASE", "malicious_db")

TRUSTED_SQLITE_PATH = PROJECT_ROOT / "data" / "trusted_domains.db"
if not TRUSTED_SQLITE_PATH.exists():
    TRUSTED_SQLITE_PATH = PROJECT_ROOT / "labeler" / "intel" / "trusted_domains.db"

MALICIOUS_SQLITE_PATH = PROJECT_ROOT / "data" / "malicious_domains.db"
if not MALICIOUS_SQLITE_PATH.exists():
    MALICIOUS_SQLITE_PATH = PROJECT_ROOT / "labeler" / "intel" / "malicious" / "malicious_domains.db"


def migrate_trusted_sqlite() -> dict[str, Any]:
    logger.info("=" * 60)
    logger.info("Migrating Trusted SQLite -> PostgreSQL: %s", TRUSTED_DB)
    logger.info("Source file: %s", TRUSTED_SQLITE_PATH)
    logger.info("=" * 60)

    if not TRUSTED_SQLITE_PATH.exists():
        raise FileNotFoundError(f"Trusted SQLite database not found at {TRUSTED_SQLITE_PATH}")

    sqlite_conn = sqlite3.connect(TRUSTED_SQLITE_PATH)
    sqlite_cur = sqlite_conn.cursor()

    sqlite_cur.execute("SELECT COUNT(*) FROM trusted_domains")
    src_count = sqlite_cur.fetchone()[0]
    logger.info("Trusted source rows (SQLite): %d", src_count)

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

    # Batch stream trusted_domains
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
        logger.info("Migrated %d / %d trusted domains...", total_migrated, src_count)

    pg_conn.commit()
    elapsed = time.perf_counter() - start_t

    pg_cur.execute("SELECT COUNT(*) FROM trusted_domains")
    dst_count = pg_cur.fetchone()[0]

    pg_cur.execute("SELECT domain, rank, source, downloaded_at FROM trusted_domains LIMIT 3")
    sample_records = pg_cur.fetchall()

    pg_cur.close()
    pg_conn.close()
    sqlite_conn.close()

    logger.info("Trusted migration complete in %.2fs (PostgreSQL count: %d)", elapsed, dst_count)
    return {
        "database": TRUSTED_DB,
        "table": "trusted_domains",
        "src_count": src_count,
        "dst_count": dst_count,
        "mismatch": dst_count - src_count,
        "sample": sample_records,
    }


def migrate_malicious_sqlite() -> dict[str, Any]:
    logger.info("=" * 60)
    logger.info("Migrating Malicious SQLite -> PostgreSQL: %s", MALICIOUS_DB)
    logger.info("Source file: %s", MALICIOUS_SQLITE_PATH)
    logger.info("=" * 60)

    if not MALICIOUS_SQLITE_PATH.exists():
        raise FileNotFoundError(f"Malicious SQLite database not found at {MALICIOUS_SQLITE_PATH}")

    sqlite_conn = sqlite3.connect(MALICIOUS_SQLITE_PATH)
    sqlite_cur = sqlite_conn.cursor()

    sqlite_cur.execute("SELECT COUNT(*) FROM malicious_domains")
    src_count = sqlite_cur.fetchone()[0]
    logger.info("Malicious source rows (SQLite): %d", src_count)

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

    # Batch stream malicious_domains
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
    dst_count = pg_cur.fetchone()[0]

    pg_cur.execute("SELECT domain, source, downloaded_at FROM malicious_domains LIMIT 3")
    sample_records = pg_cur.fetchall()

    pg_cur.close()
    pg_conn.close()
    sqlite_conn.close()

    logger.info("Malicious migration complete in %.2fs (PostgreSQL count: %d)", elapsed, dst_count)
    return {
        "database": MALICIOUS_DB,
        "table": "malicious_domains",
        "src_count": src_count,
        "dst_count": dst_count,
        "mismatch": dst_count - src_count,
        "sample": sample_records,
    }


def main() -> int:
    try:
        trusted_res = migrate_trusted_sqlite()
        malicious_res = migrate_malicious_sqlite()

        print("\n" + "=" * 80)
        print(f"{'SQLITE -> POSTGRESQL MIGRATION SUMMARY':^80}")
        print("=" * 80)
        print(f"{'Target Database':<18} | {'Table':<20} | {'Source Rows':<12} | {'Postgres Rows':<14} | {'Diff':<6}")
        print("-" * 80)
        for r in [trusted_res, malicious_res]:
            print(f"{r['database']:<18} | {r['table']:<20} | {r['src_count']:<12} | {r['dst_count']:<14} | {r['mismatch']:<6}")
        print("=" * 80)

        print("\nSample Records:")
        for r in [trusted_res, malicious_res]:
            print(f"\n--- {r['database']}.{r['table']} ---")
            for item in r['sample']:
                print(" ", item)
        return 0
    except Exception as exc:
        logger.exception("SQLite migration failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
