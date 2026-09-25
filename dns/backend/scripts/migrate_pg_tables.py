#!/usr/bin/env python3
"""
migrate_pg_tables.py
====================
Phase 4 Migration Script:
Moves existing PostgreSQL threat intelligence data:
  - dns_threat_detection.reputation_domains -> reputation_db.reputation_domains
  - dns_threat_detection.unknown_domains -> daily_review_db.unknown_domains
"""

from __future__ import annotations

import os
import sys
import logging
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
logger = logging.getLogger("migrate_pg_tables")

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

PRIMARY_DB = os.getenv("DB_NAME", "dns_threat_detection")
REPUTATION_DB = os.getenv("REPUTATION_DB_DATABASE", "reputation_db")
DAILY_REVIEW_DB = os.getenv("DAILY_REVIEW_DB_DATABASE", "daily_review_db")


def migrate_reputation_table() -> dict[str, Any]:
    logger.info("=" * 60)
    logger.info("Moving %s.reputation_domains -> %s.reputation_domains", PRIMARY_DB, REPUTATION_DB)
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
    src_count = src_cur.fetchone()[0]
    logger.info("Source reputation_domains row count: %d", src_count)

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
    dst_count = dst_cur.fetchone()[0]

    dst_cur.execute("SELECT domain, status, source, confidence, match_scope FROM reputation_domains LIMIT 3")
    sample_records = dst_cur.fetchall()

    dst_cur.close()
    dst_conn.close()
    src_cur.close()
    src_conn.close()

    logger.info("Reputation move complete (Source: %d, Destination: %d)", src_count, dst_count)
    return {
        "database": REPUTATION_DB,
        "table": "reputation_domains",
        "src_count": src_count,
        "dst_count": dst_count,
        "mismatch": dst_count - src_count,
        "sample": sample_records,
    }


def migrate_daily_review_table() -> dict[str, Any]:
    logger.info("=" * 60)
    logger.info("Moving %s.unknown_domains -> %s.unknown_domains", PRIMARY_DB, DAILY_REVIEW_DB)
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
    src_count = src_cur.fetchone()[0]
    logger.info("Source unknown_domains row count: %d", src_count)

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
    dst_count = dst_cur.fetchone()[0]

    dst_cur.execute("SELECT domain, source, status, first_seen, last_seen FROM unknown_domains LIMIT 3")
    sample_records = dst_cur.fetchall()

    dst_cur.close()
    dst_conn.close()
    src_cur.close()
    src_conn.close()

    logger.info("Unknown domains move complete (Source: %d, Destination: %d)", src_count, dst_count)
    return {
        "database": DAILY_REVIEW_DB,
        "table": "unknown_domains",
        "src_count": src_count,
        "dst_count": dst_count,
        "mismatch": dst_count - src_count,
        "sample": sample_records,
    }


def main() -> int:
    try:
        rep_res = migrate_reputation_table()
        udr_res = migrate_daily_review_table()

        print("\n" + "=" * 80)
        print(f"{'POSTGRESQL -> POSTGRESQL MIGRATION SUMMARY':^80}")
        print("=" * 80)
        print(f"{'Target Database':<18} | {'Table':<20} | {'Source Rows':<12} | {'Postgres Rows':<14} | {'Diff':<6}")
        print("-" * 80)
        for r in [rep_res, udr_res]:
            print(f"{r['database']:<18} | {r['table']:<20} | {r['src_count']:<12} | {r['dst_count']:<14} | {r['mismatch']:<6}")
        print("=" * 80)

        print("\nSample Records:")
        for r in [rep_res, udr_res]:
            print(f"\n--- {r['database']}.{r['table']} ---")
            for item in r['sample']:
                print(" ", item)
        return 0
    except Exception as exc:
        logger.exception("PostgreSQL table migration failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
