#!/usr/bin/env python3
"""
import_malicious_domains.py
===========================
Incremental importer for malicious domains from SQLite into PostgreSQL.

Reads malicious domains from an existing SQLite database, normalizes domain
names according to canonical project standards, deduplicates indicators,
and merges them into the active PostgreSQL malicious_domains table without
overwriting or dropping existing records.

Usage:
    python backend/scripts/import_malicious_domains.py --dry-run
    python backend/scripts/import_malicious_domains.py
    python backend/scripts/import_malicious_domains.py --source sqlite_import
"""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

# Project root setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = PROJECT_ROOT.parent
load_dotenv(PROJECT_ROOT / ".env")

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from labeler.intel.malicious.downloader import normalize_domain

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("import_malicious_domains")

# Database connection settings
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
MALICIOUS_DB = os.getenv("MALICIOUS_DB_DATABASE", "malicious_db")

DEFAULT_SQLITE_CANDIDATES = [
    WORKSPACE_ROOT / "dns (1)" / "dns" / "backend" / "data" / "malicious_domains.db",
    WORKSPACE_ROOT / "DNS1" / "backend" / "data" / "malicious_domains.db",
    WORKSPACE_ROOT / "dns (1)" / "backend" / "data" / "malicious_domains.db",
    PROJECT_ROOT / "data" / "malicious_domains.db",
]


def resolve_sqlite_path(custom_path: Optional[str] = None) -> Path:
    """Finds the existing SQLite database path."""
    if custom_path:
        p = Path(custom_path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Specified SQLite file does not exist: {p}")
        return p

    for candidate in DEFAULT_SQLITE_CANDIDATES:
        if candidate.exists() and candidate.stat().st_size > 1000:
            return candidate

    raise FileNotFoundError(
        f"Could not locate SQLite malicious_domains.db in expected paths: "
        f"{[str(p) for p in DEFAULT_SQLITE_CANDIDATES]}"
    )


def validate_sqlite_database(sqlite_path: Path) -> Tuple[int, List[str]]:
    """Validates the SQLite schema and returns total row count and available columns."""
    conn = sqlite3.connect(sqlite_path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='malicious_domains';")
        if not cur.fetchone():
            raise ValueError(f"Table 'malicious_domains' not found in SQLite database {sqlite_path}")

        cur.execute("PRAGMA table_info(malicious_domains);")
        columns = [row[1] for row in cur.fetchall()]
        if "domain" not in columns:
            raise ValueError("Required column 'domain' missing from SQLite table 'malicious_domains'")

        cur.execute("SELECT COUNT(*) FROM malicious_domains;")
        row_count = cur.fetchone()[0]
        return row_count, columns
    finally:
        conn.close()


def canonicalize_domain(raw_domain: str) -> Optional[str]:
    """
    Applies the project's canonical domain normalization:
    - strips surrounding whitespace and quotes
    - lowercases
    - strips protocol (http://, https://), URL path, query params, fragments, ports
    - strips leading www.
    - strips trailing dot (.)
    - validates length (3 <= len <= 253)
    """
    if not raw_domain:
        return None
    normalized = normalize_domain(raw_domain)
    if not normalized:
        return None
    normalized = normalized.rstrip(".")
    if not normalized or len(normalized) < 3 or len(normalized) > 253:
        return None
    return normalized


def stream_sqlite_domains(
    sqlite_path: Path,
    batch_size: int = 10000,
    source_override: Optional[str] = None,
) -> Iterator[List[Tuple[str, str, Optional[str]]]]:
    """
    Streams and normalizes records from SQLite in batches.
    Yields list of tuples: (normalized_domain, source, downloaded_at).
    """
    conn = sqlite3.connect(sqlite_path)
    cur = conn.cursor()
    try:
        cur.execute("SELECT domain, source, downloaded_at FROM malicious_domains;")
        while True:
            rows = cur.fetchmany(batch_size)
            if not rows:
                break
            batch: List[Tuple[str, str, Optional[str]]] = []
            for d, src, dl_at in rows:
                norm = canonicalize_domain(d)
                if not norm:
                    continue
                # Determine source value (max 50 chars for PostgreSQL schema)
                final_source = (source_override or src or "sqlite_import")[:50]
                batch.append((norm, final_source, dl_at))
            yield batch
    finally:
        conn.close()


def run_import(
    sqlite_path: Path,
    dry_run: bool = False,
    batch_size: int = 10000,
    source_name: str = "sqlite_import",
    preserve_source: bool = False,
) -> Dict[str, int]:
    """
    Performs the incremental import using a transactional PostgreSQL staging table.
    """
    start_time = time.perf_counter()
    logger.info("=" * 65)
    logger.info("Starting Malicious Domain Importer")
    logger.info("  SQLite source:     %s", sqlite_path)
    logger.info("  Target database:   %s:%d/%s", DB_HOST, DB_PORT, MALICIOUS_DB)
    logger.info("  Mode:              %s", "DRY-RUN (no modifications)" if dry_run else "LIVE IMPORT")
    logger.info("  Source tag:        %s", "Preserve SQLite feed name" if preserve_source else source_name)
    logger.info("=" * 65)

    sqlite_row_count, _ = validate_sqlite_database(sqlite_path)
    logger.info("SQLite database verified. Total source records: %d", sqlite_row_count)

    pg_conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=MALICIOUS_DB,
        user=DB_USER,
        password=DB_PASSWORD,
    )
    pg_conn.autocommit = False
    pg_cur = pg_conn.cursor()

    try:
        # Get baseline PostgreSQL count
        pg_cur.execute("SELECT COUNT(*) FROM malicious_domains;")
        initial_pg_count = pg_cur.fetchone()[0]
        logger.info("Current PostgreSQL malicious_domains total: %d", initial_pg_count)

        # Create temporary staging table
        logger.info("Creating temporary PostgreSQL staging table...")
        pg_cur.execute("""
            CREATE TEMP TABLE staging_malicious_import (
                domain VARCHAR(253) PRIMARY KEY,
                source VARCHAR(50) NOT NULL,
                downloaded_at TIMESTAMPTZ
            ) ON COMMIT DROP;
        """)

        # Stream from SQLite into staging table with deduplication
        source_override = None if preserve_source else source_name
        total_streamed = 0
        total_unique_valid = 0
        invalid_or_skipped = 0

        logger.info("Streaming and normalizing records into staging table...")
        for batch in stream_sqlite_domains(sqlite_path, batch_size, source_override):
            total_streamed += len(batch)
            if not batch:
                continue

            insert_staging_sql = """
                INSERT INTO staging_malicious_import (domain, source, downloaded_at)
                VALUES %s
                ON CONFLICT (domain) DO NOTHING;
            """
            psycopg2.extras.execute_values(
                pg_cur,
                insert_staging_sql,
                batch,
                page_size=2000,
            )

        pg_cur.execute("SELECT COUNT(*) FROM staging_malicious_import;")
        total_unique_valid = pg_cur.fetchone()[0]
        invalid_or_skipped = sqlite_row_count - total_unique_valid

        # Check overlap with existing PostgreSQL malicious_domains
        pg_cur.execute("""
            SELECT COUNT(*)
            FROM staging_malicious_import s
            JOIN malicious_domains m ON s.domain = m.domain;
        """)
        already_in_pg = pg_cur.fetchone()[0]

        would_insert_count = total_unique_valid - already_in_pg
        logger.info("Staging complete:")
        logger.info("  Unique valid in SQLite:   %d", total_unique_valid)
        logger.info("  Already in PostgreSQL:    %d", already_in_pg)
        logger.info("  New candidates to insert: %d", would_insert_count)

        newly_inserted = 0
        final_pg_count = initial_pg_count

        if dry_run:
            logger.info("DRY-RUN mode enabled: Rolling back staging table without modifying PostgreSQL.")
            pg_conn.rollback()
            final_pg_count = initial_pg_count
        else:
            logger.info("Performing set-based merge insert into malicious_domains...")
            merge_sql = """
                INSERT INTO malicious_domains (domain, source, downloaded_at, created_at, updated_at)
                SELECT
                    s.domain,
                    s.source,
                    COALESCE(s.downloaded_at, NOW()),
                    NOW(),
                    NOW()
                FROM staging_malicious_import s
                ON CONFLICT (domain) DO NOTHING;
            """
            pg_cur.execute(merge_sql)
            newly_inserted = pg_cur.rowcount
            pg_cur.execute("SELECT COUNT(*) FROM malicious_domains;")
            final_pg_count = pg_cur.fetchone()[0]

            # Keep metadata synchronized with current record count and timestamp
            pg_cur.execute("""
                INSERT INTO metadata (key, value, updated_at)
                VALUES
                    ('last_update', TO_CHAR(NOW(), 'YYYY-MM-DD HH24:MI:SS'), NOW()),
                    ('record_count', %s, NOW())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
            """, (str(final_pg_count),))
            pg_conn.commit()

            logger.info("Merge transaction committed successfully. Newly inserted: %d", newly_inserted)

        elapsed = time.perf_counter() - start_time
        logger.info("Import operation completed in %.2f seconds.", elapsed)

        stats = {
            "sqlite_records": sqlite_row_count,
            "unique_valid_domains": total_unique_valid,
            "already_in_postgres": already_in_pg,
            "newly_inserted": newly_inserted if not dry_run else would_insert_count,
            "invalid_or_skipped": invalid_or_skipped,
            "final_pg_total": final_pg_count,
        }

        # Print clean standardized summary report
        print("\n" + "=" * 50)
        print(f"{'Malicious Domain Import Summary':^50}")
        print("=" * 50)
        print(f"SQLite records:             {stats['sqlite_records']:>12,}")
        print(f"Unique valid domains:       {stats['unique_valid_domains']:>12,}")
        print(f"Already in PostgreSQL:      {stats['already_in_postgres']:>12,}")
        if dry_run:
            print(f"Would insert:               {stats['newly_inserted']:>12,}")
        else:
            print(f"Newly inserted:             {stats['newly_inserted']:>12,}")
        print(f"Invalid/skipped:            {stats['invalid_or_skipped']:>12,}")
        print(f"Final PostgreSQL total:     {stats['final_pg_total']:>12,}")
        print("=" * 50 + "\n")

        return stats

    except Exception as exc:
        pg_conn.rollback()
        logger.exception("Import operation failed and was rolled back: %s", exc)
        raise
    finally:
        pg_cur.close()
        pg_conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Incremental importer for malicious domains from SQLite into PostgreSQL."
    )
    parser.add_argument(
        "--sqlite-path",
        type=str,
        default=None,
        help="Path to the SQLite database file. Auto-detected if omitted.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a preflight simulation without modifying the PostgreSQL database.",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=10000,
        help="Number of records to stream per batch (default: 10000).",
    )
    parser.add_argument(
        "--source",
        type=str,
        default="sqlite_import",
        help="Source provenance tag to assign to imported domains (default: 'sqlite_import').",
    )
    parser.add_argument(
        "--preserve-source",
        action="store_true",
        help="Preserve the granular source feed name stored in SQLite instead of overriding with --source.",
    )

    args = parser.parse_args()

    try:
        sqlite_file = resolve_sqlite_path(args.sqlite_path)
        run_import(
            sqlite_path=sqlite_file,
            dry_run=args.dry_run,
            batch_size=args.batch_size,
            source_name=args.source,
            preserve_source=args.preserve_source,
        )
        return 0
    except Exception as exc:
        logger.error("Import failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
