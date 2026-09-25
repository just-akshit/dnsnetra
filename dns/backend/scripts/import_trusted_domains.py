#!/usr/bin/env python3
"""
Trusted Domains Database Importer
=================================
Imports domains from top-1m.csv (Tranco top sites list) into SQLite trusted_domains.db.

Usage:
    python scripts/import_trusted_domains.py
    python scripts/import_trusted_domains.py --csv data/top-1m.csv
    python scripts/import_trusted_domains.py --csv data/top-1m.csv --target-all
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import logging
import os
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Tuple

# Project root setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from labeler.intel import config
from labeler.intel.database import (
    create_trusted_domains_database,
    normalize_domain,
    validate_database,
    is_domain_trusted,
    read_metadata,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("import_trusted_domains")


def parse_csv_stream(csv_path: Path) -> Tuple[Iterator[Tuple[int, str]], str]:
    """
    Stream (rank, domain) tuples from CSV file and compute SHA256 version hash.
    """
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    # First calculate file hash
    hasher = hashlib.sha256()
    with open(csv_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    dataset_version = hasher.hexdigest()

    def generator() -> Iterator[Tuple[int, str]]:
        with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row:
                    continue
                if len(row) == 1:
                    # Domain only (assume sequential rank)
                    domain = row[0].strip()
                    yield 1, domain
                elif len(row) >= 2:
                    rank_str = row[0].strip()
                    domain = row[1].strip()
                    try:
                        rank = int(rank_str)
                    except ValueError:
                        continue
                    yield rank, domain

    return generator(), dataset_version


def import_csv_to_db(csv_path: Path, db_path: Path) -> int:
    """
    Import all valid domains from CSV into the target SQLite database.
    """
    logger.info("Starting import from: %s", csv_path)
    logger.info("Target database:      %s", db_path)

    start_time = time.perf_counter()
    rows_stream, dataset_version = parse_csv_stream(csv_path)
    downloaded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    temp_db_path = db_path.parent / f"{db_path.name}.importing"

    inserted_count = create_trusted_domains_database(
        database_path=temp_db_path,
        domain_rows=rows_stream,
        dataset_version=dataset_version,
        downloaded_at=downloaded_at,
    )

    # Atomic move
    if db_path.exists():
        backup_path = db_path.parent / f"{db_path.name}.bak"
        try:
            shutil.copy2(db_path, backup_path)
        except Exception:
            pass

    os.replace(str(temp_db_path), str(db_path))

    # Clean any stray temp/wal files
    for suffix in ("-wal", "-shm", ".importing"):
        stray = Path(str(db_path) + suffix)
        if stray.exists():
            try:
                stray.unlink()
            except Exception:
                pass

    elapsed = time.perf_counter() - start_time
    logger.info(
        "Import completed: %d domains inserted in %.2f seconds (%.0f domains/sec)",
        inserted_count,
        elapsed,
        inserted_count / elapsed if elapsed > 0 else 0,
    )

    # Verification
    validate_database(db_path, expected_count=inserted_count, require_integrity=True)
    metadata = read_metadata(db_path)
    logger.info("Metadata verified: %s", metadata)

    return inserted_count


def verify_sample_domains(db_path: Path) -> bool:
    """Test standard lookups against the newly built database."""
    test_domains = [
        ("google.com", True),
        ("cloudflare.com", True),
        ("microsoft.com", True),
        ("apple.com", True),
        ("github.com", True),
        ("definitely-nonexistent-malicious-domain-123456789.xyz", False),
    ]

    all_passed = True
    print("\n--- Verification Lookups ---")
    for dom, expected in test_domains:
        result = is_domain_trusted(db_path, dom)
        status = "PASS" if result == expected else "FAIL"
        if result != expected:
            all_passed = False
        print(f"  [{status}] {dom:<55s} -> {result} (expected {expected})")
    print("----------------------------\n")
    return all_passed


def main() -> int:
    parser = argparse.ArgumentParser(description="Import top-1m.csv into trusted_domains.db")
    parser.add_argument(
        "--csv",
        type=Path,
        default=PROJECT_ROOT / "data" / "top-1m.csv",
        help="Path to top-1m.csv",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=PROJECT_ROOT / "labeler" / "intel" / "trusted_domains.db",
        help="Primary target database path",
    )
    parser.add_argument(
        "--target-all",
        action="store_true",
        default=True,
        help="Also copy to backend/data/trusted_domains.db for full sync",
    )

    args = parser.parse_args()

    if not args.csv.exists():
        logger.error("CSV file not found at: %s", args.csv)
        return 1

    try:
        inserted = import_csv_to_db(args.csv, args.db)
        verify_sample_domains(args.db)

        if args.target_all:
            alt_db = PROJECT_ROOT / "data" / "trusted_domains.db"
            logger.info("Syncing copy to: %s", alt_db)
            alt_db.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(args.db, alt_db)
            logger.info("Synced successfully.")

        print(f"SUCCESS: {inserted:,} domains imported into trusted_domains.db")
        return 0
    except Exception as exc:
        logger.exception("Import failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
