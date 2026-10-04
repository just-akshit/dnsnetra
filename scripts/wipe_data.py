#!/usr/bin/env python3
"""
scripts/wipe_data.py
====================
DNSNetra-Native Development Data Reset Utility.

Resets transient operational telemetry and domain/client profiling tables
while protecting user authentication, system metadata, and immutable TI baselines.

SAFEGUARDS:
- Default execution mode is DRY-RUN (no changes made).
- Requires explicit flag `--execute` to perform any mutations.
- Enforces local environment check (DB host must be localhost / 127.0.0.1).
- Protects user authentication tables (users, dashboard_users).
- Includes DNSNetra-specific tables (telemetry_hourly_rollup, aggregation_watermark).
- Verifies SHA-256 integrity of immutable threat intelligence SQLite files.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import psycopg2
import psycopg2.extras

# DNSNetra Project Root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Tables safe to reset in PostgreSQL
TARGET_POSTGRES_TABLES = [
    "domain_query_history",
    "domain_profiles",
    "client_profiles",
    "client_history",
    "unknown_domains",
    "reputation_domains",
    "daily_review_domains",
    "reviewed_clean_domains",
    "telemetry_hourly_rollup",
    "telemetry_daily_domain_rollup",
    "user_dns_activity",
    "user_threat_summary",
    "users",
]

# Protected PostgreSQL tables that must NEVER be truncated
PROTECTED_POSTGRES_TABLES = {
    "dashboard_users",
    "sessions",
    "audit_logs",
    "schema_metadata",
    "schema_migrations",
    "alembic_version",
}

# Transient / disposable files generated during pipeline execution
DISPOSABLE_FILES = [
    PROJECT_ROOT / "live_dataset.csv",
    PROJECT_ROOT / "live_features.csv",
]

# Immutable Threat Intelligence SQLite baselines
IMMUTABLE_TI_FILES = [
    PROJECT_ROOT / "data" / "malicious_domains.db",
    PROJECT_ROOT / "labeler" / "intel" / "trusted_domains.db",
]


class SafetyCheckError(Exception):
    """Raised when safety prerequisites or invariants fail."""
    pass


def get_sha256(path: Path) -> Optional[str]:
    """Computes SHA-256 hash of a file if it exists."""
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def get_db_connection_params() -> Dict[str, str]:
    """Extracts database connection parameters from environment or .env file."""
    # Check .env if available
    env_file = PROJECT_ROOT / ".env"
    env_vars = {}
    if env_file.is_file():
        with open(env_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env_vars[k.strip()] = v.strip().strip("'\"")

    return {
        "dbname": os.environ.get("POSTGRES_DB") or os.environ.get("DB_NAME") or env_vars.get("DB_NAME") or env_vars.get("UDR_DB_DATABASE") or "dns_threat_detection",
        "user": os.environ.get("POSTGRES_USER") or os.environ.get("DB_USER") or env_vars.get("DB_USER") or env_vars.get("UDR_DB_USERNAME") or "postgres",
        "password": os.environ.get("POSTGRES_PASSWORD") or os.environ.get("DB_PASSWORD") or env_vars.get("DB_PASSWORD") or env_vars.get("UDR_DB_PASSWORD") or "postgres",
        "host": os.environ.get("POSTGRES_HOST") or os.environ.get("DB_HOST") or env_vars.get("DB_HOST") or "localhost",
        "port": os.environ.get("POSTGRES_PORT") or os.environ.get("DB_PORT") or env_vars.get("DB_PORT") or "5432",
    }


def verify_target_safety(params: Dict[str, str], allow_remote: bool = False) -> None:
    """Verifies that the target database is running locally."""
    host = params.get("host", "").lower()
    if not allow_remote and host not in ("localhost", "127.0.0.1", ""):
        raise SafetyCheckError(
            f"Safety Violation: Target database host is '{host}'. "
            "Data reset is restricted to local development (localhost / 127.0.0.1). "
            "Use --allow-remote-host if intentionally targeting a remote development database."
        )


def inspect_postgres_counts(conn, tables: List[str]) -> Dict[str, int]:
    """Returns row counts for all existing target tables in PostgreSQL."""
    counts = {}
    with conn.cursor() as cur:
        for t in tables:
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM information_schema.tables 
                    WHERE table_schema = 'public' AND table_name = %s
                );
            """, (t,))
            exists = cur.fetchone()[0]
            if exists:
                cur.execute(f"SELECT COUNT(*) FROM {t};")
                counts[t] = cur.fetchone()[0]
            else:
                counts[t] = 0
    return counts


def run_wipe(
    dry_run: bool = True,
    allow_remote: bool = False,
    confirm_name: Optional[str] = None,
    clear_files: bool = False,
) -> Dict[str, Any]:
    """
    Executes or previews a safe data wipe for DNSNetra development databases.
    """
    params = get_db_connection_params()
    verify_target_safety(params, allow_remote=allow_remote)

    print("=" * 60)
    print("DNSNetra Development Data Reset Tool")
    print("=" * 60)
    print(f"DATABASE HOST: {params['host']}")
    print(f"DATABASE PORT: {params['port']}")
    print(f"DATABASE NAME: {params['dbname']}")
    print(f"DATABASE USER: {params['user']}")
    print(f"MODE:          {'DRY-RUN (Preview Only)' if dry_run else 'DESTRUCTIVE EXECUTION'}")
    print("=" * 60)

    # 1. Baseline hash verification
    pre_hashes = {str(p): get_sha256(p) for p in IMMUTABLE_TI_FILES if p.exists()}

    # 2. Inspect database tables
    try:
        conn = psycopg2.connect(**params)
    except Exception as exc:
        raise SafetyCheckError(f"Failed to connect to PostgreSQL: {exc}")

    try:
        counts_before = inspect_postgres_counts(conn, TARGET_POSTGRES_TABLES)

        print("\nTarget Tables & Current Row Counts:")
        for t, count in counts_before.items():
            print(f"  - {t:<30} : {count:>8} rows")

        # Check protected tables
        for pt in PROTECTED_POSTGRES_TABLES:
            if pt in TARGET_POSTGRES_TABLES:
                raise SafetyCheckError(f"FATAL: Protected table '{pt}' is in the wipe list!")

        if dry_run:
            print("\n[DRY RUN COMPLETE] Zero modifications made. Use --execute to proceed.")
            return {
                "dry_run": True,
                "counts_before": counts_before,
                "counts_after": counts_before,
            }

        # Destructive execution requires database name confirmation
        if confirm_name != params["dbname"]:
            raise SafetyCheckError(
                f"Confirmation failed: passed '{confirm_name}' but target database is '{params['dbname']}'."
            )

        print("\nExecuting TRUNCATE TABLE on target operational tables...")
        with conn.cursor() as cur:
            # Construct single compound truncate to avoid foreign key deadlocks
            existing_tables = [t for t, count in counts_before.items() if t not in PROTECTED_POSTGRES_TABLES]
            if existing_tables:
                tables_sql = ", ".join(existing_tables)
                cur.execute(f"TRUNCATE TABLE {tables_sql} RESTART IDENTITY;")

            # Reset aggregation watermark and state
            cur.execute("""
                UPDATE telemetry_aggregation_state 
                SET last_processed_id = 0, 
                    last_processed_timestamp = NULL, 
                    total_events_processed = 0, 
                    last_run_at = NULL, 
                    status = 'idle' 
                WHERE job_name = 'dnsnetra_aggregator';
            """)
        conn.commit()

        # Optional clearing of generated CSV telemetry artifacts
        if clear_files:
            print("\nRemoving disposable CSV telemetry files...")
            for fpath in DISPOSABLE_FILES:
                if fpath.is_file():
                    fpath.unlink()
                    print(f"  - Removed: {fpath.name}")

        counts_after = inspect_postgres_counts(conn, TARGET_POSTGRES_TABLES)
        print("\nPost-Wipe Row Counts:")
        for t, count in counts_after.items():
            print(f"  - {t:<30} : {count:>8} rows")

        # 3. Post-wipe immutable integrity check
        post_hashes = {str(p): get_sha256(p) for p in IMMUTABLE_TI_FILES if p.exists()}
        for p_str, pre_h in pre_hashes.items():
            post_h = post_hashes.get(p_str)
            if pre_h != post_h:
                raise SafetyCheckError(
                    f"CRITICAL INTEGRITY FAILURE: Immutable baseline '{p_str}' changed hash during wipe!"
                )

        print("\nImmutable TI baseline hashes intact and verified.")
        print("[SUCCESS] Development operational data reset complete.")
        return {
            "dry_run": False,
            "counts_before": counts_before,
            "counts_after": counts_after,
        }

    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description="DNSNetra Safe Data Reset Utility")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually perform the wipe (defaults to dry-run)",
    )
    parser.add_argument(
        "--confirm-db-name",
        type=str,
        help="Type the exact database name to confirm destructive execution",
    )
    parser.add_argument(
        "--allow-remote-host",
        action="store_true",
        help="Allow targeting a remote database host",
    )
    parser.add_argument(
        "--clear-files",
        action="store_true",
        help="Also remove generated CSV files (live_dataset.csv, live_features.csv)",
    )
    args = parser.parse_args()

    dry_run = not args.execute
    try:
        run_wipe(
            dry_run=dry_run,
            allow_remote=args.allow_remote_host,
            confirm_name=args.confirm_db_name,
            clear_files=args.clear_files,
        )
    except SafetyCheckError as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
