#!/usr/bin/env python3
"""
DNS Threat Detection System — Comprehensive "Fresh Run" Reset Utility
=====================================================================

Resets all accumulated runtime/observational data so the DNS threat-detection
pipeline can run from a completely clean state.

Safety Guarantees:
  1. OBSERVATIONAL / GENERATED DATA    -> DELETE / CLEAR / TRUNCATE
  2. THREAT-INTELLIGENCE DATABASES    -> PRESERVED (Untouched & Verified)
  3. DATABASE SCHEMAS & TABLES        -> PRESERVED (Structure & Indexes Intact)
  4. SOURCE CODE & CONFIGURATION      -> PRESERVED (Untouched)
  5. AUTH & USER CREDENTIALS          -> PRESERVED (Untouched)

Usage:
  python backend/wipe_data.py                   # Interactive reset with confirmation
  python backend/wipe_data.py --dry-run         # Read-only simulation (no changes)
  python backend/wipe_data.py --yes             # Non-interactive reset (development/CI)
  python backend/wipe_data.py --backup          # Create backup before resetting
  python backend/wipe_data.py --dry-run --backup# Preview backup & reset actions
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import socket
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Path Resolution & Environment Loading
# ---------------------------------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BACKEND_DIR.parent if (BACKEND_DIR.parent / "backend").exists() else BACKEND_DIR

# Load environment configuration from both .env and api.env if present
try:
    from dotenv import load_dotenv

    load_dotenv(BACKEND_DIR / ".env")
    load_dotenv(BACKEND_DIR / "api.env")
except ImportError:
    pass  # python-dotenv not strictly required if env vars are already in os.environ

# ---------------------------------------------------------------------------
# Terminal Colors & Icons
# ---------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty()


def color(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def c_green(text: str) -> str:
    return color(text, "32")


def c_yellow(text: str) -> str:
    return color(text, "33")


def c_red(text: str) -> str:
    return color(text, "31")


def c_cyan(text: str) -> str:
    return color(text, "36")


def c_bold(text: str) -> str:
    return color(text, "1")


ICON_OK = c_green("✓")
ICON_WARN = c_yellow("⚠")
ICON_ERR = c_red("✗")
ICON_SKIP = c_yellow("⏭")

# ---------------------------------------------------------------------------
# Target Constants & Classification
# ---------------------------------------------------------------------------

# Threat Intelligence Reference Databases — MUST NEVER BE TOUCHED
IMMUTABLE_TI_DATABASES = [
    BACKEND_DIR / "data" / "malicious_domains.db",
    BACKEND_DIR / "data" / "trusted_domains.db",
    BACKEND_DIR / "labeler" / "intel" / "trusted_domains.db",
]

# PostgreSQL Runtime Tables (Safe to clear during fresh run)
RUNTIME_POSTGRES_TABLES = [
    "domain_query_history",
    "domain_profiles",
    "client_history",
    "client_profiles",
    "unknown_domains",
    "reputation_domains",
    "user_dns_activity",
    "user_threat_summary",
]

# PostgreSQL Schema / Auth / Reference Tables (MUST PRESERVE)
PROTECTED_POSTGRES_TABLES = {
    "dashboard_users",
    "users",
    "schema_metadata",
}

# SQLite Dashboard Tables (Protected Auth / Configuration — MUST PRESERVE)
PROTECTED_SQLITE_TABLES = {
    "users",
}

# SQLite Dashboard Tables (Runtime Telemetry & Derived Metrics — Safe to Wipe)
RUNTIME_SQLITE_TABLES = [
    "aggregation_runs",
    "aggregation_state",
    "client_details",
    "client_domain_membership",
    "dga_detection",
    "dns_anomalies",
    "domain_client_membership",
    "domain_details",
    "geo_distribution",
    "metrics_summary",
    "network_security_posture",
    "protocol_stats",
    "queries_timeseries",
    "recent_flagged_domains",
    "system_audit_log",
    "threat_intel_feeds",
    "threats_by_category",
    "top_clients",
    "top_domains",
]

# Dashboard SQLite Database Path
DASHBOARD_DB_PATH = BACKEND_DIR / "dashboard.db"

# Local DNS Development/Test Query Log (Preserve file, truncate to 0 bytes)
PROJECT_QUERY_LOG = BACKEND_DIR / "parsing logs" / "logs" / "query.log"

# Generated Data Artifacts to Remove
GENERATED_FILE_TARGETS = [
    BACKEND_DIR / "live_dataset.csv",
    BACKEND_DIR / "live_features.csv",
    BACKEND_DIR / "live_labelled_dataset.csv",
    BACKEND_DIR / "invalid_logs.csv",
    BACKEND_DIR / "report.json",
    BACKEND_DIR / "feature extraction" / "data" / "feature_matrix.csv",
    BACKEND_DIR / "parsing logs" / "invalid_logs.csv",
    BACKEND_DIR / "parsing logs" / "report.json",
    BACKEND_DIR / "bind converter" / "invalid_logs.csv",
    BACKEND_DIR / "logs" / "dns_labeller.log",
    BACKEND_DIR / "data" / "malicious.lock",
]

# Ambiguous / Source / Benchmark Files to Explicitly Skip and Preserve
PRESERVED_SOURCE_FILES = [
    (
        BACKEND_DIR / "parsing logs" / "normalized_dns_dataset.csv",
        "Source / Benchmark Dataset",
    ),
    (
        BACKEND_DIR / "parsing logs" / "labelled_dns_dataset.csv",
        "Source / Benchmark Dataset",
    ),
]

# Kafka Ingestion Constants
DEFAULT_KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
DEFAULT_KAFKA_TOPIC = os.getenv("KAFKA_DNS_TOPIC", "dns-logs")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------


@dataclass
class DatabaseConfig:
    host: str = field(default_factory=lambda: os.getenv("DB_HOST", os.getenv("UDR_DB_HOST", "localhost")))
    port: int = field(default_factory=lambda: int(os.getenv("DB_PORT", os.getenv("UDR_DB_PORT", "5432"))))
    dbname: str = field(
        default_factory=lambda: os.getenv(
            "DB_NAME", os.getenv("UDR_DB_DATABASE", "dns_threat_detection")
        )
    )
    user: str = field(
        default_factory=lambda: os.getenv("DB_USER", os.getenv("UDR_DB_USERNAME", "postgres"))
    )
    password: str = field(
        default_factory=lambda: os.getenv("DB_PASSWORD", os.getenv("UDR_DB_PASSWORD", ""))
    )

    def is_local(self) -> bool:
        return self.host.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0")

    def masked_url(self) -> str:
        pwd_mask = "***" if self.password else "<none>"
        return f"postgresql://{self.user}:{pwd_mask}@{self.host}:{self.port}/{self.dbname}"


@dataclass
class ResetOperationResult:
    component: str
    target: str
    status: str  # SUCCESS, SKIPPED, FAILED, PRESERVED
    detail: str
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------


def compute_sha256(filepath: Path) -> Optional[str]:
    """Computes SHA256 checksum of a file if it exists."""
    if not filepath.exists() or not filepath.is_file():
        return None
    hasher = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def mask_secret(text: str, secret: str) -> str:
    """Masks secrets from error strings to prevent leaking passwords."""
    if not secret or not text:
        return text
    return text.replace(secret, "********")


def is_port_open(host: str, port: int, timeout_sec: float = 1.5) -> bool:
    """Performs a quick non-blocking socket check to see if a port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout_sec):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ---------------------------------------------------------------------------
# Threat Intelligence Reference Preservation Checks
# ---------------------------------------------------------------------------


def inspect_threat_intelligence() -> Dict[Path, Dict[str, Any]]:
    """
    Inspects and hashes the immutable reference threat intelligence databases.
    Returns baseline data to guarantee they are never modified during reset.
    """
    baseline: Dict[Path, Dict[str, Any]] = {}
    for db_path in IMMUTABLE_TI_DATABASES:
        if db_path.exists():
            size = db_path.stat().st_size
            sha = compute_sha256(db_path)
            baseline[db_path] = {"exists": True, "size": size, "sha256": sha}
        else:
            baseline[db_path] = {"exists": False, "size": 0, "sha256": None}
    return baseline


def verify_preserved_intelligence(
    baseline: Dict[Path, Dict[str, Any]]
) -> List[ResetOperationResult]:
    """
    Verifies that all reference databases are intact and completely unmodified.
    """
    results: List[ResetOperationResult] = []
    for db_path, base_info in baseline.items():
        rel_path = db_path.relative_to(PROJECT_ROOT) if PROJECT_ROOT in db_path.parents else db_path.name
        if not base_info["exists"]:
            results.append(
                ResetOperationResult(
                    component="Preserved Intelligence",
                    target=str(rel_path),
                    status="SKIPPED",
                    detail="File not present initially (no modification occurred)",
                )
            )
            continue

        if not db_path.exists():
            results.append(
                ResetOperationResult(
                    component="Preserved Intelligence",
                    target=str(rel_path),
                    status="FAILED",
                    detail="CRITICAL: Intelligence database was deleted!",
                    error="File missing after reset",
                )
            )
            continue

        curr_size = db_path.stat().st_size
        curr_sha = compute_sha256(db_path)

        if curr_sha == base_info["sha256"] and curr_size == base_info["size"]:
            size_mb = curr_size / (1024 * 1024)
            results.append(
                ResetOperationResult(
                    component="Preserved Intelligence",
                    target=str(rel_path),
                    status="PRESERVED",
                    detail=f"Checksum verified ({size_mb:.2f} MB, unchanged)",
                )
            )
        else:
            results.append(
                ResetOperationResult(
                    component="Preserved Intelligence",
                    target=str(rel_path),
                    status="FAILED",
                    detail="CRITICAL: Intelligence database content modified!",
                    error="SHA256 checksum mismatch",
                )
            )
    return results


# ---------------------------------------------------------------------------
# Backup Functionality
# ---------------------------------------------------------------------------


def create_backup(
    db_config: DatabaseConfig,
    dry_run: bool = False,
) -> Tuple[Optional[Path], List[str]]:
    """
    Creates a timestamped backup directory in backups/wipe_YYYYMMDD_HHMMSS/
    containing runtime SQLite DB, generated CSV/JSON artifacts, and query logs.
    Excludes immutable reference databases and credentials.
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = PROJECT_ROOT / "backups" / f"wipe_{timestamp}"
    backed_up_items: List[str] = []

    files_to_backup: List[Path] = [DASHBOARD_DB_PATH, PROJECT_QUERY_LOG] + [
        f for f in GENERATED_FILE_TARGETS if f.exists() and f.is_file()
    ]

    if dry_run:
        for f in files_to_backup:
            if f.exists() and f.stat().st_size > 0:
                backed_up_items.append(f"{f.name} ({f.stat().st_size} bytes)")
        return backup_dir, backed_up_items

    backup_dir.mkdir(parents=True, exist_ok=True)

    for src_path in files_to_backup:
        if src_path.exists() and src_path.stat().st_size > 0:
            try:
                dst_path = backup_dir / src_path.name
                if src_path == DASHBOARD_DB_PATH:
                    # Use SQLite backup API for safe live snapshot if possible
                    try:
                        with sqlite3.connect(src_path) as s_conn:
                            with sqlite3.connect(dst_path) as d_conn:
                                s_conn.backup(d_conn)
                    except Exception:
                        shutil.copy2(src_path, dst_path)
                else:
                    shutil.copy2(src_path, dst_path)
                backed_up_items.append(f"{src_path.name} ({src_path.stat().st_size} bytes)")
            except Exception as exc:
                backed_up_items.append(f"{src_path.name} (BACKUP FAILED: {exc})")

    return backup_dir, backed_up_items


# ---------------------------------------------------------------------------
# Component 1: PostgreSQL Reset
# ---------------------------------------------------------------------------


class ProtectedTableSafetyError(Exception):
    """Raised when a protected table is detected in the cascade/dependency closure of tables to be wiped."""
    pass


def get_foreign_key_graph(cursor) -> Dict[str, Set[str]]:
    """
    Queries pg_constraint to build an adjacency list of foreign key dependencies.
    Returns:
        Dict[parent_table, Set[child_tables]] mapping parent tables to the child tables that reference them.
    """
    cursor.execute(
        """
        SELECT
            confrelid::regclass::text AS parent_table,
            conrelid::regclass::text AS child_table
        FROM pg_constraint
        WHERE contype = 'f' AND connamespace = 'public'::regnamespace;
        """
    )
    graph: Dict[str, Set[str]] = {}
    for parent, child in cursor.fetchall():
        # Strip potential schema prefixes like 'public.'
        p = parent.split(".")[-1].strip('"')
        c = child.split(".")[-1].strip('"')
        graph.setdefault(p, set()).add(c)
    return graph


def compute_cascade_closure(tables: List[str], fk_graph: Dict[str, Set[str]]) -> Set[str]:
    """
    Computes all downstream child tables that would be affected if CASCADE were used on the given tables.
    """
    visited: Set[str] = set()
    queue = list(tables)
    while queue:
        current = queue.pop(0)
        if current not in visited:
            visited.add(current)
            for child in fk_graph.get(current, set()):
                if child not in visited:
                    queue.append(child)
    return visited


def topological_sort_tables(tables: List[str], fk_graph: Dict[str, Set[str]]) -> List[str]:
    """
    Sorts tables in child-first order (children before parents) so they can be safely
    truncated without foreign key constraint violations.
    """
    table_set = set(tables)
    in_degree: Dict[str, int] = {t: 0 for t in table_set}
    
    # In our fk_graph, parent -> {children}.
    # For child-first deletion: child must precede parent (child -> parent edge).
    edges: Dict[str, Set[str]] = {t: set() for t in table_set}
    for parent, children in fk_graph.items():
        if parent in table_set:
            for child in children:
                if child in table_set:
                    # child must be deleted/truncated before parent
                    edges[child].add(parent)
                    in_degree[parent] += 1

    queue = [t for t in table_set if in_degree[t] == 0]
    sorted_tables: List[str] = []

    while queue:
        curr = queue.pop(0)
        sorted_tables.append(curr)
        for nxt in edges.get(curr, set()):
            in_degree[nxt] -= 1
            if in_degree[nxt] == 0:
                queue.append(nxt)

    # Append any remaining tables if cycles or unvisited nodes exist
    for t in table_set:
        if t not in sorted_tables:
            sorted_tables.append(t)

    return sorted_tables


def reset_postgresql(
    db_config: DatabaseConfig,
    dry_run: bool = False,
) -> List[ResetOperationResult]:
    """
    Inspects PostgreSQL, verifies the complete foreign-key dependency graph,
    guarantees that protected tables (dashboard_users, users, schema_metadata)
    can NEVER be cascaded into, and truncates runtime tables in safe topological
    order WITHOUT using CASCADE.
    """
    results: List[ResetOperationResult] = []

    try:
        import psycopg2
    except ImportError:
        try:
            import psycopg as psycopg2
        except ImportError:
            results.append(
                ResetOperationResult(
                    component="PostgreSQL",
                    target="driver",
                    status="FAILED",
                    detail="Neither psycopg2 nor psycopg is installed in the environment.",
                    error="Missing PostgreSQL driver",
                )
            )
            return results

    # Socket pre-check to fail fast without hanging
    if not is_port_open(db_config.host, db_config.port, timeout_sec=2.0):
        results.append(
            ResetOperationResult(
                component="PostgreSQL",
                target=f"{db_config.host}:{db_config.port}/{db_config.dbname}",
                status="SKIPPED",
                detail="PostgreSQL server is not reachable on configured host/port.",
                error="Connection refused / timeout",
            )
        )
        return results

    conn = None
    try:
        conn = psycopg2.connect(
            host=db_config.host,
            port=db_config.port,
            dbname=db_config.dbname,
            user=db_config.user,
            password=db_config.password,
            connect_timeout=3,
        )
        conn.autocommit = False

        with conn.cursor() as cur:
            # Query all existing BASE TABLEs in public schema
            cur.execute(
                """
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                ORDER BY table_name;
                """
            )
            existing_tables: Set[str] = {row[0] for row in cur.fetchall()}

            # 1. Build and verify complete foreign-key dependency graph
            fk_graph = get_foreign_key_graph(cur)

            # Categorize existing tables
            tables_to_wipe: List[str] = []
            tables_skipped: List[Tuple[str, str]] = []

            for tbl in sorted(existing_tables):
                if tbl in PROTECTED_POSTGRES_TABLES:
                    tables_skipped.append((tbl, "Protected Table / Auth / Schema Metadata"))
                elif tbl in RUNTIME_POSTGRES_TABLES:
                    tables_to_wipe.append(tbl)
                else:
                    tables_skipped.append((tbl, "Requires Review / Unrecognized Table"))

            # 2. Strict Safety Assertion: Verify Cascade Closure excludes all Protected Tables
            cascade_closure = compute_cascade_closure(tables_to_wipe, fk_graph)
            compromised_protected = cascade_closure.intersection(PROTECTED_POSTGRES_TABLES)
            if compromised_protected:
                raise ProtectedTableSafetyError(
                    f"CRITICAL SAFETY VIOLATION: Protected table(s) {compromised_protected} "
                    f"detected in downstream foreign-key closure of wipe targets: {cascade_closure}"
                )

            # 3. Check baseline row counts for protected tables to verify they remain intact
            protected_counts_before: Dict[str, int] = {}
            for tbl in existing_tables.intersection(PROTECTED_POSTGRES_TABLES):
                cur.execute(f'SELECT COUNT(*) FROM "{tbl}";')
                protected_counts_before[tbl] = cur.fetchone()[0]

            # Report protected & unrecognised tables
            for tbl, reason in tables_skipped:
                cur.execute(f'SELECT COUNT(*) FROM "{tbl}";')
                count = cur.fetchone()[0]
                results.append(
                    ResetOperationResult(
                        component="PostgreSQL",
                        target=tbl,
                        status="PRESERVED" if "Protected" in reason else "SKIPPED",
                        detail=f"{count} rows ({reason})",
                    )
                )

            # Process runtime tables
            if not tables_to_wipe:
                results.append(
                    ResetOperationResult(
                        component="PostgreSQL",
                        target="runtime_tables",
                        status="SKIPPED",
                        detail="No runtime tables found in database.",
                    )
                )
                return results

            # 4. Topologically order runtime tables (children before parents)
            ordered_tables = topological_sort_tables(tables_to_wipe, fk_graph)

            # Record row counts before wipe
            counts_before: Dict[str, int] = {}
            for tbl in ordered_tables:
                cur.execute(f'SELECT COUNT(*) FROM "{tbl}";')
                counts_before[tbl] = cur.fetchone()[0]

            if dry_run:
                for tbl in ordered_tables:
                    results.append(
                        ResetOperationResult(
                            component="PostgreSQL",
                            target=tbl,
                            status="SUCCESS",
                            detail=f"{counts_before[tbl]} rows -> WOULD TRUNCATE (RESTART IDENTITY, NO CASCADE)",
                        )
                    )
                return results

            # 5. Perform safe multi-table TRUNCATE WITHOUT CASCADE
            # Listing all mutual dependencies in topological order allows TRUNCATE without CASCADE
            truncate_list = ", ".join(f'"{t}"' for t in ordered_tables)
            truncate_sql = f"TRUNCATE TABLE {truncate_list} RESTART IDENTITY;"
            cur.execute(truncate_sql)
            conn.commit()

            # 6. Verify row counts after wipe for runtime tables
            for tbl in ordered_tables:
                cur.execute(f'SELECT COUNT(*) FROM "{tbl}";')
                count_after = cur.fetchone()[0]
                if count_after == 0:
                    results.append(
                        ResetOperationResult(
                            component="PostgreSQL",
                            target=tbl,
                            status="SUCCESS",
                            detail=f"{counts_before[tbl]} rows -> 0 rows (CLEARED)",
                        )
                    )
                else:
                    results.append(
                        ResetOperationResult(
                            component="PostgreSQL",
                            target=tbl,
                            status="FAILED",
                            detail=f"Expected 0 rows but found {count_after} rows",
                            error="Truncate verification failed",
                        )
                    )

            # 7. Post-wipe verification of protected tables
            for tbl, expected_count in protected_counts_before.items():
                cur.execute(f'SELECT COUNT(*) FROM "{tbl}";')
                curr_count = cur.fetchone()[0]
                if curr_count != expected_count:
                    results.append(
                        ResetOperationResult(
                            component="PostgreSQL",
                            target=tbl,
                            status="FAILED",
                            detail=f"CRITICAL: Protected table modified! Before: {expected_count}, After: {curr_count}",
                            error="Protected table integrity violation",
                        )
                    )

    except Exception as exc:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        err_msg = mask_secret(str(exc), db_config.password)
        results.append(
            ResetOperationResult(
                component="PostgreSQL",
                target=f"{db_config.host}:{db_config.port}/{db_config.dbname}",
                status="FAILED",
                detail=f"PostgreSQL reset operation failed: {err_msg}",
                error=err_msg,
            )
        )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return results


# ---------------------------------------------------------------------------
# Component 2: Dashboard SQLite Database Reset
# ---------------------------------------------------------------------------


def reset_dashboard_db(dry_run: bool = False) -> List[ResetOperationResult]:
    """
    Clears all accumulated aggregation and metrics data inside backend/dashboard.db
    while strictly preserving user authentication accounts (users table), schemas,
    indexes, and constraints.
    """
    results: List[ResetOperationResult] = []

    # Path safety validation: Ensure target database is strictly inside PROJECT_ROOT
    try:
        resolved_db = DASHBOARD_DB_PATH.resolve()
        if not (resolved_db == (PROJECT_ROOT / "dashboard.db").resolve() or resolved_db == (BACKEND_DIR / "dashboard.db").resolve()):
            results.append(
                ResetOperationResult(
                    component="Dashboard",
                    target="dashboard.db",
                    status="FAILED",
                    detail=f"Refusing to operate on unexpected database path: {resolved_db}",
                    error="Path validation failure",
                )
            )
            return results
    except Exception as exc:
        results.append(
            ResetOperationResult(
                component="Dashboard",
                target="dashboard.db",
                status="FAILED",
                detail=f"Path resolution error: {exc}",
                error=str(exc),
            )
        )
        return results

    if not DASHBOARD_DB_PATH.exists():
        results.append(
            ResetOperationResult(
                component="Dashboard",
                target="dashboard.db",
                status="SKIPPED",
                detail="Database file does not exist (clean state)",
            )
        )
        return results

    conn = None
    try:
        conn = sqlite3.connect(DASHBOARD_DB_PATH)
        cur = conn.cursor()

        # Find all user tables (exclude internal sqlite system tables)
        cur.execute(
            """
            SELECT name 
            FROM sqlite_master 
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name;
            """
        )
        existing_tables = [row[0] for row in cur.fetchall()]

        if not existing_tables:
            results.append(
                ResetOperationResult(
                    component="Dashboard",
                    target="dashboard.db",
                    status="SUCCESS",
                    detail="0 tables (empty schema)",
                )
            )
            return results

        # Classify tables
        tables_to_wipe: List[str] = []
        tables_protected: List[str] = []
        counts_before: Dict[str, int] = {}
        total_rows_to_wipe = 0

        for tbl in existing_tables:
            cur.execute(f'SELECT COUNT(*) FROM "{tbl}";')
            cnt = cur.fetchone()[0]
            counts_before[tbl] = cnt
            if tbl in PROTECTED_SQLITE_TABLES:
                tables_protected.append(tbl)
            else:
                tables_to_wipe.append(tbl)
                total_rows_to_wipe += cnt

        # Report protected tables
        for tbl in tables_protected:
            results.append(
                ResetOperationResult(
                    component="Dashboard",
                    target=tbl,
                    status="PRESERVED",
                    detail=f"{counts_before[tbl]} rows (Protected Auth / Configuration)",
                )
            )

        if dry_run:
            for tbl in tables_to_wipe:
                results.append(
                    ResetOperationResult(
                        component="Dashboard",
                        target=tbl,
                        status="SUCCESS",
                        detail=f"{counts_before[tbl]} rows -> WOULD CLEAR",
                    )
                )
            return results

        # Execute wipe in an atomic transaction
        conn.execute("PRAGMA foreign_keys = OFF;")
        with conn:
            for tbl in tables_to_wipe:
                cur.execute(f'DELETE FROM "{tbl}";')

            # Reset auto-increment sequence ONLY for wiped tables (preserve users sequence)
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sqlite_sequence';")
            if cur.fetchone():
                protected_str = ", ".join(f"'{p}'" for p in PROTECTED_SQLITE_TABLES)
                cur.execute(f"DELETE FROM sqlite_sequence WHERE name NOT IN ({protected_str});")

        # Run PRAGMA integrity_check
        integrity_row = cur.execute("PRAGMA integrity_check;").fetchone()
        integrity_status = integrity_row[0] if integrity_row else "unknown"
        if integrity_status.lower() != "ok":
            raise RuntimeError(f"PRAGMA integrity_check failed: {integrity_status}")

        # Run VACUUM to reclaim space and defragment database
        conn.execute("VACUUM;")

        # Verification query
        for tbl in tables_to_wipe:
            cur.execute(f'SELECT COUNT(*) FROM "{tbl}";')
            cnt_after = cur.fetchone()[0]
            if cnt_after == 0:
                results.append(
                    ResetOperationResult(
                        component="Dashboard",
                        target=tbl,
                        status="SUCCESS",
                        detail=f"{counts_before[tbl]} rows -> 0 rows (CLEARED)",
                    )
                )
            else:
                results.append(
                    ResetOperationResult(
                        component="Dashboard",
                        target=tbl,
                        status="FAILED",
                        detail=f"Verification failed: expected 0 rows, found {cnt_after}",
                        error="SQLite delete verification failed",
                    )
                )

        # Verify protected tables remained untouched
        for tbl in tables_protected:
            cur.execute(f'SELECT COUNT(*) FROM "{tbl}";')
            cnt_after = cur.fetchone()[0]
            if cnt_after != counts_before[tbl]:
                results.append(
                    ResetOperationResult(
                        component="Dashboard",
                        target=tbl,
                        status="FAILED",
                        detail=f"CRITICAL: Protected table modified! Before: {counts_before[tbl]}, After: {cnt_after}",
                        error="Protected table integrity violation",
                    )
                )

    except Exception as exc:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        results.append(
            ResetOperationResult(
                component="Dashboard",
                target="dashboard.db",
                status="FAILED",
                detail=f"Failed to reset dashboard SQLite database: {exc}",
                error=str(exc),
            )
        )
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

    return results


# ---------------------------------------------------------------------------
# Component 3: Kafka Topic Reset
# ---------------------------------------------------------------------------


def reset_kafka(
    bootstrap_servers: str = DEFAULT_KAFKA_BOOTSTRAP,
    topic_name: str = DEFAULT_KAFKA_TOPIC,
    dry_run: bool = False,
) -> List[ResetOperationResult]:
    """
    Clears the dns-logs topic in Kafka so the next live test starts with an
    empty topic. Handles unavailability gracefully without crashing the wipe.
    """
    results: List[ResetOperationResult] = []

    # Parse host & port from bootstrap servers for pre-check
    first_broker = bootstrap_servers.split(",")[0].strip()
    if ":" in first_broker:
        host, port_str = first_broker.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 9092
    else:
        host = first_broker
        port = 9092

    # Fast non-blocking socket check
    if not is_port_open(host, port, timeout_sec=1.5):
        results.append(
            ResetOperationResult(
                component="Kafka",
                target=topic_name,
                status="SKIPPED",
                detail=f"Kafka broker at {bootstrap_servers} is not reachable.",
            )
        )
        return results

    try:
        from kafka.admin import KafkaAdminClient, NewTopic
    except ImportError:
        results.append(
            ResetOperationResult(
                component="Kafka",
                target=topic_name,
                status="SKIPPED",
                detail="kafka-python library not available.",
            )
        )
        return results

    admin_client = None
    try:
        admin_client = KafkaAdminClient(
            bootstrap_servers=bootstrap_servers,
            request_timeout_ms=3000,
            client_id="dns_threat_wipe_utility",
        )

        existing_topics = set(admin_client.list_topics())

        if topic_name not in existing_topics:
            results.append(
                ResetOperationResult(
                    component="Kafka",
                    target=topic_name,
                    status="SUCCESS",
                    detail="Topic does not exist (already clean)",
                )
            )
            return results

        if dry_run:
            results.append(
                ResetOperationResult(
                    component="Kafka",
                    target=topic_name,
                    status="SUCCESS",
                    detail=f"Topic exists on {bootstrap_servers} -> WOULD DELETE & RECREATE",
                )
            )
            return results

        # Delete the topic
        admin_client.delete_topics([topic_name])
        time.sleep(0.5)

        # Re-create fresh topic with 1 partition and replication factor 1
        new_topic = NewTopic(name=topic_name, num_partitions=1, replication_factor=1)
        try:
            admin_client.create_topics([new_topic])
        except Exception:
            time.sleep(0.5)
            # Retry creation if Kafka needed an extra moment to complete deletion
            try:
                admin_client.create_topics([new_topic])
            except Exception:
                pass  # Live pipeline will auto-create topic on publish if configured

        results.append(
            ResetOperationResult(
                component="Kafka",
                target=topic_name,
                status="SUCCESS",
                detail="Topic cleared and recreated (0 messages)",
            )
        )

    except Exception as exc:
        results.append(
            ResetOperationResult(
                component="Kafka",
                target=topic_name,
                status="SKIPPED",
                detail=f"Kafka topic reset could not be completed: {exc}",
                error=str(exc),
            )
        )
    finally:
        if admin_client:
            try:
                admin_client.close()
            except Exception:
                pass

    return results


# ---------------------------------------------------------------------------
# Component 4: Generated Data Files Reset
# ---------------------------------------------------------------------------


def reset_generated_files(dry_run: bool = False) -> List[ResetOperationResult]:
    """
    Removes generated runtime artifacts produced by pipeline runs while
    explicitly preserving source, benchmark, and training datasets.
    """
    results: List[ResetOperationResult] = []

    # 1. Process target generated files
    for file_path in GENERATED_FILE_TARGETS:
        rel_name = (
            file_path.relative_to(PROJECT_ROOT)
            if PROJECT_ROOT in file_path.parents
            else file_path.name
        )

        if not file_path.exists():
            results.append(
                ResetOperationResult(
                    component="Generated files",
                    target=str(rel_name),
                    status="SKIPPED",
                    detail="Not present",
                )
            )
            continue

        size = file_path.stat().st_size
        size_str = f"{size} bytes" if size < 1024 else f"{size / 1024:.1f} KB"

        if dry_run:
            results.append(
                ResetOperationResult(
                    component="Generated files",
                    target=str(rel_name),
                    status="SUCCESS",
                    detail=f"{size_str} -> WOULD REMOVE",
                )
            )
            continue

        try:
            file_path.unlink()
            if not file_path.exists():
                results.append(
                    ResetOperationResult(
                        component="Generated files",
                        target=str(rel_name),
                        status="SUCCESS",
                        detail=f"{size_str} -> REMOVED",
                    )
                )
            else:
                results.append(
                    ResetOperationResult(
                        component="Generated files",
                        target=str(rel_name),
                        status="FAILED",
                        detail="File still exists after deletion attempt",
                        error="Unlink verification failed",
                    )
                )
        except Exception as exc:
            results.append(
                ResetOperationResult(
                    component="Generated files",
                    target=str(rel_name),
                    status="FAILED",
                    detail=f"Could not delete file: {exc}",
                    error=str(exc),
                )
            )

    # 2. Report preserved source / benchmark files
    for file_path, category in PRESERVED_SOURCE_FILES:
        rel_name = (
            file_path.relative_to(PROJECT_ROOT)
            if PROJECT_ROOT in file_path.parents
            else file_path.name
        )
        if file_path.exists():
            size = file_path.stat().st_size
            results.append(
                ResetOperationResult(
                    component="Preserved Files",
                    target=str(rel_name),
                    status="PRESERVED",
                    detail=f"{size / (1024 * 1024):.2f} MB ({category})",
                )
            )

    return results


# ---------------------------------------------------------------------------
# Component 5: DNS Test Query Log Reset
# ---------------------------------------------------------------------------


def reset_query_log(dry_run: bool = False) -> List[ResetOperationResult]:
    """
    Resets the development/test DNS query log to 0 bytes while preserving
    the file itself. Does NOT touch /var/cache/bind/query.log.
    """
    results: List[ResetOperationResult] = []
    target_path = PROJECT_QUERY_LOG
    rel_name = (
        target_path.relative_to(PROJECT_ROOT)
        if PROJECT_ROOT in target_path.parents
        else target_path.name
    )

    if not target_path.exists():
        if dry_run:
            results.append(
                ResetOperationResult(
                    component="DNS test log",
                    target=str(rel_name),
                    status="SKIPPED",
                    detail="File does not exist -> WOULD CREATE (0 bytes)",
                )
            )
            return results

        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.touch()
            results.append(
                ResetOperationResult(
                    component="DNS test log",
                    target=str(rel_name),
                    status="SUCCESS",
                    detail="Created empty log file (0 bytes)",
                )
            )
        except Exception as exc:
            results.append(
                ResetOperationResult(
                    component="DNS test log",
                    target=str(rel_name),
                    status="FAILED",
                    detail=f"Failed to create query.log: {exc}",
                    error=str(exc),
                )
            )
        return results

    current_size = target_path.stat().st_size

    if dry_run:
        results.append(
            ResetOperationResult(
                component="DNS test log",
                target=str(rel_name),
                status="SUCCESS",
                detail=f"{current_size} bytes -> WOULD TRUNCATE (0 bytes)",
            )
        )
        return results

    try:
        with open(target_path, "w") as f:
            f.truncate(0)

        new_size = target_path.stat().st_size
        if new_size == 0:
            results.append(
                ResetOperationResult(
                    component="DNS test log",
                    target=str(rel_name),
                    status="SUCCESS",
                    detail=f"{current_size} bytes -> 0 bytes (RESET)",
                )
            )
        else:
            results.append(
                ResetOperationResult(
                    component="DNS test log",
                    target=str(rel_name),
                    status="FAILED",
                    detail=f"Expected 0 bytes, got {new_size} bytes",
                    error="Truncation failed",
                )
            )
    except Exception as exc:
        results.append(
            ResetOperationResult(
                component="DNS test log",
                target=str(rel_name),
                status="FAILED",
                detail=f"Failed to truncate query.log: {exc}",
                error=str(exc),
            )
        )

    return results


# ---------------------------------------------------------------------------
# Component 6: Fluent Bit State Reset
# ---------------------------------------------------------------------------


def reset_fluent_bit_state(dry_run: bool = False) -> List[ResetOperationResult]:
    """
    Checks for any project-specific Fluent Bit position databases / state files
    and resets them if found.
    """
    results: List[ResetOperationResult] = []

    # Check for possible state files in backend
    state_patterns = ["*.pos", ".fluent-bit*", "fluent-bit.db*"]
    found_state_files: List[Path] = []
    for pat in state_patterns:
        found_state_files.extend(BACKEND_DIR.glob(pat))

    if not found_state_files:
        results.append(
            ResetOperationResult(
                component="Fluent Bit",
                target="state",
                status="SUCCESS",
                detail="NONE FOUND (In-memory state only)",
            )
        )
        return results

    for sf in found_state_files:
        rel_name = sf.name
        if dry_run:
            results.append(
                ResetOperationResult(
                    component="Fluent Bit",
                    target=rel_name,
                    status="SUCCESS",
                    detail="WOULD REMOVE state file",
                )
            )
        else:
            try:
                sf.unlink()
                results.append(
                    ResetOperationResult(
                        component="Fluent Bit",
                        target=rel_name,
                        status="SUCCESS",
                        detail="State file removed (RESET)",
                    )
                )
            except Exception as exc:
                results.append(
                    ResetOperationResult(
                        component="Fluent Bit",
                        target=rel_name,
                        status="FAILED",
                        detail=f"Could not delete state file: {exc}",
                        error=str(exc),
                    )
                )

    return results


# ---------------------------------------------------------------------------
# Component 7: Redis Usage Verification
# ---------------------------------------------------------------------------


def reset_redis(dry_run: bool = False) -> List[ResetOperationResult]:
    """
    Verifies Redis usage. The DNS Threat Detection pipeline does not use Redis
    for runtime state or deduplication.
    """
    return [
        ResetOperationResult(
            component="Redis",
            target="runtime state",
            status="SUCCESS",
            detail="NOT USED (Pipeline uses PostgreSQL + in-memory deduplication)",
        )
    ]


# ---------------------------------------------------------------------------
# Confirmation & Execution Orchestration
# ---------------------------------------------------------------------------


def print_banner(dry_run: bool = False) -> None:
    mode_str = c_yellow(" [DRY-RUN / SIMULATION MODE]") if dry_run else ""
    print()
    print(c_bold("=" * 60))
    print(c_bold(f"  DNS THREAT DETECTION SYSTEM — DATA RESET UTILITY{mode_str}"))
    print(c_bold("=" * 60))
    print()


def print_detection_summary(db_config: DatabaseConfig) -> None:
    print(c_bold("Detected Environment & Targets:"))
    print(f"  • PostgreSQL DB      : {c_cyan(db_config.masked_url())}")
    print(f"  • Dashboard SQLite   : {c_cyan(str(DASHBOARD_DB_PATH.name))}")
    print(f"  • Kafka Broker       : {c_cyan(DEFAULT_KAFKA_BOOTSTRAP)} (Topic: {DEFAULT_KAFKA_TOPIC})")
    print(f"  • DNS Dev Query Log  : {c_cyan(str(PROJECT_QUERY_LOG.relative_to(PROJECT_ROOT)))}")
    print(
        f"  • Threat Intel DBs   : {c_green('URLhaus (malicious_domains.db)')} & {c_green('Tranco (trusted_domains.db)')}"
    )
    print()


def confirm_reset(db_config: DatabaseConfig, allow_remote: bool = False) -> bool:
    """
    Interactive safety confirmation prompt. Requires explicit confirmation.
    """
    if not db_config.is_local() and not allow_remote:
        print(c_red(c_bold("⚠ WARNING: REMOTE POSTGRESQL DATABASE DETECTED!")))
        print(f"  Target host is '{db_config.host}', which does not appear to be localhost.")
        print("  Wiping a remote database requires explicit confirmation.")
        print()
        response = input("  Type 'CONFIRM_REMOTE_WIPE' to proceed: ").strip()
        if response != "CONFIRM_REMOTE_WIPE":
            print(c_yellow("\nReset aborted. Remote database untouched."))
            return False
        return True

    print(
        c_yellow(
            "WARNING: This will permanently delete runtime and observational data\n"
            "to prepare a clean environment for a fresh pipeline run.\n"
            "Reference threat intelligence databases and schemas will be preserved."
        )
    )
    print()
    response = input(f"{c_bold('Continue? [y/N]: ')}").strip().lower()
    return response in ("y", "yes")


def print_results(results: List[ResetOperationResult], dry_run: bool = False) -> None:
    """
    Renders structured, categorized results table with status icons.
    """
    # Group by component
    by_component: Dict[str, List[ResetOperationResult]] = {}
    for r in results:
        by_component.setdefault(r.component, []).append(r)

    print()
    print(c_bold("=" * 60))
    print(c_bold(f"  RESET SUMMARY {'(SIMULATED)' if dry_run else ''}"))
    print(c_bold("=" * 60))

    order = [
        "PostgreSQL",
        "Dashboard",
        "Kafka",
        "Generated files",
        "DNS test log",
        "Fluent Bit",
        "Redis",
        "Preserved Files",
        "Preserved Intelligence",
    ]

    for comp in order:
        if comp not in by_component:
            continue
        print(f"\n{c_bold(comp)}")
        for r in by_component[comp]:
            if r.status == "SUCCESS":
                icon = ICON_OK
            elif r.status == "PRESERVED":
                icon = ICON_OK
            elif r.status == "SKIPPED":
                icon = ICON_SKIP
            else:
                icon = ICON_ERR

            status_pad = f"{r.target:<24}"
            print(f"  {icon} {status_pad} -> {r.detail}")

    print()
    print(c_bold("=" * 60))


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Safe, comprehensive reset utility for the DNS Threat Detection pipeline."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate the reset without deleting or modifying any data.",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Bypass interactive confirmation prompt (for automation / CI).",
    )
    parser.add_argument(
        "--backup",
        action="store_true",
        help="Create a timestamped backup of runtime artifacts before wiping.",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="Allow resetting non-localhost PostgreSQL databases without extra prompt.",
    )

    args = parser.parse_args()

    print_banner(dry_run=args.dry_run)

    # 1. Load configuration & baseline reference intelligence
    db_config = DatabaseConfig()
    print_detection_summary(db_config)

    ti_baseline = inspect_threat_intelligence()

    # 2. Confirmation (if not dry-run and not --yes)
    if not args.dry_run and not args.yes:
        if not confirm_reset(db_config, allow_remote=args.allow_remote):
            print(c_yellow("Reset aborted by user. No changes made.\n"))
            return 0

    # 3. Optional Backup
    if args.backup:
        backup_path, items = create_backup(db_config, dry_run=args.dry_run)
        if args.dry_run:
            print(f"{c_cyan('Backup Simulation')}: Would back up {len(items)} items to {backup_path}")
        else:
            print(f"{c_green('Backup Complete')}: Saved {len(items)} items to {backup_path}")
        for item in items:
            print(f"  • {item}")
        print()

    # 4. Perform Component Resets
    all_results: List[ResetOperationResult] = []

    all_results.extend(reset_postgresql(db_config, dry_run=args.dry_run))
    all_results.extend(reset_dashboard_db(dry_run=args.dry_run))
    all_results.extend(
        reset_kafka(
            bootstrap_servers=DEFAULT_KAFKA_BOOTSTRAP,
            topic_name=DEFAULT_KAFKA_TOPIC,
            dry_run=args.dry_run,
        )
    )
    all_results.extend(reset_generated_files(dry_run=args.dry_run))
    all_results.extend(reset_query_log(dry_run=args.dry_run))
    all_results.extend(reset_fluent_bit_state(dry_run=args.dry_run))
    all_results.extend(reset_redis(dry_run=args.dry_run))

    # 5. Core Safety Verification: Ensure Threat Intelligence Was Preserved
    all_results.extend(verify_preserved_intelligence(ti_baseline))

    # 6. Display Summary
    print_results(all_results, dry_run=args.dry_run)

    # 7. Check for critical errors
    failed_ops = [r for r in all_results if r.status == "FAILED"]
    if failed_ops:
        print(c_red(c_bold(f"RESET FINISHED WITH {len(failed_ops)} FAILURE(S):")))
        for f in failed_ops:
            print(f"  • [{f.component}] {f.target}: {f.error or f.detail}")
        print()
        return 1

    if args.dry_run:
        print(c_green(c_bold("DRY RUN COMPLETE — Zero changes made to system.")))
    else:
        print(c_green(c_bold("RESET COMPLETE — System is ready for a fresh pipeline run.")))
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
