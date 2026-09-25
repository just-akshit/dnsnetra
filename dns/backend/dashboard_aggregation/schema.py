"""
Dashboard Aggregation Schema Module
====================================
Defines SQLite DDL statements and database initialization functions for `dashboard.db`.

Tables
------
Existing (preserved — do not rename or drop):
  metrics_summary, threats_by_category, queries_timeseries, geo_distribution,
  top_domains, top_clients, recent_flagged_domains

New (incremental aggregation):
  aggregation_state         -- durable watermark checkpoint
  aggregation_runs          -- full audit trail of every aggregation execution
  domain_details            -- per-domain read model
  client_details            -- per-client read model
  domain_client_membership  -- enables correct unique_clients per domain
  client_domain_membership  -- enables correct unique_domains per client
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Union

logger = logging.getLogger(__name__)

# ===========================================================================
# EXISTING TABLES (preserved)
# ===========================================================================

CREATE_METRICS_SUMMARY_TABLE = """
CREATE TABLE IF NOT EXISTS metrics_summary (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    total_queries INTEGER NOT NULL DEFAULT 0,
    total_threats INTEGER NOT NULL DEFAULT 0,
    threats_blocked_pct REAL NOT NULL DEFAULT 0.0,
    unique_clients INTEGER NOT NULL DEFAULT 0,
    unique_domains INTEGER NOT NULL DEFAULT 0,
    last_pipeline_run_at TEXT NOT NULL
);
"""

CREATE_THREATS_BY_CATEGORY_TABLE = """
CREATE TABLE IF NOT EXISTS threats_by_category (
    category TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0,
    pct REAL NOT NULL DEFAULT 0.0
);
"""

CREATE_QUERIES_TIMESERIES_TABLE = """
CREATE TABLE IF NOT EXISTS queries_timeseries (
    time_bucket TEXT PRIMARY KEY,
    total_queries INTEGER NOT NULL DEFAULT 0,
    threat_queries INTEGER NOT NULL DEFAULT 0
);
"""

CREATE_GEO_DISTRIBUTION_TABLE = """
CREATE TABLE IF NOT EXISTS geo_distribution (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    country TEXT NOT NULL,
    asn TEXT NOT NULL,
    query_count INTEGER NOT NULL DEFAULT 0,
    threat_count INTEGER NOT NULL DEFAULT 0
);
"""

CREATE_TOP_DOMAINS_TABLE = """
CREATE TABLE IF NOT EXISTS top_domains (
    domain TEXT PRIMARY KEY,
    query_count INTEGER NOT NULL DEFAULT 0,
    label TEXT NOT NULL,
    threat_score REAL NOT NULL DEFAULT 0.0,
    last_seen TEXT NOT NULL
);
"""

CREATE_TOP_CLIENTS_TABLE = """
CREATE TABLE IF NOT EXISTS top_clients (
    client_ip TEXT PRIMARY KEY,
    query_count INTEGER NOT NULL DEFAULT 0,
    malicious_query_count INTEGER NOT NULL DEFAULT 0,
    last_seen TEXT NOT NULL
);
"""

CREATE_RECENT_FLAGGED_DOMAINS_TABLE = """
CREATE TABLE IF NOT EXISTS recent_flagged_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    label TEXT NOT NULL,
    label_reason TEXT,
    ti_source TEXT,
    confidence REAL DEFAULT 0.0,
    flagged_at TEXT NOT NULL
);
"""

# ===========================================================================
# NEW: Incremental aggregation infrastructure
# ===========================================================================

CREATE_AGGREGATION_STATE_TABLE = """
CREATE TABLE IF NOT EXISTS aggregation_state (
    aggregation_name TEXT PRIMARY KEY,
    last_processed_event_id INTEGER NOT NULL DEFAULT 0,
    last_processed_event_timestamp TEXT,
    last_successful_run_id TEXT,
    updated_at TEXT NOT NULL
);
"""
# Single-row durable watermark. Normally one row: aggregation_name='dashboard'.
# last_processed_event_id = domain_query_history.id of the last committed event.
# Watermark advances ONLY inside a successful SQLite COMMIT -- never before.

CREATE_AGGREGATION_RUNS_TABLE = """
CREATE TABLE IF NOT EXISTS aggregation_runs (
    run_id TEXT PRIMARY KEY,
    aggregation_name TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_ms INTEGER,
    status TEXT NOT NULL,
    source_type TEXT,
    source_identifier TEXT,
    first_event_id INTEGER,
    last_event_id INTEGER,
    first_event_timestamp TEXT,
    last_event_timestamp TEXT,
    rows_seen INTEGER DEFAULT 0,
    rows_processed INTEGER DEFAULT 0,
    rows_rejected INTEGER DEFAULT 0,
    batches_processed INTEGER DEFAULT 0,
    error_message TEXT
);
"""
# status: running | success | partial | failed
# source_type: postgres_incremental | postgres_rebuild | csv_legacy

CREATE_DOMAIN_DETAILS_TABLE = """
CREATE TABLE IF NOT EXISTS domain_details (
    domain TEXT PRIMARY KEY,
    total_queries INTEGER NOT NULL DEFAULT 0,
    unique_clients INTEGER NOT NULL DEFAULT 0,
    threat_count INTEGER NOT NULL DEFAULT 0,
    malicious_count INTEGER NOT NULL DEFAULT 0,
    suspicious_count INTEGER NOT NULL DEFAULT 0,
    clean_count INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    last_label TEXT,
    threat_score REAL,
    confidence REAL,
    last_ti_source TEXT,
    label_reason TEXT,
    query_type_breakdown TEXT,
    response_code_breakdown TEXT,
    asn TEXT,
    asn_org TEXT,
    country TEXT,
    resolved_ips TEXT,
    domain_age_days REAL,
    enrichment_json TEXT,
    updated_at TEXT NOT NULL
);
"""
# Fields NULL until backend provides them: threat_score, confidence, asn,
# asn_org, country, resolved_ips, domain_age_days, enrichment_json.
# unique_clients = COUNT(*) from domain_client_membership (never a running sum).
# query_type_breakdown / response_code_breakdown stored as JSON: '{"A":10,"MX":2}'

CREATE_CLIENT_DETAILS_TABLE = """
CREATE TABLE IF NOT EXISTS client_details (
    client_ip TEXT PRIMARY KEY,
    total_queries INTEGER NOT NULL DEFAULT 0,
    unique_domains INTEGER NOT NULL DEFAULT 0,
    threat_count INTEGER NOT NULL DEFAULT 0,
    malicious_count INTEGER NOT NULL DEFAULT 0,
    suspicious_count INTEGER NOT NULL DEFAULT 0,
    clean_count INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT,
    last_seen TEXT,
    top_domains TEXT,
    updated_at TEXT NOT NULL
);
"""
# unique_domains = COUNT(*) from client_domain_membership (never a running sum).
# top_domains: JSON '[{"domain":"evil.com","count":5}]'

CREATE_DOMAIN_CLIENT_MEMBERSHIP_TABLE = """
CREATE TABLE IF NOT EXISTS domain_client_membership (
    domain TEXT NOT NULL,
    client_ip TEXT NOT NULL,
    PRIMARY KEY (domain, client_ip)
);
"""
# INSERT OR IGNORE -- idempotent.
# unique_clients for a domain = SELECT COUNT(*) FROM domain_client_membership WHERE domain = ?

CREATE_CLIENT_DOMAIN_MEMBERSHIP_TABLE = """
CREATE TABLE IF NOT EXISTS client_domain_membership (
    client_ip TEXT NOT NULL,
    domain TEXT NOT NULL,
    PRIMARY KEY (client_ip, domain)
);
"""
# INSERT OR IGNORE -- idempotent.
# unique_domains for a client = SELECT COUNT(*) FROM client_domain_membership WHERE client_ip = ?

# ===========================================================================
# NEW: Indexes
# ===========================================================================

CREATE_INDEX_AGGREGATION_RUNS_NAME = """
CREATE INDEX IF NOT EXISTS idx_aggregation_runs_name
    ON aggregation_runs(aggregation_name, started_at DESC);
"""

CREATE_INDEX_DOMAIN_DETAILS_LAST_SEEN = """
CREATE INDEX IF NOT EXISTS idx_domain_details_last_seen
    ON domain_details(last_seen DESC);
"""

CREATE_INDEX_DOMAIN_DETAILS_THREAT_COUNT = """
CREATE INDEX IF NOT EXISTS idx_domain_details_threat_count
    ON domain_details(threat_count DESC);
"""

CREATE_INDEX_CLIENT_DETAILS_LAST_SEEN = """
CREATE INDEX IF NOT EXISTS idx_client_details_last_seen
    ON client_details(last_seen DESC);
"""

CREATE_INDEX_CLIENT_DETAILS_THREAT_COUNT = """
CREATE INDEX IF NOT EXISTS idx_client_details_threat_count
    ON client_details(threat_count DESC);
"""

# ===========================================================================
# Ordered lists (used by initialize_dashboard_db)
# ===========================================================================

EXISTING_TABLE_DDLS = [
    CREATE_METRICS_SUMMARY_TABLE,
    CREATE_THREATS_BY_CATEGORY_TABLE,
    CREATE_QUERIES_TIMESERIES_TABLE,
    CREATE_GEO_DISTRIBUTION_TABLE,
    CREATE_TOP_DOMAINS_TABLE,
    CREATE_TOP_CLIENTS_TABLE,
    CREATE_RECENT_FLAGGED_DOMAINS_TABLE,
]

NEW_TABLE_DDLS = [
    CREATE_AGGREGATION_STATE_TABLE,
    CREATE_AGGREGATION_RUNS_TABLE,
    CREATE_DOMAIN_DETAILS_TABLE,
    CREATE_CLIENT_DETAILS_TABLE,
    CREATE_DOMAIN_CLIENT_MEMBERSHIP_TABLE,
    CREATE_CLIENT_DOMAIN_MEMBERSHIP_TABLE,
]

NEW_INDEX_DDLS = [
    CREATE_INDEX_AGGREGATION_RUNS_NAME,
    CREATE_INDEX_DOMAIN_DETAILS_LAST_SEEN,
    CREATE_INDEX_DOMAIN_DETAILS_THREAT_COUNT,
    CREATE_INDEX_CLIENT_DETAILS_LAST_SEEN,
    CREATE_INDEX_CLIENT_DETAILS_THREAT_COUNT,
]

ALL_TABLE_DDLS = EXISTING_TABLE_DDLS + NEW_TABLE_DDLS


def initialize_dashboard_db(db_path: Union[str, Path]) -> None:
    """
    Ensures parent directories exist and initializes all tables and indexes
    in `dashboard.db`.

    Idempotent -- safe to call on every startup.
    Never drops or renames existing tables.
    """
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA foreign_keys=ON;")

        for ddl in ALL_TABLE_DDLS:
            cursor.execute(ddl)

        for idx_ddl in NEW_INDEX_DDLS:
            cursor.execute(idx_ddl)

        conn.commit()

    logger.info("Initialized SQLite database schema at %s", db_path)
