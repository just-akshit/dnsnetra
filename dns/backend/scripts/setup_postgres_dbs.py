#!/usr/bin/env python3
"""
setup_postgres_dbs.py
=====================
Idempotently provisions the 4 PostgreSQL databases and their exact schemas:
  1. trusted_db
  2. malicious_db
  3. reputation_db
  4. daily_review_db
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
logger = logging.getLogger("setup_postgres_dbs")

# ---------------------------------------------------------------------------
# Connection helpers reading from environment
# ---------------------------------------------------------------------------
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")

DATABASES = [
    os.getenv("TRUSTED_DB_DATABASE", "trusted_db"),
    os.getenv("MALICIOUS_DB_DATABASE", "malicious_db"),
    os.getenv("REPUTATION_DB_DATABASE", "reputation_db"),
    os.getenv("DAILY_REVIEW_DB_DATABASE", "daily_review_db"),
]

# ---------------------------------------------------------------------------
# DDL Statements
# ---------------------------------------------------------------------------
TRUSTED_DB_DDL = """
CREATE TABLE IF NOT EXISTS trusted_domains (
    domain VARCHAR(253) PRIMARY KEY,
    rank INTEGER NOT NULL,
    source VARCHAR(50) NOT NULL DEFAULT 'tranco',
    downloaded_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS metadata (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

MALICIOUS_DB_DDL = """
CREATE TABLE IF NOT EXISTS malicious_domains (
    domain VARCHAR(253) PRIMARY KEY,
    source VARCHAR(50) NOT NULL DEFAULT 'urlhaus',
    downloaded_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS metadata (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

REPUTATION_DB_DDL = """
CREATE TABLE IF NOT EXISTS reputation_domains (
    id              BIGSERIAL PRIMARY KEY,
    domain          VARCHAR(255) UNIQUE NOT NULL,
    status          VARCHAR(20)  NOT NULL DEFAULT 'malicious',
    source          VARCHAR(50)  NOT NULL DEFAULT 'URLHaus',
    confidence      FLOAT,
    match_scope     VARCHAR(32)  NULL,
    matched_domain  VARCHAR(255) NULL,
    first_seen      TIMESTAMP    NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMP    NOT NULL DEFAULT NOW(),
    times_seen      INTEGER      NOT NULL DEFAULT 1,
    query_count     INTEGER      NOT NULL DEFAULT 1,
    client_ip       INET,
    query_type      VARCHAR(10),
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reputation_domain      ON reputation_domains (domain);
CREATE INDEX IF NOT EXISTS idx_reputation_last_seen   ON reputation_domains (last_seen);
CREATE INDEX IF NOT EXISTS idx_reputation_status      ON reputation_domains (status);
CREATE INDEX IF NOT EXISTS idx_reputation_match_scope ON reputation_domains (match_scope);
"""

DAILY_REVIEW_DB_DDL = """
DO $$ BEGIN
    CREATE TYPE domain_source AS ENUM (
        'dns_query_log',
        'manual_import',
        'system_test'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE domain_status AS ENUM (
        'new',
        'processing',
        'malicious',
        'clean',
        'review_needed',
        'error'
    );
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

CREATE TABLE IF NOT EXISTS unknown_domains (
    id BIGSERIAL PRIMARY KEY,
    domain VARCHAR(253) NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    query_count INTEGER NOT NULL DEFAULT 1,
    source domain_source NOT NULL DEFAULT 'dns_query_log',
    status domain_status NOT NULL DEFAULT 'new',
    previous_status domain_status NULL,
    last_checked TIMESTAMPTZ NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    schema_version INTEGER NOT NULL DEFAULT 2,
    CONSTRAINT uq_unknown_domains_domain UNIQUE (domain)
);

CREATE INDEX IF NOT EXISTS idx_unknown_domains_domain ON unknown_domains (domain);
CREATE INDEX IF NOT EXISTS idx_unknown_domains_first_seen ON unknown_domains (first_seen);
CREATE INDEX IF NOT EXISTS idx_unknown_domains_last_seen ON unknown_domains (last_seen);
CREATE INDEX IF NOT EXISTS idx_unknown_domains_status ON unknown_domains (status);
CREATE INDEX IF NOT EXISTS idx_unknown_domains_status_first_seen ON unknown_domains (status, first_seen);
CREATE INDEX IF NOT EXISTS idx_unknown_domains_source ON unknown_domains (source);
CREATE INDEX IF NOT EXISTS idx_unknown_domains_last_checked ON unknown_domains (last_checked);

CREATE TABLE IF NOT EXISTS schema_metadata (
    component VARCHAR(50) NOT NULL PRIMARY KEY,
    version INTEGER NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    description TEXT
);

INSERT INTO schema_metadata (component, version, description)
VALUES (
    'unknown_domain_repository',
    2,
    'Production schema version 2'
) ON CONFLICT (component) DO UPDATE SET
    version = EXCLUDED.version,
    applied_at = NOW(),
    description = EXCLUDED.description;
"""

SCHEMA_MAP = {
    os.getenv("TRUSTED_DB_DATABASE", "trusted_db"): TRUSTED_DB_DDL,
    os.getenv("MALICIOUS_DB_DATABASE", "malicious_db"): MALICIOUS_DB_DDL,
    os.getenv("REPUTATION_DB_DATABASE", "reputation_db"): REPUTATION_DB_DDL,
    os.getenv("DAILY_REVIEW_DB_DATABASE", "daily_review_db"): DAILY_REVIEW_DB_DDL,
}


def create_databases() -> None:
    logger.info("Connecting to PostgreSQL maintenance database (postgres)...")
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname="postgres",
        user=DB_USER,
        password=DB_PASSWORD,
    )
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
    existing_dbs = {row[0] for row in cur.fetchall()}

    for db_name in DATABASES:
        if db_name in existing_dbs:
            logger.info("Database '%s' already exists.", db_name)
        else:
            logger.info("Creating database '%s'...", db_name)
            cur.execute(f'CREATE DATABASE "{db_name}";')
            logger.info("Created database '%s'.", db_name)

    cur.close()
    conn.close()


def apply_schemas() -> None:
    for db_name, ddl in SCHEMA_MAP.items():
        logger.info("Applying schema to '%s'...", db_name)
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=db_name,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        conn.autocommit = True
        cur = conn.cursor()
        cur.execute(ddl)
        cur.close()
        conn.close()
        logger.info("Schema applied successfully to '%s'.", db_name)


def main() -> int:
    try:
        create_databases()
        apply_schemas()
        logger.info("All 4 threat-intelligence databases and schemas are ready!")
        return 0
    except Exception as exc:
        logger.exception("Failed to setup PostgreSQL databases: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
