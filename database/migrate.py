"""
Database Migration Runner for DNSNetra
======================================
Executes SQL migrations idempotently against PostgreSQL.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import psycopg2
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env", override=True)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migrate")


def get_connection():
    return psycopg2.connect(
        host=os.getenv("UDR_DB_HOST", "localhost"),
        port=int(os.getenv("UDR_DB_PORT", "5432")),
        dbname=os.getenv("UDR_DB_DATABASE", "dns_threat_detection"),
        user=os.getenv("UDR_DB_USERNAME", "postgres"),
        password=os.getenv("UDR_DB_PASSWORD", "Akshit!1"),
    )


def run_migrations():
    migrations_dir = PROJECT_ROOT / "database" / "migrations"
    migration_files = sorted(migrations_dir.glob("*.sql"))

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    migration_name VARCHAR(100) PRIMARY KEY,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                );
            """)
            conn.commit()

            for sql_file in migration_files:
                name = sql_file.name
                cur.execute("SELECT 1 FROM schema_migrations WHERE migration_name = %s;", (name,))
                if cur.fetchone():
                    logger.info("Migration %s already applied.", name)
                    continue

                logger.info("Applying migration %s...", name)
                sql = sql_file.read_text(encoding="utf-8")
                cur.execute(sql)
                cur.execute("INSERT INTO schema_migrations (migration_name) VALUES (%s);", (name,))
                conn.commit()
                logger.info("Migration %s applied successfully.", name)


if __name__ == "__main__":
    run_migrations()
