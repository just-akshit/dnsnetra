"""
PostgreSQL Database Helper
==========================
Connection pool manager for the PostgreSQL database,
used exclusively for Authentication (dashboard_users).
"""

from __future__ import annotations

import os
from collections.abc import Generator
from contextlib import contextmanager
import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()

def get_pg_connection_string() -> str:
    """Constructs the PostgreSQL connection string from environment variables."""
    host = os.environ.get("DB_HOST", "localhost")
    port = os.environ.get("DB_PORT", "5432")
    dbname = os.environ.get("DB_NAME", "dns_threat_detection")
    user = os.environ.get("DB_USER", "postgres")
    password = os.environ.get("DB_PASSWORD", "postgres")
    return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"

@contextmanager
def get_pg_db() -> Generator[psycopg.Connection, None, None]:
    """
    Context manager for a PostgreSQL database connection.
    Yields a connection configured to return dictionary rows.
    """
    conn_info = get_pg_connection_string()
    with psycopg.connect(conn_info, row_factory=dict_row) as conn:
        yield conn
