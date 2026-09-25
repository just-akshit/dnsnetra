# labeler/intel/malicious/database.py
"""
Malicious Domain Database Implementation (PostgreSQL).

Handles PostgreSQL connection pooling, exact-match queries, batch insertions, and metadata.
"""

from __future__ import annotations

import os
import logging
import threading
from typing import Optional, Any, List

import psycopg2
import psycopg2.pool
import psycopg2.extras

from .config import (
    DB_HOST,
    DB_PORT,
    DB_DATABASE,
    DB_USERNAME,
    DB_PASSWORD,
    DB_PATH,
)

logger = logging.getLogger(__name__)


# --- Custom Exceptions ---
class MaliciousDatabaseError(Exception):
    """Base exception for all malicious database errors."""
    pass


class MaliciousDBConnectionError(MaliciousDatabaseError):
    """Raised when a database connection fails."""
    pass


class MaliciousDBValidationError(MaliciousDatabaseError):
    """Raised when database validation fails."""
    pass


# --- Connection Pool ---
_POOL: Optional[psycopg2.pool.ThreadedConnectionPool] = None
_POOL_LOCK = threading.Lock()
_local = threading.local()


def get_connection_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _POOL
    if _POOL is None:
        with _POOL_LOCK:
            if _POOL is None:
                try:
                    _POOL = psycopg2.pool.ThreadedConnectionPool(
                        minconn=1,
                        maxconn=10,
                        host=DB_HOST,
                        port=DB_PORT,
                        dbname=DB_DATABASE,
                        user=DB_USERNAME,
                        password=DB_PASSWORD,
                    )
                except Exception as e:
                    logger.error(f"Failed to connect to PostgreSQL malicious_db at {DB_HOST}:{DB_PORT}/{DB_DATABASE}: {e}")
                    raise MaliciousDBConnectionError(f"Database connection failed: {e}")
    return _POOL


def initialize_db_structure(db_path: str = DB_PATH) -> None:
    """Verifies that malicious_domains table exists in PostgreSQL."""
    try:
        pool = get_connection_pool()
        conn = pool.getconn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM malicious_domains LIMIT 1;")
        pool.putconn(conn)
    except Exception as e:
        logger.debug(f"DB structure check: {e}")


def validate_integrity(db_path: str = DB_PATH) -> bool:
    """Validates connectivity to PostgreSQL malicious_db."""
    try:
        pool = get_connection_pool()
        conn = pool.getconn()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM malicious_domains;")
            count = cur.fetchone()[0]
        pool.putconn(conn)
        return count > 0
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        return False


def verify_schema(db_path: str = DB_PATH) -> bool:
    """Verifies that malicious_domains table exists."""
    return validate_integrity(db_path)


def get_connection(db_path: str = DB_PATH):
    """Retrieves a connection from the pool."""
    pool = get_connection_pool()
    return pool.getconn()


def close_connection():
    """No-op for thread-local or releases connections if needed."""
    pass


def release_connection(conn):
    if _POOL and conn:
        try:
            _POOL.putconn(conn)
        except Exception:
            pass


def execute_query(query: str, params: tuple = ()) -> Optional[Any]:
    """
    Executes a query against malicious_db.
    Converts SQLite '?' parameter placeholders to PostgreSQL '%s' if necessary.
    """
    pg_query = query.replace("?", "%s")
    conn = None
    try:
        pool = get_connection_pool()
        conn = pool.getconn()
        with conn.cursor() as cursor:
            cursor.execute(pg_query, params)
            return cursor.fetchone()
    except Exception as e:
        logger.error(f"Failed to execute query '{pg_query}': {e}")
        return None
    finally:
        if _POOL and conn:
            try:
                _POOL.putconn(conn)
            except Exception:
                pass


def execute_many_queries(queries: List[tuple], db_path: str = DB_PATH) -> int:
    """
    Executes batch insertions into PostgreSQL malicious_domains table.
    """
    conn = None
    try:
        pool = get_connection_pool()
        conn = pool.getconn()
        conn.autocommit = False
        with conn.cursor() as cur:
            insert_sql = """
                INSERT INTO malicious_domains (domain, source, downloaded_at, created_at, updated_at)
                VALUES (%s, %s, NOW(), NOW(), NOW())
                ON CONFLICT (domain) DO UPDATE SET
                    source = EXCLUDED.source,
                    updated_at = NOW();
            """
            rows = [(q[1], "urlhaus") if len(q) > 1 else (q[0], "urlhaus") for q in queries]
            psycopg2.extras.execute_batch(cur, insert_sql, rows, page_size=1000)
        conn.commit()
        return len(queries)
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        logger.error(f"Batch write transaction failed: {e}")
        raise MaliciousDBValidationError(f"Batch insert failed: {e}")
    finally:
        if _POOL and conn:
            try:
                _POOL.putconn(conn)
            except Exception:
                pass


def get_metadata_value(key: str) -> Optional[str]:
    """Retrieves a metadata value from PostgreSQL metadata table."""
    conn = None
    try:
        pool = get_connection_pool()
        conn = pool.getconn()
        with conn.cursor() as cur:
            cur.execute("SELECT value FROM metadata WHERE key = %s LIMIT 1", (key,))
            row = cur.fetchone()
            return row[0] if row else None
    except Exception as e:
        logger.debug(f"Failed to get metadata key '{key}': {e}")
        return None
    finally:
        if _POOL and conn:
            try:
                _POOL.putconn(conn)
            except Exception:
                pass


def set_metadata_value(key: str, value: str) -> None:
    """Sets a metadata value in PostgreSQL metadata table."""
    conn = None
    try:
        pool = get_connection_pool()
        conn = pool.getconn()
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO metadata (key, value, updated_at)
                VALUES (%s, %s, NOW())
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW();
                """,
                (key, value),
            )
    except Exception as e:
        logger.error(f"Failed to set metadata key '{key}': {e}")
    finally:
        if _POOL and conn:
            try:
                _POOL.putconn(conn)
            except Exception:
                pass