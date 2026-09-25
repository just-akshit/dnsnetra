# backend/labeler/intel/daily_review.py
"""
Daily Review Database Synchronous Lookup (PostgreSQL).

Provides high-performance, thread-safe synchronous lookups into `daily_review_db.unknown_domains`
for Local Intelligence Stage 5.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.extras
import psycopg2.pool
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

DB_HOST = os.getenv("DAILY_REVIEW_DB_HOST", os.getenv("DB_HOST", "localhost"))
DB_PORT = int(os.getenv("DAILY_REVIEW_DB_PORT", os.getenv("DB_PORT", "5432")))
DB_DATABASE = os.getenv("DAILY_REVIEW_DB_DATABASE", "daily_review_db")
DB_USERNAME = os.getenv("DAILY_REVIEW_DB_USERNAME", os.getenv("DB_USER", "postgres"))
DB_PASSWORD = os.getenv("DAILY_REVIEW_DB_PASSWORD", os.getenv("DB_PASSWORD", ""))

_POOL: Optional[psycopg2.pool.ThreadedConnectionPool] = None
_POOL_LOCK = threading.Lock()


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
                except psycopg2.OperationalError as exc:
                    logger.error("Failed to connect to Daily Review DB: %s", exc)
                    raise
    return _POOL


def close_connection_pool() -> None:
    global _POOL
    with _POOL_LOCK:
        if _POOL is not None:
            _POOL.closeall()
            _POOL = None


def get_daily_review_verdict(domain: str) -> Optional[Dict[str, Any]]:
    """
    Synchronous indexed lookup in daily_review_db.unknown_domains.

    Args:
        domain: FQDN or registered domain name to check.

    Returns:
        Dict containing domain, status, previous_status, query_count,
        first_seen, last_seen, last_checked if found, else None.
    """
    if not domain or not isinstance(domain, str):
        return None

    normalized = domain.strip().lower().rstrip(".")
    if not normalized:
        return None

    pool = None
    conn = None
    try:
        pool = get_connection_pool()
        conn = pool.getconn()
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            cur.execute(
                """
                SELECT domain, status, previous_status, query_count, first_seen, last_seen, last_checked
                FROM unknown_domains
                WHERE domain = %s
                LIMIT 1;
                """,
                (normalized,),
            )
            row = cur.fetchone()
            if row:
                return {
                    "domain": row["domain"],
                    "status": str(row["status"]).lower() if row["status"] else None,
                    "previous_status": str(row["previous_status"]).lower() if row["previous_status"] else None,
                    "query_count": row["query_count"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "last_checked": row["last_checked"],
                }
            return None
    except Exception as exc:
        logger.warning("Daily review lookup failed for '%s': %s", normalized, exc)
        return None
    finally:
        if pool is not None and conn is not None:
            pool.putconn(conn)
