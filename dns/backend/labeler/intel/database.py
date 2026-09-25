from datetime import datetime, timezone
from pathlib import Path
import os
import logging
import threading
from typing import Optional, Dict, Any, List

import psycopg2
import psycopg2.pool
import psycopg2.extras

from . import config

logger = logging.getLogger(__name__)


class TrustedDatabaseError(Exception):
    pass


_THREAD_LOCAL = threading.local()
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
                        host=config.DB_HOST,
                        port=config.DB_PORT,
                        dbname=config.DB_DATABASE,
                        user=config.DB_USERNAME,
                        password=config.DB_PASSWORD,
                    )
                except Exception as exc:
                    raise TrustedDatabaseError(
                        f"Failed to connect to PostgreSQL trusted_db at {config.DB_HOST}:{config.DB_PORT}/{config.DB_DATABASE}"
                    ) from exc
    return _POOL


def get_pg_connection():
    pool = get_connection_pool()
    return pool.getconn()


def release_pg_connection(conn):
    if _POOL and conn:
        try:
            _POOL.putconn(conn)
        except Exception:
            pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp_now() -> str:
    return utc_now().isoformat(timespec="seconds")


def parse_timestamp(value: str) -> datetime | None:
    if not value:
        return None

    try:
        normalized = value.strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        parsed = datetime.fromisoformat(normalized)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def normalize_domain(domain: str) -> str:
    if not isinstance(domain, str):
        return ""

    value = domain.strip().strip("'\"").lower()

    if not value:
        return ""

    value = value.replace("\\", "/")

    if "://" in value:
        value = value.split("://", 1)[1]

    if value.startswith("//"):
        value = value[2:]

    value = value.split("/", 1)[0]
    value = value.split("?", 1)[0]
    value = value.split("#", 1)[0]

    if "@" in value:
        value = value.rsplit("@", 1)[1]

    if value.startswith("["):
        return ""

    if ":" in value:
        value = value.split(":", 1)[0]

    value = value.strip().strip(".")

    if not value or len(value) > 253:
        return ""

    try:
        ascii_domain = value.encode("idna").decode("ascii").lower().strip(".")
    except UnicodeError:
        return ""

    if not ascii_domain or len(ascii_domain) > 253:
        return ""

    labels = ascii_domain.split(".")

    if len(labels) < 2:
        return ""

    for label in labels:
        if not label or len(label) > 63:
            return ""

        if label.startswith("-") or label.endswith("-"):
            return ""

        for character in label:
            if not (character.isascii() and (character.isalnum() or character == "-")):
                return ""

    if labels[-1].isdigit():
        return ""

    return ascii_domain


def is_domain_trusted(domain: str, database_path: Optional[Path] = None) -> bool:
    normalized_domain = normalize_domain(domain)
    if not normalized_domain:
        return False

    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM trusted_domains WHERE domain = %s LIMIT 1",
                (normalized_domain,),
            )
            return cur.fetchone() is not None
    except Exception as exc:
        logger.error("Trusted domain lookup failed for %s: %s", domain, exc)
        raise TrustedDatabaseError("Trusted domain lookup failed") from exc
    finally:
        if conn:
            release_pg_connection(conn)


def read_metadata(database_path: Optional[Path] = None) -> Dict[str, str]:
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT key, value FROM metadata")
            rows = cur.fetchall()
            return {str(k): str(v) for k, v in rows}
    except Exception as exc:
        logger.warning("Failed to read trusted domains metadata: %s", exc)
        return {}
    finally:
        if conn:
            release_pg_connection(conn)


def validate_database(
    database_path: Optional[Path] = None,
    expected_count: Optional[int] = None,
    require_integrity: bool = False,
) -> bool:
    conn = None
    try:
        conn = get_pg_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM trusted_domains")
            count = cur.fetchone()[0]
            if count <= 0:
                raise TrustedDatabaseError("trusted_domains table is empty")
            if expected_count is not None and count != expected_count:
                raise TrustedDatabaseError(f"Expected {expected_count} records, found {count}")
            return True
    except Exception as exc:
        raise TrustedDatabaseError("Trusted database validation failed") from exc
    finally:
        if conn:
            release_pg_connection(conn)