"""
Dashboard Integration — PostgreSQL Repository
===============================================
Read-only queries against the existing backend's PostgreSQL tables:
  - domain_profiles
  - domain_query_history
  - client_profiles
  - client_history

This module does NOT create, modify, or own these tables.
They belong to the backend (domain_profiling/ and client_profiling/).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from .models import DomainDetail

logger = logging.getLogger(__name__)


def _get_pg_connection() -> Any | None:
    """
    Connects to the backend's PostgreSQL using the same env vars
    the backend itself uses (DB_HOST, DB_PORT, etc.).
    Returns None if unavailable.
    """
    try:
        import psycopg
        import os
        from dotenv import load_dotenv
        from pathlib import Path

        load_dotenv(Path(__file__).parent.parent / "api.env")
        load_dotenv(Path(__file__).parent.parent / ".env")

        conn = psycopg.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            dbname=os.getenv("DB_NAME", "dns_threat_detection"),
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "postgres"),
            connect_timeout=5,
        )
        return conn
    except Exception as exc:
        logger.warning("PostgreSQL unavailable for dashboard integration: %s", exc)
        return None


def get_domain_detail(domain: str) -> Optional[DomainDetail]:
    """
    Fetches enriched domain information from the backend's PostgreSQL.
    Returns None if the domain is not found or PostgreSQL is unavailable.
    """
    conn = _get_pg_connection()
    if conn is None:
        return None

    try:
        import psycopg

        with conn.cursor() as cur:
            # 1. Domain profile
            cur.execute(
                """
                SELECT
                    domain, total_queries, unique_clients,
                    first_seen::text, last_seen::text,
                    last_label, last_ti_source,
                    malicious_queries, clean_queries, unknown_queries,
                    query_a_count, query_aaaa_count, query_mx_count,
                    query_txt_count, query_ns_count, query_other_count
                FROM domain_profiles
                WHERE domain = %s
                """,
                (domain,),
            )
            row = cur.fetchone()
            if row is None:
                return None

            detail = DomainDetail(
                domain=row[0],
                total_queries=row[1] or 0,
                unique_clients=row[2] or 0,
                first_seen=row[3],
                last_seen=row[4],
                last_label=row[5],
                last_ti_source=row[6],
                malicious_queries=row[7] or 0,
                clean_queries=row[8] or 0,
                unknown_queries=row[9] or 0,
                query_a_count=row[10] or 0,
                query_aaaa_count=row[11] or 0,
                query_mx_count=row[12] or 0,
                query_txt_count=row[13] or 0,
                query_ns_count=row[14] or 0,
                query_other_count=row[15] or 0,
            )

            # 2. Recent client IPs that queried this domain
            cur.execute(
                """
                SELECT DISTINCT client_ip::text
                FROM domain_query_history
                WHERE domain = %s
                ORDER BY client_ip
                LIMIT 20
                """,
                (domain,),
            )
            detail.recent_clients = [r[0] for r in cur.fetchall()]

            # 3. Query types used for this domain
            cur.execute(
                """
                SELECT DISTINCT query_type
                FROM domain_query_history
                WHERE domain = %s
                """,
                (domain,),
            )
            detail.recent_query_types = [r[0] for r in cur.fetchall()]

        conn.close()
        return detail

    except Exception as exc:
        logger.warning("Failed to fetch domain detail for %s: %s", domain, exc)
        try:
            conn.close()
        except Exception:
            pass
        return None
