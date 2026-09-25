"""
Repository Module
=================
Provides all CRUD functions for interacting with the ``reputation_domains``
table in PostgreSQL.

Features:
- Atomic upsert (INSERT ... ON CONFLICT DO UPDATE) for deduplication.
- Explicit evidence scope preservation (EXACT_FQDN, REGISTERED_DOMAIN, ROOT_ARTIFACT, CORRELATED, EXTERNAL_PROVIDER, LEGACY).
- Reusable connection helpers with automatic rollback on error.
- Thread-safe via psycopg2 ThreadedConnectionPool.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional, Tuple, List

import psycopg2.extras
import tldextract

from .connection import get_connection, close_pool
from ..manager import is_trusted
from ..malicious import is_malicious

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & Defaults
# ---------------------------------------------------------------------------
_DEFAULT_STATUS: str = "malicious"
_DEFAULT_SOURCE: str = "URLHaus"
_DEFAULT_DAYS: int = 180

# Valid match scopes
VALID_MATCH_SCOPES = {
    "EXACT_FQDN",
    "REGISTERED_DOMAIN",
    "ROOT_ARTIFACT",
    "CORRELATED",
    "EXTERNAL_PROVIDER",
    "LEGACY",
}


def _extract_registered_domain(domain: str) -> str:
    """Helper to extract registered domain using tldextract."""
    cleaned = (domain or "").strip().lower().rstrip(".")
    if not cleaned:
        return ""
    ext = tldextract.extract(cleaned)
    rd = getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain
    return rd or cleaned


def initialize_database() -> bool:
    """Initialize or migrate the reputation database schema and indexes."""
    from .schema import create_reputation_table
    with get_connection() as conn:
        return create_reputation_table(conn)


# ──────────────────────────────────────────────────────────────────────
# Insert / Upsert
# ──────────────────────────────────────────────────────────────────────
def store_malicious_domain(
    domain: str,
    metadata: Optional[dict[str, Any]] = None,
) -> bool:
    """Store a malicious domain in the reputation database with scope provenance.

    Parameters
    ----------
    domain : str
        The fully-qualified domain name to store (e.g. ``evil.example``).
    metadata : dict or None
        Optional overrides for the row columns:
        * ``source``         — threat-intel source name (default ``URLHaus``)
        * ``confidence``     — float confidence score (default ``None``)
        * ``match_scope``    — evidence scope (e.g. ``EXACT_FQDN``, ``REGISTERED_DOMAIN``, ``CORRELATED``)
        * ``matched_domain`` — exact string that matched in the TI feed
        * ``query_count``    — int (default ``1``)
        * ``client_ip``      — originating client IP (default ``None``)
        * ``query_type``     — DNS query type (default ``None``)

    Returns
    -------
    bool
        ``True`` if a new row was inserted, ``False`` if an existing row
        was updated or if persistence was rejected by policy.
    """
    metadata = metadata or {}
    clean_domain = (domain or "").strip().lower().rstrip(".")
    if not clean_domain:
        return False

    source: str = metadata.get("source", _DEFAULT_SOURCE)
    confidence: Optional[float] = metadata.get("confidence")
    match_scope: Optional[str] = metadata.get("match_scope")
    matched_domain: Optional[str] = metadata.get("matched_domain") or clean_domain
    query_count: int = metadata.get("query_count", 1)
    client_ip: Optional[str] = metadata.get("client_ip")
    query_type: Optional[str] = metadata.get("query_type")

    # Normalize match_scope
    if match_scope not in VALID_MATCH_SCOPES:
        match_scope = "LEGACY" if match_scope is None else match_scope

    # ──────────────────────────────────────────────────────────────────
    # Persistence Invariant Guard:
    # 1. ROOT_ARTIFACT must NEVER become active malicious reputation.
    # 2. A Tranco apex domain from URLhaus must not be persisted as malicious
    #    unless an exact FQDN match exists on a distinct subdomain.
    # ──────────────────────────────────────────────────────────────────
    if match_scope == "ROOT_ARTIFACT":
        logger.debug(
            "Persistence blocked for %s: match_scope is ROOT_ARTIFACT.", clean_domain
        )
        return False

    if source == "URLHaus" and match_scope != "EXACT_FQDN" and is_trusted(clean_domain):
        logger.warning(
            "Persistence blocked for %s: Tranco apex domain with non-exact URLhaus scope (%s).",
            clean_domain,
            match_scope,
        )
        return False

    upsert_sql: str = """
        INSERT INTO reputation_domains
            (domain, status, source, confidence, match_scope, matched_domain,
             first_seen, last_seen, times_seen, query_count, client_ip, query_type, created_at, updated_at)
        VALUES
            (%s, %s, %s, %s, %s, %s, NOW(), NOW(), 1, %s, %s, %s, NOW(), NOW())
        ON CONFLICT (domain) DO UPDATE
            SET last_seen      = NOW(),
                times_seen     = reputation_domains.times_seen + 1,
                query_count    = reputation_domains.query_count + %s,
                match_scope    = COALESCE(EXCLUDED.match_scope, reputation_domains.match_scope),
                matched_domain = COALESCE(EXCLUDED.matched_domain, reputation_domains.matched_domain),
                client_ip      = EXCLUDED.client_ip,
                query_type     = EXCLUDED.query_type,
                updated_at     = NOW()
        RETURNING (xmax = 0) AS inserted;
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                upsert_sql,
                (
                    clean_domain,
                    _DEFAULT_STATUS,
                    source,
                    confidence,
                    match_scope,
                    matched_domain,
                    query_count,
                    client_ip,
                    query_type,
                    query_count,
                ),
            )
            inserted: bool = cur.fetchone()[0]

    if inserted:
        logger.info("Inserted malicious domain: %s (source=%s, scope=%s)", clean_domain, source, match_scope)
    else:
        logger.info("Updated existing malicious domain: %s (scope=%s)", clean_domain, match_scope)

    return inserted


# ──────────────────────────────────────────────────────────────────────
# Select
# ──────────────────────────────────────────────────────────────────────
def get_domain(domain: str) -> Optional[dict[str, Any]]:
    """Fetch a single domain's reputation record."""
    clean_domain = (domain or "").strip().lower().rstrip(".")
    if not clean_domain:
        return None

    sql: str = "SELECT * FROM reputation_domains WHERE domain = %s;"
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (clean_domain,))
            row = cur.fetchone()

    if row is None:
        return None

    return dict(row)


def get_domains_by_status(status: str) -> list[dict[str, Any]]:
    """Fetch all domains matching a given status."""
    sql: str = "SELECT * FROM reputation_domains WHERE status = %s ORDER BY last_seen DESC;"
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (status,))
            rows = cur.fetchall()
    return [dict(r) for r in rows]


def get_recent_domains(limit: int = 50) -> list[dict[str, Any]]:
    """Fetch the most recently seen domains."""
    sql: str = "SELECT * FROM reputation_domains ORDER BY last_seen DESC LIMIT %s;"
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (limit,))
            rows = cur.fetchall()
    return [dict(r) for r in rows]


def count_domains(status: Optional[str] = None) -> int:
    """Return total number of domains in the table."""
    if status is not None:
        sql = "SELECT COUNT(*) FROM reputation_domains WHERE status = %s;"
        params: tuple = (status,)
    else:
        sql = "SELECT COUNT(*) FROM reputation_domains;"
        params = ()

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return cur.fetchone()[0]


# ──────────────────────────────────────────────────────────────────────
# Update (generic)
# ──────────────────────────────────────────────────────────────────────
def update_domain(domain: str, **kwargs: Any) -> bool:
    """Update arbitrary columns on an existing domain record."""
    if not kwargs:
        return False

    clean_domain = (domain or "").strip().lower().rstrip(".")
    set_clauses: list[str] = []
    values: list[Any] = []
    for col, val in kwargs.items():
        set_clauses.append(f"{col} = %s")
        values.append(val)

    set_clauses.append("updated_at = NOW()")
    values.append(clean_domain)

    sql: str = f"UPDATE reputation_domains SET {', '.join(set_clauses)} WHERE domain = %s;"

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, values)
            updated: int = cur.rowcount

    return updated > 0


def remove_malicious_domain(domain: str) -> bool:
    """Delete a domain from reputation_domains if it is no longer malicious."""
    clean_domain = (domain or "").strip().lower().rstrip(".")
    if not clean_domain:
        return False
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM reputation_domains WHERE domain = %s;", (clean_domain,))
            return cur.rowcount > 0


# ──────────────────────────────────────────────────────────────────────
# Cleanup & Reconciliation
# ──────────────────────────────────────────────────────────────────────
def cleanup_old_domains(days: int = _DEFAULT_DAYS) -> int:
    """Delete records whose ``last_seen`` is older than *days*."""
    sql: str = "DELETE FROM reputation_domains WHERE CURRENT_DATE - last_seen::date > %s;"
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (days,))
            deleted: int = cur.rowcount

    if deleted:
        logger.info("Deleted %d expired records (last_seen > %d days).", deleted, days)
    return deleted


def reconcile_reputation_records() -> dict[str, Any]:
    """Audit and reconcile legacy / unclassified rows in reputation_domains.

    Applies conservative classification to existing rows based on raw intelligence:
    - Case A: URLHaus source on Tranco apex domain -> ROOT_ARTIFACT -> Purged from active reputation.
    - Case B: URLHaus source on subdomain where exact URLhaus entry exists -> EXACT_FQDN -> Retained.
    - Case C: URLHaus source where registered domain is in URLhaus and not in Tranco -> REGISTERED_DOMAIN -> Retained.
    - Case D: Threat Correlation Engine source -> CORRELATED -> Retained.
    - Case E: Subdomain of Tranco apex domain with NO exact URLhaus match (un-gated fallback artifact) -> ROOT_ARTIFACT -> Purged.
    - Case F: Insufficient evidence -> LEGACY.

    Returns summary dictionary of reconciliation results.
    """
    stats = {
        "total_examined": 0,
        "exact_fqdn": 0,
        "registered_domain": 0,
        "root_artifacts_purged": 0,
        "correlated": 0,
        "legacy": 0,
        "active_remaining": 0,
    }

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, domain, status, source, confidence, match_scope FROM reputation_domains ORDER BY id;")
            rows = cur.fetchall()

        stats["total_examined"] = len(rows)
        ids_to_purge: list[int] = []

        for row in rows:
            row_id: int = row["id"]
            d: str = row["domain"]
            src: str = row.get("source") or ""
            current_scope: Optional[str] = row.get("match_scope")
            reg_d: str = _extract_registered_domain(d)

            # Determine appropriate scope
            if src == "Threat Correlation Engine":
                new_scope = "CORRELATED"
                matched_d = d
                stats["correlated"] += 1
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE reputation_domains SET match_scope = %s, matched_domain = %s, updated_at = NOW() WHERE id = %s;",
                        (new_scope, matched_d, row_id),
                    )

            elif src == "URLHaus":
                is_apex = (d == reg_d)
                d_is_trusted = is_trusted(d)
                reg_is_trusted = is_trusted(reg_d)
                d_in_urlhaus = is_malicious(d)
                reg_in_urlhaus = is_malicious(reg_d) if reg_d else False

                if is_apex and d_is_trusted:
                    # Case A: Tranco apex with URLhaus root artifact
                    new_scope = "ROOT_ARTIFACT"
                    stats["root_artifacts_purged"] += 1
                    ids_to_purge.append(row_id)

                elif not is_apex and reg_is_trusted and not d_in_urlhaus:
                    # Case E: Subdomain of Tranco apex domain created by old ungated fallback
                    new_scope = "ROOT_ARTIFACT"
                    stats["root_artifacts_purged"] += 1
                    ids_to_purge.append(row_id)

                elif not is_apex and d_in_urlhaus:
                    # Case B: Exact FQDN match on subdomain
                    new_scope = "EXACT_FQDN"
                    matched_d = d
                    stats["exact_fqdn"] += 1
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE reputation_domains SET match_scope = %s, matched_domain = %s, updated_at = NOW() WHERE id = %s;",
                            (new_scope, matched_d, row_id),
                        )

                elif not is_apex and not reg_is_trusted and reg_in_urlhaus:
                    # Case C: Untrusted registered domain fallback
                    new_scope = "REGISTERED_DOMAIN"
                    matched_d = reg_d
                    stats["registered_domain"] += 1
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE reputation_domains SET match_scope = %s, matched_domain = %s, updated_at = NOW() WHERE id = %s;",
                            (new_scope, matched_d, row_id),
                        )

                elif is_apex and not d_is_trusted and d_in_urlhaus:
                    # Apex domain in URLhaus, untrusted in Tranco
                    new_scope = "EXACT_FQDN"
                    matched_d = d
                    stats["exact_fqdn"] += 1
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE reputation_domains SET match_scope = %s, matched_domain = %s, updated_at = NOW() WHERE id = %s;",
                            (new_scope, matched_d, row_id),
                        )
                else:
                    new_scope = "LEGACY"
                    stats["legacy"] += 1
                    with conn.cursor() as cur:
                        cur.execute(
                            "UPDATE reputation_domains SET match_scope = %s, updated_at = NOW() WHERE id = %s;",
                            (new_scope, row_id),
                        )
            else:
                new_scope = "LEGACY"
                stats["legacy"] += 1
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE reputation_domains SET match_scope = %s, updated_at = NOW() WHERE id = %s;",
                        (new_scope, row_id),
                    )

        # Purge demonstrably invalid root artifacts from active reputation
        if ids_to_purge:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM reputation_domains WHERE id = ANY(%s);", (ids_to_purge,))
            conn.commit()

        # Count active remaining
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM reputation_domains;")
            stats["active_remaining"] = cur.fetchone()[0]

    logger.info("Reputation reconciliation completed: %s", stats)
    return stats


# ──────────────────────────────────────────────────────────────────────
# Connection lifecycle
# ──────────────────────────────────────────────────────────────────────
def close_connection() -> None:
    """Close the PostgreSQL connection pool."""
    close_pool()