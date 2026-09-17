"""
Core client profiling logic
===========================
Handles the insertion and updating of client profiles and their query history.
Uses PostgreSQL UPSERT for efficient, atomic operations with out-of-order event safety.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from labeler.config import CanonicalVerdict
from .db import get_pool

logger = logging.getLogger(__name__)

# Atomic UPSERT for client_profiles
UPSERT_CLIENT = """
INSERT INTO client_profiles (
    client_ip, first_seen, last_seen, total_queries, unique_domains,
    benign_queries, malicious_queries, review_needed_queries, unknown_queries,
    last_domain, last_query_type, updated_at
)
VALUES (%s, %s, %s, 1, 0, %s, %s, %s, %s, %s, %s, NOW())
ON CONFLICT (client_ip)
DO UPDATE SET
    first_seen = LEAST(client_profiles.first_seen, EXCLUDED.first_seen),
    last_seen = GREATEST(client_profiles.last_seen, EXCLUDED.last_seen),
    total_queries = client_profiles.total_queries + 1,
    benign_queries = client_profiles.benign_queries + EXCLUDED.benign_queries,
    malicious_queries = client_profiles.malicious_queries + EXCLUDED.malicious_queries,
    review_needed_queries = client_profiles.review_needed_queries + EXCLUDED.review_needed_queries,
    unknown_queries = client_profiles.unknown_queries + EXCLUDED.unknown_queries,
    last_domain = CASE WHEN EXCLUDED.last_seen >= client_profiles.last_seen THEN EXCLUDED.last_domain ELSE client_profiles.last_domain END,
    last_query_type = CASE WHEN EXCLUDED.last_seen >= client_profiles.last_seen THEN EXCLUDED.last_query_type ELSE client_profiles.last_query_type END,
    updated_at = NOW();
"""

# Atomic UPSERT for client_history with new-domain detection
UPSERT_HISTORY = """
INSERT INTO client_history (
    client_ip, domain, first_seen, last_seen, visit_count,
    benign_visits, malicious_visits, review_needed_visits, unknown_visits
)
VALUES (%s, %s, %s, %s, 1, %s, %s, %s, %s)
ON CONFLICT (client_ip, domain)
DO UPDATE SET
    first_seen = LEAST(client_history.first_seen, EXCLUDED.first_seen),
    last_seen = GREATEST(client_history.last_seen, EXCLUDED.last_seen),
    visit_count = client_history.visit_count + 1,
    benign_visits = client_history.benign_visits + EXCLUDED.benign_visits,
    malicious_visits = client_history.malicious_visits + EXCLUDED.malicious_visits,
    review_needed_visits = client_history.review_needed_visits + EXCLUDED.review_needed_visits,
    unknown_visits = client_history.unknown_visits + EXCLUDED.unknown_visits
RETURNING (xmax = 0) AS is_new_domain;
"""

UPDATE_CLIENT_UNIQUE_DOMAINS = """
UPDATE client_profiles
SET unique_domains = unique_domains + 1
WHERE client_ip = %s;
"""


def process_query(
    client_ip: str,
    domain: str,
    timestamp: Optional[datetime] = None,
    query_type: Optional[str] = None,
    final_label: Optional[str] = None,
) -> None:
    """
    Process a single DNS query into client profiling.
    
    Maintains client_profiles and client_history atomically with out-of-order
    event timestamp safety and canonical four-verdict counters.
    
    Args:
        client_ip (str): Client IP address (e.g. "192.168.1.100")
        domain (str): Queried domain (e.g. "google.com")
        timestamp (Optional[datetime]): DNS event timestamp. If None, defaults to current UTC.
        query_type (Optional[str]): DNS query type (A, AAAA, MX, etc.)
        final_label (Optional[str]): Canonical verdict (Benign, Malicious, Review Needed, Unknown)
    """
    # Input validation
    if not client_ip or not isinstance(client_ip, str) or not client_ip.strip():
        raise ValueError(f"Invalid client_ip: {client_ip}")
    
    if not domain or not isinstance(domain, str) or not domain.strip():
        raise ValueError(f"Invalid domain: {domain}")
    
    # Normalization
    domain = domain.lower().strip()
    client_ip = client_ip.strip()
    
    if timestamp is None:
        event_ts = datetime.now(timezone.utc)
    elif timestamp.tzinfo is None:
        event_ts = timestamp.replace(tzinfo=timezone.utc)
    else:
        event_ts = timestamp.astimezone(timezone.utc)
    
    q_type = str(query_type or "A").strip().upper()
    canon_verdict = CanonicalVerdict.from_str(final_label or "Unknown").value
    
    # Map verdict counters
    b_cnt = 1 if canon_verdict == CanonicalVerdict.BENIGN.value else 0
    m_cnt = 1 if canon_verdict == CanonicalVerdict.MALICIOUS.value else 0
    r_cnt = 1 if canon_verdict == CanonicalVerdict.REVIEW_NEEDED.value else 0
    u_cnt = 1 if canon_verdict == CanonicalVerdict.UNKNOWN.value else 0
    
    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                # 1. UPSERT client profile
                cur.execute(
                    UPSERT_CLIENT,
                    (
                        client_ip, event_ts, event_ts,
                        b_cnt, m_cnt, r_cnt, u_cnt,
                        domain, q_type,
                    ),
                )
                
                # 2. UPSERT client history (and detect if this is a newly seen domain)
                cur.execute(
                    UPSERT_HISTORY,
                    (
                        client_ip, domain, event_ts, event_ts,
                        b_cnt, m_cnt, r_cnt, u_cnt,
                    ),
                )
                
                row = cur.fetchone()
                is_new_domain = bool(row[0]) if row else False
                
                # 3. If new domain for this client, increment unique_domains counter
                if is_new_domain:
                    cur.execute(UPDATE_CLIENT_UNIQUE_DOMAINS, (client_ip,))
                
                conn.commit()
                
                logger.debug(
                    "Processed client query: ip=%s, domain=%s, ts=%s, verdict=%s",
                    client_ip, domain, event_ts, canon_verdict,
                )
                
    except Exception as e:
        logger.error(
            "Failed to process client query (ip=%s, domain=%s): %s",
            client_ip, domain, e,
        )
        raise


def get_client_profile(client_ip: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a client's complete lifetime profile.
    
    Args:
        client_ip (str): The client's IP address
        
    Returns:
        dict: Complete client profile fields, or None if not found.
    """
    if not client_ip or not isinstance(client_ip, str) or not client_ip.strip():
        return None

    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 
                        host(client_ip) AS client_ip,
                        first_seen, last_seen, total_queries, unique_domains,
                        benign_queries, malicious_queries, review_needed_queries, unknown_queries,
                        last_domain, last_query_type, created_at, updated_at
                    FROM client_profiles
                    WHERE client_ip = %s;
                    """,
                    (client_ip.strip(),),
                )
                
                row = cur.fetchone()
                if row:
                    return {
                        "client_ip": str(row[0]),
                        "first_seen": row[1],
                        "last_seen": row[2],
                        "total_queries": int(row[3]),
                        "unique_domains": int(row[4]),
                        "benign_queries": int(row[5]),
                        "malicious_queries": int(row[6]),
                        "review_needed_queries": int(row[7]),
                        "unknown_queries": int(row[8]),
                        "last_domain": row[9],
                        "last_query_type": row[10],
                        "created_at": row[11],
                        "updated_at": row[12],
                    }
                return None
                
    except Exception as e:
        logger.error("Failed to get client profile for %s: %s", client_ip, e)
        raise


def get_client_history(client_ip: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Retrieve a client's domain interaction history.
    
    Args:
        client_ip (str): The client's IP address
        limit (int): Maximum records to return
        
    Returns:
        list: List of dicts containing domain interaction metrics.
    """
    if not client_ip or not isinstance(client_ip, str) or not client_ip.strip():
        return []

    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT 
                        domain, first_seen, last_seen, visit_count,
                        benign_visits, malicious_visits, review_needed_visits, unknown_visits
                    FROM client_history
                    WHERE client_ip = %s
                    ORDER BY last_seen DESC
                    LIMIT %s;
                    """,
                    (client_ip.strip(), limit),
                )
                
                rows = cur.fetchall()
                return [
                    {
                        "domain": row[0],
                        "first_seen": row[1],
                        "last_seen": row[2],
                        "visit_count": int(row[3]),
                        "benign_visits": int(row[4]),
                        "malicious_visits": int(row[5]),
                        "review_needed_visits": int(row[6]),
                        "unknown_visits": int(row[7]),
                    }
                    for row in rows
                ]
                
    except Exception as e:
        logger.error("Failed to get client history for %s: %s", client_ip, e)
        raise