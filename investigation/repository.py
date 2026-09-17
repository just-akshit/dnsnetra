"""
investigation/repository.py
===========================
PostgreSQL data access layer for DNSNetra Investigation Engine.
Pure SQL, parameterized queries, deterministic sorting, and zero HTTP dependencies.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional
import psycopg2
import psycopg2.extras

from domain_profiling.connection import get_db_connection

logger = logging.getLogger(__name__)


def _sanitize_evidence_summary(vt: Any, otx: Any) -> Optional[Dict[str, Any]]:
    """
    Safely extract a strict whitelisted summary of VT/OTX evidence payloads.
    Only explicitly defined stable counters are exposed:
      - VirusTotal: provider, malicious_count, harmless_count, suspicious_count
      - AlienVault OTX: provider, pulse_count
    Arbitrary third-party keys, raw JSON, or nested dumps are strictly ignored and never leaked.
    Tolerates NULL, empty, or unexpected JSON structures by returning None.
    """
    evidence: Dict[str, Any] = {}

    # 1. VirusTotal whitelist extraction
    if isinstance(vt, dict) and vt:
        vt_stats: Optional[Dict[str, Any]] = None
        if "malicious_count" in vt and "harmless_count" in vt:
            try:
                vt_stats = {
                    "provider": "VirusTotal",
                    "malicious_count": int(vt["malicious_count"]),
                    "harmless_count": int(vt["harmless_count"]),
                    "suspicious_count": int(vt.get("suspicious_count", 0)),
                }
            except (TypeError, ValueError):
                vt_stats = None
        elif "data" in vt and isinstance(vt.get("data"), dict):
            stats = vt["data"].get("attributes", {}).get("last_analysis_stats", {})
            if isinstance(stats, dict) and "malicious" in stats and "harmless" in stats:
                try:
                    vt_stats = {
                        "provider": "VirusTotal",
                        "malicious_count": int(stats["malicious"]),
                        "harmless_count": int(stats["harmless"]),
                        "suspicious_count": int(stats.get("suspicious", 0)),
                    }
                except (TypeError, ValueError):
                    vt_stats = None
        if vt_stats:
            evidence["virustotal"] = vt_stats

    # 2. AlienVault OTX whitelist extraction
    if isinstance(otx, dict) and otx:
        otx_stats: Optional[Dict[str, Any]] = None
        pulse_info = None
        if "pulse_info" in otx and isinstance(otx["pulse_info"], dict):
            pulse_info = otx["pulse_info"]
        elif (
            "general" in otx
            and isinstance(otx["general"], dict)
            and "pulse_info" in otx["general"]
            and isinstance(otx["general"]["pulse_info"], dict)
        ):
            pulse_info = otx["general"]["pulse_info"]

        if pulse_info is not None:
            if "count" in pulse_info and isinstance(pulse_info["count"], (int, float)):
                try:
                    otx_stats = {
                        "provider": "AlienVault OTX",
                        "pulse_count": int(pulse_info["count"]),
                    }
                except (TypeError, ValueError):
                    otx_stats = None
            elif "pulses" in pulse_info and isinstance(pulse_info["pulses"], list):
                otx_stats = {
                    "provider": "AlienVault OTX",
                    "pulse_count": len(pulse_info["pulses"]),
                }
        elif "pulse_count" in otx and isinstance(otx["pulse_count"], (int, float)):
            try:
                otx_stats = {
                    "provider": "AlienVault OTX",
                    "pulse_count": int(otx["pulse_count"]),
                }
            except (TypeError, ValueError):
                otx_stats = None

        if otx_stats:
            evidence["alienvault_otx"] = otx_stats

    return evidence if evidence else None


class InvestigationRepository:
    """
    Data access repository handling read-only queries for investigation dossiers.
    """

    def __init__(self, connection_factory: Optional[Callable[[], Any]] = None) -> None:
        self._connection_factory = connection_factory or get_db_connection

    def _get_conn(self):
        return self._connection_factory()

    # -----------------------------------------------------------------------
    # Client Investigation Queries
    # -----------------------------------------------------------------------

    def get_client_profile(self, client_ip: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves lifetime profile for an individual client IP.
        """
        query = """
            SELECT 
                host(client_ip) AS client_ip,
                to_char(first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen,
                total_queries,
                unique_domains,
                benign_queries,
                malicious_queries,
                review_needed_queries,
                unknown_queries,
                last_domain,
                last_query_type
            FROM client_profiles
            WHERE client_ip = %s::inet;
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, (client_ip.strip(),))
                row = cur.fetchone()
                return dict(row) if row else None

    def get_client_relationships(self, client_ip: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Retrieves bounded top queried domains for a client, sorted deterministically.
        """
        query = """
            SELECT 
                domain,
                visit_count,
                benign_visits,
                malicious_visits,
                review_needed_visits,
                unknown_visits,
                to_char(first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
            FROM client_history
            WHERE client_ip = %s::inet
            ORDER BY visit_count DESC, last_seen DESC, domain ASC
            LIMIT %s;
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, (client_ip.strip(), limit))
                return [dict(r) for r in cur.fetchall()]

    def get_client_threat_activity(self, client_ip: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Retrieves bounded suspect/non-benign relationships for a client.
        Includes any relationship with malicious > 0 OR review_needed > 0 OR unknown > 0.
        """
        query = """
            SELECT 
                domain,
                visit_count,
                benign_visits,
                malicious_visits,
                review_needed_visits,
                unknown_visits,
                to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
            FROM client_history
            WHERE client_ip = %s::inet
              AND (malicious_visits > 0 OR review_needed_visits > 0 OR unknown_visits > 0)
            ORDER BY 
                malicious_visits DESC,
                review_needed_visits DESC,
                unknown_visits DESC,
                visit_count DESC,
                last_seen DESC,
                domain ASC
            LIMIT %s;
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, (client_ip.strip(), limit))
                return [dict(r) for r in cur.fetchall()]

    # -----------------------------------------------------------------------
    # Domain Investigation Queries
    # -----------------------------------------------------------------------

    def get_domain_profile(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves lifetime profile for an individual domain entity.
        Maps domain_profiles.clean_queries to benign_queries.
        """
        query = """
            SELECT 
                domain,
                to_char(first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen,
                total_queries,
                unique_clients,
                clean_queries AS benign_queries,
                malicious_queries,
                review_needed_queries,
                unknown_queries,
                query_a_count,
                query_aaaa_count,
                query_mx_count,
                query_txt_count,
                query_ns_count,
                query_other_count,
                last_client_ip,
                last_label,
                last_ti_source
            FROM domain_profiles
            WHERE domain = %s;
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, (domain.strip().lower(),))
                row = cur.fetchone()
                if not row:
                    return None
                data = dict(row)
                data["query_type_distribution"] = {
                    "A": int(data.pop("query_a_count") or 0),
                    "AAAA": int(data.pop("query_aaaa_count") or 0),
                    "MX": int(data.pop("query_mx_count") or 0),
                    "TXT": int(data.pop("query_txt_count") or 0),
                    "NS": int(data.pop("query_ns_count") or 0),
                    "OTHER": int(data.pop("query_other_count") or 0),
                }
                return data

    def get_domain_querying_clients(self, domain: str, limit: int = 20) -> List[Dict[str, Any]]:
        """
        Retrieves bounded top querying clients for a domain via reverse relationship lookup.
        """
        query = """
            SELECT 
                host(client_ip) AS client_ip,
                visit_count,
                benign_visits,
                malicious_visits,
                review_needed_visits,
                unknown_visits,
                to_char(first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
            FROM client_history
            WHERE domain = %s
            ORDER BY visit_count DESC, last_seen DESC, client_ip ASC
            LIMIT %s;
        """
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(query, (domain.strip().lower(), limit))
                return [dict(r) for r in cur.fetchall()]

    def get_domain_threat_intel(self, domain: str) -> Dict[str, Optional[Dict[str, Any]]]:
        """
        Retrieves all persisted local threat intelligence contexts for a domain.
        Returns dict with keys: 'reputation', 'daily_review', 'reviewed_clean'.
        """
        clean_domain = domain.strip().lower()
        result: Dict[str, Optional[Dict[str, Any]]] = {
            "reputation": None,
            "daily_review": None,
            "reviewed_clean": None,
        }

        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                # 1. reputation_domains
                cur.execute("""
                    SELECT 
                        status,
                        source,
                        confidence,
                        match_scope,
                        matched_domain,
                        times_seen,
                        query_count,
                        to_char(first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                        to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen,
                        to_char(last_verified_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_verified_at,
                        verification_count
                    FROM reputation_domains
                    WHERE domain = %s;
                """, (clean_domain,))
                rep_row = cur.fetchone()
                if rep_row:
                    result["reputation"] = dict(rep_row)

                # 2. daily_review_domains
                cur.execute("""
                    SELECT 
                        status,
                        review_reason,
                        review_count,
                        to_char(first_seen_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen_at,
                        to_char(last_seen_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen_at,
                        to_char(last_checked_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_checked_at,
                        to_char(next_check_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS next_check_at,
                        vt_result,
                        otx_result
                    FROM daily_review_domains
                    WHERE domain = %s;
                """, (clean_domain,))
                rev_row = cur.fetchone()
                if rev_row:
                    rev_dict = dict(rev_row)
                    evidence = _sanitize_evidence_summary(rev_dict.pop("vt_result", None), rev_dict.pop("otx_result", None))
                    rev_dict["evidence_summary"] = evidence
                    result["daily_review"] = rev_dict

                # 3. reviewed_clean_domains
                cur.execute("""
                    SELECT 
                        status,
                        verification_source,
                        to_char(verified_at, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS verified_at,
                        review_count,
                        vt_summary,
                        otx_summary
                    FROM reviewed_clean_domains
                    WHERE domain = %s;
                """, (clean_domain,))
                clean_row = cur.fetchone()
                if clean_row:
                    clean_dict = dict(clean_row)
                    evidence = _sanitize_evidence_summary(clean_dict.pop("vt_summary", None), clean_dict.pop("otx_summary", None))
                    clean_dict["evidence_summary"] = evidence
                    result["reviewed_clean"] = clean_dict

        return result
