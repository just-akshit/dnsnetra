"""
Investigation API Routes
========================
Dedicated Phase 3 investigation endpoints:
- GET /api/v1/investigation/domain/{domain}
- GET /api/v1/investigation/client/{client_ip}

Orchestrates and presents existing threat intelligence, reputation records,
and DNS telemetry without bypassing frozen Phase 2.7 precedence rules or spamming external APIs.
Implements the canonical evidence model: Provider, Status, Result, Provenance, Freshness, Scope.
"""

from __future__ import annotations

import os
import json
import logging
import time
import ipaddress
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import tldextract
from fastapi import APIRouter, HTTPException, Path as PathParam, Query

from labeler.config import LabelingConfig
from labeler.intel.manager import is_trusted
from labeler.intel.malicious import is_malicious
from labeler.intel.reputation import get_domain as get_reputation_domain
from labeler.intel.providers.virustotal import VirusTotalProvider
from labeler.intel.providers.alienvault import AlienVaultOTXProvider
from labeler.intel.correlation.models import ThreatDecision, ThreatProviderResult
from labeler.intel.correlation.scoring import WeightedScorer
from enrichment.manager import EnrichmentManager

from analytics.time_window import resolve_time_window, TimeWindow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/investigation", tags=["Investigation"])

# Cached TI config & Enrichment Manager
_CONFIG = LabelingConfig()
_ONLINE_CONFIG = _CONFIG.get_online_ti_config()
_ENRICHMENT_MANAGER = EnrichmentManager()
_INVESTIGATION_DEADLINE_SECONDS = float(os.getenv("INVESTIGATION_DEADLINE_SECONDS", "5.0"))


def _resolve_optional_window(
    window: Optional[str] = None,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
) -> Optional[TimeWindow]:
    """Helper to resolve a time window if parameters are provided. Custom > preset."""
    if start_time and end_time:
        return resolve_time_window(start=start_time, end=end_time)
    elif window and window.strip():
        return resolve_time_window(window=window.strip())
    return None


# ---------------------------------------------------------------------------
# Normalization Helper
# ---------------------------------------------------------------------------
def normalize_domain_string(raw_domain: str) -> Dict[str, str]:
    """Normalize a domain string and extract FQDN, apex/registered domain, and TLD."""
    raw = (raw_domain or "").strip().lower()
    cleaned = raw.rstrip(".")
    if not cleaned:
        return {
            "queried": raw_domain,
            "normalized": "",
            "fqdn": "",
            "registered_domain": "",
            "tld": "",
            "subdomain": "",
        }

    ext = tldextract.extract(cleaned)
    registered_domain = (
        getattr(ext, "top_domain_under_public_suffix", None)
        or getattr(ext, "registered_domain", "")
        or cleaned
    )
    tld = ext.suffix
    subdomain = ext.subdomain

    return {
        "queried": raw_domain,
        "normalized": cleaned,
        "fqdn": cleaned,
        "registered_domain": registered_domain,
        "tld": tld,
        "subdomain": subdomain,
    }


# ---------------------------------------------------------------------------
# PostgreSQL Query Helpers (Safe & Pooled)
# ---------------------------------------------------------------------------
def _query_pg_domain_history(domain: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Query recent query logs from PostgreSQL domain_query_history."""
    try:
        from domain_profiling.connection import get_db_connection
        import psycopg2.extras
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT id, client_ip, query_type, timestamp, response_code,
                           registered_domain, tld, final_label, ti_source
                    FROM domain_query_history
                    WHERE domain = %s
                    ORDER BY timestamp DESC
                    LIMIT %s;
                    """,
                    (domain, limit),
                )
                rows = cur.fetchall()
                return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("PostgreSQL domain_query_history query failed: %s", exc)
        return []


def _query_pg_client_query_history(client_ip: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Query recent query logs for a client from PostgreSQL domain_query_history."""
    try:
        from domain_profiling.connection import get_db_connection
        import psycopg2.extras
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT domain, query_type, timestamp, response_code, final_label, ti_source
                    FROM domain_query_history
                    WHERE client_ip = %s
                    ORDER BY timestamp DESC
                    LIMIT %s;
                    """,
                    (client_ip, limit),
                )
                rows = cur.fetchall()
                return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("PostgreSQL client query history lookup failed: %s", exc)
        return []


def _query_pg_client_domain_breakdown(client_ip: str) -> List[Dict[str, Any]]:
    """Query aggregated domains queried by this client with their labels and hit counts."""
    try:
        from domain_profiling.connection import get_db_connection
        import psycopg2.extras
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT domain, final_label, ti_source, COUNT(*) as query_count, MAX(timestamp) as last_seen
                    FROM domain_query_history
                    WHERE client_ip = %s
                    GROUP BY domain, final_label, ti_source
                    ORDER BY query_count DESC;
                    """,
                    (client_ip,),
                )
                rows = cur.fetchall()
                return [dict(r) for r in rows]
    except Exception as exc:
        logger.warning("PostgreSQL client domain breakdown failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# GET /api/v1/investigation/domain/{domain}
# ---------------------------------------------------------------------------
@router.get("/domain/{domain:path}")
def investigate_domain(
    domain: str = PathParam(..., description="The domain name to investigate"),
    force_external: bool = Query(False, description="Force external TI evaluation even if local match is authoritative"),
    window: Optional[str] = Query(None, description="Rolling window preset (e.g. 5m, 1h, 24h)"),
    start_time: Optional[str] = Query(None, description="ISO8601 UTC start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO8601 UTC end timestamp"),
):
    """
    Domain Intelligence Search & Investigation.
    
    Orchestrates:
    1. Normalization (FQDN, registered domain, TLD).
    2. Local Threat Intelligence (Tranco popularity context, URLhaus exact/parent scope).
    3. Active PostgreSQL Reputation (persisted scope, confidence, first/last seen).
    4. DNS Telemetry from PostgreSQL domain_profiles and domain_query_history (query volume, codes, types).
    5. Querying clients list.
    6. Controlled External TI (VT, OTX, Correlation Scorer) with strict provenance/freshness separation.
    7. Explicit evidence provenance (LOCAL, REAL, PERSISTED, COMPUTED, NO_DATA, NOT_CONFIGURED, PROVIDER_FAILURE).
    """
    perf_start = time.perf_counter()
    deadline = time.monotonic() + _INVESTIGATION_DEADLINE_SECONDS

    # Step 1: Normalization
    norm = normalize_domain_string(domain)
    fqdn = norm["fqdn"]
    reg = norm["registered_domain"]

    if not fqdn:
        raise HTTPException(status_code=400, detail="Invalid domain name provided")

    # Step 2: Local Threat Intelligence Evaluation (Scope Precedence)
    local_verdict = "UNKNOWN"
    local_source = "NO_DATA"
    match_scope = None
    matched_domain = None

    tranco_info = {
        "provider": "Tranco",
        "matched": False,
        "status": "NO_DATA",
        "result": None,
        "provenance": "LOCAL",
        "freshness": "NOT_APPLICABLE",
    }
    urlhaus_info = {
        "provider": "URLhaus",
        "matched": False,
        "status": "NO_DATA",
        "result": None,
        "provenance": "LOCAL",
        "freshness": "NOT_APPLICABLE",
    }

    # Rule 1: Exact FQDN Malicious Match (URLhaus)
    if fqdn and fqdn != reg and is_malicious(fqdn):
        local_verdict = "KNOWN_MALICIOUS"
        local_source = "URLhaus"
        match_scope = "EXACT_FQDN"
        matched_domain = fqdn
        tranco_info = {
            "provider": "Tranco",
            "matched": False,
            "status": "NO_DATA",
            "result": None,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
        }
        urlhaus_info = {
            "provider": "URLhaus",
            "matched": True,
            "status": "AVAILABLE",
            "result": "MALICIOUS",
            "match_scope": "EXACT_FQDN",
            "matched_domain": fqdn,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
            "confidence": 1.0,
        }

    # Rule 2: Tranco Popularity Context
    elif (reg and is_trusted(reg)) or (fqdn and is_trusted(fqdn)):
        is_root_art = (fqdn == reg and is_malicious(reg))
        match_scope = "ROOT_ARTIFACT" if is_root_art else "POPULARITY_CONTEXT"
        local_verdict = "POPULAR_BENIGN_CONTEXT"
        local_source = "Tranco"
        matched_domain = reg or fqdn
        tranco_info = {
            "provider": "Tranco",
            "matched": True,
            "status": "AVAILABLE",
            "result": "POPULAR_BENIGN_CONTEXT",
            "match_scope": match_scope,
            "matched_domain": matched_domain,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
        }
        urlhaus_info = {
            "provider": "URLhaus",
            "matched": is_root_art,
            "status": "SUPPRESSED_ROOT_ARTIFACT" if is_root_art else "NO_DATA",
            "result": None,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
            "reason": "URLhaus apex root artifact suppressed by Tranco popularity context" if is_root_art else "No record found",
        }

    # Rule 3: Untrusted Registered Domain Fallback (URLhaus)
    elif reg and is_malicious(reg):
        match_scope = "EXACT_FQDN" if fqdn == reg else "REGISTERED_DOMAIN"
        local_verdict = "KNOWN_MALICIOUS"
        local_source = "URLhaus"
        matched_domain = reg
        tranco_info = {
            "provider": "Tranco",
            "matched": False,
            "status": "NO_DATA",
            "result": None,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
        }
        urlhaus_info = {
            "provider": "URLhaus",
            "matched": True,
            "status": "AVAILABLE",
            "result": "MALICIOUS",
            "match_scope": match_scope,
            "matched_domain": reg,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
            "confidence": 1.0,
        }

    # Step 3: Active PostgreSQL Reputation Check
    pg_rep = None
    try:
        pg_rep = get_reputation_domain(fqdn)
    except Exception as exc:
        logger.warning("Reputation lookup failed: %s", exc)

    reputation_data = {
        "active_record": pg_rep is not None,
        "status": pg_rep.get("status") if pg_rep else None,
        "source": pg_rep.get("source") if pg_rep else None,
        "confidence": pg_rep.get("confidence") if pg_rep else None,
        "match_scope": pg_rep.get("match_scope") if pg_rep else None,
        "matched_domain": pg_rep.get("matched_domain") if pg_rep else None,
        "first_seen": str(pg_rep.get("first_seen")) if pg_rep and pg_rep.get("first_seen") else None,
        "last_seen": str(pg_rep.get("last_seen")) if pg_rep and pg_rep.get("last_seen") else None,
    }

    # Step 4: DNS Telemetry & Querying Clients from PostgreSQL domain_profiles and domain_query_history
    telemetry = {
        "status": "NOT_OBSERVED",
        "query_count": 0,
        "unique_clients": 0,
        "malicious_count": 0,
        "suspicious_count": 0,
        "clean_count": 0,
        "first_seen": None,
        "last_seen": None,
        "query_types": {},
        "response_codes": {},
    }
    querying_clients: List[Dict[str, Any]] = []

    # Query PostgreSQL domain_profiles and client_history
    try:
        from domain_profiling.connection import get_db_connection
        import psycopg2.extras
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT domain, total_queries, unique_clients,
                           malicious_queries AS threat_count, malicious_queries AS malicious_count,
                           clean_queries AS clean_count, unknown_queries AS unknown_count,
                           query_a_count, query_aaaa_count, query_mx_count,
                           query_txt_count, query_ns_count, query_other_count,
                           to_char(first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                           to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM domain_profiles
                    WHERE domain = %s;
                """, (fqdn,))
                row = cur.fetchone()
                if row:
                    telemetry["status"] = "OBSERVED"
                    telemetry["query_count"] = row["total_queries"]
                    telemetry["unique_clients"] = row["unique_clients"]
                    telemetry["malicious_count"] = row["malicious_count"]
                    telemetry["suspicious_count"] = 0
                    telemetry["clean_count"] = row["clean_count"]
                    telemetry["first_seen"] = row["first_seen"]
                    telemetry["last_seen"] = row["last_seen"]
                    telemetry["query_types"] = {
                        "A": row["query_a_count"] or 0,
                        "AAAA": row["query_aaaa_count"] or 0,
                        "MX": row["query_mx_count"] or 0,
                        "TXT": row["query_txt_count"] or 0,
                        "NS": row["query_ns_count"] or 0,
                        "OTHER": row["query_other_count"] or 0,
                    }

                # Fetch querying clients from client_history
                cur.execute("""
                    SELECT host(client_ip) AS client_ip, visit_count,
                           to_char(last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM client_history
                    WHERE domain = %s
                    ORDER BY visit_count DESC
                    LIMIT 20;
                """, (fqdn,))
                for cr in cur.fetchall():
                    querying_clients.append({
                        "client_ip": cr["client_ip"],
                        "query_count": cr["visit_count"],
                        "last_seen": cr["last_seen"],
                    })
    except Exception as exc:
        logger.debug("PostgreSQL domain profile lookup exception: %s", exc)

    # Enrich querying clients & telemetry from PostgreSQL domain_query_history if available
    pg_history = _query_pg_domain_history(fqdn, limit=100)
    if pg_history:
        if telemetry["status"] == "NOT_OBSERVED":
            telemetry["status"] = "OBSERVED"
            telemetry["query_count"] = len(pg_history)
            telemetry["first_seen"] = str(pg_history[-1]["timestamp"])
            telemetry["last_seen"] = str(pg_history[0]["timestamp"])

        # Aggregate client counts
        client_stats: Dict[str, Dict[str, Any]] = {}
        for h in pg_history:
            cip = str(h["client_ip"])
            ts = str(h["timestamp"])
            if cip not in client_stats:
                client_stats[cip] = {"client_ip": cip, "query_count": 0, "last_seen": ts}
            client_stats[cip]["query_count"] += 1
            if ts > client_stats[cip]["last_seen"]:
                client_stats[cip]["last_seen"] = ts

        querying_clients = sorted(
            list(client_stats.values()), key=lambda c: c["query_count"], reverse=True
        )

    # Time-window scoped telemetry override if requested
    tw = _resolve_optional_window(window, start_time, end_time)
    if tw:
        try:
            from domain_profiling.connection import get_db_connection
            import psycopg2.extras
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT COUNT(*) AS total_queries,
                               COUNT(DISTINCT client_ip) AS unique_clients,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_count,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) != 'malicious') AS clean_count
                        FROM domain_query_history
                        WHERE domain = %s AND timestamp >= %s AND timestamp < %s;
                    """, (fqdn, tw.start, tw.end))
                    r_row = cur.fetchone() or {}

                    cur.execute("""
                        SELECT client_ip, COUNT(*) AS query_count,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE domain = %s AND timestamp >= %s AND timestamp < %s
                        GROUP BY client_ip
                        ORDER BY query_count DESC
                        LIMIT 20;
                    """, (fqdn, tw.start, tw.end))
                    range_clients = [dict(r) for r in cur.fetchall()]

                    telemetry["selected_range"] = {
                        "start": tw.start_iso,
                        "end": tw.end_iso,
                        "query_count": r_row.get("total_queries") or 0,
                        "unique_clients": r_row.get("unique_clients") or 0,
                        "malicious_count": r_row.get("malicious_count") or 0,
                        "clean_count": r_row.get("clean_count") or 0,
                    }
                    if range_clients:
                        querying_clients = range_clients
        except Exception as exc:
            logger.debug("Error fetching domain range metrics: %s", exc)

    # Step 5: External Threat Intelligence (Strict Status, Provenance & Freshness Separation)
    ext_results: List[ThreatProviderResult] = []
    ext_status = "SKIPPED"
    ext_prov: Optional[str] = "LOCAL"
    ext_fresh = "NOT_APPLICABLE"
    correlation_data: Dict[str, Any] = {}

    # Case A: Local authoritative match (URLhaus or Tranco) without force_external
    if local_verdict in ("KNOWN_MALICIOUS", "POPULAR_BENIGN_CONTEXT") and not force_external:
        ext_status = "SKIPPED"
        ext_prov = "LOCAL"
        ext_fresh = "NOT_APPLICABLE"
        vt_data = {
            "provider": "VirusTotal",
            "status": "SKIPPED",
            "result": None,
            "malicious_count": 0,
            "harmless_count": 0,
            "suspicious_count": 0,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
            "confidence": None,
            "reason": "Skipped due to local authoritative match",
        }
        otx_data = {
            "provider": "AlienVault OTX",
            "status": "SKIPPED",
            "result": None,
            "malicious_count": 0,
            "harmless_count": 0,
            "suspicious_count": 0,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
            "confidence": None,
            "reason": "Skipped due to local authoritative match",
        }
        correlation_data = {
            "engine": "Threat Correlation Engine",
            "status": "NOT_APPLICABLE",
            "score": None,
            "threshold": 0.60,
            "confidence": None,
            "verdict": None,
            "provenance": None,
            "freshness": "NOT_APPLICABLE",
            "reason": "Correlation not applicable due to authoritative local intelligence match.",
        }
        decision = ThreatDecision(
            domain=fqdn,
            malicious=False,
            score=0.0,
            confidence=0.0,
            threshold=0.60,
            provider_results=[],
        )

    # Case B: Authoritative persisted reputation record exists without force_external
    elif pg_rep and pg_rep.get("status") == "malicious" and not force_external:
        ext_status = "AVAILABLE"
        ext_prov = "PERSISTED"
        ext_fresh = "ACTIVE_REPUTATION"
        rep_is_mal = pg_rep.get("status") == "malicious"
        rep_conf = pg_rep.get("confidence") or 0.95
        rep_seen = str(pg_rep.get("last_seen") or pg_rep.get("first_seen") or "")
        rep_source = pg_rep.get("source") or "Threat Correlation Engine"
        rep_scope = pg_rep.get("match_scope") or "CORRELATED"

        # Attribute external provider results honestly based on persisted source
        if rep_source == "VirusTotal":
            vt_data = {
                "provider": "VirusTotal",
                "status": "AVAILABLE",
                "result": "MALICIOUS" if rep_is_mal else "CLEAN",
                "malicious_count": 1 if rep_is_mal else 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": "PERSISTED",
                "freshness": "ACTIVE_REPUTATION",
                "confidence": rep_conf,
                "observed_at": rep_seen,
                "reason": f"Active reputation record (Scope: {rep_scope})",
            }
            otx_data = {
                "provider": "AlienVault OTX",
                "status": "NO_DATA",
                "result": None,
                "malicious_count": 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": "PERSISTED",
                "freshness": "ACTIVE_REPUTATION",
                "availability_reason": "NOT_RECORDED_IN_PERSISTED_REPUTATION",
                "confidence": None,
                "observed_at": None,
                "reason": "Provider-specific evidence was not recorded in the persisted reputation.",
            }
        elif rep_source == "AlienVault OTX":
            vt_data = {
                "provider": "VirusTotal",
                "status": "NO_DATA",
                "result": None,
                "malicious_count": 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": "PERSISTED",
                "freshness": "ACTIVE_REPUTATION",
                "availability_reason": "NOT_RECORDED_IN_PERSISTED_REPUTATION",
                "confidence": None,
                "observed_at": None,
                "reason": "Provider-specific evidence was not recorded in the persisted reputation.",
            }
            otx_data = {
                "provider": "AlienVault OTX",
                "status": "AVAILABLE",
                "result": "MALICIOUS" if rep_is_mal else "CLEAN",
                "malicious_count": 1 if rep_is_mal else 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": "PERSISTED",
                "freshness": "ACTIVE_REPUTATION",
                "confidence": rep_conf,
                "observed_at": rep_seen,
                "reason": f"Active reputation record (Scope: {rep_scope})",
            }
        else:
            # Sourced from Threat Correlation Engine or URLhaus: neither individual provider is stored
            vt_data = {
                "provider": "VirusTotal",
                "status": "NO_DATA",
                "result": None,
                "malicious_count": 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": "PERSISTED",
                "freshness": "ACTIVE_REPUTATION",
                "availability_reason": "NOT_RECORDED_IN_PERSISTED_REPUTATION",
                "confidence": None,
                "observed_at": None,
                "reason": f"Provider-specific evidence was not recorded in the persisted reputation (Source: {rep_source}).",
            }
            otx_data = {
                "provider": "AlienVault OTX",
                "status": "NO_DATA",
                "result": None,
                "malicious_count": 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": "PERSISTED",
                "freshness": "ACTIVE_REPUTATION",
                "availability_reason": "NOT_RECORDED_IN_PERSISTED_REPUTATION",
                "confidence": None,
                "observed_at": None,
                "reason": f"Provider-specific evidence was not recorded in the persisted reputation (Source: {rep_source}).",
            }

        correlation_data = {
            "engine": "Threat Correlation Engine",
            "status": "NOT_EVALUATED",
            "score": None,
            "threshold": 0.60,
            "confidence": None,
            "verdict": None,
            "provenance": None,
            "freshness": "NOT_APPLICABLE",
            "reason": "Correlation evaluation was skipped because an authoritative active reputation record exists.",
        }
        decision = ThreatDecision(
            domain=fqdn,
            malicious=False,
            score=0.0,
            confidence=0.0,
            threshold=0.60,
            provider_results=[],
        )

    # Case C: Query external providers live
    else:
        ext_prov = "REAL"
        ext_fresh = "LIVE_LOOKUP"
        now_iso = datetime.now(timezone.utc).isoformat()

        ti_timeout = max(1, int(min(3.0, max(0.1, deadline - time.monotonic()))))
        ti_cfg = dict(_ONLINE_CONFIG, API_TIMEOUT=ti_timeout)

        def _fetch_vt():
            vt = VirusTotalProvider(ti_cfg)
            if not vt.is_enabled():
                return None, "NOT_CONFIGURED"
            try:
                vt.timeout = ti_timeout
                res = vt.lookup(fqdn)
                return res, None
            except Exception as exc:
                return None, exc
            finally:
                vt.close()

        def _fetch_otx():
            otx = AlienVaultOTXProvider(ti_cfg)
            if not otx.is_enabled():
                return None, "NOT_CONFIGURED"
            try:
                otx.timeout = ti_timeout
                otx._timeout = ti_timeout
                res = otx.lookup(fqdn)
                return res, None
            except Exception as exc:
                return None, exc
            finally:
                otx.close()


        fut_vt = _ENRICHMENT_MANAGER._executor.submit(_fetch_vt)
        fut_otx = _ENRICHMENT_MANAGER._executor.submit(_fetch_otx)

        time_left_vt = max(0.01, deadline - time.monotonic())
        try:
            vt_res, vt_err = fut_vt.result(timeout=time_left_vt)
        except Exception as exc:
            vt_res, vt_err = None, exc

        time_left_otx = max(0.01, deadline - time.monotonic())
        try:
            otx_res, otx_err = fut_otx.result(timeout=time_left_otx)
        except Exception as exc:
            otx_res, otx_err = None, exc

        # Format VT data
        if vt_err == "NOT_CONFIGURED":
            vt_data = {
                "provider": "VirusTotal",
                "status": "NOT_CONFIGURED",
                "result": None,
                "malicious_count": 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": None,
                "freshness": "NOT_APPLICABLE",
                "confidence": None,
                "reason": "VT_API_KEY credentials not set",
            }
        elif vt_res is not None:
            ext_results.append(vt_res)
            if vt_res.unavailable:
                vt_data = {
                    "provider": "VirusTotal",
                    "status": "PROVIDER_FAILURE",
                    "result": None,
                    "malicious_count": 0,
                    "harmless_count": 0,
                    "suspicious_count": 0,
                    "provenance": "REAL",
                    "freshness": "LIVE_LOOKUP",
                    "confidence": None,
                    "error": vt_res.error or "Provider returned unavailable",
                    "reason": f"VirusTotal provider failure: {vt_res.error}",
                }
            elif vt_res.found:
                vt_data = {
                    "provider": "VirusTotal",
                    "status": "AVAILABLE",
                    "result": "MALICIOUS" if vt_res.malicious else "CLEAN",
                    "malicious_count": vt_res.malicious_count,
                    "harmless_count": vt_res.harmless_count,
                    "suspicious_count": vt_res.suspicious_count,
                    "provenance": "REAL",
                    "freshness": "LIVE_LOOKUP",
                    "confidence": vt_res.confidence,
                    "observed_at": now_iso,
                }
            else:
                vt_data = {
                    "provider": "VirusTotal",
                    "status": "NO_DATA",
                    "result": None,
                    "malicious_count": 0,
                    "harmless_count": 0,
                    "suspicious_count": 0,
                    "provenance": "REAL",
                    "freshness": "LIVE_LOOKUP",
                    "confidence": None,
                    "observed_at": now_iso,
                    "reason": "VirusTotal queried successfully; domain unrated / zero positive signals (404/undetected)",
                }
        else:
            vt_data = {
                "provider": "VirusTotal",
                "status": "PROVIDER_FAILURE",
                "result": None,
                "malicious_count": 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": "REAL",
                "freshness": "LIVE_LOOKUP",
                "error": str(vt_err),
                "confidence": None,
                "reason": f"VirusTotal provider failure: {vt_err}",
            }

        # Format OTX data
        if otx_err == "NOT_CONFIGURED":
            otx_data = {
                "provider": "AlienVault OTX",
                "status": "NOT_CONFIGURED",
                "result": None,
                "malicious_count": 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": None,
                "freshness": "NOT_APPLICABLE",
                "confidence": None,
                "reason": "OTX_API_KEY credentials not set",
            }
        elif otx_res is not None:
            ext_results.append(otx_res)
            if otx_res.unavailable:
                otx_data = {
                    "provider": "AlienVault OTX",
                    "status": "PROVIDER_FAILURE",
                    "result": None,
                    "malicious_count": 0,
                    "harmless_count": 0,
                    "suspicious_count": 0,
                    "provenance": "REAL",
                    "freshness": "LIVE_LOOKUP",
                    "confidence": None,
                    "error": otx_res.error or "Provider returned unavailable",
                    "reason": f"AlienVault OTX provider failure: {otx_res.error}",
                }
            elif otx_res.found:
                otx_data = {
                    "provider": "AlienVault OTX",
                    "status": "AVAILABLE",
                    "result": "MALICIOUS" if otx_res.malicious else "CLEAN",
                    "malicious_count": otx_res.malicious_count,
                    "harmless_count": otx_res.harmless_count,
                    "suspicious_count": otx_res.suspicious_count,
                    "provenance": "REAL",
                    "freshness": "LIVE_LOOKUP",
                    "confidence": otx_res.confidence,
                    "observed_at": now_iso,
                }
            else:
                otx_data = {
                    "provider": "AlienVault OTX",
                    "status": "NO_DATA",
                    "result": None,
                    "malicious_count": 0,
                    "harmless_count": 0,
                    "suspicious_count": 0,
                    "provenance": "REAL",
                    "freshness": "LIVE_LOOKUP",
                    "confidence": None,
                    "observed_at": now_iso,
                    "reason": "AlienVault OTX queried successfully; zero threat pulses found",
                }
        else:
            otx_data = {
                "provider": "AlienVault OTX",
                "status": "PROVIDER_FAILURE",
                "result": None,
                "malicious_count": 0,
                "harmless_count": 0,
                "suspicious_count": 0,
                "provenance": "REAL",
                "freshness": "LIVE_LOOKUP",
                "error": str(otx_err),
                "confidence": None,
                "reason": f"AlienVault OTX provider failure: {otx_err}",
            }

        # Resolve top-level external status from providers
        if vt_data.get("status") == "AVAILABLE" or otx_data.get("status") == "AVAILABLE":
            ext_status = "AVAILABLE"
        elif vt_data.get("status") == "PROVIDER_FAILURE" or otx_data.get("status") == "PROVIDER_FAILURE":
            ext_status = "PROVIDER_FAILURE"
        elif vt_data.get("status") == "NO_DATA" and otx_data.get("status") == "NO_DATA":
            ext_status = "NO_DATA"
        elif vt_data.get("status") == "NOT_CONFIGURED" and otx_data.get("status") == "NOT_CONFIGURED":
            ext_status = "NOT_CONFIGURED"
            ext_prov = None
            ext_fresh = "NOT_APPLICABLE"
        else:
            ext_status = "AVAILABLE"

        # Calculate live correlation
        weights = {
            "VirusTotal": float(_ONLINE_CONFIG.get("WEIGHT_VT", 0.60)),
            "AlienVault OTX": float(_ONLINE_CONFIG.get("WEIGHT_OTX", 0.40)),
        }
        scorer = WeightedScorer(
            weights=weights,
            threshold=float(_ONLINE_CONFIG.get("MALICIOUS_THRESHOLD", 0.60)),
        )
        score, confidence, is_ext_malicious = scorer.calculate(ext_results)
        decision = ThreatDecision(
            domain=fqdn,
            malicious=is_ext_malicious,
            score=score,
            confidence=confidence,
            threshold=scorer.threshold,
            provider_results=ext_results,
        )

        all_unconfigured = (
            vt_data.get("status") == "NOT_CONFIGURED"
            and otx_data.get("status") == "NOT_CONFIGURED"
        )
        all_failed = (
            vt_data.get("status") == "PROVIDER_FAILURE"
            and otx_data.get("status") == "PROVIDER_FAILURE"
        )

        if all_unconfigured:
            correlation_data = {
                "engine": "Threat Correlation Engine",
                "status": "NOT_EVALUATED",
                "score": None,
                "threshold": scorer.threshold,
                "confidence": None,
                "verdict": None,
                "provenance": None,
                "freshness": "NOT_APPLICABLE",
                "reason": "Correlation skipped: external threat intelligence providers not configured.",
            }
        elif all_failed:
            correlation_data = {
                "engine": "Threat Correlation Engine",
                "status": "FAILED",
                "score": None,
                "threshold": scorer.threshold,
                "confidence": None,
                "verdict": None,
                "provenance": "COMPUTED",
                "freshness": "LIVE_LOOKUP",
                "reason": "Correlation evaluation failed due to upstream provider errors.",
            }
        else:
            correlation_data = {
                "engine": "Threat Correlation Engine",
                "status": "EVALUATED",
                "score": decision.score,
                "threshold": decision.threshold,
                "confidence": decision.confidence,
                "verdict": "MALICIOUS" if decision.malicious else "INCONCLUSIVE",
                "provenance": "COMPUTED",
                "freshness": "LIVE_LOOKUP",
                "reason": "Live weighted threat correlation computed across available external providers.",
            }


    # Derive verdict & human reason strictly adhering to frozen Phase 2.7 precedence
    evidence_list: List[Dict[str, Any]] = []

    # 1. Exact local malicious match (URLhaus EXACT_FQDN)
    if local_verdict == "KNOWN_MALICIOUS" and match_scope == "EXACT_FQDN":
        final_status = "KNOWN_MALICIOUS"
        final_label = "malicious"
        risk_score = 100.0
        final_confidence = 1.0
        final_source = local_source
        final_scope = match_scope
        reason = f"Listed in URLhaus malware database (Scope: {match_scope}, Matched: {matched_domain})"
        why = "Exact domain match in local URLhaus threat intelligence database."
        evidence_list.append({
            "provider": "URLhaus",
            "result": "MALICIOUS",
            "scope": match_scope,
            "matched_domain": matched_domain,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
            "confidence": 1.0,
        })

    # 2. Local registered-domain malicious match (URLhaus REGISTERED_DOMAIN)
    elif local_verdict == "KNOWN_MALICIOUS":
        final_status = "KNOWN_MALICIOUS"
        final_label = "malicious"
        risk_score = 100.0
        final_confidence = 1.0
        final_source = local_source
        final_scope = match_scope
        reason = f"Listed in URLhaus malware database (Scope: {match_scope}, Matched: {matched_domain})"
        why = "Apex domain match in local URLhaus threat intelligence database."
        evidence_list.append({
            "provider": "URLhaus",
            "result": "MALICIOUS",
            "scope": match_scope,
            "matched_domain": matched_domain,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
            "confidence": 1.0,
        })

    # 3. Active authoritative persisted reputation record in PostgreSQL (reputation_domains)
    elif pg_rep and pg_rep.get("status") == "malicious":
        final_status = "KNOWN_MALICIOUS"
        final_label = "malicious"
        risk_score = 100.0
        final_confidence = pg_rep.get("confidence") or 0.95
        final_source = pg_rep.get("source") or "Threat Correlation Engine"
        final_scope = pg_rep.get("match_scope") or "CORRELATED"
        reason = f"Flagged as malicious by {final_source} (Persisted reputation scope: {final_scope})"
        why = "Active malicious reputation record found in the reputation database."
        evidence_list.append({
            "provider": final_source,
            "result": "MALICIOUS",
            "scope": final_scope,
            "provenance": "PERSISTED",
            "freshness": "ACTIVE_REPUTATION",
            "confidence": final_confidence,
        })

    # 4. Live computed correlation exceeds threshold
    elif correlation_data.get("status") == "EVALUATED" and decision.malicious:
        final_status = "KNOWN_MALICIOUS"
        final_label = "malicious"
        risk_score = decision.score * 100.0
        final_confidence = decision.confidence
        final_source = "Threat Correlation Engine"
        final_scope = "CORRELATED"
        reason = f"Correlated threat score ({decision.score:.2f}) exceeds threshold ({decision.threshold:.2f})"
        why = "Multiple threat intelligence providers confirmed malicious signals exceeding threshold."
        evidence_list.append({
            "provider": "Threat Correlation Engine",
            "result": "MALICIOUS",
            "score": decision.score,
            "threshold": decision.threshold,
            "provenance": "COMPUTED",
            "freshness": "LIVE_LOOKUP",
            "confidence": decision.confidence,
        })

    # 5. Local Tranco popularity context (Trusted / Top 1M apex or subdomain)
    elif local_verdict == "POPULAR_BENIGN_CONTEXT":
        final_status = "POPULAR_BENIGN_CONTEXT"
        final_label = "benign"
        risk_score = 0.0
        final_confidence = 0.0
        final_source = "Tranco"
        final_scope = match_scope
        reason = f"Top-ranked global domain in Tranco database (Scope: {match_scope})"
        why = "Domain is recognized as a trusted apex/registered domain in the Tranco top-1M list."
        evidence_list.append({
            "provider": "Tranco",
            "result": "POPULAR_BENIGN_CONTEXT",
            "scope": match_scope,
            "matched_domain": matched_domain,
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
            "confidence": 1.0,
        })

    # 6. Live external providers returned positive clean evidence (significant multi-engine consensus: harmless_count >= 5 with 0 malicious/suspicious)
    elif (
        correlation_data.get("status") == "EVALUATED"
        and not decision.malicious
        and any(
            r.found and getattr(r, "harmless_count", 0) >= 5 and getattr(r, "malicious_count", 0) == 0 and getattr(r, "suspicious_count", 0) == 0
            for r in ext_results
        )
    ):
        best_clean = next(
            (r for r in ext_results if getattr(r, "harmless_count", 0) >= 5),
            None,
        )
        clean_conf = best_clean.confidence if best_clean else 0.8
        final_status = "KNOWN_CLEAN"
        final_label = "benign"
        risk_score = 0.0
        final_confidence = clean_conf
        final_source = "External Threat Intelligence"
        final_scope = "EXTERNAL_PROVIDER"
        reason = f"Queried across threat providers with positive clean analysis ({best_clean.harmless_count if best_clean else 0} harmless votes)."
        why = "Live threat provider analysis confirmed positive clean status with significant multi-engine consensus."
        evidence_list.append({
            "provider": "External Threat Intelligence",
            "result": "CLEAN",
            "provenance": "REAL",
            "freshness": "LIVE_LOOKUP",
            "confidence": clean_conf,
        })

    # 7. Unknown / Inconclusive (unindexed, insufficient clean consensus, unconfigured, or provider failure)
    else:
        final_status = "REVIEW_NEEDED"
        final_label = "review_needed"
        risk_score = 0.0
        final_confidence = 0.0
        final_source = "NO_DATA"
        final_scope = "UNKNOWN"
        reason = "No authoritative local or external intelligence found."
        why = "Domain is unindexed across local threat lists, reputation cache, and threat feeds."
        evidence_list.append({
            "provider": "System",
            "result": "INCONCLUSIVE",
            "provenance": "LOCAL",
            "freshness": "NOT_APPLICABLE",
            "confidence": 0.0,
        })


    # Step 7: Phase 4 Domain Enrichment (DNS, IP Geo/ASN, RDAP)
    enrichment_data = _ENRICHMENT_MANAGER.enrich_domain(fqdn, deadline=deadline)
    enrichment_dict = (
        enrichment_data.model_dump()
        if hasattr(enrichment_data, "model_dump")
        else enrichment_data.dict()
    )

    duration_ms = (time.perf_counter() - perf_start) * 1000.0

    return {
        "status": "success",
        "data": {
            "domain": norm,
            "classification": {
                "status": final_status,
                "label": final_label,
                "risk_score": risk_score,
                "confidence": final_confidence,
                "reason": reason,
                "source": final_source,
                "scope": final_scope,
            },
            "local_intelligence": {
                "tranco": tranco_info,
                "urlhaus": urlhaus_info,
            },
            "external_intelligence": {
                "status": ext_status,
                "provenance": ext_prov,
                "freshness": ext_fresh,
                "virustotal": vt_data,
                "otx": otx_data,
            },
            "correlation": correlation_data,
            "dns_activity": telemetry,
            "reputation": reputation_data,
            "querying_clients": querying_clients,
            "investigation": {
                "known": final_status in ("KNOWN_MALICIOUS", "POPULAR_BENIGN_CONTEXT", "KNOWN_CLEAN"),
                "why": why,
                "evidence": evidence_list,
            },
            "enrichment": enrichment_dict,
            "duration_ms": round(duration_ms, 2),
        },
    }



# ---------------------------------------------------------------------------
# GET /api/v1/investigation/client/{client_ip}
# ---------------------------------------------------------------------------
@router.get("/client/{client_ip:path}")
def investigate_client(
    client_ip: str = PathParam(..., description="Client IP address to investigate"),
    window: Optional[str] = Query(None, description="Rolling window preset (e.g. 5m, 1h, 24h)"),
    start_time: Optional[str] = Query(None, description="ISO8601 UTC start timestamp"),
    end_time: Optional[str] = Query(None, description="ISO8601 UTC end timestamp"),
):
    """
    Client Endpoint Investigation.
    
    Returns:
    1. Client identity (IP, private/public network type, first/last seen).
    2. Activity summary with explicit metrics:
       - total_queries, unique_domains
       - malicious_queries, malicious_domains
       - suspicious_queries, suspicious_domains
       - benign_queries, benign_domains
       - unknown_queries, unknown_domains
       - threat_traffic_ratio (% malicious queries)
       - threat_domain_ratio (% unique malicious domains)
       - threat_ratio (backward compatible, equals threat_traffic_ratio)
    3. Categorized threat destinations queried by this host.
    4. Top destinations queried.
    5. Recent chronological query log stream with consistent provenance.
    """
    perf_start = time.perf_counter()
    deadline = time.monotonic() + _INVESTIGATION_DEADLINE_SECONDS
    clean_ip = (client_ip or "").strip()
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        is_private = ip_obj.is_private
        network_type = "Private / RFC 1918 Internal Network" if is_private else "Public Network Endpoint"
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid IP address format: '{client_ip}'")

    # Query PostgreSQL client_profiles & client_history
    client_row = None
    top_domains_from_db: List[Dict[str, Any]] = []
    try:
        from domain_profiling.connection import get_db_connection
        import psycopg2.extras
        with get_db_connection() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("""
                    SELECT host(cp.client_ip) AS client_ip,
                           COALESCE(SUM(ch.visit_count), 0) AS total_queries,
                           COUNT(DISTINCT ch.domain) AS unique_domains,
                           COALESCE(t.threat_count, 0) AS threat_count,
                           COALESCE(t.threat_count, 0) AS malicious_count,
                           0 AS suspicious_count,
                           COALESCE(SUM(ch.visit_count), 0) - COALESCE(t.threat_count, 0) AS clean_count,
                           to_char(cp.first_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS first_seen,
                           to_char(cp.last_seen, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                    FROM client_profiles cp
                    LEFT JOIN client_history ch ON cp.client_ip = ch.client_ip
                    LEFT JOIN (
                        SELECT client_ip, COUNT(*) AS threat_count
                        FROM domain_query_history
                        WHERE LOWER(COALESCE(final_label, '')) = 'malicious'
                        GROUP BY client_ip
                    ) t ON host(cp.client_ip) = t.client_ip
                    WHERE host(cp.client_ip) = %s
                    GROUP BY cp.client_ip, cp.first_seen, cp.last_seen, t.threat_count;
                """, (clean_ip,))
                row = cur.fetchone()
                if row:
                    client_row = dict(row)

                cur.execute("""
                    SELECT domain, visit_count AS count
                    FROM client_history
                    WHERE host(client_ip) = %s
                    ORDER BY visit_count DESC
                    LIMIT 10;
                """, (clean_ip,))
                top_domains_from_db = [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        logger.debug("PostgreSQL client query exception: %s", exc)

    # Query PostgreSQL for recent activity and detailed domain categorization
    pg_activity = _query_pg_client_query_history(clean_ip, limit=50)
    pg_breakdown = _query_pg_client_domain_breakdown(clean_ip)

    # Check if client was found in either database
    if not client_row and not pg_activity and not pg_breakdown:
        raise HTTPException(
            status_code=404,
            detail=f"Client IP '{clean_ip}' not found in telemetry database",
        )

    # Summary metrics calculation
    total_queries = client_row["total_queries"] if client_row else sum(b["query_count"] for b in pg_breakdown)
    unique_domains = client_row["unique_domains"] if client_row else len(pg_breakdown)
    first_seen = client_row.get("first_seen") if client_row else (str(pg_activity[-1]["timestamp"]) if pg_activity else None)
    last_seen = client_row.get("last_seen") if client_row else (str(pg_activity[0]["timestamp"]) if pg_activity else None)

    # Partition domain metrics
    malicious_domains_count = 0
    malicious_queries_count = 0
    suspicious_domains_count = 0
    suspicious_queries_count = 0
    benign_domains_count = 0
    benign_queries_count = 0
    unknown_domains_count = 0
    unknown_queries_count = 0

    threat_domains_list: List[Dict[str, Any]] = []
    top_domains_list: List[Dict[str, Any]] = []

    if pg_breakdown:
        for item in pg_breakdown:
            d = item["domain"]
            raw_label = (item.get("final_label") or "Unknown").strip().lower()
            ti = item.get("ti_source") or ""
            count = item["query_count"]
            ls = str(item["last_seen"]) if item.get("last_seen") else None

            # Enforce honest provenance: do NOT use "unknown" source for heuristics
            if raw_label in ("malicious", "threat"):
                malicious_domains_count += 1
                malicious_queries_count += count
                provenance = "PERSISTED" if ti in ("URLhaus", "URLHaus") else "COMPUTED"
                threat_domains_list.append({
                    "domain": d,
                    "label": "malicious",
                    "query_count": count,
                    "ti_source": ti or "Threat Correlation Engine",
                    "provenance": provenance,
                    "last_seen": ls,
                })
            elif raw_label in ("suspicious", "anomaly", "review_needed", "review needed"):
                suspicious_domains_count += 1
                suspicious_queries_count += count
                # If source was empty/unknown, attribute to heuristic detector explicitly
                heur_source = ti if (ti and ti.lower() != "unknown") else "heuristic_anomaly"
                threat_domains_list.append({
                    "domain": d,
                    "label": "review_needed",
                    "query_count": count,
                    "ti_source": heur_source,
                    "provenance": "COMPUTED",
                    "last_seen": ls,
                })
            elif raw_label in ("clean", "trusted", "benign"):
                benign_domains_count += 1
                benign_queries_count += count
            else:
                unknown_domains_count += 1
                unknown_queries_count += count

            # Top domain categorization
            top_source = ti
            if raw_label in ("suspicious", "anomaly", "review_needed", "review needed") and (not ti or ti.lower() == "unknown"):
                top_source = "heuristic_anomaly"
            elif not ti or ti.lower() == "unknown":
                top_source = None

            norm_top_label = raw_label
            if raw_label in ("suspicious", "anomaly", "review_needed", "review needed"):
                norm_top_label = "review_needed"
            elif raw_label in ("clean", "trusted"):
                norm_top_label = "benign"

            top_domains_list.append({
                "domain": d,
                "label": norm_top_label,
                "query_count": count,
                "ti_source": top_source,
                "provenance": "COMPUTED" if norm_top_label == "review_needed" else ("PERSISTED" if raw_label in ("malicious", "threat") else ("LOCAL" if top_source else "NO_DATA")),
                "last_seen": ls,
            })

        top_domains_list = sorted(top_domains_list, key=lambda x: x["query_count"], reverse=True)[:20]
    elif client_row:
        # Fallback to client_row aggregates if PG breakdown empty
        malicious_domains_count = client_row.get("malicious_count", 0)
        malicious_queries_count = client_row.get("threat_count", 0)
        benign_domains_count = client_row.get("clean_count", 0)
        benign_queries_count = client_row.get("clean_count", 0)
        for item in top_domains_from_db:
            top_domains_list.append({
                "domain": item.get("domain"),
                "query_count": item.get("count", 0),
                "label": "monitored",
                "ti_source": None,
                "provenance": "NO_DATA",
                "last_seen": None,
            })

    # Calculate ratios
    threat_traffic_ratio = (
        round((malicious_queries_count / max(1, total_queries)) * 100.0, 2)
        if total_queries > 0
        else 0.0
    )
    threat_domain_ratio = (
        round((malicious_domains_count / max(1, unique_domains)) * 100.0, 2)
        if unique_domains > 0
        else 0.0
    )

    # Format recent activity logs with consistent provenance & ti_source
    recent_activity_formatted = []
    for a in pg_activity:
        raw_lbl = str(a.get("final_label") or "").strip()
        raw_lbl_lower = raw_lbl.lower()
        ti = a.get("ti_source")

        if raw_lbl_lower in ("suspicious", "anomaly", "review_needed", "review needed"):
            lbl_mapped = "Review Needed"
            src = ti if (ti and str(ti).lower() != "unknown") else "heuristic_anomaly"
            prov = "COMPUTED"
        elif raw_lbl_lower in ("malicious", "threat"):
            lbl_mapped = "Malicious"
            src = ti or "Threat Correlation Engine"
            prov = "PERSISTED" if str(ti).lower() in ("urlhaus", "virustotal", "alienvault otx") else "COMPUTED"
        elif raw_lbl_lower in ("benign", "clean", "trusted"):
            lbl_mapped = "Benign"
            src = ti or "trusted"
            prov = "LOCAL"
        else:
            lbl_mapped = "Unknown"
            src = ti if (ti and str(ti).lower() != "unknown") else None
            prov = "NO_DATA"

        recent_activity_formatted.append({
            "timestamp": str(a.get("timestamp")),
            "domain": a.get("domain"),
            "query_type": a.get("query_type"),
            "response_code": a.get("response_code"),
            "final_label": lbl_mapped,
            "ti_source": src,
            "provenance": prov,
        })

    # Time-window scoped telemetry override if requested
    tw = _resolve_optional_window(window, start_time, end_time)
    range_summary = None
    if tw:
        try:
            from domain_profiling.connection import get_db_connection
            import psycopg2.extras
            with get_db_connection() as conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute("""
                        SELECT COUNT(*) AS total_queries,
                               COUNT(DISTINCT domain) AS unique_domains,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) = 'malicious') AS malicious_queries,
                               COUNT(DISTINCT CASE WHEN LOWER(COALESCE(final_label, '')) = 'malicious' THEN domain END) AS malicious_domains,
                               COUNT(*) FILTER (WHERE LOWER(COALESCE(final_label, '')) != 'malicious') AS clean_queries
                        FROM domain_query_history
                        WHERE client_ip = %s AND timestamp >= %s AND timestamp < %s;
                    """, (clean_ip, tw.start, tw.end))
                    cr_row = cur.fetchone() or {}

                    cur.execute("""
                        SELECT domain, COUNT(*) AS count,
                               CASE 
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) IN ('suspicious', 'review_needed', 'review needed') THEN 'Review Needed'
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) IN ('clean', 'benign') THEN 'Benign'
                                   WHEN LOWER(COALESCE(MODE() WITHIN GROUP (ORDER BY final_label), '')) = 'malicious' THEN 'Malicious'
                                   ELSE 'Unknown'
                               END AS label,
                               COALESCE(MODE() WITHIN GROUP (ORDER BY ti_source), 'internal') AS ti_source,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %s AND timestamp >= %s AND timestamp < %s
                        GROUP BY domain
                        ORDER BY count DESC
                        LIMIT 20;
                    """, (clean_ip, tw.start, tw.end))
                    cr_top = cur.fetchall()

                    cur.execute("""
                        SELECT domain, COUNT(*) AS count,
                               COALESCE(MODE() WITHIN GROUP (ORDER BY ti_source), 'Internal Engine') AS ti_source,
                               to_char(MAX(timestamp), 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS last_seen
                        FROM domain_query_history
                        WHERE client_ip = %s AND LOWER(COALESCE(final_label, '')) = 'malicious'
                          AND timestamp >= %s AND timestamp < %s
                        GROUP BY domain
                        ORDER BY count DESC
                        LIMIT 20;
                    """, (clean_ip, tw.start, tw.end))
                    cr_threats = cur.fetchall()

                    cur.execute("""
                        SELECT to_char(timestamp, 'YYYY-MM-DD"T"HH24:MI:SS"Z"') AS timestamp,
                               domain, query_type, response_code,
                               COALESCE(final_label, 'Unknown') AS final_label,
                               COALESCE(ti_source, 'Internal Engine') AS ti_source
                        FROM domain_query_history
                        WHERE client_ip = %s AND timestamp >= %s AND timestamp < %s
                        ORDER BY timestamp DESC
                        LIMIT 50;
                    """, (clean_ip, tw.start, tw.end))
                    cr_recent = cur.fetchall()

                    range_summary = {
                        "start": tw.start_iso,
                        "end": tw.end_iso,
                        "total_queries": cr_row.get("total_queries") or 0,
                        "unique_domains": cr_row.get("unique_domains") or 0,
                        "malicious_queries": cr_row.get("malicious_queries") or 0,
                        "malicious_domains": cr_row.get("malicious_domains") or 0,
                        "clean_queries": cr_row.get("clean_queries") or 0,
                    }
                    if cr_top:
                        top_domains_list = [{
                            "domain": r["domain"],
                            "query_count": r["count"],
                            "label": r["label"].lower(),
                            "ti_source": r["ti_source"],
                            "provenance": "PERSISTED" if r["label"].lower() == "malicious" else "LOCAL",
                            "last_seen": r["last_seen"],
                        } for r in cr_top]
                    if cr_threats:
                        threat_domains_list = [{
                            "domain": r["domain"],
                            "label": "malicious",
                            "query_count": r["count"],
                            "ti_source": r["ti_source"],
                            "provenance": "PERSISTED",
                            "last_seen": r["last_seen"],
                        } for r in cr_threats]
                    if cr_recent:
                        recent_activity_formatted = [{
                            "timestamp": r["timestamp"],
                            "domain": r["domain"],
                            "query_type": r["query_type"],
                            "response_code": r["response_code"],
                            "final_label": r["final_label"],
                            "ti_source": r["ti_source"],
                            "provenance": "PERSISTED" if r["final_label"].lower() == "malicious" else "LOCAL",
                        } for r in cr_recent]
        except Exception as exc:
            logger.debug("Error fetching client range metrics: %s", exc)

    # Phase 4 Client Endpoint Enrichment
    client_enrichment = _ENRICHMENT_MANAGER.enrich_client_ip(clean_ip, deadline=deadline)
    client_enrichment_dict = (
        client_enrichment.model_dump()
        if hasattr(client_enrichment, "model_dump")
        else client_enrichment.dict()
    )

    duration_ms = (time.perf_counter() - perf_start) * 1000.0

    return {
        "status": "success",
        "data": {
            "client": {
                "ip": clean_ip,
                "network_type": network_type,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "total_queries": total_queries,
            },
            "summary": {
                "total_queries": total_queries,
                "unique_domains": unique_domains,
                "malicious_queries": malicious_queries_count,
                "malicious_domains": malicious_domains_count,
                "suspicious_queries": suspicious_queries_count,
                "suspicious_domains": suspicious_domains_count,
                "benign_queries": benign_queries_count,
                "benign_domains": benign_domains_count,
                "unknown_queries": unknown_queries_count,
                "unknown_domains": unknown_domains_count,
                "threat_traffic_ratio": threat_traffic_ratio,
                "threat_domain_ratio": threat_domain_ratio,
                "threat_ratio": threat_traffic_ratio,  # Backward compatible alias
                "risk_status": "THREATS_DETECTED" if malicious_domains_count > 0 or suspicious_domains_count > 0 else "CLEAN_TRAFFIC",
            },
            "selected_range": range_summary,
            "threat_domains": threat_domains_list,
            "top_domains": top_domains_list,
            "recent_activity": recent_activity_formatted,
            "enrichment": client_enrichment_dict,
            "duration_ms": round(duration_ms, 2),
        },
    }
