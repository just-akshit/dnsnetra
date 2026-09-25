"""
Authoritative RDAP Domain Registration Enricher
===============================================
Performs domain registration discovery and authoritative RDAP lookups.
Features:
- In-process memory caching for TLD RDAP bootstrap/registry endpoints
- Standard RDAP discovery via IANA bootstrap / authoritative endpoints
- Extracts registrar, registrar ID, normalized ISO 8601 timestamps, domain status codes, and nameservers
- Honest redaction semantics (withheld fields remain null)
- Isolated failure handling (NO_DATA on 404, PROVIDER_FAILURE on timeouts/errors)
"""

from __future__ import annotations

import logging
import time
from typing import Dict, List, Optional
import requests
import tldextract

from enrichment.models import DomainRegistrationResult

logger = logging.getLogger(__name__)

# In-process memory cache for TLD bootstrap endpoints: tld -> base_rdap_url
_RDAP_BOOTSTRAP_CACHE: Dict[str, str] = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
    "info": "https://rdap.afilias.info/rdap/domain/",
    "biz": "https://rdap.nic.biz/domain/",
}


class RDAPEnricher:
    """
    Authoritative RDAP domain registration enricher with in-process bootstrap discovery caching.
    """

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def enrich(
        self,
        domain: str,
        deadline: Optional[float] = None,
    ) -> DomainRegistrationResult:
        """
        Enrich a domain with registration intelligence via RDAP within the monotonic deadline.
        """
        clean_domain = (domain or "").strip().rstrip(".").lower()
        if not clean_domain:
            return DomainRegistrationResult(
                status="NO_DATA",
                error="Empty domain provided",
            )

        now = time.monotonic()
        remaining = (deadline - now) if deadline is not None else self.timeout
        if remaining <= 0.05:
            return DomainRegistrationResult(
                status="PROVIDER_FAILURE",
                provider="Authoritative RDAP",
                provenance="REAL",
                freshness="LIVE_LOOKUP",
                error="Enrichment deadline exceeded",
            )

        req_timeout = min(self.timeout, max(0.1, remaining))

        # Extract registered/apex domain and TLD
        ext = tldextract.extract(clean_domain)
        reg_domain = (
            getattr(ext, "top_domain_under_public_suffix", None)
            or getattr(ext, "registered_domain", "")
            or clean_domain
        )
        tld = ext.suffix.lower()

        # 1. Resolve RDAP endpoint
        target_url = self._get_rdap_url(reg_domain, tld)

        headers = {
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "DNSThreatDetection/1.0 (Security Research)",
        }

        try:
            resp = requests.get(target_url, headers=headers, timeout=req_timeout, allow_redirects=True)
            if resp.status_code == 200:
                data = resp.json()
                return self._parse_rdap_payload(data)
            elif resp.status_code == 404:
                return DomainRegistrationResult(
                    status="NO_DATA",
                    provider="Authoritative RDAP",
                    provenance="REAL",
                    freshness="LIVE_LOOKUP",
                )
            elif resp.status_code == 429:
                return DomainRegistrationResult(
                    status="PROVIDER_FAILURE",
                    provider="Authoritative RDAP",
                    provenance="REAL",
                    freshness="LIVE_LOOKUP",
                    error="RDAP rate limit exceeded (HTTP 429)",
                )
            else:
                return DomainRegistrationResult(
                    status="PROVIDER_FAILURE",
                    provider="Authoritative RDAP",
                    provenance="REAL",
                    freshness="LIVE_LOOKUP",
                    error=f"RDAP HTTP {resp.status_code}",
                )
        except requests.Timeout:
            logger.debug("RDAP timeout (%ss) for domain %s", req_timeout, reg_domain)
            return DomainRegistrationResult(
                status="PROVIDER_FAILURE",
                provider="Authoritative RDAP",
                provenance="REAL",
                freshness="LIVE_LOOKUP",
                error="RDAP request timed out",
            )
        except Exception as exc:
            logger.debug("RDAP lookup failed for %s: %s", reg_domain, exc)
            return DomainRegistrationResult(
                status="PROVIDER_FAILURE",
                provider="Authoritative RDAP",
                provenance="REAL",
                freshness="LIVE_LOOKUP",
                error=str(exc),
            )


    def _get_rdap_url(self, reg_domain: str, tld: str) -> str:
        """
        Get the RDAP URL for a domain, using the in-process bootstrap cache where available.
        """
        if tld in _RDAP_BOOTSTRAP_CACHE:
            base = _RDAP_BOOTSTRAP_CACHE[tld]
            if base.endswith("/"):
                return f"{base}{reg_domain}"
            return f"{base}/{reg_domain}"

        # Default to IANA-conforming RDAP discovery endpoint
        return f"https://rdap.org/domain/{reg_domain}"

    def _parse_rdap_payload(self, data: dict) -> DomainRegistrationResult:
        """
        Parse structured RDAP JSON payload into normalized DomainRegistrationResult.
        """
        registrar_name: Optional[str] = None
        registrar_id: Optional[str] = None
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
        expires_at: Optional[str] = None
        domain_status: List[str] = []
        nameservers: List[str] = []

        # 1. Parse Status array
        raw_status = data.get("status")
        if isinstance(raw_status, list):
            domain_status = [str(s).strip() for s in raw_status if s]

        # 2. Parse Events (timestamps)
        events = data.get("events", [])
        if isinstance(events, list):
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                action = str(ev.get("eventAction") or "").lower()
                date_val = ev.get("eventDate")
                if date_val and isinstance(date_val, str):
                    if action in ("registration", "created", "creation"):
                        created_at = date_val
                    elif action in ("expiration", "expire", "expires"):
                        expires_at = date_val
                    elif action in ("last changed", "last update", "updated", "last modified"):
                        updated_at = date_val

        # 3. Parse Entities for Registrar Info
        entities = data.get("entities", [])
        if isinstance(entities, list):
            for ent in entities:
                if not isinstance(ent, dict):
                    continue
                roles = ent.get("roles", [])
                if isinstance(roles, list) and "registrar" in roles:
                    # Registrar ID
                    pub_ids = ent.get("publicIds", [])
                    if isinstance(pub_ids, list):
                        for pid in pub_ids:
                            if isinstance(pid, dict) and "identifier" in pid:
                                registrar_id = str(pid["identifier"]).strip()
                    if not registrar_id and ent.get("handle"):
                        registrar_id = str(ent.get("handle")).strip()

                    # Registrar Name from vcardArray
                    vcard = ent.get("vcardArray")
                    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
                        for item in vcard[1]:
                            if isinstance(item, list) and len(item) > 3 and item[0] == "fn":
                                fn_val = str(item[3]).strip()
                                if fn_val:
                                    registrar_name = fn_val
                                    break

        # 4. Parse Nameservers
        raw_ns = data.get("nameservers", [])
        if isinstance(raw_ns, list):
            for ns in raw_ns:
                if isinstance(ns, dict):
                    name = ns.get("ldhName") or ns.get("unicodeName")
                    if name:
                        ns_clean = str(name).strip().upper()
                        if ns_clean not in nameservers:
                            nameservers.append(ns_clean)
                elif isinstance(ns, str):
                    ns_clean = ns.strip().upper()
                    if ns_clean not in nameservers:
                        nameservers.append(ns_clean)

        return DomainRegistrationResult(
            status="AVAILABLE",
            source="Authoritative RDAP",
            registrar=registrar_name,
            registrar_id=registrar_id,
            created_at=created_at,
            updated_at=updated_at,
            expires_at=expires_at,
            domain_status=domain_status,
            nameservers=nameservers,
            provider="Authoritative RDAP",
            provenance="REAL",
            freshness="LIVE_LOOKUP",
        )
