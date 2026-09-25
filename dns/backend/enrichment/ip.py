"""
IP Geolocation & ASN Enrichment
===============================
Independent IP enrichment:
- IP classification (PUBLIC, PRIVATE, LOOPBACK, LINK_LOCAL, MULTICAST, UNSPECIFIED, RESERVED)
- Local ASN enrichment via GeoLite2-ASN.mmdb (provenance: LOCAL)
- Public IP geographic enrichment via IPinfo (provenance: REAL)
- Strict RFC 1918 / non-public IP isolation (external GeoIP is NEVER called)
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

from enrichment.models import IPEnrichmentItem, IPGeoResult, IPNetworkResult

logger = logging.getLogger(__name__)

# Default ASN database path
_DEFAULT_ASN_DB = Path(__file__).parent.parent / "feature extraction" / "enrichment" / "databases" / "GeoLite2-ASN.mmdb"

try:
    import geoip2.database
except ImportError:
    geoip2 = None


def classify_ip(ip_str: str) -> Tuple[Optional[ipaddress.IPv4Address | ipaddress.IPv6Address], str]:
    """
    Classify an IP address string into standardized categories.
    Returns: (ip_obj, category)
    Categories: PUBLIC | PRIVATE | LOOPBACK | LINK_LOCAL | MULTICAST | UNSPECIFIED | RESERVED | INVALID
    """
    clean = (ip_str or "").strip()
    try:
        ip_obj = ipaddress.ip_address(clean)
    except ValueError:
        return None, "INVALID"

    if ip_obj.is_loopback:
        return ip_obj, "LOOPBACK"
    if ip_obj.is_link_local:
        return ip_obj, "LINK_LOCAL"
    if ip_obj.is_multicast:
        return ip_obj, "MULTICAST"
    if ip_obj.is_unspecified:
        return ip_obj, "UNSPECIFIED"
    if ip_obj.is_reserved:
        return ip_obj, "RESERVED"
    if ip_obj.is_private:
        return ip_obj, "PRIVATE"
    if ip_obj.is_global:
        return ip_obj, "PUBLIC"

    return ip_obj, "PRIVATE"


class IPEnricher:
    """
    Orchestrates ASN (local GeoLite2) and GeoIP (IPinfo) for individual and batched IP addresses.
    """

    def __init__(
        self,
        asn_db_path: Optional[str] = None,
        ipinfo_token: Optional[str] = None,
        ipinfo_base_url: Optional[str] = None,
        ipinfo_timeout: Optional[float] = None,
    ):
        self.asn_db_path = asn_db_path or os.getenv("GEOIP_ASN_DB_PATH", str(_DEFAULT_ASN_DB))
        self.ipinfo_token = (
            ipinfo_token
            if ipinfo_token is not None
            else os.getenv("IPINFO_TOKEN", "").strip()
        )
        self.ipinfo_base_url = (
            ipinfo_base_url or os.getenv("IPINFO_BASE_URL", "https://ipinfo.io")
        ).rstrip("/")
        self.ipinfo_timeout = (
            ipinfo_timeout
            if ipinfo_timeout is not None
            else float(os.getenv("IPINFO_TIMEOUT_SECONDS", "2.0"))
        )

        self._asn_reader = None
        self._init_asn_reader()

    def _init_asn_reader(self) -> None:
        if geoip2 is not None and os.path.exists(self.asn_db_path):
            try:
                self._asn_reader = geoip2.database.Reader(self.asn_db_path)
                logger.info("GeoLite2-ASN database loaded successfully from %s", self.asn_db_path)
            except Exception as exc:
                logger.warning("Failed to initialize GeoLite2-ASN database from %s: %s", self.asn_db_path, exc)
                self._asn_reader = None
        else:
            logger.debug("GeoLite2-ASN DB not available at %s", self.asn_db_path)
            self._asn_reader = None

    def enrich_ip(
        self,
        ip_str: str,
        deadline: Optional[float] = None,
    ) -> IPEnrichmentItem:
        """
        Enrich a single IP address with ASN and Geographic intelligence within the monotonic deadline.
        """
        ip_obj, category = classify_ip(ip_str)
        if ip_obj is None:
            return IPEnrichmentItem(
                ip=ip_str,
                ip_type="INVALID",
                geo=IPGeoResult(
                    status="NOT_APPLICABLE",
                    provider="IPinfo",
                    provenance="COMPUTED",
                    freshness="NOT_APPLICABLE",
                    error="Invalid IP address format",
                ),
                network=IPNetworkResult(
                    status="NOT_APPLICABLE",
                    provider="GeoLite2-ASN",
                    provenance="COMPUTED",
                    freshness="NOT_APPLICABLE",
                    error="Invalid IP address format",
                ),
            )

        # 1. If IP is not PUBLIC (e.g. RFC 1918 private, loopback, link-local):
        # External GeoIP must NOT be called.
        if category != "PUBLIC":
            return IPEnrichmentItem(
                ip=ip_str,
                ip_type=category,
                geo=IPGeoResult(
                    status="NOT_APPLICABLE",
                    provider="IPinfo",
                    provenance="COMPUTED",
                    freshness="NOT_APPLICABLE",
                ),
                network=IPNetworkResult(
                    status="NOT_APPLICABLE",
                    provider="GeoLite2-ASN",
                    provenance="COMPUTED",
                    freshness="NOT_APPLICABLE",
                ),
            )

        # 2. Public IP — Lookup ASN locally via GeoLite2-ASN (instant in-memory)
        network_result = self._lookup_asn(ip_str)

        # 3. Public IP — Lookup Geolocation via IPinfo bounded by deadline
        geo_result = self._lookup_geo(ip_str, deadline=deadline)

        return IPEnrichmentItem(
            ip=ip_str,
            ip_type="PUBLIC",
            geo=geo_result,
            network=network_result,
        )


    def _lookup_asn(self, ip_str: str) -> IPNetworkResult:
        """Lookup ASN using local GeoLite2-ASN.mmdb."""
        if not self._asn_reader:
            return IPNetworkResult(
                status="NO_DATA",
                provider="GeoLite2-ASN",
                provenance="LOCAL",
                freshness="LIVE_LOOKUP",
                error="GeoLite2-ASN database not loaded",
            )

        try:
            response = self._asn_reader.asn(ip_str)
            asn_num = response.autonomous_system_number
            asn_org = response.autonomous_system_organization

            if asn_num is not None:
                return IPNetworkResult(
                    status="AVAILABLE",
                    asn=f"AS{asn_num}",
                    asn_organization=asn_org,
                    provider="GeoLite2-ASN",
                    provenance="LOCAL",
                    freshness="LIVE_LOOKUP",
                )
            else:
                return IPNetworkResult(
                    status="NO_DATA",
                    provider="GeoLite2-ASN",
                    provenance="LOCAL",
                    freshness="LIVE_LOOKUP",
                )
        except geoip2.errors.AddressNotFoundError:
            return IPNetworkResult(
                status="NO_DATA",
                provider="GeoLite2-ASN",
                provenance="LOCAL",
                freshness="LIVE_LOOKUP",
            )
        except Exception as exc:
            logger.debug("Local ASN lookup error for %s: %s", ip_str, exc)
            return IPNetworkResult(
                status="PROVIDER_FAILURE",
                provider="GeoLite2-ASN",
                provenance="LOCAL",
                freshness="LIVE_LOOKUP",
                error=str(exc),
            )

    def _lookup_geo(
        self,
        ip_str: str,
        deadline: Optional[float] = None,
    ) -> IPGeoResult:
        """Lookup Geolocation using IPinfo API with deadline bounding."""
        if not self.ipinfo_token:
            return IPGeoResult(
                status="NOT_CONFIGURED",
                provider="IPinfo",
                provenance="REAL",
                freshness="NOT_APPLICABLE",
                error="IPINFO_TOKEN not configured",
            )

        now = time.monotonic()
        remaining = (deadline - now) if deadline is not None else self.ipinfo_timeout
        if remaining <= 0.05:
            return IPGeoResult(
                status="PROVIDER_FAILURE",
                provider="IPinfo",
                provenance="REAL",
                freshness="LIVE_LOOKUP",
                error="Enrichment deadline exceeded",
            )

        req_timeout = min(self.ipinfo_timeout, max(0.1, remaining))

        url = f"{self.ipinfo_base_url}/{ip_str}/json"
        headers = {
            "Authorization": f"Bearer {self.ipinfo_token}",
            "Accept": "application/json",
            "User-Agent": "DNSThreatDetection/1.0",
        }

        try:
            resp = requests.get(url, headers=headers, timeout=req_timeout)
            if resp.status_code == 200:
                data = resp.json()
                lat: Optional[float] = None
                lon: Optional[float] = None
                loc = data.get("loc")
                if loc and isinstance(loc, str) and "," in loc:
                    try:
                        parts = loc.split(",")
                        lat = float(parts[0].strip())
                        lon = float(parts[1].strip())
                    except (ValueError, IndexError):
                        lat, lon = None, None

                return IPGeoResult(
                    status="AVAILABLE",
                    country=data.get("country_name") or data.get("country"),
                    country_code=data.get("country"),
                    region=data.get("region"),
                    city=data.get("city"),
                    latitude=lat,
                    longitude=lon,
                    timezone=data.get("timezone"),
                    postal=data.get("postal"),
                    accuracy_radius=data.get("accuracy_radius"),
                    provider="IPinfo",
                    provenance="REAL",
                    freshness="LIVE_LOOKUP",
                )
            elif resp.status_code == 429:
                logger.warning("IPinfo rate limited (HTTP 429) for IP %s", ip_str)
                return IPGeoResult(
                    status="PROVIDER_FAILURE",
                    provider="IPinfo",
                    provenance="REAL",
                    freshness="LIVE_LOOKUP",
                    error="Rate limit exceeded (HTTP 429)",
                )
            elif resp.status_code == 404:
                return IPGeoResult(
                    status="NO_DATA",
                    provider="IPinfo",
                    provenance="REAL",
                    freshness="LIVE_LOOKUP",
                )
            else:
                return IPGeoResult(
                    status="PROVIDER_FAILURE",
                    provider="IPinfo",
                    provenance="REAL",
                    freshness="LIVE_LOOKUP",
                    error=f"HTTP {resp.status_code}",
                )
        except requests.Timeout:
            logger.debug("IPinfo timeout (%ss) for IP %s", self.ipinfo_timeout, ip_str)
            return IPGeoResult(
                status="PROVIDER_FAILURE",
                provider="IPinfo",
                provenance="REAL",
                freshness="LIVE_LOOKUP",
                error="Request timed out",
            )
        except Exception as exc:
            logger.debug("IPinfo request failed for %s: %s", ip_str, exc)
            return IPGeoResult(
                status="PROVIDER_FAILURE",
                provider="IPinfo",
                provenance="REAL",
                freshness="LIVE_LOOKUP",
                error=str(exc),
            )

    def enrich_ips_deduplicated(self, ip_list: List[str]) -> List[IPEnrichmentItem]:
        """
        Deduplicate IP addresses and enrich each unique IP once.
        Preserves encounter order.
        """
        seen = set()
        unique_ips: List[str] = []
        for ip in ip_list:
            clean = (ip or "").strip()
            if clean and clean not in seen:
                seen.add(clean)
                unique_ips.append(clean)

        return [self.enrich_ip(ip) for ip in unique_ips]
