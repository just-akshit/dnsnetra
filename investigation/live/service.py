"""
investigation/live/service.py
=============================
Live external intelligence for an arbitrary domain or IP address.

Orchestrates:

* VirusTotal + AlienVault OTX reputation (concurrently, reusing the existing
  provider stack, key rotation, and rate-limit handling).
* Live DNS resolution and RDAP registration for domains.
* A short in-process TTL cache so a page refresh does not burn API quota.

The service never raises because a provider failed — it degrades to an
``unknown`` verdict with per-provider status instead.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from investigation.enrichment.dns_resolver import DNSResolver
from investigation.enrichment.models import DNSResolutionResult, DomainRegistrationResult
from investigation.enrichment.rdap import RDAPEnricher
from investigation.live.models import (
    IPContext,
    IndicatorVerdict,
    LiveIntelReport,
    ProviderEvidence,
)
from investigation.live.verdict import evaluate_verdict
from labeler.config import LabelingConfig
from labeler.intel.correlation.models import ThreatProviderResult

logger = logging.getLogger(__name__)

DEFAULT_CACHE_TTL_SECONDS = 900
DEFAULT_PROVIDER_TIMEOUT_SECONDS = 5
DEFAULT_PROVIDER_DEADLINE_SECONDS = 6.0
DEFAULT_ENRICHMENT_DEADLINE_SECONDS = 2.0

# Bounded so a long-running process cannot grow one cache entry per searched
# indicator forever.
_CACHE_MAX_ENTRIES = 2000
_CACHE: "OrderedDict[str, Tuple[float, LiveIntelReport]]" = OrderedDict()
_CACHE_LOCK = threading.Lock()

_DEFAULT_PROVIDERS: Optional[List[Any]] = None
_DEFAULT_PROVIDERS_LOCK = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _get_default_providers() -> List[Any]:
    """Build the provider list once so key cooldowns survive across requests."""
    global _DEFAULT_PROVIDERS
    if _DEFAULT_PROVIDERS is None:
        with _DEFAULT_PROVIDERS_LOCK:
            if _DEFAULT_PROVIDERS is None:
                from labeler.intel.providers import get_enabled_providers

                if os.getenv("LIVE_INTEL_ENABLED", "true").strip().lower() in {
                    "0",
                    "false",
                    "no",
                    "off",
                }:
                    _DEFAULT_PROVIDERS = []
                    return _DEFAULT_PROVIDERS

                config = dict(LabelingConfig().get_online_ti_config())
                config.setdefault("API_TIMEOUT", DEFAULT_PROVIDER_TIMEOUT_SECONDS)
                _DEFAULT_PROVIDERS = get_enabled_providers(config)
    return _DEFAULT_PROVIDERS


def reset_live_intel_cache() -> None:
    """Clear the in-process cache and provider singletons (tests / config reload)."""
    global _DEFAULT_PROVIDERS
    with _CACHE_LOCK:
        _CACHE.clear()
    with _DEFAULT_PROVIDERS_LOCK:
        _DEFAULT_PROVIDERS = None


def _as_int(value: Any, fallback: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _bounded_dict(value: Any, limit: int = 20) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        str(key)[:80]: str(item)[:200]
        for key, item in list(value.items())[:limit]
    }


def _bounded_list(value: Any, limit: int = 20) -> List[str]:
    if not isinstance(value, (list, tuple)):
        return []
    return [str(item)[:120] for item in list(value)[:limit]]


class LiveIntelService:
    """Query live external reputation and infrastructure for one indicator."""

    def __init__(
        self,
        providers: Optional[List[Any]] = None,
        dns_resolver: Optional[Any] = None,
        rdap_enricher: Optional[Any] = None,
        cache_ttl: int = DEFAULT_CACHE_TTL_SECONDS,
    ) -> None:
        self._providers = providers
        self._dns_resolver = dns_resolver
        self._rdap_enricher = rdap_enricher
        self._cache_ttl = cache_ttl

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def lookup_domain(self, domain: str, refresh: bool = False) -> LiveIntelReport:
        clean = (domain or "").strip().rstrip(".").lower()
        if not clean:
            raise ValueError("Domain must be non-empty.")
        return self._cached(f"domain:{clean}", lambda: self._build_domain(clean), refresh)

    def lookup_ip(self, ip: str, refresh: bool = False) -> LiveIntelReport:
        clean = str(ipaddress.ip_address((ip or "").strip()))
        return self._cached(f"ip:{clean}", lambda: self._build_ip(clean), refresh)

    # ------------------------------------------------------------------
    # Cache
    # ------------------------------------------------------------------
    def _cached(self, key: str, builder: Any, refresh: bool = False) -> LiveIntelReport:
        now = time.monotonic()
        with _CACHE_LOCK:
            hit = _CACHE.get(key)
            if hit is not None and now < hit[0]:
                if not refresh:
                    _CACHE.move_to_end(key)
                    return hit[1]
                del _CACHE[key]

        report = builder()

        with _CACHE_LOCK:
            _CACHE[key] = (now + self._cache_ttl, report)
            _CACHE.move_to_end(key)
            while len(_CACHE) > _CACHE_MAX_ENTRIES:
                _CACHE.popitem(last=False)
        return report

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------
    def _build_domain(self, domain: str) -> LiveIntelReport:
        providers = self._providers if self._providers is not None else _get_default_providers()
        dns_resolver = self._dns_resolver or DNSResolver(timeout=1.5)
        rdap_enricher = self._rdap_enricher or RDAPEnricher(timeout=DEFAULT_ENRICHMENT_DEADLINE_SECONDS)
        deadline = time.monotonic() + DEFAULT_ENRICHMENT_DEADLINE_SECONDS

        with ThreadPoolExecutor(max_workers=2) as pool:
            dns_future = pool.submit(self._safe_dns, dns_resolver, domain, deadline)
            rdap_future = pool.submit(self._safe_rdap, rdap_enricher, domain, deadline)
            provider_results = self._run_providers(providers, domain, "domain")
            dns_records = dns_future.result()
            registration = rdap_future.result()

        evidences = [self._to_evidence(result) for result in provider_results]
        verdict = evaluate_verdict(evidences, registration)

        return LiveIntelReport(
            indicator=domain,
            kind="domain",
            verdict=verdict,
            providers=evidences,
            registration=registration,
            dns_records=dns_records,
            checked_at=_now_iso(),
        )

    def _build_ip(self, ip: str) -> LiveIntelReport:
        parsed = ipaddress.ip_address(ip)
        if (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
            or parsed.is_multicast
            or parsed.is_unspecified
        ):
            verdict = IndicatorVerdict(
                state="unknown",
                confidence=0.0,
                reasons=[
                    "Private, loopback, or reserved address — no external reputation exists."
                ],
            )
            return LiveIntelReport(
                indicator=str(parsed),
                kind="ip",
                verdict=verdict,
                checked_at=_now_iso(),
            )

        providers = self._providers if self._providers is not None else _get_default_providers()
        provider_results = self._run_providers(providers, ip, "ip")

        evidences = [self._to_evidence(result) for result in provider_results]
        verdict = evaluate_verdict(evidences)

        return LiveIntelReport(
            indicator=str(parsed),
            kind="ip",
            verdict=verdict,
            providers=evidences,
            ip_context=self._ip_context(evidences),
            checked_at=_now_iso(),
        )

    # ------------------------------------------------------------------
    # Provider helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _run_providers(providers: List[Any], value: str, kind: str) -> List[ThreatProviderResult]:
        """Query providers concurrently but never block the page past the deadline."""
        if not providers:
            return []

        pool = ThreadPoolExecutor(max_workers=len(providers))
        futures = {
            pool.submit(LiveIntelService._provider_lookup, provider, value, kind): provider
            for provider in providers
        }
        wait(futures, timeout=DEFAULT_PROVIDER_DEADLINE_SECONDS)

        results: List[ThreatProviderResult] = []
        for future, provider in futures.items():
            if future.done():
                results.append(future.result())
            else:
                results.append(
                    ThreatProviderResult(
                        provider=getattr(provider, "provider_name", "Unknown provider"),
                        unavailable=True,
                        error="Provider lookup timed out.",
                    )
                )

        # ponytail: stragglers finish in the background; do not block the request on them.
        pool.shutdown(wait=False, cancel_futures=True)
        return results

    @staticmethod
    def _provider_lookup(provider: Any, value: str, kind: str) -> ThreatProviderResult:
        name = getattr(provider, "provider_name", "Unknown provider")
        try:
            if kind == "domain":
                return provider.lookup(value)
            lookup_ip = getattr(provider, "lookup_ip", None)
            if lookup_ip is None:
                return ThreatProviderResult(
                    provider=name,
                    unavailable=True,
                    error="Provider does not support IP lookups.",
                )
            return lookup_ip(value)
        except Exception as exc:  # noqa: BLE001 - provider failures must not break the page
            logger.warning("[LIVE] %s lookup failed for %s: %s", name, value, exc)
            return ThreatProviderResult(
                provider=name,
                unavailable=True,
                error=str(exc),
            )

    @staticmethod
    def _safe_dns(
        resolver: Any,
        domain: str,
        deadline: float,
    ) -> Optional[DNSResolutionResult]:
        try:
            return resolver.resolve(domain, deadline=deadline)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[LIVE] DNS resolution failed for %s: %s", domain, exc)
            return None

    @staticmethod
    def _safe_rdap(
        enricher: Any,
        domain: str,
        deadline: float,
    ) -> Optional[DomainRegistrationResult]:
        try:
            return enricher.enrich(domain, deadline=deadline)
        except Exception as exc:  # noqa: BLE001
            logger.debug("[LIVE] RDAP lookup failed for %s: %s", domain, exc)
            return None

    @staticmethod
    def _to_evidence(result: ThreatProviderResult) -> ProviderEvidence:
        if result.provider == "VirusTotal":
            return LiveIntelService._virustotal_evidence(result)
        if result.provider == "AlienVault OTX":
            return LiveIntelService._otx_evidence(result)
        return ProviderEvidence(
            provider=result.provider,
            status="unavailable" if result.unavailable else "ok",
            malicious=result.malicious_count,
            suspicious=result.suspicious_count,
            harmless=result.harmless_count,
            confidence=result.confidence,
            error=result.error,
        )

    @staticmethod
    def _virustotal_evidence(result: ThreatProviderResult) -> ProviderEvidence:
        raw = result.raw_data if isinstance(result.raw_data, dict) else {}
        data = raw.get("data")
        attributes = data.get("attributes") if isinstance(data, dict) else None
        attributes = attributes if isinstance(attributes, dict) else {}
        stats = attributes.get("last_analysis_stats")
        stats = stats if isinstance(stats, dict) else {}

        malicious = _as_int(stats.get("malicious"), result.malicious_count)
        harmless = _as_int(stats.get("harmless"), result.harmless_count)
        suspicious = _as_int(stats.get("suspicious"), result.suspicious_count)
        undetected = _as_int(stats.get("undetected"), 0)
        total = malicious + harmless + suspicious + undetected
        if total == 0:
            total = result.malicious_count + result.harmless_count + result.suspicious_count

        if result.unavailable:
            status = "no_data" if attributes else "unavailable"
        elif total == 0:
            status = "no_data"
        else:
            status = "ok"

        details = {
            "categories": _bounded_dict(attributes.get("categories")),
            "reputation": attributes.get("reputation"),
            "votes": _bounded_dict(attributes.get("total_votes")),
            "creation_date": attributes.get("creation_date"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "registrar": attributes.get("registrar"),
            "tags": _bounded_list(attributes.get("tags")),
            "asn": attributes.get("asn"),
            "as_owner": attributes.get("as_owner"),
            "country": attributes.get("country"),
            "network": attributes.get("network"),
        }
        details = {
            key: value
            for key, value in details.items()
            if value not in (None, {}, [])
        }

        return ProviderEvidence(
            provider=result.provider,
            status=status,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            undetected=undetected,
            total=total,
            confidence=result.confidence,
            error=result.error,
            details=details,
        )

    @staticmethod
    def _otx_evidence(result: ThreatProviderResult) -> ProviderEvidence:
        raw = result.raw_data if isinstance(result.raw_data, dict) else {}
        general = raw.get("general") if isinstance(raw, dict) else None
        general = general if isinstance(general, dict) else {}

        pulse_count = result.malicious_count
        pulse_names: List[str] = []
        pulse_info = general.get("pulse_info")
        if isinstance(pulse_info, dict):
            pulses = pulse_info.get("pulses")
            if isinstance(pulses, list):
                pulse_count = len(pulses)
                pulse_names = [
                    str(pulse.get("name"))
                    for pulse in pulses[:10]
                    if isinstance(pulse, dict) and pulse.get("name")
                ]
            else:
                pulse_count = _as_int(pulse_info.get("count"), pulse_count)

        if result.unavailable:
            status = "unavailable"
        elif not raw:
            status = "no_data"
        else:
            status = "ok"

        details: Dict[str, Any] = {"pulse_count": pulse_count}
        if pulse_names:
            details["pulse_names"] = pulse_names

        return ProviderEvidence(
            provider=result.provider,
            status=status,
            pulse_count=pulse_count,
            confidence=result.confidence,
            error=result.error,
            details=details,
        )

    @staticmethod
    def _ip_context(evidences: List[ProviderEvidence]) -> Optional[IPContext]:
        virustotal = next(
            (
                evidence
                for evidence in evidences
                if evidence.provider == "VirusTotal" and evidence.status == "ok"
            ),
            None,
        )
        if virustotal is None:
            return None

        details = virustotal.details
        asn = details.get("asn")
        as_owner = details.get("as_owner")
        country = details.get("country")
        network = details.get("network")
        reputation = details.get("reputation")

        if all(value is None for value in (asn, as_owner, country, network, reputation)):
            return None

        return IPContext(
            asn=_as_int(asn) if asn is not None else None,
            as_owner=str(as_owner) if as_owner is not None else None,
            country=str(country) if country is not None else None,
            network=str(network) if network is not None else None,
            reputation=_as_int(reputation) if reputation is not None else None,
        )
