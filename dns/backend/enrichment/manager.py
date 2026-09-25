"""
Enrichment Orchestrator
=======================
Coordinates DNS, RDAP, and IP enrichment with:
- Monotonic request-scoped deadline (default 3.5s budget)
- Concurrent execution via ThreadPoolExecutor
- Deduplication of resolved IPs
- Independent failure isolation and explicit availability aggregation
- Strict non-contamination (enrichment is observational only)
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from enrichment.dns import DNSResolverEnricher
from enrichment.ip import IPEnricher, classify_ip
from enrichment.models import (
    ClientIPEnrichmentResult,
    DNSResolutionResult,
    DomainEnrichmentResult,
    DomainRegistrationResult,
    IPEnrichmentItem,
    IPGeoResult,
    IPNetworkResult,
)
from enrichment.rdap import RDAPEnricher

logger = logging.getLogger(__name__)


class EnrichmentManager:
    """
    Orchestrates live domain and client enrichment with bounded timeouts and independent failure isolation.
    """

    def __init__(
        self,
        overall_budget: float = 3.5,
        dns_timeout: float = 0.8,
        ipinfo_timeout: float = 1.5,
        rdap_timeout: float = 2.5,
        asn_db_path: Optional[str] = None,
        ipinfo_token: Optional[str] = None,
    ):
        self.overall_budget = overall_budget
        self.dns_enricher = DNSResolverEnricher(timeout=dns_timeout)
        self.rdap_enricher = RDAPEnricher(timeout=rdap_timeout)
        self.ip_enricher = IPEnricher(
            asn_db_path=asn_db_path,
            ipinfo_token=ipinfo_token,
            ipinfo_timeout=ipinfo_timeout,
        )
        self._executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="enrich_worker")

    def enrich_domain(
        self,
        domain: str,
        deadline: Optional[float] = None,
    ) -> DomainEnrichmentResult:
        """
        Enrich a domain with live DNS resolution, resolved IP intelligence, and RDAP registration.
        Enforces monotonic deadline across all lookups without blocking main thread.
        """
        start_time = time.perf_counter()
        target_deadline = deadline if deadline is not None else (time.monotonic() + self.overall_budget)

        dns_result: Optional[DNSResolutionResult] = None
        rdap_result: Optional[DomainRegistrationResult] = None
        enriched_ips: List[IPEnrichmentItem] = []

        # Step 1: Concurrently dispatch DNS and RDAP on managed thread pool
        future_dns = self._executor.submit(self.dns_enricher.resolve, domain, target_deadline)
        future_rdap = self._executor.submit(self.rdap_enricher.enrich, domain, target_deadline)

        # Wait for DNS with remaining deadline
        time_left_dns = max(0.01, target_deadline - time.monotonic())
        try:
            dns_result = future_dns.result(timeout=time_left_dns)
        except Exception as exc:
            logger.debug("DNS resolution future timed out or failed: %s", exc)
            dns_result = DNSResolutionResult(
                status="PROVIDER_FAILURE",
                provider="DNS Resolver",
                provenance="REAL",
                freshness="LIVE_LOOKUP",
                error="Enrichment deadline exceeded" if (target_deadline - time.monotonic()) <= 0.05 else str(exc),
            )

        # Wait for RDAP with remaining deadline
        time_left_rdap = max(0.01, target_deadline - time.monotonic())
        try:
            rdap_result = future_rdap.result(timeout=time_left_rdap)
        except Exception as exc:
            logger.debug("RDAP future timed out or failed: %s", exc)
            rdap_result = DomainRegistrationResult(
                status="PROVIDER_FAILURE",
                provider="Authoritative RDAP",
                provenance="REAL",
                freshness="LIVE_LOOKUP",
                error="Enrichment deadline exceeded" if (target_deadline - time.monotonic()) <= 0.05 else str(exc),
            )

        # Fallback defaults if None
        if dns_result is None:
            dns_result = DNSResolutionResult(status="PROVIDER_FAILURE", error="Resolution not executed")
        if rdap_result is None:
            rdap_result = DomainRegistrationResult(status="PROVIDER_FAILURE", error="RDAP not executed")

        # Step 2: Extract unique resolved IPs from DNS answers
        all_resolved_ips = []
        for ip in dns_result.a + dns_result.aaaa:
            clean_ip = (ip or "").strip()
            if clean_ip and clean_ip not in all_resolved_ips:
                all_resolved_ips.append(clean_ip)

        # Step 3: Concurrently enrich unique resolved IPs within remaining deadline
        if all_resolved_ips:
            time_left_ip = target_deadline - time.monotonic()
            if time_left_ip > 0.05:
                ip_futures = {
                    self._executor.submit(self.ip_enricher.enrich_ip, ip, target_deadline): ip
                    for ip in all_resolved_ips
                }
                try:
                    for fut in as_completed(ip_futures, timeout=time_left_ip):
                        try:
                            enriched_item = fut.result()
                            enriched_ips.append(enriched_item)
                        except Exception as exc:
                            ip_addr = ip_futures[fut]
                            logger.debug("IP enrichment future failed for %s: %s", ip_addr, exc)
                            enriched_ips.append(
                                IPEnrichmentItem(
                                    ip=ip_addr,
                                    ip_type="PUBLIC",
                                    geo=IPGeoResult(
                                        status="PROVIDER_FAILURE",
                                        provider="IPinfo",
                                        provenance="REAL",
                                        freshness="LIVE_LOOKUP",
                                        error=str(exc),
                                    ),
                                    network=IPNetworkResult(
                                        status="PROVIDER_FAILURE",
                                        provider="GeoLite2-ASN",
                                        provenance="LOCAL",
                                        freshness="LIVE_LOOKUP",
                                        error=str(exc),
                                    ),
                                )
                            )
                except Exception as exc:
                    logger.debug("IP enrichment pool timed out: %s", exc)
                    # For any futures that didn't complete, append deadline-exceeded results
                    completed_ips = {item.ip for item in enriched_ips}
                    for ip in all_resolved_ips:
                        if ip not in completed_ips:
                            enriched_ips.append(
                                IPEnrichmentItem(
                                    ip=ip,
                                    ip_type="PUBLIC",
                                    geo=IPGeoResult(
                                        status="PROVIDER_FAILURE",
                                        provider="IPinfo",
                                        provenance="REAL",
                                        freshness="LIVE_LOOKUP",
                                        error="Enrichment deadline exceeded",
                                    ),
                                    network=IPNetworkResult(
                                        status="PROVIDER_FAILURE",
                                        provider="GeoLite2-ASN",
                                        provenance="LOCAL",
                                        freshness="LIVE_LOOKUP",
                                        error="Enrichment deadline exceeded",
                                    ),
                                )
                            )
            else:
                # Deadline reached before IP enrichment could start
                for ip in all_resolved_ips:
                    enriched_ips.append(
                        IPEnrichmentItem(
                            ip=ip,
                            ip_type="PUBLIC",
                            geo=IPGeoResult(
                                status="PROVIDER_FAILURE",
                                provider="IPinfo",
                                provenance="REAL",
                                freshness="LIVE_LOOKUP",
                                error="Enrichment deadline exceeded",
                            ),
                            network=IPNetworkResult(
                                status="PROVIDER_FAILURE",
                                provider="GeoLite2-ASN",
                                provenance="LOCAL",
                                freshness="LIVE_LOOKUP",
                                error="Enrichment deadline exceeded",
                            ),
                        )
                    )

        # Step 4: Aggregate overall domain enrichment status
        overall_status = self._aggregate_domain_status(dns_result, enriched_ips, rdap_result)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        return DomainEnrichmentResult(
            status=overall_status,
            dns=dns_result,
            ips=enriched_ips,
            registration=rdap_result,
            duration_ms=round(elapsed_ms, 2),
        )

    def enrich_client_ip(
        self,
        client_ip: str,
        deadline: Optional[float] = None,
    ) -> ClientIPEnrichmentResult:
        """
        Enrich a client IP address with ASN and Geographic intelligence.
        Guards private/internal IPs with NOT_APPLICABLE.
        """
        start_time = time.perf_counter()
        enriched_item = self.ip_enricher.enrich_ip(client_ip, deadline=deadline)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0


        # Overall client IP status
        if enriched_item.ip_type != "PUBLIC":
            status = "NOT_APPLICABLE"
        elif (
            enriched_item.geo.status == "AVAILABLE"
            or enriched_item.network.status == "AVAILABLE"
        ):
            status = (
                "AVAILABLE"
                if (enriched_item.geo.status in ("AVAILABLE", "NOT_CONFIGURED") and enriched_item.network.status == "AVAILABLE")
                else "PARTIAL"
            )
        elif (
            enriched_item.geo.status == "PROVIDER_FAILURE"
            and enriched_item.network.status == "PROVIDER_FAILURE"
        ):
            status = "PROVIDER_FAILURE"
        elif enriched_item.geo.status == "NOT_CONFIGURED" and enriched_item.network.status == "NO_DATA":
            status = "PARTIAL"
        else:
            status = "NO_DATA"

        return ClientIPEnrichmentResult(
            ip=enriched_item.ip,
            ip_type=enriched_item.ip_type,
            status=status,
            geo=enriched_item.geo,
            network=enriched_item.network,
            duration_ms=round(elapsed_ms, 2),
        )

    def _aggregate_domain_status(
        self,
        dns_res: DNSResolutionResult,
        ips: List[IPEnrichmentItem],
        rdap_res: DomainRegistrationResult,
    ) -> str:
        """
        Derive overall availability status across DNS, IP Geo/ASN, and RDAP.
        """
        components = [dns_res.status, rdap_res.status]
        for item in ips:
            components.append(item.network.status)
            components.append(item.geo.status)

        has_available = any(c == "AVAILABLE" for c in components)
        has_failure = any(c == "PROVIDER_FAILURE" for c in components)
        has_no_data = any(c == "NO_DATA" for c in components)
        has_not_configured = any(c == "NOT_CONFIGURED" for c in components)

        if has_available:
            if has_failure or has_no_data or has_not_configured:
                return "PARTIAL"
            return "AVAILABLE"

        if has_failure and not has_available and not has_no_data:
            return "PROVIDER_FAILURE"

        if has_no_data and not has_available:
            return "NO_DATA"

        if has_not_configured and not has_available and not has_no_data:
            return "NOT_CONFIGURED"

        return "PARTIAL" if (has_failure or has_no_data) else "NO_DATA"
