"""
Live DNS Infrastructure Resolver
=================================
Resolves A, AAAA, CNAME, NS, and MX records live using dnspython with bounded timeouts.
Preserves complete record information (including MX priority and exchange).
Strictly separates live DNS resolution from historical DNS query telemetry.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Optional

import dns.resolver
import dns.exception

from enrichment.models import DNSResolutionResult, MXRecord

logger = logging.getLogger(__name__)


class DNSResolverEnricher:
    """
    Performs live DNS resolution for domain names with bounded timeout,
    parallel record resolution, and strict deadline propagation.
    """

    def __init__(self, timeout: float = 0.8):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _resolve_single_type(
        self,
        domain: str,
        qtype: str,
        query_timeout: float,
    ) -> tuple[str, List[Any], Optional[Exception]]:
        try:
            answers = self.resolver.resolve(domain, qtype, lifetime=query_timeout)
            return qtype, list(answers), None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers) as exc:
            return qtype, [], exc
        except Exception as exc:
            logger.debug("DNS %s lookup failed for %s: %s", qtype, domain, exc)
            return qtype, [], exc


    def resolve(
        self,
        domain: str,
        deadline: Optional[float] = None,
    ) -> DNSResolutionResult:
        """
        Resolve A, AAAA, CNAME, NS, and MX records in parallel within the deadline.
        """
        clean_domain = (domain or "").strip().rstrip(".")
        if not clean_domain:
            return DNSResolutionResult(
                status="NO_DATA",
                error="Empty domain name provided",
            )

        now = time.monotonic()
        remaining = (deadline - now) if deadline is not None else self.timeout
        if remaining <= 0.05:
            return DNSResolutionResult(
                status="PROVIDER_FAILURE",
                provider="DNS Resolver",
                provenance="REAL",
                freshness="LIVE_LOOKUP",
                error="Enrichment deadline exceeded",
            )

        query_timeout = min(self.timeout, max(0.1, remaining))

        a_records: List[str] = []
        aaaa_records: List[str] = []
        cname_records: List[str] = []
        ns_records: List[str] = []
        mx_records: List[MXRecord] = []

        had_successful_query = False
        had_provider_failure = False
        error_msg: Optional[str] = None

        qtypes = ["A", "AAAA", "CNAME", "NS", "MX"]

        # Run record resolutions in parallel
        with ThreadPoolExecutor(max_workers=5, thread_name_prefix="dns_res") as pool:
            futures = {
                pool.submit(self._resolve_single_type, clean_domain, qt, query_timeout): qt
                for qt in qtypes
            }

            try:
                for fut in as_completed(futures, timeout=max(0.1, remaining)):
                    qt, answers, exc = fut.result()
                    if exc is not None:
                        if isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers)):
                            pass
                        else:
                            had_provider_failure = True
                            if not error_msg:
                                error_msg = str(exc)
                    elif answers:
                        had_successful_query = True
                        if qt == "A":
                            for rdata in answers:
                                addr = str(rdata.address).strip()
                                if addr and addr not in a_records:
                                    a_records.append(addr)
                        elif qt == "AAAA":
                            for rdata in answers:
                                addr = str(rdata.address).strip()
                                if addr and addr not in aaaa_records:
                                    aaaa_records.append(addr)
                        elif qt == "CNAME":
                            for rdata in answers:
                                target = str(rdata.target).rstrip(".").strip()
                                if target and target not in cname_records:
                                    cname_records.append(target)
                        elif qt == "NS":
                            for rdata in answers:
                                ns_target = str(rdata.target).rstrip(".").strip()
                                if ns_target and ns_target not in ns_records:
                                    ns_records.append(ns_target)
                        elif qt == "MX":
                            seen_mx = set()
                            for rdata in answers:
                                exchange = str(rdata.exchange).rstrip(".").strip()
                                prio = int(rdata.preference)
                                if (prio, exchange) not in seen_mx:
                                    seen_mx.add((prio, exchange))
                                    mx_records.append(MXRecord(priority=prio, exchange=exchange))
            except Exception as exc:
                logger.debug("DNS parallel resolution pool timed out or failed: %s", exc)
                had_provider_failure = True
                if not error_msg:
                    error_msg = f"DNS resolution timeout: {exc}"

        # Determine overall DNS status
        if had_successful_query:
            status = "AVAILABLE"
        elif had_provider_failure and not had_successful_query and not (a_records or aaaa_records):
            status = "PROVIDER_FAILURE"
        else:
            status = "NO_DATA"

        return DNSResolutionResult(
            status=status,
            a=a_records,
            aaaa=aaaa_records,
            cname=cname_records,
            ns=ns_records,
            mx=mx_records,
            provider="DNS Resolver",
            provenance="REAL",
            freshness="LIVE_LOOKUP",
            error=error_msg if status == "PROVIDER_FAILURE" else None,
        )

