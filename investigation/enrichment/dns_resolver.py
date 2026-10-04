"""
investigation/enrichment/dns_resolver.py
========================================
Bounded live DNS infrastructure resolver for DNSNetra.
Resolves A, AAAA, CNAME, NS, and MX records via dnspython within strict deadlines.
"""

from __future__ import annotations

import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, List, Optional, Tuple

import dns.resolver
import dns.exception

from .models import DNSResolutionResult, MXRecord

logger = logging.getLogger(__name__)


class DNSResolver:
    """
    Performs live DNS resolution for domain names with bounded timeouts,
    parallel record resolution, and monotonic deadline propagation.
    """

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def _resolve_single_type(
        self,
        domain: str,
        qtype: str,
        query_timeout: float,
    ) -> Tuple[str, List[Any], Optional[Exception]]:
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

        with ThreadPoolExecutor(max_workers=5, thread_name_prefix="dnsnetra_res") as pool:
            futures = {
                pool.submit(self._resolve_single_type, clean_domain, qt, query_timeout): qt
                for qt in qtypes
            }

            try:
                for fut in as_completed(futures, timeout=max(0.1, remaining)):
                    try:
                        qt, answers, exc = fut.result()
                        if exc is None:
                            had_successful_query = True
                            for r in answers:
                                if qt == "A":
                                    a_records.append(str(r.address))
                                elif qt == "AAAA":
                                    aaaa_records.append(str(r.address))
                                elif qt == "CNAME":
                                    cname_records.append(str(r.target).rstrip("."))
                                elif qt == "NS":
                                    ns_records.append(str(r.target).rstrip("."))
                                elif qt == "MX":
                                    mx_records.append(
                                        MXRecord(
                                            priority=int(r.preference),
                                            exchange=str(r.exchange).rstrip("."),
                                        )
                                    )
                        elif isinstance(exc, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers)):
                            pass
                        else:
                            had_provider_failure = True
                            if not error_msg:
                                error_msg = str(exc)
                    except Exception as exc:
                        had_provider_failure = True
                        if not error_msg:
                            error_msg = str(exc)
            except TimeoutError:
                had_provider_failure = True
                error_msg = "DNS resolution pool deadline exceeded"

        # Determine overall status
        status = "AVAILABLE" if had_successful_query else ("PROVIDER_FAILURE" if had_provider_failure else "NO_DATA")

        return DNSResolutionResult(
            status=status,
            a=sorted(list(set(a_records))),
            aaaa=sorted(list(set(aaaa_records))),
            cname=sorted(list(set(cname_records))),
            ns=sorted(list(set(ns_records))),
            mx=sorted(mx_records, key=lambda x: (x.priority, x.exchange)),
            provider="DNS Resolver",
            provenance="REAL",
            freshness="LIVE_LOOKUP",
            error=error_msg,
        )
