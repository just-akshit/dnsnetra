"""
DNS Threat Intelligence — PostgreSQL Reputation Database
=======================================================
A production-quality, extensible reputation database module
that stores malicious domains detected by the DNS pipeline.

Exposed public API (single import):
    initialize_database()
    store_malicious_domain(domain, metadata=None)
    get_domain(domain)
    update_domain(domain, **kwargs)
    cleanup_old_domains(days=180)
    reconcile_reputation_records()
    close_connection()
"""

from .repository import (
    initialize_database,
    store_malicious_domain,
    get_domain,
    get_domains_by_status,
    get_recent_domains,
    count_domains,
    update_domain,
    cleanup_old_domains,
    reconcile_reputation_records,
    remove_malicious_domain,
    close_connection,
)

__all__ = [
    "initialize_database",
    "store_malicious_domain",
    "get_domain",
    "get_domains_by_status",
    "get_recent_domains",
    "count_domains",
    "update_domain",
    "cleanup_old_domains",
    "reconcile_reputation_records",
    "remove_malicious_domain",
    "close_connection",
]
