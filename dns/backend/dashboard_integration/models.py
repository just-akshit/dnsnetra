"""
Dashboard Integration Models
==============================
Lightweight data containers for the integration boundary.
These do NOT replace the backend's models — they represent
the subset of data the dashboard needs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DomainDetail:
    """Enriched domain information assembled from backend stores."""

    domain: str
    total_queries: int = 0
    unique_clients: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    last_label: Optional[str] = None
    last_ti_source: Optional[str] = None
    malicious_queries: int = 0
    clean_queries: int = 0
    unknown_queries: int = 0

    # Query-type breakdown
    query_a_count: int = 0
    query_aaaa_count: int = 0
    query_mx_count: int = 0
    query_txt_count: int = 0
    query_ns_count: int = 0
    query_other_count: int = 0

    # Recent query history
    recent_clients: list[str] = field(default_factory=list)
    recent_query_types: list[str] = field(default_factory=list)


@dataclass
class DataSourceStatus:
    """Health/availability status of backend data sources."""

    live_csv_available: bool = False
    live_csv_row_count: int = 0
    batch_csv_available: bool = False
    batch_csv_row_count: int = 0
    postgres_available: bool = False
    dashboard_db_available: bool = False
    error: Optional[str] = None
