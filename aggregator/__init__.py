"""
aggregator
==========
DNSNetra High-Performance Streaming & Batch Aggregation Engine.
"""

from aggregator.engine import DNSNetraAggregator, AggregationResult
from aggregator.config import DEFAULT_BATCH_SIZE, JOB_NAME
from aggregator.queries import (
    get_summary_kpis,
    get_timeseries,
    get_top_domains,
    get_top_malicious_domains,
    get_top_trusted_domains,
    get_top_clients,
    get_daily_review_queue,
)

__all__ = [
    "DNSNetraAggregator",
    "AggregationResult",
    "DEFAULT_BATCH_SIZE",
    "JOB_NAME",
    "get_summary_kpis",
    "get_timeseries",
    "get_top_domains",
    "get_top_malicious_domains",
    "get_top_trusted_domains",
    "get_top_clients",
    "get_daily_review_queue",
]
