"""
Dashboard Aggregation Package
=============================
Provides pre-computed dashboard metrics and summaries stored in SQLite (`dashboard.db`).

Usage:
    from dashboard_aggregation import DashboardAggregator
    from dashboard_aggregation import IncrementalAggregator
"""


from .aggregator import DashboardAggregator
from .incremental_aggregator import IncrementalAggregator


__all__ = ["DashboardAggregator", "IncrementalAggregator"]
