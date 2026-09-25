"""
Dashboard Integration Layer
============================
Thin adapter between the existing DNS threat detection backend
and the dashboard aggregation / API layer.

The backend is the canonical source of truth.
This layer only reads — it never duplicates processing.
"""

from .data_source import DashboardDataSource

__all__ = ["DashboardDataSource"]
