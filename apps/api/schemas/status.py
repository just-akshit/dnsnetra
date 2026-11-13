"""
api/schemas/status.py
=====================
System status and health schemas for GET /api/v1/status.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class DatabaseHealth(BaseModel):
    """PostgreSQL connection health metrics."""
    model_config = ConfigDict(frozen=True)

    connected: bool = Field(..., description="Whether PostgreSQL is reachable")
    database: str = Field(..., description="Target database name")
    latency_ms: Optional[float] = Field(None, description="Round-trip query latency in ms")


class AggregationStatus(BaseModel):
    """Aggregation pipeline state and watermark tracking."""
    model_config = ConfigDict(frozen=True)

    job_name: str = Field(..., description="Aggregation job identifier")
    status: str = Field(..., description="Pipeline execution state (e.g. idle, processing)")
    watermark_id: int = Field(..., description="Highest processed query history event ID")
    pending_events: int = Field(..., description="Number of unaggregated query history events")
    total_history_events: int = Field(..., description="Total rows in domain_query_history")
    total_events_processed: int = Field(..., description="Lifetime count of processed events")
    last_run_at: Optional[str] = Field(None, description="Timestamp of last aggregation execution")
    hourly_rollup_buckets: int = Field(0, description="Total buckets in telemetry_hourly_rollup")
    daily_domain_rollup_records: int = Field(0, description="Total records in telemetry_daily_domain_rollup")


class SystemStatusResponse(BaseModel):
    """
    Authoritative backend and pipeline status.
    """
    model_config = ConfigDict(frozen=True)

    status: str = Field("healthy", description="Overall service status")
    service: str = Field("dnsnetra-backend", description="Service identifier")
    version: str = Field("2.0.0", description="Service version")
    database: DatabaseHealth
    aggregation: Optional[AggregationStatus] = None
    timestamp: str = Field(..., description="ISO-8601 UTC timestamp of status check")


__all__ = [
    "DatabaseHealth",
    "AggregationStatus",
    "SystemStatusResponse",
]
