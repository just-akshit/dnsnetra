"""
api/routes/status.py
====================
Authoritative system status endpoint:
- GET /api/v1/status
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status

from api.auth import get_current_user
from api.schemas import (
    AggregationStatus,
    DatabaseHealth,
    SystemStatusResponse,
)
from domain_profiling.connection import get_db_connection

logger = logging.getLogger("api_status")

router = APIRouter(prefix="/api/v1/status", tags=["Status"])


def _check_db_connectivity() -> tuple[bool, str, Optional[float]]:
    """Test PostgreSQL connectivity directly via SELECT 1."""
    start = time.perf_counter()
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_database();")
                row = cur.fetchone()
                dbname = row[0] if row else "dns_threat_detection"
        elapsed_ms = round((time.perf_counter() - start) * 1000, 2)
        return True, dbname, elapsed_ms
    except Exception as exc:
        logger.error("PostgreSQL status check failed: %s", exc)
        return False, "unknown", None


def _get_aggregator_status() -> Optional[AggregationStatus]:
    """Retrieve current aggregation watermark and pipeline state."""
    try:
        from aggregator.engine import DNSNetraAggregator
        engine = DNSNetraAggregator()
        raw = engine.get_status()
        return AggregationStatus(
            job_name=raw.get("job_name", "hourly_telemetry_rollup"),
            status=raw.get("status", "unknown"),
            watermark_id=raw.get("watermark_id", 0),
            pending_events=raw.get("pending_events", 0),
            total_history_events=raw.get("total_history_events", 0),
            total_events_processed=raw.get("total_events_processed", 0),
            last_run_at=str(raw["last_run_at"]) if raw.get("last_run_at") else None,
            hourly_rollup_buckets=raw.get("hourly_rollup_buckets", 0),
            daily_domain_rollup_records=raw.get("daily_domain_rollup_records", 0),
        )
    except Exception as exc:
        logger.warning("Could not retrieve aggregator status: %s", exc)
        return None


@router.get(
    "",
    response_model=SystemStatusResponse,
    summary="System and Pipeline Health Status",
    description="Reports authoritative PostgreSQL connectivity, aggregation watermark pointer, and pipeline state.",
)
def get_system_status(current_user: dict[str, Any] = Depends(get_current_user)) -> SystemStatusResponse:
    """Authoritative backend status check."""
    connected, dbname, latency = _check_db_connectivity()
    if not connected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="PostgreSQL database unreachable",
        )

    agg_status = _get_aggregator_status()
    now_iso = datetime.now(timezone.utc).isoformat()

    return SystemStatusResponse(
        status="healthy",
        service="dnsnetra-backend",
        version="2.0.0",
        database=DatabaseHealth(
            connected=connected,
            database=dbname,
            latency_ms=latency,
        ),
        aggregation=agg_status,
        timestamp=now_iso,
    )
