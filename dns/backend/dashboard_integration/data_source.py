"""
Dashboard Integration — Data Source
=====================================
Provides a clean interface for the DashboardAggregator to consume
processed data from the existing backend, regardless of whether
the data came from the live pipeline or batch pipeline.

The aggregator should call DashboardDataSource instead of reading
CSVs or PostgreSQL directly.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import pandas as pd

from .models import DataSourceStatus

logger = logging.getLogger(__name__)

# Paths relative to backend/ root
_BACKEND_ROOT = Path(__file__).parent.parent.resolve()

# Live pipeline labeled output (written by the hook we add to run_live_pipeline.py)
LIVE_LABELLED_PATH = _BACKEND_ROOT / "live_labelled_dataset.csv"

# Batch pipeline labeled output (existing)
BATCH_LABELLED_PATH = _BACKEND_ROOT / "parsing logs" / "labelled_dns_dataset.csv"


class DashboardDataSource:
    """
    Reads processed/labelled DNS event data from the backend.

    The aggregator does not need to know whether the data came from
    Kafka, Fluent Bit, BIND logs, or batch processing.
    """

    def __init__(
        self,
        live_path: Path = LIVE_LABELLED_PATH,
        batch_path: Path = BATCH_LABELLED_PATH,
    ) -> None:
        self.live_path = live_path
        self.batch_path = batch_path

    # ------------------------------------------------------------------
    # Core data access
    # ------------------------------------------------------------------

    def get_labelled_events(self, source: str = "auto") -> pd.DataFrame:
        """
        Returns a DataFrame of labelled DNS events.

        Args:
            source: "live", "batch", or "auto".
                    "auto" prefers live if it exists, falls back to batch.

        Returns:
            pd.DataFrame with at minimum: domain, client_ip, query_type,
            response_code, label, threat_score, confidence, label_reason,
            ti_source, and a timestamp column.

        Raises:
            FileNotFoundError: if no labelled dataset is available.
        """
        path = self._resolve_path(source)

        if path is None:
            raise FileNotFoundError(
                "No labelled dataset found. "
                f"Checked: live={self.live_path}, batch={self.batch_path}"
            )

        logger.info("Loading labelled events from %s", path)
        df = pd.read_csv(path)
        logger.info("Loaded %d rows, %d columns from %s", len(df), len(df.columns), path.name)
        return df

    # ------------------------------------------------------------------
    # Status / health
    # ------------------------------------------------------------------

    def get_status(self) -> DataSourceStatus:
        """Reports which data sources are currently available."""
        status = DataSourceStatus()

        if self.live_path.exists():
            status.live_csv_available = True
            try:
                # Count lines without loading full file
                with open(self.live_path, "r") as f:
                    status.live_csv_row_count = max(sum(1 for _ in f) - 1, 0)
            except Exception:
                pass

        if self.batch_path.exists():
            status.batch_csv_available = True
            try:
                with open(self.batch_path, "r") as f:
                    status.batch_csv_row_count = max(sum(1 for _ in f) - 1, 0)
            except Exception:
                pass

        # Check PostgreSQL
        try:
            from .repository import _get_pg_connection

            conn = _get_pg_connection()
            if conn is not None:
                status.postgres_available = True
                conn.close()
        except Exception:
            pass

        # Check dashboard.db
        try:
            from dashboard_aggregation.config import DASHBOARD_DB_PATH

            status.dashboard_db_available = DASHBOARD_DB_PATH.exists()
        except Exception:
            pass

        return status

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _resolve_path(self, source: str) -> Optional[Path]:
        """Resolves which CSV to read based on source preference."""
        if source == "live":
            return self.live_path if self.live_path.exists() else None
        elif source == "batch":
            return self.batch_path if self.batch_path.exists() else None
        else:
            # auto: prefer live, fall back to batch
            if self.live_path.exists():
                return self.live_path
            if self.batch_path.exists():
                return self.batch_path
            return None
