"""
Dashboard Aggregation Configuration Module
===========================================
Loads SQLite database path and PostgreSQL credentials from environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).parent.parent.resolve()

# Load environment configuration
load_dotenv(PROJECT_ROOT / ".env")
load_dotenv(PROJECT_ROOT / "api.env")

# SQLite Dashboard Database Path
DASHBOARD_DB_PATH = Path(os.getenv("DASHBOARD_DB_PATH", str(PROJECT_ROOT / "dashboard.db"))).resolve()

# PostgreSQL Credentials (shared with client_profiling, domain_profiling, and reputation)
PG_HOST = os.getenv("DB_HOST", "localhost")
PG_PORT = int(os.getenv("DB_PORT", "5432"))
PG_NAME = os.getenv("DB_NAME", "dns_threat_detection")
PG_USER = os.getenv("DB_USER", "postgres")
PG_PASSWORD = os.getenv("DB_PASSWORD", "postgres")

# SQLite Source Paths
MALICIOUS_DB_PATH = PROJECT_ROOT / "data" / "malicious_domains.db"
TRUSTED_DB_PATH = PROJECT_ROOT / "labeler" / "intel" / "trusted_domains.db"

# CSV Source Paths
LABELLED_DATASET_PATH = PROJECT_ROOT / "parsing logs" / "labelled_dns_dataset.csv"
FEATURE_MATRIX_PATH = PROJECT_ROOT / "feature extraction" / "data" / "feature_matrix.csv"

# Live Pipeline Labelled Output (written by run_live_pipeline.py dashboard hook)
LIVE_LABELLED_DATASET_PATH = PROJECT_ROOT / "live_labelled_dataset.csv"

# ---------------------------------------------------------------------------
# Incremental aggregation configuration
# ---------------------------------------------------------------------------

# Number of domain_query_history rows fetched per batch.
# Larger values are more efficient but use more memory.
AGGREGATION_BATCH_SIZE: int = int(os.getenv("AGGREGATION_BATCH_SIZE", "10000"))

# Logical name of the dashboard aggregation job (matches aggregation_state row).
AGGREGATION_NAME: str = os.getenv("AGGREGATION_NAME", "dashboard")

# Maximum rows retained in recent_flagged_domains.
RECENT_FLAGGED_DOMAINS_LIMIT: int = int(os.getenv("RECENT_FLAGGED_DOMAINS_LIMIT", "100"))

# Minutes after which a 'running' aggregation_runs record is considered stale.
# Used on startup to detect crashed processes and mark them failed.
AGGREGATION_STALE_THRESHOLD_MINUTES: int = int(
    os.getenv("AGGREGATION_STALE_THRESHOLD_MINUTES", "60")
)
