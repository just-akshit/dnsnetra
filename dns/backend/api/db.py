"""
API Database Helper
===================
Read-only SQLite connection context manager for `dashboard.db`.
The API layer must ONLY read from this pre-computed SQLite database —
never from Postgres, CSVs, or other SQLite files directly.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from dashboard_aggregation.config import DASHBOARD_DB_PATH


def get_dashboard_db_path() -> Path:
    """Returns the resolved path to dashboard.db."""
    return DASHBOARD_DB_PATH


@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    """
    Read-only connection context manager for dashboard.db.
    Returns rows as sqlite3.Row objects for dict-like access.
    """
    db_path = get_dashboard_db_path()
    if not db_path.exists():
        raise FileNotFoundError(
            f"dashboard.db not found at {db_path}. "
            "Run the pipeline first to generate it."
        )

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()
