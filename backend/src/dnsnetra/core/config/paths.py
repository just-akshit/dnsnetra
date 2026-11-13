"""Canonical filesystem locations for a source checkout or deployment.

The repository root is resolved once and reused by configuration modules so
that moving a module never silently changes where data or log files live.
Set ``DNSNETRA_ROOT`` to override the detected location in production.
"""

from __future__ import annotations

import os
from pathlib import Path


def _discover_repo_root() -> Path:
    override = os.getenv("DNSNETRA_ROOT")
    if override:
        return Path(override).expanduser().resolve()

    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "pyproject.toml").is_file() and (parent / "apps").is_dir():
            return parent
    for parent in here.parents:
        if (parent / ".git").is_dir():
            return parent
    return Path.cwd().resolve()


REPO_ROOT: Path = _discover_repo_root()
DATA_DIR: Path = REPO_ROOT / "data"
DATASETS_DIR: Path = DATA_DIR / "datasets"
INTELLIGENCE_DIR: Path = DATA_DIR / "intelligence"
SAMPLES_DIR: Path = DATA_DIR / "samples"
LOGS_DIR: Path = DATA_DIR / "logs"


def ensure_data_dirs() -> None:
    """Create runtime data directories without touching existing content."""
    for directory in (DATASETS_DIR, INTELLIGENCE_DIR, SAMPLES_DIR, LOGS_DIR):
        directory.mkdir(parents=True, exist_ok=True)


__all__ = [
    "REPO_ROOT",
    "DATA_DIR",
    "DATASETS_DIR",
    "INTELLIGENCE_DIR",
    "SAMPLES_DIR",
    "LOGS_DIR",
    "ensure_data_dirs",
]
