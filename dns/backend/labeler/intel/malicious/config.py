# labeler/intel/malicious/config.py
"""
Configuration constants for the Malicious Domain Database (PostgreSQL).
"""

from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

_PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = _PACKAGE_DIR.parents[2]

load_dotenv(PROJECT_ROOT / ".env", override=True)

# --- PostgreSQL Database Configuration ---
DB_HOST = os.environ.get("MALICIOUS_DB_HOST", os.environ.get("DB_HOST", "localhost"))
DB_PORT = int(os.environ.get("MALICIOUS_DB_PORT", os.environ.get("DB_PORT", "5432")))
DB_DATABASE = os.environ.get("MALICIOUS_DB_DATABASE", "malicious_db")
DB_USERNAME = os.environ.get("MALICIOUS_DB_USERNAME", os.environ.get("DB_USER", "postgres"))
DB_PASSWORD = os.environ.get("MALICIOUS_DB_PASSWORD", os.environ.get("DB_PASSWORD", ""))

# Backward compatibility / legacy SQLite reference
DB_NAME = "malicious_domains.db"
BASE_DIR = os.environ.get(
    "INTEL_DB_BASE_DIR",
    str(_PACKAGE_DIR.parents[2] / "data"),
)
DB_PATH = os.path.join(BASE_DIR, DB_NAME)
NEW_DB_SUFFIX = ".new"
FULL_NEW_DB_PATH = f"{DB_PATH}{NEW_DB_SUFFIX}"

# --- Update Configuration ---
UPDATE_INTERVAL_SECONDS = 86400
DEFAULT_UPDATE_INTERVAL_HOURS = 24

# --- Network / Download Configuration ---
DATA_SOURCE_URL = "https://urlhaus.abuse.ch/downloads/csv/"
DOWNLOAD_TIMEOUT = 30
MAX_DOWNLOAD_RETRIES = 3
TEMP_DOWNLOAD_BUFFER_SIZE = 8192
CHECKSUM_ALGORITHM = "sha256"

# --- Domain Filtering ---
MIN_DOMAIN_LENGTH = 3
IGNORE_TLDS = set()

# --- Logging ---
LOG_LEVEL = os.environ.get("MALICIOUS_DB_LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(BASE_DIR, "malicious_db.log")
