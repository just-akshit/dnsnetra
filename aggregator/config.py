"""
aggregator/config.py
====================
Configuration settings for the DNSNetra Native Aggregator.
"""

from pathlib import Path
import os
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env", override=True)

# Database connection defaults (aligned with domain_profiling)
DB_HOST = os.getenv("UDR_DB_HOST", "localhost")
DB_PORT = int(os.getenv("UDR_DB_PORT", "5432"))
DB_NAME = os.getenv("UDR_DB_DATABASE", "dns_threat_detection")
DB_USER = os.getenv("UDR_DB_USERNAME", "postgres")
DB_PASSWORD = os.getenv("UDR_DB_PASSWORD", "Akshit!1")

# Aggregator settings
DEFAULT_BATCH_SIZE = int(os.getenv("AGGREGATOR_BATCH_SIZE", "10000"))
ADVISORY_LOCK_ID = int(os.getenv("AGGREGATOR_LOCK_ID", "0x444e5341"), 16)
JOB_NAME = "dnsnetra_aggregator"
