from datetime import timedelta
from pathlib import Path
import os
from dotenv import load_dotenv

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_DIR.parents[1]

load_dotenv(PROJECT_ROOT / ".env", override=True)

# PostgreSQL Configuration for trusted_db
DB_HOST = os.environ.get("TRUSTED_DB_HOST", os.environ.get("DB_HOST", "localhost"))
DB_PORT = int(os.environ.get("TRUSTED_DB_PORT", os.environ.get("DB_PORT", "5432")))
DB_DATABASE = os.environ.get("TRUSTED_DB_DATABASE", "trusted_db")
DB_USERNAME = os.environ.get("TRUSTED_DB_USERNAME", os.environ.get("DB_USER", "postgres"))
DB_PASSWORD = os.environ.get("TRUSTED_DB_PASSWORD", os.environ.get("DB_PASSWORD", ""))

# Backward compatibility / legacy SQLite reference
DATABASE_FILENAME = "trusted_domains.db"
DATABASE_PATH = Path(
    os.environ.get(
        "TRUSTED_DOMAINS_DB",
        str(PACKAGE_DIR / DATABASE_FILENAME),
    )
).expanduser().resolve()

LOCK_PATH = PACKAGE_DIR / "trusted_domains.lock"

TRANCO_DOWNLOAD_URL = "https://tranco-list.eu/top-1m.csv.zip"
SOURCE_NAME = "tranco"

REFRESH_INTERVAL_DAYS = 30
REFRESH_INTERVAL = timedelta(days=REFRESH_INTERVAL_DAYS)

REQUEST_TIMEOUT = (10, 300)
CHUNK_SIZE = 1024 * 1024

USER_AGENT = "TrustedWhitelistManager/1.0"
TEMP_PREFIX = "trusted_domains_"

METADATA_KEYS = (
    "last_update",
    "dataset_version",
    "record_count",
    "source",
)