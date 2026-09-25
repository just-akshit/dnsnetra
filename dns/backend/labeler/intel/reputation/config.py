"""
Configuration Module
====================
Loads PostgreSQL credentials and database settings for reputation_db from environment
variables. No secrets are hardcoded.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from dotenv import load_dotenv

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parents[2]

load_dotenv(_PROJECT_ROOT / ".env", override=True)
load_dotenv(_PROJECT_ROOT / "api.env", override=True)


@dataclass(frozen=True)
class DatabaseConfig:
    """Immutable configuration container for the PostgreSQL reputation_db connection."""

    host: str = field(
        default_factory=lambda: os.getenv(
            "REPUTATION_DB_HOST", os.getenv("DB_HOST", os.getenv("UDR_DB_HOST", "localhost"))
        )
    )
    port: int = field(
        default_factory=lambda: int(
            os.getenv("REPUTATION_DB_PORT", os.getenv("DB_PORT", os.getenv("UDR_DB_PORT", "5432")))
        )
    )
    dbname: str = field(
        default_factory=lambda: os.getenv("REPUTATION_DB_DATABASE", "reputation_db")
    )
    user: str = field(
        default_factory=lambda: os.getenv(
            "REPUTATION_DB_USERNAME", os.getenv("DB_USER", os.getenv("UDR_DB_USERNAME", "postgres"))
        )
    )
    password: str = field(
        default_factory=lambda: os.getenv(
            "REPUTATION_DB_PASSWORD", os.getenv("DB_PASSWORD", os.getenv("UDR_DB_PASSWORD", ""))
        )
    )
    min_conn: int = field(
        default_factory=lambda: int(os.getenv("REPUTATION_DB_MIN_CONNECTIONS", "2"))
    )
    max_conn: int = field(
        default_factory=lambda: int(os.getenv("REPUTATION_DB_MAX_CONNECTIONS", "10"))
    )

    @property
    def dsn(self) -> str:
        """Return a PostgreSQL DSN string built from the config fields."""
        return (
            f"host={self.host} port={self.port} "
            f"dbname={self.dbname} user={self.user} password={self.password}"
        )

    def validate(self) -> None:
        """Raise ValueError if required credentials are missing."""
        missing: list[str] = []
        if not self.user:
            missing.append("REPUTATION_DB_USERNAME")
        if missing:
            raise ValueError(
                f"Missing required environment variable(s): {', '.join(missing)}. "
                "Create a .env file. See .env.example."
            )


config: DatabaseConfig = DatabaseConfig()
