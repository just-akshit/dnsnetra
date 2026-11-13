#!/usr/bin/env python3
"""Run the Kafka-backed live DNS ingestion pipeline from a source checkout."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "src"))

from dnsnetra.ingestion.pipelines.live import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
