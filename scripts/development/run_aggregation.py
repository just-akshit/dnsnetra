#!/usr/bin/env python3
"""Run the DNSNetra aggregation CLI from a source checkout.

Equivalent to ``python -m dnsnetra.aggregation`` after ``pip install -e .``.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend" / "src"))

from dnsnetra.aggregation.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
