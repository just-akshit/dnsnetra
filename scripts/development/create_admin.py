#!/usr/bin/env python3
"""
scripts/create_admin.py
=======================
Convenience wrapper to run `python -m api.cli create-admin`.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "backend" / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "backend" / "src"))

from apps.api.cli import main

if __name__ == "__main__":
    if len(sys.argv) == 1:
        sys.argv.append("create-admin")
    main()
