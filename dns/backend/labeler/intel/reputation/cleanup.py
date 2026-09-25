"""
Cleanup & Reconciliation Module
===============================
Provides scheduled / manual cleanup routines for expired reputation records
and evidence scope reconciliation for legacy / unclassified rows.
"""

from __future__ import annotations

import argparse
import logging

from .repository import cleanup_old_domains, reconcile_reputation_records

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------
def main() -> None:
    """Run cleanup or reconciliation from the command line."""
    parser = argparse.ArgumentParser(
        description="Cleanup expired records and reconcile reputation scope.",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=180,
        help="Delete records whose last_seen is older than this many days (default: 180).",
    )
    parser.add_argument(
        "--reconcile",
        action="store_true",
        default=True,
        help="Audit and reconcile legacy reputation rows against current intelligence.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    if args.reconcile:
        stats = reconcile_reputation_records()
        print(f"Reconciliation complete: {stats}")

    deleted = cleanup_old_domains(days=args.days)
    print(f"Cleanup complete — {deleted} record(s) deleted.")


if __name__ == "__main__":
    main()
