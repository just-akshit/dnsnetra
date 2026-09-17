#!/usr/bin/env python3
"""
run_aggregation.py
==================
DNSNetra Standalone Aggregation CLI.

Commands:
    python run_aggregation.py --status
    python run_aggregation.py --incremental
    python run_aggregation.py --rebuild
    python run_aggregation.py --dry-run
"""

import sys
import time
import argparse
import logging
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from aggregator import DNSNetraAggregator, DEFAULT_BATCH_SIZE

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("run_aggregation")


def print_status(aggregator: DNSNetraAggregator) -> None:
    status = aggregator.get_status()
    print()
    print("=" * 60)
    print("DNSNetra Aggregation Engine Status")
    print("=" * 60)
    print(f"  Job Name                : {status['job_name']}")
    print(f"  Current Watermark (ID)  : {status['watermark_id']:,}")
    print(f"  Max Event ID in History : {status['max_history_id']:,}")
    print(f"  Pending Events to Run   : {status['pending_events']:,}")
    print(f"  Total History Records   : {status['total_history_events']:,}")
    print(f"  Total Events Processed  : {status['total_events_processed']:,}")
    print(f"  Last Run Timestamp      : {status['last_run_at']}")
    print(f"  Engine Status           : {status['status']}")
    print(f"  Hourly Rollup Buckets   : {status['hourly_rollup_buckets']:,}")
    print(f"  Daily Domain Records    : {status['daily_domain_rollup_records']:,}")
    print("=" * 60)


def print_dry_run(aggregator: DNSNetraAggregator) -> None:
    report = aggregator.run_dry_run()
    print()
    print("=" * 60)
    print("Dry Run Report (no changes made)")
    print("=" * 60)
    print(f"  Current watermark ID   : {report['current_watermark_id']:,}")
    print(f"  Pending events         : {report['pending_event_count']:,}")
    print(f"  Total history events   : {report['total_history_events']:,}")
    print(f"  Max history event ID   : {report['max_history_id']:,}")
    if report["first_pending_id"] is not None:
        print(f"  First pending event ID : {report['first_pending_id']:,}")
        print(f"  Last pending event ID  : {report['last_pending_id']:,}")
    print(f"  Estimated batches      : {report['estimated_batches']:,} (batch_size={report['batch_size']})")
    print("=" * 60)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "DNSNetra Aggregation Engine CLI\n\n"
            "Production: --incremental (PostgreSQL incremental rollup)\n"
            "Recovery:   --rebuild    (full rebuild from raw history)\n"
            "Inspect:    --status     (show watermark and lag status)\n"
            "Preview:    --dry-run    (non-destructive inspection)\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--incremental",
        action="store_true",
        help="[PRODUCTION] Process pending events from domain_query_history",
    )
    mode_group.add_argument(
        "--rebuild",
        action="store_true",
        help="[RECOVERY] Truncate rollups and rebuild from history ID 0",
    )
    mode_group.add_argument(
        "--status",
        action="store_true",
        help="Print current aggregator watermark, status, and lag",
    )
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Non-destructive: show pending events without modifying database",
    )

    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt for --rebuild",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Batch size for event processing (default: {DEFAULT_BATCH_SIZE})",
    )
    parser.add_argument(
        "--loop",
        type=int,
        default=0,
        help="Continuous loop interval in seconds (0 for single run)",
    )

    args = parser.parse_args()

    # Default to --status if no mode provided
    if not any([args.incremental, args.rebuild, args.status, args.dry_run]):
        args.status = True

    aggregator = DNSNetraAggregator(batch_size=args.batch_size)

    if args.status:
        print_status(aggregator)
        return 0

    if args.dry_run:
        print_dry_run(aggregator)
        return 0

    if args.rebuild:
        if not args.yes:
            print("WARNING: This will clear and rebuild all PostgreSQL aggregation rollups.")
            confirm = input("Type 'yes' to proceed: ").strip().lower() if sys.stdin.isatty() else "no"
            if confirm != "yes":
                print("Rebuild cancelled.")
                return 0

        logger.info("Starting rebuild...")
        start_t = time.perf_counter()
        result = aggregator.run_rebuild()
        elapsed = time.perf_counter() - start_t

        print()
        print("=" * 60)
        print("Rebuild Result")
        print("=" * 60)
        print(f"  Status          : {result.status}")
        print(f"  Events processed: {result.events_processed:,}")
        print(f"  Batches executed: {result.batches_run:,}")
        print(f"  Final watermark : {result.final_watermark:,}")
        print(f"  Duration        : {elapsed:.2f}s")
        if result.message:
            print(f"  Message         : {result.message}")
        print("=" * 60)
        return 0 if result.status == "success" else 1

    if args.incremental or args.loop > 0:
        while True:
            logger.info("Running incremental aggregation...")
            start_t = time.perf_counter()
            result = aggregator.run_incremental()
            elapsed = time.perf_counter() - start_t

            print()
            print("=" * 60)
            print("Incremental Aggregation Result")
            print("=" * 60)
            print(f"  Status          : {result.status}")
            print(f"  Events processed: {result.events_processed:,}")
            print(f"  Batches executed: {result.batches_run:,}")
            print(f"  Initial mark    : {result.initial_watermark:,}")
            print(f"  Final watermark : {result.final_watermark:,}")
            print(f"  Duration        : {elapsed:.2f}s")
            if result.message:
                print(f"  Message         : {result.message}")
            print("=" * 60)

            if args.loop <= 0:
                break
            time.sleep(args.loop)
        return 0 if result.status in ("success", "idle") else 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
