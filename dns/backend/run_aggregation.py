"""
run_aggregation.py
==================
CLI entry point for the DNS Threat Detection Dashboard Aggregator.

Production usage:
    python run_aggregation.py --incremental   # Normal incremental run
    python run_aggregation.py --rebuild       # Full rebuild from PostgreSQL
    python run_aggregation.py --status        # Show watermark and run history
    python run_aggregation.py --dry-run       # Non-destructive inspection

Legacy CSV mode (offline / ML use):
    python run_aggregation.py --source live   # Live labelled CSV
    python run_aggregation.py --source batch  # Batch labelled CSV
    python run_aggregation.py --source auto   # Prefers live, falls back to batch

Architecture:
    PostgreSQL domain_query_history
        ↓  WHERE id > watermark (incremental)
    IncrementalAggregator
        ↓  batch upserts (atomic)
    dashboard.db (SQLite read model)
        ↓
    FastAPI → React
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from dashboard_aggregation import IncrementalAggregator
from dashboard_integration.data_source import DashboardDataSource
from dashboard_aggregation import DashboardAggregator
from dashboard_aggregation.config import DASHBOARD_DB_PATH


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Mode handlers
# ---------------------------------------------------------------------------

def handle_incremental() -> int:
    """Normal production path: PostgreSQL incremental aggregation."""
    agg = IncrementalAggregator()
    result = agg.run_incremental()

    print()
    print("=" * 60)
    print("Incremental Aggregation Result")
    print("=" * 60)
    print(f"  Run ID          : {result.run_id}")
    print(f"  Status          : {result.status}")
    print(f"  Batches         : {result.batches_processed}")
    print(f"  Events seen     : {result.total_rows_seen}")
    print(f"  Events processed: {result.total_rows_processed}")
    print(f"  Events rejected : {result.total_rows_rejected}")
    if result.first_event_id is not None:
        print(f"  Event range     : [{result.first_event_id}, {result.last_event_id}]")
    print(f"  Duration        : {result.duration_ms}ms")
    if result.error_message:
        print(f"  Error           : {result.error_message}")
    print("=" * 60)

    return 0 if result.status == "success" else 1


def handle_rebuild(yes: bool = False) -> int:
    """Full rebuild from PostgreSQL (disaster recovery)."""
    if not yes:
        print("WARNING: This will clear and rebuild the entire dashboard read model.")
        print("This operation cannot be undone without another rebuild or manual restore.")
        confirm = input("Type 'yes' to proceed: ").strip().lower()
        if confirm != "yes":
            print("Rebuild cancelled.")
            return 0

    agg = IncrementalAggregator()
    result = agg.run_rebuild()

    print()
    print("=" * 60)
    print("Rebuild Result")
    print("=" * 60)
    print(f"  Run ID          : {result.run_id}")
    print(f"  Status          : {result.status}")
    print(f"  Batches         : {result.batches_processed}")
    print(f"  Events processed: {result.total_rows_processed}")
    print(f"  Duration        : {result.duration_ms}ms")
    if result.error_message:
        print(f"  Error           : {result.error_message}")
    print("=" * 60)

    return 0 if result.status == "success" else 1


def handle_status() -> int:
    """Show watermark, run history, and pending events."""
    agg = IncrementalAggregator()
    status = agg.get_status()

    print()
    print("=" * 60)
    print("Dashboard Aggregator Status")
    print("=" * 60)
    print(f"  Aggregation name       : {status.aggregation_name}")
    print(f"  Current watermark ID   : {status.current_watermark_id}")
    print(f"  Current watermark TS   : {status.current_watermark_ts or 'never processed'}")
    print(f"  Last successful run    : {status.last_successful_run_id or 'none'}")
    print(f"  Last successful at     : {status.last_successful_run_started_at or 'never'}")
    print(f"  Last run ID            : {status.last_run_id or 'none'}")
    print(f"  Last run status        : {status.last_run_status or 'none'}")
    print(f"  Last run duration      : {status.last_run_duration_ms or 0}ms")
    print(f"  Last run started at    : {status.last_run_started_at or 'never'}")
    print(f"  Pending events         : {status.pending_event_count}")
    print(f"  Source type            : {status.source_type or 'none'}")
    if status.last_error:
        print(f"  Last error             : {status.last_error}")
    print("=" * 60)

    return 0


def handle_dry_run() -> int:
    """Non-destructive inspection — does not modify any database."""
    agg = IncrementalAggregator()
    report = agg.run_dry_run()

    print()
    print("=" * 60)
    print("Dry Run Report (no changes made)")
    print("=" * 60)
    print(f"  Current watermark ID   : {report.current_watermark_id}")
    print(f"  Current watermark TS   : {report.current_watermark_ts or 'never processed'}")
    print(f"  Pending events         : {report.pending_event_count}")
    if report.first_pending_id is not None:
        print(f"  First pending event ID : {report.first_pending_id}")
        print(f"  Last pending event ID  : {report.last_pending_id}")
    print(f"  Estimated batches      : {report.estimated_batches}")
    print("=" * 60)

    return 0


def handle_csv_source(source: str) -> int:
    """Legacy CSV aggregation mode. Preserved for offline/ML use."""
    logger = logging.getLogger("run_aggregation")

    data_source = DashboardDataSource()

    # --status for CSV mode shows CSV availability
    status = data_source.get_status()
    print("=" * 50)
    print("Dashboard Data Source Status (CSV mode)")
    print("=" * 50)
    print(f"  Live CSV available   : {status.live_csv_available} ({status.live_csv_row_count} rows)")
    print(f"  Batch CSV available  : {status.batch_csv_available} ({status.batch_csv_row_count} rows)")
    print(f"  PostgreSQL available : {status.postgres_available}")
    print(f"  dashboard.db exists  : {status.dashboard_db_available}")
    print("=" * 50)
    print()

    start = time.perf_counter()

    try:
        df = data_source.get_labelled_events(source=source)
    except FileNotFoundError as exc:
        logger.error("No data available: %s", exc)
        print("\nNo labelled dataset found. Run the pipeline first:")
        print("  Live:  python run_live_pipeline.py ...")
        print("  Batch: python run_pipeline.py ...")
        return 1

    logger.info("Loaded %d labelled events from source=%s", len(df), source)

    aggregator = DashboardAggregator(dashboard_db_path=DASHBOARD_DB_PATH)
    resolved_path = data_source._resolve_path(source)
    if resolved_path is not None:
        aggregator.labelled_dataset_path = resolved_path

    counts = aggregator.run_all()

    elapsed = time.perf_counter() - start
    print()
    print(f"Aggregation complete in {elapsed:.2f}s (CSV legacy mode)")
    print(f"Dashboard DB: {DASHBOARD_DB_PATH}")

    if not counts:
        print("No data was aggregated. Check that the source CSV has data.")
        return 1

    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    configure_logging()

    parser = argparse.ArgumentParser(
        description=(
            "DNS Threat Detection Dashboard Aggregator\n\n"
            "Production: --incremental (PostgreSQL incremental)\n"
            "Recovery:   --rebuild    (full PostgreSQL rebuild)\n"
            "Inspect:    --status     (show watermark and run history)\n"
            "Preview:    --dry-run    (non-destructive inspection)\n"
            "Legacy CSV: --source auto|live|batch\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--incremental",
        action="store_true",
        help="[PRODUCTION] Process new PostgreSQL events since last watermark",
    )
    mode_group.add_argument(
        "--rebuild",
        action="store_true",
        help="[RECOVERY] Clear and rebuild dashboard from all retained PostgreSQL events",
    )
    mode_group.add_argument(
        "--status",
        action="store_true",
        help="Show watermark, run history, and pending event count",
    )
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        dest="dry_run",
        help="Non-destructive: show pending events without modifying anything",
    )
    mode_group.add_argument(
        "--source",
        choices=["live", "batch", "auto"],
        help="[LEGACY] Aggregate from CSV (offline/ML use only)",
    )

    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip confirmation prompt for --rebuild",
    )

    args = parser.parse_args()

    # Default to --incremental if no mode given
    if not any([args.incremental, args.rebuild, args.status, args.dry_run, args.source]):
        args.incremental = True

    if args.incremental:
        return handle_incremental()
    elif args.rebuild:
        return handle_rebuild(yes=args.yes)
    elif args.status:
        return handle_status()
    elif args.dry_run:
        return handle_dry_run()
    elif args.source:
        return handle_csv_source(args.source)

    return 0


if __name__ == "__main__":
    sys.exit(main())
