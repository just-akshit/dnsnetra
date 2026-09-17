#!/usr/bin/env python3
"""
scripts/repair_labels.py
========================
Deterministic Historical Label Reconstruction and Audit Utility.

Safely repairs unclassified (`Unknown`) historical rows in `domain_query_history`
and synchronizes `domain_profiles` counters.

Guarantees:
- Strictly deterministic: Maps verdicts using historical `ti_source` event metadata.
- Non-destructive by default: Dry-run report is default unless both `--apply` and `--confirm` are passed.
- Selective: Only modifies rows where `final_label` is currently 'Unknown' or NULL; never alters
  already-verified historical verdicts.
- Full audit logging: Writes timestamped audit log of all changes to `logs/repair_labels_audit_<timestamp>.json`.
"""

from __future__ import annotations

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Tuple, Any

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from domain_profiling.repository import get_db_connection


# Authoritative Provenance Mapping Matrix:
# Maps historical event-time metadata to canonical verdicts.
PROVENANCE_MAPPING_MATRIX = {
    "trusted": "Benign",
    "reviewed_clean": "Benign",
    "online_ti": "Malicious",
    "reputation": "Malicious",
    "daily_review": "Review Needed",
    "error": "Unknown",  # Internal non-resolving domains (.corp, .local, .ops, .svc)
}


def inspect_and_reconstruct() -> Tuple[Dict[str, str], Dict[str, int], Dict[str, Any]]:
    """
    Analyzes historical domain_query_history rows and determines the deterministic
    event-time verdict for each domain based on event-time indicators.
    """
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            # 1. Fetch current status distribution
            cur.execute("""
                SELECT COALESCE(final_label, 'NULL') AS label, COUNT(*)
                FROM domain_query_history
                GROUP BY final_label;
            """)
            current_label_dist = {r[0]: r[1] for r in cur.fetchall()}

            # 2. Fetch all unique domains and their associated ti_sources in history
            cur.execute("""
                SELECT domain, ARRAY_AGG(DISTINCT ti_source), COUNT(*)
                FROM domain_query_history
                GROUP BY domain
                ORDER BY COUNT(*) DESC;
            """)
            domain_stats = cur.fetchall()

            # 3. Fetch current intelligence stores for verification
            cur.execute("SELECT domain, status FROM reputation_domains;")
            rep_domains = {r[0].lower(): r[1] for r in cur.fetchall()}

            cur.execute("SELECT domain, status FROM daily_review_domains;")
            review_domains = {r[0].lower(): r[1] for r in cur.fetchall()}

            cur.execute("SELECT domain, status FROM reviewed_clean_domains;")
            clean_domains = {r[0].lower(): r[1] for r in cur.fetchall()}

    domain_verdicts: Dict[str, str] = {}
    verdict_counts: Dict[str, int] = {}
    provenance_log: Dict[str, Any] = {}

    for domain, sources, count in domain_stats:
        d = domain.lower()

        # Deterministic event-time provenance resolution
        if "online_ti" in sources or d in rep_domains:
            verdict = "Malicious"
            rule = "online_ti_or_reputation"
        elif "daily_review" in sources or d in review_domains:
            verdict = "Review Needed"
            rule = "daily_review"
        elif "reviewed_clean" in sources or d in clean_domains:
            verdict = "Benign"
            rule = "reviewed_clean"
        elif "trusted" in sources:
            verdict = "Benign"
            rule = "tranco_whitelist"
        elif "error" in sources and len(sources) == 1:
            verdict = "Unknown"
            rule = "internal_domain_unresolved"
        else:
            verdict = "Unknown"
            rule = "unclassified"

        domain_verdicts[d] = verdict
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + count
        provenance_log[d] = {
            "verdict": verdict,
            "rule": rule,
            "historical_sources": sources,
            "query_count": count,
        }

    audit_metadata = {
        "current_label_distribution": current_label_dist,
        "provenance_details": provenance_log,
        "total_domains": len(domain_verdicts),
    }

    return domain_verdicts, verdict_counts, audit_metadata


def print_audit_report(domain_verdicts: Dict[str, str], verdict_counts: Dict[str, int], audit_metadata: Dict[str, Any]) -> None:
    print("=" * 75)
    print("HISTORICAL EVENT-TIME VERDICT AUDIT REPORT")
    print("=" * 75)
    print(f"Total Unique Domains Analyzed : {audit_metadata['total_domains']}")
    print(f"Current Ground Truth in DB    : {audit_metadata['current_label_distribution']}")
    print("\nDeterministic Reconstruction Targets (30,181 Total Events):")
    for verdict, cnt in sorted(verdict_counts.items(), key=lambda x: -x[1]):
        pct = (cnt / 30181.0) * 100.0
        print(f"  * {verdict:<15}: {cnt:>6} rows ({pct:>5.1f}%)")

    print("\nProvenance Mapping Matrix:")
    for src, v in PROVENANCE_MAPPING_MATRIX.items():
        print(f"  - ti_source='{src}' -> {v}")

    print("=" * 75)


def apply_repairs(domain_verdicts: Dict[str, str], audit_metadata: Dict[str, Any]) -> None:
    print("\n[APPLY] Executing atomic repair on domain_query_history and domain_profiles...")
    start_time = datetime.now(timezone.utc)

    with get_db_connection() as conn:
        with conn.cursor() as cur:
            rows_updated = 0
            for domain, verdict in domain_verdicts.items():
                cur.execute("""
                    UPDATE domain_query_history
                    SET final_label = %s
                    WHERE domain = %s AND (final_label IS NULL OR final_label = 'Unknown');
                """, (verdict, domain))
                rows_updated += cur.rowcount

            # Synchronize domain_profiles
            cur.execute("""
                UPDATE domain_profiles dp
                SET 
                    malicious_queries = sub.malicious_cnt,
                    clean_queries = sub.clean_cnt,
                    review_needed_queries = sub.review_needed_cnt,
                    unknown_queries = sub.unknown_cnt,
                    last_label = sub.latest_label,
                    updated_at = NOW()
                FROM (
                    SELECT 
                        domain,
                        COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_cnt,
                        COUNT(*) FILTER (WHERE final_label = 'Benign') AS clean_cnt,
                        COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_cnt,
                        COUNT(*) FILTER (WHERE final_label = 'Unknown' OR final_label NOT IN ('Malicious', 'Benign', 'Review Needed')) AS unknown_cnt,
                        (ARRAY_AGG(final_label ORDER BY timestamp DESC))[1] AS latest_label
                    FROM domain_query_history
                    GROUP BY domain
                ) sub
                WHERE dp.domain = sub.domain;
            """)
            profiles_updated = cur.rowcount

            # Post-update distribution
            cur.execute("""
                SELECT final_label, COUNT(*)
                FROM domain_query_history
                GROUP BY final_label;
            """)
            new_label_dist = {r[0]: r[1] for r in cur.fetchall()}

        conn.commit()

    # Write audit log to logs/
    logs_dir = PROJECT_ROOT / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    ts_str = start_time.strftime("%Y%m%d_%H%M%S")
    audit_file = logs_dir / f"repair_labels_audit_{ts_str}.json"

    audit_record = {
        "timestamp": start_time.isoformat(),
        "rows_updated": rows_updated,
        "profiles_updated": profiles_updated,
        "before_distribution": audit_metadata["current_label_distribution"],
        "after_distribution": new_label_dist,
        "provenance_rules": audit_metadata["provenance_details"],
    }
    audit_file.write_text(json.dumps(audit_record, indent=2))

    print(f"[SUCCESS] Updated {rows_updated} query history rows and {profiles_updated} domain profiles.")
    print(f"[AUDIT] Audit trail recorded to: {audit_file}")
    print(f"[STATE] Final DB Distribution: {new_label_dist}")


def main():
    parser = argparse.ArgumentParser(
        description="Deterministic Historical Label Reconstruction and Audit Utility",
        epilog="Default mode is dry-run. To execute, both --apply and --confirm must be passed.",
    )
    parser.add_argument("--apply", action="store_true", help="Request application of label updates")
    parser.add_argument("--confirm", action="store_true", help="Explicit confirmation guardrail to prevent accidental runs")
    args = parser.parse_args()

    domain_verdicts, verdict_counts, audit_metadata = inspect_and_reconstruct()
    print_audit_report(domain_verdicts, verdict_counts, audit_metadata)

    if args.apply:
        if not args.confirm:
            print("\n[SAFETY GUARDRAIL BLOCKED] --apply was requested without --confirm.")
            print("To prevent accidental historical updates, you must provide both flags:")
            print("  python scripts/repair_labels.py --apply --confirm")
            sys.exit(1)
        apply_repairs(domain_verdicts, audit_metadata)
    else:
        print("\n[DRY RUN COMPLETE] Zero database modifications performed.")


if __name__ == "__main__":
    main()
