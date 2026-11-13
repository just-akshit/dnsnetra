"""
Daily Review Administrative CLI
================================
Management tool for inspecting daily review state, manually triggering
investigations, or applying human-reviewed verdicts.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from .models import ReviewStatus
from .repository import (
    get_review_domain,
    get_reviewed_clean_domain,
    get_stats,
    list_domains,
    promote_to_clean,
    promote_to_malicious,
    upsert_review_needed,
)
from .scheduler import DailyReviewWorker


def _format_table(headers: list[str], rows: list[list[Any]]) -> str:
    col_widths = [len(h) for h in headers]
    for row in rows:
        for idx, val in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(str(val)))

    header_line = " | ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    data_lines = [
        " | ".join(f"{str(r[i]):<{col_widths[i]}}" for i in range(len(headers)))
        for r in rows
    ]
    return "\n".join([header_line, sep_line] + data_lines)


def cmd_stats(args: argparse.Namespace) -> None:
    stats = get_stats()
    print("\n=== Daily Review Lifecycle Statistics ===")
    for k, v in stats.items():
        print(f"  {k.replace('_', ' ').title():<30}: {v}")
    print()


def cmd_list(args: argparse.Namespace) -> None:
    records, total = list_domains(
        status=args.status,
        search=args.search,
        limit=args.limit,
        offset=args.offset,
    )
    print(f"\nFound {total} records (showing {len(records)}):")
    if not records:
        print("  (no records found)")
        return

    headers = ["Domain", "Status", "Review Count", "Next Check", "Last Checked", "Reason"]
    rows = [
        [
            r.domain,
            r.status,
            r.review_count,
            r.next_check_at.strftime("%Y-%m-%d %H:%M") if r.next_check_at else "None",
            r.last_checked_at.strftime("%Y-%m-%d %H:%M") if r.last_checked_at else "Never",
            (r.review_reason or "")[:35],
        ]
        for r in records
    ]
    print(_format_table(headers, rows))
    print()


def cmd_get(args: argparse.Namespace) -> None:
    record = get_review_domain(args.domain)
    if not record:
        print(f"Domain '{args.domain}' not found in daily_review_domains.")
        clean = get_reviewed_clean_domain(args.domain)
        if clean:
            print(f"Domain '{args.domain}' is in reviewed_clean_domains (verified at {clean.verified_at}).")
        return

    print(f"\n=== Domain Dossier: {record.domain} ===")
    print(f"Status        : {record.status}")
    print(f"First Seen    : {record.first_seen_at}")
    print(f"Last Seen     : {record.last_seen_at}")
    print(f"Last Checked  : {record.last_checked_at}")
    print(f"Next Check    : {record.next_check_at}")
    print(f"Review Count  : {record.review_count}")
    print(f"Review Reason : {record.review_reason}")
    if record.vt_result:
        print(f"VT Result     : {json.dumps(record.vt_result, indent=2)}")
    if record.otx_result:
        print(f"OTX Result    : {json.dumps(record.otx_result, indent=2)}")
    print()


def cmd_verdict(args: argparse.Namespace) -> None:
    verdict = args.verdict.lower()
    domain = args.domain.strip().lower()
    reviewer = args.reviewer or "admin_cli"
    reason = args.reason or "Admin manual review"

    if verdict == "malicious":
        promote_to_malicious(
            domain,
            metadata={
                "source": "admin_review",
                "confidence": 1.0,
                "notes": f"Manual verdict by {reviewer}: {reason}",
            },
        )
        print(f"Domain '{domain}' successfully promoted to MALICIOUS in reputation_domains.")
    elif verdict == "clean":
        promote_to_clean(
            domain,
            source=f"admin_review ({reviewer})",
            vt_summary={"admin_verdict": True, "reviewer": reviewer, "reason": reason},
        )
        print(f"Domain '{domain}' successfully promoted to CLEAN in reviewed_clean_domains.")
    else:
        print(f"Unknown verdict: {verdict}. Supported: malicious, clean")
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DNSNetra Daily Review Administrative CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # stats
    subparsers.add_parser("stats", help="Show KPI stats on daily review queue")

    # list
    list_p = subparsers.add_parser("list", help="List domains in daily review")
    list_p.add_argument("--status", choices=["review_needed", "processing", "malicious", "clean", "error"])
    list_p.add_argument("--search", help="Substring search on domain name")
    list_p.add_argument("--limit", type=int, default=50)
    list_p.add_argument("--offset", type=int, default=0)

    # get
    get_p = subparsers.add_parser("get", help="View domain review dossier")
    get_p.add_argument("domain", help="Domain to inspect")

    # verdict
    v_p = subparsers.add_parser("verdict", help="Apply human admin verdict to domain")
    v_p.add_argument("domain", help="Domain name")
    v_p.add_argument("--verdict", choices=["malicious", "clean"], required=True)
    v_p.add_argument("--reason", required=True, help="Rationale for decision")
    v_p.add_argument("--reviewer", default="admin_cli", help="Reviewer username/email")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "stats":
        cmd_stats(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "get":
        cmd_get(args)
    elif args.command == "verdict":
        cmd_verdict(args)


if __name__ == "__main__":
    main()
