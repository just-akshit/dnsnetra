"""Delete every dashboard user except an explicit keep-list.

    python scripts/purge_test_users.py --keep admin                 # dry run
    python scripts/purge_test_users.py --keep admin --execute --purge-audit-logs
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "backend" / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "backend" / "src"))

from dnsnetra.intelligence.reputation.connection import get_connection


def plan_purge(keep: list[str]) -> list[tuple]:
    if not keep:
        raise ValueError("keep-list cannot be empty")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, username, role, status
                FROM dashboard_users
                WHERE lower(username) <> ALL(%s)
                ORDER BY id;
                """,
                ([name.lower() for name in keep],),
            )
            rows = cur.fetchall()
            cur.execute(
                "SELECT count(*) FROM dashboard_users WHERE role = 'ADMIN' AND lower(username) = ANY(%s);",
                ([name.lower() for name in keep],),
            )
            admins = cur.fetchone()[0]
            conn.rollback()
    if admins < 1:
        raise ValueError("keep-list must retain at least one ADMIN account")
    return rows


def purge_users(keep: list[str], execute: bool, purge_audit_logs: bool) -> int:
    doomed = plan_purge(keep)
    if not execute:
        return len(doomed)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM dashboard_users WHERE lower(username) <> ALL(%s);",
                ([name.lower() for name in keep],),
            )
            deleted = cur.rowcount
            if purge_audit_logs:
                cur.execute("DELETE FROM audit_logs;")
            conn.commit()
    return deleted


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="append", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--purge-audit-logs", action="store_true")
    args = parser.parse_args()

    try:
        doomed = plan_purge(args.keep)
    except ValueError as exc:
        print(f"Refusing: {exc}", file=sys.stderr)
        return 1

    for user_id, username, role, status in doomed:
        print(f"  would delete id={user_id} username={username} role={role} status={status}")

    if not args.execute:
        print(f"Dry run: {len(doomed)} user(s) would be deleted. Re-run with --execute.")
        return 0

    deleted = purge_users(args.keep, execute=True, purge_audit_logs=args.purge_audit_logs)
    print(f"Deleted {deleted} user(s). Kept: {', '.join(args.keep)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
