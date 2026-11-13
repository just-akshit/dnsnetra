"""Rotate a local ADMIN or SUPER_ADMIN password and force a change at the next login.

    python scripts/rotate_admin_password.py --username admin            # dry run
    python scripts/rotate_admin_password.py --username admin --execute  # rotate

This is the break-glass path. It writes an audit row with actor "system/cli".
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "backend" / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "backend" / "src"))

from dnsnetra.core.security.audit import AuditAction, log_audit_event
from dnsnetra.core.security.auth import generate_temporary_password, hash_password
from dnsnetra.core.security.sessions import revoke_all_user_sessions
from dnsnetra.intelligence.reputation.connection import get_connection


def rotate_admin(username: str, execute: bool) -> tuple[bool, str | None]:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, role FROM dashboard_users WHERE lower(username) = lower(%s);",
                (username,),
            )
            row = cur.fetchone()
            if not row:
                return False, None
            user_id, role = row
            if role not in ("ADMIN", "SUPER_ADMIN"):
                return False, None

            if not execute:
                conn.rollback()
                return True, None

            password = generate_temporary_password(20)
            cur.execute(
                """
                UPDATE dashboard_users
                SET password_hash = %s,
                    hashed_password = NULL,
                    must_change_password = true,
                    status = 'ACTIVE',
                    is_active = true,
                    updated_at = NOW()
                WHERE id = %s;
                """,
                (hash_password(password), user_id),
            )
            conn.commit()

    revoke_all_user_sessions(user_id)
    log_audit_event(
        action=AuditAction.PASSWORD_RESET,
        user_id=None,
        target_user_id=user_id,
        metadata={"actor": "system/cli", "outcome": "success"},
    )
    return True, password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default="admin")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    ok, password = rotate_admin(args.username, args.execute)
    if not ok:
        print(
            f"Refusing: '{args.username}' is missing or is not an ADMIN or SUPER_ADMIN.",
            file=sys.stderr,
        )
        return 1
    if not args.execute:
        print(f"Dry run: would rotate '{args.username}'. Re-run with --execute.")
        return 0

    print(f"Rotated '{args.username}'. One-time password (shown once):")
    print(password)
    print("The account must change this password at next login.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
