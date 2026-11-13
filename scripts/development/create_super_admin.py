"""Bootstrap the first SUPER_ADMIN account.

    python scripts/create_super_admin.py --username superadmin            # dry run
    python scripts/create_super_admin.py --username superadmin --execute  # create

The created account is ACTIVE with must_change_password=true and receives a
one-time password printed to stdout. There is no automatic promotion of any
existing account and no API path to create the first SUPER_ADMIN.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT / "backend" / "src") not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT / "backend" / "src"))

from dnsnetra.core.security.audit import AuditAction, log_audit_event
from dnsnetra.core.security.auth import (
    generate_temporary_password,
    hash_password,
    normalize_username,
    validate_username,
)
from dnsnetra.intelligence.reputation.connection import get_connection


def create_super_admin(username: str, execute: bool) -> tuple[str, str | None]:
    clean = normalize_username(username)
    ok, _reason = validate_username(clean, is_signup=False)
    if not ok:
        return "invalid", None

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id FROM dashboard_users WHERE lower(username) = lower(%s);",
                (clean,),
            )
            if cur.fetchone():
                conn.rollback()
                return "exists", None

            if not execute:
                conn.rollback()
                return "dry-run", None

            password = generate_temporary_password(20)
            cur.execute(
                """
                INSERT INTO dashboard_users
                    (username, email, password_hash, hashed_password, role, status,
                     is_active, must_change_password, created_at, updated_at)
                VALUES (%s, %s, %s, NULL, 'SUPER_ADMIN', 'ACTIVE', true, true, NOW(), NOW())
                RETURNING id;
                """,
                (clean, f"{clean}@dnsnetra.local", hash_password(password)),
            )
            user_id = cur.fetchone()[0]
            conn.commit()

    log_audit_event(
        action=AuditAction.USER_CREATED,
        user_id=None,
        target_user_id=user_id,
        metadata={"actor": "system/cli", "role": "SUPER_ADMIN", "username": clean},
    )
    return "created", password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    status, password = create_super_admin(args.username, args.execute)
    if status == "invalid":
        print(f"Invalid username: {args.username}", file=sys.stderr)
        return 1
    if status == "exists":
        print(f"Refusing: '{args.username}' already exists.", file=sys.stderr)
        return 1
    if status == "dry-run":
        print(f"Dry run: would create SUPER_ADMIN '{args.username}'. Re-run with --execute.")
        return 0

    print(f"Created SUPER_ADMIN '{args.username}'. One-time password (shown once):")
    print(password)
    print("The account must change this password at first login.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
