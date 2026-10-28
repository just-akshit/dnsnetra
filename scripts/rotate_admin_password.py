"""Rotate a local admin password and force a change at the next login.

    python scripts/rotate_admin_password.py --username admin            # dry run
    python scripts/rotate_admin_password.py --username admin --execute  # rotate
"""

from __future__ import annotations

import argparse
import secrets
import string
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from api.auth import hash_password, validate_password_strength
from api.sessions import revoke_all_user_sessions
from labeler.intel.reputation.connection import get_connection

ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*"


def generate_temporary_password(length: int = 20) -> str:
    while True:
        candidate = "".join(secrets.choice(ALPHABET) for _ in range(length))
        if validate_password_strength(candidate)[0]:
            return candidate


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
            if role != "ADMIN":
                return False, None

            password = generate_temporary_password()
            if not execute:
                conn.rollback()
                return True, None

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
    return True, password


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default="admin")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()

    ok, password = rotate_admin(args.username, args.execute)
    if not ok:
        print(f"Refusing: '{args.username}' is missing or is not an ADMIN.", file=sys.stderr)
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
