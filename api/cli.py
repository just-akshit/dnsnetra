"""
DNSNetra Administrative Management CLI
======================================
Usage:
    python -m api.cli create-admin
    python -m api.cli create-admin --username myadmin --password MySecretPassword!1
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from labeler.intel.reputation.connection import get_connection
from api.audit import AuditAction, log_audit_event
from api.auth import (
    get_user_by_username,
    hash_password,
    validate_password_strength,
    validate_username,
)


def create_admin_interactive(username: str | None = None, password: str | None = None) -> int:
    """Interactively or programmatically provision an administrator account."""
    print("=" * 60)
    print("  DNSNetra — Initial Administrator Creation CLI")
    print("=" * 60)

    # 1. Prompt for username if not provided
    if not username:
        try:
            username = input("Username: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return 1

    valid_un, un_err = validate_username(username)
    if not valid_un:
        print(f"Error: {un_err}", file=sys.stderr)
        return 1

    # Check existence
    existing = get_user_by_username(username)
    if existing:
        print(f"Error: User '{username}' already exists.", file=sys.stderr)
        return 1

    # 2. Prompt for password if not provided
    if not password:
        try:
            password = getpass.getpass("Password: ")
            confirm = getpass.getpass("Confirm password: ")
        except (KeyboardInterrupt, EOFError):
            print("\nAborted.")
            return 1

        if password != confirm:
            print("Error: Passwords do not match.", file=sys.stderr)
            return 1

    valid_pw, pw_err = validate_password_strength(password)
    if not valid_pw:
        print(f"Error: {pw_err}", file=sys.stderr)
        return 1

    # 3. Hash with Argon2id and insert
    pwd_hash = hash_password(password)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO dashboard_users (
                    username,
                    email,
                    password_hash,
                    hashed_password,
                    role,
                    status,
                    is_active,
                    created_at,
                    updated_at
                ) VALUES (%s, %s, %s, %s, 'ADMIN', 'ACTIVE', true, NOW(), NOW())
                RETURNING id;
                """,
                (username, f"{username}@dnsnetra.local", pwd_hash, pwd_hash),
            )
            admin_id = cur.fetchone()[0]
            conn.commit()

    log_audit_event(
        action=AuditAction.USER_CREATED,
        user_id=admin_id,
        target_user_id=admin_id,
        metadata={"cli": True, "username": username, "role": "ADMIN", "status": "ACTIVE"},
    )

    print(f"✅ Administrator '{username}' created successfully (User ID: {admin_id}).")
    return 0


def main():
    parser = argparse.ArgumentParser(description="DNSNetra Administrative Management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    admin_parser = subparsers.add_parser("create-admin", help="Create an administrator account")
    admin_parser.add_argument("--username", "-u", type=str, help="Admin username")
    admin_parser.add_argument("--password", "-p", type=str, help="Admin password (optional; prompts if omitted)")

    args = parser.parse_args()

    if args.command == "create-admin":
        sys.exit(create_admin_interactive(username=args.username, password=args.password))


if __name__ == "__main__":
    main()
