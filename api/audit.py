"""
Security Audit Logging Service for DNSNetra API
===============================================
Records authentication and administrative security events into PostgreSQL.
Never logs sensitive secrets, plaintext passwords, hashes, tokens, or CAPTCHA answers.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Optional

from labeler.intel.reputation.connection import get_connection

logger = logging.getLogger("api_audit")

# Canonical audit action identifiers
class AuditAction:
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    SIGNUP = "SIGNUP"
    ACCOUNT_APPROVED = "ACCOUNT_APPROVED"
    ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
    ACCOUNT_ENABLED = "ACCOUNT_ENABLED"
    ROLE_CHANGED = "ROLE_CHANGED"
    PASSWORD_RESET = "PASSWORD_RESET"
    SESSION_REVOKED = "SESSION_REVOKED"
    USER_CREATED = "USER_CREATED"


# Redacted / forbidden keys
FORBIDDEN_METADATA_KEYS = {
    "password",
    "password_hash",
    "confirm_password",
    "session_token",
    "access_token",
    "captcha_answer",
    "captcha_secret",
    "secret",
}


def sanitize_metadata(meta: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Sanitize metadata dict to ensure no sensitive credentials or keys are leaked."""
    if not meta:
        return {}
    clean: dict[str, Any] = {}
    for k, v in meta.items():
        if k.lower() in FORBIDDEN_METADATA_KEYS or "password" in k.lower() or "secret" in k.lower() or "token" in k.lower():
            continue
        clean[k] = v
    return clean


def log_audit_event(
    action: str,
    user_id: Optional[int] = None,
    target_user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
) -> Optional[int]:
    """
    Persist an audit record to the audit_logs table.
    Fails safely without breaking user transactions if an audit write encounters an issue.
    """
    clean_meta = sanitize_metadata(metadata)
    clean_meta_json = json.dumps(clean_meta)

    # Sanitize IP address for INET type (if invalid or empty, store NULL)
    valid_ip = None
    if ip_address and ip_address.strip() and ip_address.strip() != "testclient":
        try:
            import ipaddress
            ipaddress.ip_address(ip_address.strip())
            valid_ip = ip_address.strip()
        except ValueError:
            clean_meta["raw_client_ip"] = ip_address.strip()
            clean_meta_json = json.dumps(clean_meta)
            valid_ip = None

    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO audit_logs (user_id, action, target_user_id, ip_address, user_agent, timestamp, metadata)
                    VALUES (%s, %s, %s, %s, %s, NOW(), %s::jsonb)
                    RETURNING id;
                    """,
                    (user_id, action, target_user_id, valid_ip, user_agent, clean_meta_json),
                )
                log_id = cur.fetchone()[0]
                conn.commit()
                return log_id
    except Exception as exc:
        logger.error("Failed to write audit log event %s: %s", action, exc)
        return None


def get_audit_logs(
    limit: int = 50,
    offset: int = 0,
    action: Optional[str] = None,
    user_id: Optional[int] = None,
) -> tuple[list[dict[str, Any]], int]:
    """Retrieve paginated audit logs for administrative review."""
    conditions = []
    params: list[Any] = []

    if action:
        conditions.append("a.action = %s")
        params.append(action.upper())

    if user_id:
        conditions.append("(a.user_id = %s OR a.target_user_id = %s)")
        params.extend([user_id, user_id])

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_connection() as conn:
        with conn.cursor() as cur:
            # Count total
            cur.execute(f"SELECT COUNT(*) FROM audit_logs a {where_clause};", tuple(params))
            total = cur.fetchone()[0]

            # Fetch rows
            fetch_sql = f"""
                SELECT
                    a.id,
                    a.user_id,
                    u.username AS actor_username,
                    a.action,
                    a.target_user_id,
                    tu.username AS target_username,
                    HOST(a.ip_address) AS ip_address,
                    a.user_agent,
                    a.timestamp,
                    a.metadata
                FROM audit_logs a
                LEFT JOIN dashboard_users u ON a.user_id = u.id
                LEFT JOIN dashboard_users tu ON a.target_user_id = tu.id
                {where_clause}
                ORDER BY a.timestamp DESC
                LIMIT %s OFFSET %s;
            """
            cur.execute(fetch_sql, tuple(params + [limit, offset]))
            rows = cur.fetchall()

            items = [
                {
                    "id": r[0],
                    "user_id": r[1],
                    "actor_username": r[2],
                    "action": r[3],
                    "target_user_id": r[4],
                    "target_username": r[5],
                    "ip_address": r[6],
                    "user_agent": r[7],
                    "timestamp": r[8].isoformat() if r[8] else None,
                    "metadata": r[9] if r[9] else {},
                }
                for r in rows
            ]
            return items, total
