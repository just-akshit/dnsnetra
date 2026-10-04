"""
Server-Side Session Management for DNSNetra API
===============================================
Implements cryptographically secure, server-side sessions stored in PostgreSQL.
Tokens are URL-safe 256-bit random secrets; database stores only SHA-256 hashes.
Supports immediate revocation, expiration checks, and multi-session invalidation.
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from labeler.intel.reputation.connection import get_connection

logger = logging.getLogger("api_sessions")

DEFAULT_SESSION_EXPIRE_MINUTES = int(os.getenv("AUTH_SESSION_EXPIRE_MINUTES", "1440"))  # 24 hours


def hash_session_token(token: str) -> str:
    """Return SHA-256 hexadecimal hash of the plain session token."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()


def create_session(
    user_id: int,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    expire_minutes: Optional[int] = None,
) -> tuple[str, datetime]:
    """
    Generate a cryptographically secure session token and persist its hash in PostgreSQL.
    Returns (raw_session_token, expires_at).
    """
    raw_token = secrets.token_urlsafe(36)
    token_hash = hash_session_token(raw_token)

    mins = expire_minutes if expire_minutes is not None else DEFAULT_SESSION_EXPIRE_MINUTES
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=mins)

    valid_ip = None
    if ip_address and ip_address.strip():
        try:
            import ipaddress
            ipaddress.ip_address(ip_address.strip())
            valid_ip = ip_address.strip()
        except ValueError:
            valid_ip = None

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sessions (user_id, session_token_hash, expires_at, created_at, ip_address, user_agent)
                VALUES (%s, %s, %s, NOW(), %s, %s)
                RETURNING id;
                """,
                (user_id, token_hash, expires_at, valid_ip, user_agent),
            )
            conn.commit()

    return raw_token, expires_at


def get_session_and_user(raw_token: str) -> Optional[dict[str, Any]]:
    """
    Validate session token and return user details if session is active and not expired.
    Only users with status='ACTIVE' and is_active=true are allowed.
    """
    if not raw_token or not raw_token.strip():
        return None

    token_hash = hash_session_token(raw_token)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    s.id AS session_id,
                    s.user_id,
                    s.expires_at,
                    s.revoked_at,
                    u.id AS user_id,
                    u.username,
                    u.email,
                    u.role,
                    u.status,
                    u.is_active,
                    u.created_at,
                    u.last_login_at
                FROM sessions s
                JOIN dashboard_users u ON s.user_id = u.id
                WHERE s.session_token_hash = %s
                LIMIT 1;
                """,
                (token_hash,),
            )
            row = cur.fetchone()
            if not row:
                return None

            (
                session_id,
                s_user_id,
                expires_at,
                revoked_at,
                u_id,
                username,
                email,
                role,
                status,
                is_active,
                created_at,
                last_login_at,
            ) = row

            now = datetime.now(timezone.utc)

            # Check revocation
            if revoked_at is not None:
                return None

            # Check expiration
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if now > expires_at:
                return None

            # Check user status
            if status != "ACTIVE" or not is_active:
                return None

            return {
                "session_id": session_id,
                "id": u_id,
                "user_id": u_id,
                "username": username or email or f"user_{u_id}",
                "email": email,
                "role": role.upper(),
                "status": status,
                "is_active": is_active,
                "created_at": created_at,
                "last_login_at": last_login_at,
            }


def revoke_session(raw_token: str) -> bool:
    """Revoke a single session by its raw token."""
    if not raw_token or not raw_token.strip():
        return False

    token_hash = hash_session_token(raw_token)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE sessions
                SET revoked_at = NOW()
                WHERE session_token_hash = %s AND revoked_at IS NULL;
                """,
                (token_hash,),
            )
            affected = cur.rowcount
            conn.commit()
            return affected > 0


def revoke_all_user_sessions(user_id: int) -> int:
    """Revoke all active sessions for the specified user."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE sessions
                SET revoked_at = NOW()
                WHERE user_id = %s AND revoked_at IS NULL;
                """,
                (user_id,),
            )
            count = cur.rowcount
            conn.commit()
            logger.info("Revoked %d active sessions for user_id=%s", count, user_id)
            return count


def cleanup_expired_sessions() -> int:
    """Remove expired sessions older than 7 days from the database."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM sessions
                WHERE expires_at < NOW() - INTERVAL '7 days';
                """
            )
            count = cur.rowcount
            conn.commit()
            return count
