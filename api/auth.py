"""
Authentication & Authorization for DNSNetra API
================================================
Authoritative authentication engine implementing:
- Argon2id password hashing with automatic transparent legacy hash migration (clearing bcrypt)
- Cryptographically secure server-side session resolution
- Username-only authentication model backed by PostgreSQL dashboard_users
- Case-insensitive username uniqueness and consistent normalization
- Strict password policy with reserved-name protection and password != username enforcement
- Centralized RBAC dependency guards (ADMIN, ANALYST, SUPPORT)
- CSRF protection for cookie-authenticated browser requests
"""

from __future__ import annotations

import logging
import os
import re
import secrets
import string
from datetime import datetime
from typing import Any, Optional

import argon2
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
import bcrypt
from fastapi import Cookie, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from labeler.intel.reputation.connection import get_connection
from .csrf import verify_csrf_protection
from .sessions import (
    create_session,
    get_session_and_user,
    revoke_all_user_sessions,
    revoke_session,
)

logger = logging.getLogger("api_auth")

RESERVED_USERNAMES = {
    "admin",
    "administrator",
    "root",
    "system",
    "support",
    "analyst",
    "guest",
    "api",
    "dnsnetra",
    "superuser",
}

# Initialize Argon2id password hasher (RFC 9106 recommended configuration)
_hasher = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=1,
    hash_len=32,
    type=argon2.Type.ID,
)

# A fixed hash used to spend the same Argon2id work for unknown usernames.
_DUMMY_PASSWORD_HASH = _hasher.hash(secrets.token_urlsafe(32))

bearer_scheme = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# Password Validation & Hashing (Argon2id)
# ---------------------------------------------------------------------------

def validate_password_strength(password: str, username: Optional[str] = None) -> tuple[bool, str]:
    """
    Validate that password satisfies security requirements:
    - Minimum 8 characters, maximum 128 characters
    - Not empty or whitespace-only
    - Cannot equal the username
    - Contains at least one letter
    - Contains at least one number or special character
    """
    if not password:
        return False, "Password is required"

    trimmed = password.strip()
    if not trimmed or len(password) < 8:
        return False, "Password must be at least 8 characters in length"
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters in length"

    if username and trimmed.lower() == username.strip().lower():
        return False, "Password cannot be identical to the username"

    if not re.search(r"[a-zA-Z]", password):
        return False, "Password must contain at least one letter"
    if not re.search(r"[^A-Za-z]", password):
        return False, "Password must contain at least one digit or special character"
    return True, "OK"


_TEMP_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"


def generate_temporary_password(length: int = 20) -> str:
    """Return a random password that satisfies validate_password_strength()."""
    for _ in range(100):
        candidate = "".join(
            secrets.choice(_TEMP_PASSWORD_ALPHABET) for _ in range(length)
        )
        if validate_password_strength(candidate)[0]:
            return candidate
    raise RuntimeError("could not generate a policy-compliant temporary password")


def normalize_username(username: Optional[str]) -> str:
    """
    Authoritative username normalization function used identically across
    signup, login, user lookups, admin management, and audit resolution:
    strips leading/trailing whitespace and converts to lowercase.
    """
    if not username:
        return ""
    return username.strip().lower()


def _reserved_key(value: str) -> str:
    return value.strip().strip("._-").lower()


def validate_username(username: str, is_signup: bool = False) -> tuple[bool, str]:
    """
    Validate username format:
    - 3 to 50 characters
    - Alphanumeric, underscores, hyphens, and periods
    - For public signups: must not collide with system-reserved identifiers
    """
    if not username:
        return False, "Username is required"
    clean = username.strip()
    if len(clean) < 3 or len(clean) > 50:
        return False, "Username must be between 3 and 50 characters"
    if not re.match(r"^[a-zA-Z0-9_.-]+$", clean):
        return False, "Username may only contain letters, numbers, underscores, dashes, and periods"

    if is_signup and _reserved_key(clean) in RESERVED_USERNAMES:
        return False, f"Username '{clean}' is reserved by the system"

    return True, "OK"


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using Argon2id."""
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify plain password against hashed password.
    Supports Argon2id and transparently falls back to bcrypt for legacy hashes.
    """
    if not plain_password or not hashed_password:
        return False

    # Check for Argon2 hash format
    if hashed_password.startswith("$argon2"):
        try:
            return _hasher.verify(hashed_password, plain_password)
        except (VerifyMismatchError, VerificationError, InvalidHash):
            return False
        except Exception as exc:
            logger.warning("Error verifying Argon2 password: %s", exc)
            return False

    # Fallback for legacy bcrypt hashes ($2a$, $2b$, $2y$)
    if hashed_password.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
        except Exception as exc:
            logger.warning("Error verifying legacy bcrypt password: %s", exc)
            return False

    return False


# ---------------------------------------------------------------------------
# Database User Operations
# ---------------------------------------------------------------------------

def get_user_by_username(identifier: str) -> Optional[dict[str, Any]]:
    """Fetch user by case-insensitive username or email from dashboard_users table."""
    clean = identifier.strip() if identifier else ""
    if not clean:
        return None

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    username,
                    email,
                    COALESCE(password_hash, hashed_password) AS password_hash,
                    role,
                    status,
                    is_active,
                    created_at,
                    updated_at,
                    last_login_at,
                    must_change_password
                FROM dashboard_users
                WHERE LOWER(username) = LOWER(%s) OR LOWER(email) = LOWER(%s)
                LIMIT 1;
                """,
                (clean, clean),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "username": row[1] or row[2] or f"user_{row[0]}",
                "email": row[2],
                "password_hash": row[3],
                "role": row[4].upper() if row[4] else "ANALYST",
                "status": row[5] or ("ACTIVE" if row[6] else "PENDING"),
                "is_active": row[6],
                "created_at": row[7],
                "updated_at": row[8],
                "last_login_at": row[9],
                "must_change_password": row[10] if len(row) > 10 else False,
            }


def get_user_by_id(user_id: int) -> Optional[dict[str, Any]]:
    """Fetch user by primary key ID."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    username,
                    email,
                    COALESCE(password_hash, hashed_password) AS password_hash,
                    role,
                    status,
                    is_active,
                    created_at,
                    updated_at,
                    last_login_at,
                    must_change_password
                FROM dashboard_users
                WHERE id = %s
                LIMIT 1;
                """,
                (user_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "username": row[1] or row[2] or f"user_{row[0]}",
                "email": row[2],
                "password_hash": row[3],
                "role": row[4].upper() if row[4] else "ANALYST",
                "status": row[5] or ("ACTIVE" if row[6] else "PENDING"),
                "is_active": row[6],
                "created_at": row[7],
                "updated_at": row[8],
                "last_login_at": row[9],
                "must_change_password": row[10] if len(row) > 10 else False,
            }


def authenticate_user(identifier: str, plain_password: str) -> Optional[dict[str, Any]]:
    """
    Authenticate user with username/email and password.
    Returns user record only if user exists, password matches, and status is ACTIVE.
    Transparently upgrades legacy bcrypt hashes to Argon2id and clears the legacy bcrypt field.
    """
    user = get_user_by_username(identifier)
    if not user:
        verify_password(plain_password, _DUMMY_PASSWORD_HASH)
        return None

    if not user.get("is_active") or user.get("status") != "ACTIVE":
        verify_password(plain_password, user.get("password_hash") or _DUMMY_PASSWORD_HASH)
        return None

    stored_hash = user.get("password_hash") or ""
    if not stored_hash or not verify_password(plain_password, stored_hash):
        return None

    # Transparent upgrade to Argon2id if hash was legacy bcrypt: clear hashed_password to NULL
    if stored_hash.startswith(("$2a$", "$2b$", "$2y$")):
        try:
            new_hash = hash_password(plain_password)
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE dashboard_users
                        SET password_hash = %s, hashed_password = NULL, updated_at = NOW()
                        WHERE id = %s;
                        """,
                        (new_hash, user["id"]),
                    )
                    conn.commit()
            user["password_hash"] = new_hash
            logger.info("Migrated user id=%s from legacy bcrypt to Argon2id and cleared legacy field", user["id"])
        except Exception as exc:
            logger.warning("Could not auto-upgrade password hash: %s", exc)

    # Update last_login_at
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE dashboard_users SET last_login_at = NOW() WHERE id = %s;",
                    (user["id"],),
                )
                conn.commit()
    except Exception as exc:
        logger.warning("Failed to update last_login_at for user %s: %s", user["id"], exc)

    return user


def change_user_password(user_id: int, new_password: str) -> None:
    """Update password to Argon2id, clear must_change_password flag, and revoke all active sessions."""
    new_hash = hash_password(new_password)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE dashboard_users
                SET password_hash = %s,
                    hashed_password = NULL,
                    must_change_password = false,
                    updated_at = NOW()
                WHERE id = %s;
                """,
                (new_hash, user_id),
            )
            conn.commit()
    revoke_all_user_sessions(user_id)


# ---------------------------------------------------------------------------
# Centralized Authentication Dependencies
# ---------------------------------------------------------------------------

get_user_by_email = get_user_by_username

PASSWORD_CHANGE_ALLOWLIST = {
    "/api/v1/auth/me",
    "/api/v1/auth/logout",
    "/api/v1/auth/change-password",
}


def _requires_password_change(user: dict[str, Any], path: str) -> bool:
    return bool(user.get("must_change_password")) and path.rstrip("/") not in PASSWORD_CHANGE_ALLOWLIST


async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    canonical_cookie: Optional[str] = Cookie(None, alias="dnsnetra_session"),
    legacy_cookie: Optional[str] = Cookie(None, alias="session_token"),
) -> dict[str, Any]:
    """
    Resolve the caller from a server-side session only.
    A bearer token and a session cookie carry the same opaque token.
    """
    token = credentials.credentials if credentials else None
    auth_method = "bearer"

    if not token:
        token = canonical_cookie or legacy_cookie
        if token:
            auth_method = "cookie"

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.auth_method = auth_method

    # Enforce CSRF protection for cookie-authenticated state-changing requests
    if auth_method == "cookie":
        verify_csrf_protection(request)

    session_user = get_session_and_user(token)
    if not session_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or revoked authentication session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if _requires_password_change(session_user, request.url.path):
        raise HTTPException(
            status_code=status.HTTP_428_PRECONDITION_REQUIRED,
            detail="Password change required",
            headers={"X-Password-Change-Required": "true"},
        )

    request.state.session_token = token
    request.state.current_user = session_user
    return session_user


async def require_authenticated_user(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """Enforces that a user is successfully authenticated and active."""
    return current_user


async def require_admin(
    current_user: dict[str, Any] = Depends(get_current_user),
) -> dict[str, Any]:
    """Enforce that current authenticated user has the ADMIN role."""
    if current_user.get("role", "").upper() != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires administrator privileges",
        )
    return current_user


# ---------------------------------------------------------------------------
# Pydantic Schemas for Auth Responses
# ---------------------------------------------------------------------------

class TokenResponse(BaseModel):
    token_type: str = "bearer"
    expires_in: int
    user: dict[str, Any]


class UserPayload(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role: str
    status: str
    is_active: bool
    created_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    must_change_password: bool = False
