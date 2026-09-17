"""
Authentication & Authorization for DNSNetra API
================================================
Implements JWT authentication backed by the `dashboard_users` table in PostgreSQL.
Reads JWT secrets securely from environment variables.
"""

from __future__ import annotations

import os
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

from labeler.intel.reputation.connection import get_connection

logger = logging.getLogger("api_auth")

DEV_INSECURE_TEST_SECRET = "dnsnetra-dev-test-jwt-secret-do-not-use-in-production"
INSECURE_SECRETS = {
    "dnsnetra-secure-default-change-in-prod",
    "dnsnetra-dev-test-jwt-secret-do-not-use-in-production",
    "secret",
    "changeme",
    "default",
}


def get_jwt_secret_key(
    env: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> str:
    """Retrieve and validate JWT secret key based on environment.

    In production/prod:
        Missing or known insecure default secret raises RuntimeError.
    In development/test:
        Uses AUTH_SECRET_KEY/JWT_SECRET if present; otherwise safely falls back
        to documented test secret with an explicit warning.
    """
    current_env = (
        env
        or os.getenv("DNSNETRA_ENV")
        or os.getenv("APP_ENV")
        or os.getenv("ENVIRONMENT")
        or "development"
    ).lower().strip()

    key = secret_key if secret_key is not None else (os.getenv("AUTH_SECRET_KEY") or os.getenv("JWT_SECRET"))

    if current_env in ("production", "prod"):
        if not key or not key.strip() or key in INSECURE_SECRETS:
            raise RuntimeError(
                f"CRITICAL SECURITY CONFIGURATION ERROR: AUTH_SECRET_KEY must be set to a secure, "
                f"non-default secret in production environment (current_env='{current_env}')."
            )
        return key

    # Development / Test / Local behavior
    if key and key.strip():
        return key

    logger.warning(
        "Running in %s environment with default test JWT secret. NEVER use this in production!",
        current_env,
    )
    return DEV_INSECURE_TEST_SECRET


SECRET_KEY = get_jwt_secret_key()
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserPayload(BaseModel):
    id: int
    email: str
    role: str
    is_active: bool


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against bcrypt hashed password."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception as exc:
        logger.warning("Error verifying password: %s", exc)
        return False


def get_user_by_email(email: str) -> Optional[dict[str, Any]]:
    """Fetch user record from dashboard_users table."""
    clean_email = email.strip() if email else ""
    if not clean_email:
        return None

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, email, role, is_active, hashed_password
                FROM dashboard_users
                WHERE email = %s
                LIMIT 1
                """,
                (clean_email,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": row[0],
                "email": row[1],
                "role": row[2],
                "is_active": row[3],
                "hashed_password": row[4],
            }


def authenticate_user(email: str, password: str) -> Optional[dict[str, Any]]:
    """Authenticate user with email and password."""
    user = get_user_by_email(email)
    if not user:
        return None
    if not user.get("is_active"):
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Generate signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    secret = get_jwt_secret_key()
    encoded_jwt = jwt.encode(to_encode, secret, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
    """Validate JWT token and return active user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    secret = get_jwt_secret_key()
    try:
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise credentials_exception
    except (jwt.PyJWTError, Exception):
        raise credentials_exception

    user = get_user_by_email(email)
    if user is None or not user.get("is_active"):
        raise credentials_exception
    return user


async def require_admin(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
    """Ensure current authenticated user has admin role."""
    if current_user.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operation requires administrator privileges",
        )
    return current_user
