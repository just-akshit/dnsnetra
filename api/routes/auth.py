"""
Authentication Endpoints for DNSNetra API
==========================================
Provides public and authenticated endpoints for:
- GET  /api/v1/auth/captcha         (Generate self-hosted visual CAPTCHA with rate limiting)
- POST /api/v1/auth/signup          (Self-service registration with reserved name protection)
- POST /api/v1/auth/login           (JSON credentials + CAPTCHA authentication with HttpOnly cookie)
- POST /api/v1/auth/token           (OAuth2 form credentials login alias)
- POST /api/v1/auth/logout          (Server-side session invalidation and cookie clearing)
- GET  /api/v1/auth/me              (Current authenticated user profile)
- POST /api/v1/auth/change-password (User password update resetting must_change_password)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from labeler.intel.reputation.connection import get_connection
from ..audit import AuditAction, log_audit_event
from ..auth import (
    TokenResponse,
    UserPayload,
    authenticate_user,
    change_user_password,
    get_current_user,
    get_user_by_username,
    hash_password,
    normalize_username,
    validate_password_strength,
    validate_username,
    verify_password,
)
from ..captcha import create_captcha, verify_and_consume_captcha
from ..rate_limiter import rate_limiter
from ..sessions import create_session, revoke_session
from ..trusted_proxy import get_client_ip

logger = logging.getLogger("api_auth_router")

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

CANONICAL_COOKIE_NAME = "dnsnetra_session"
LEGACY_COOKIE_NAME = "session_token"


def _is_cookie_secure() -> bool:
    """Determine whether cookies must have the Secure attribute."""
    env = (os.getenv("DNSNETRA_ENV") or os.getenv("APP_ENV") or "development").lower()
    if env in ("production", "prod"):
        return True
    return os.getenv("AUTH_COOKIE_SECURE", "false").lower() in ("true", "1")


# ---------------------------------------------------------------------------
# Request & Response Models
# ---------------------------------------------------------------------------

class CaptchaResponse(BaseModel):
    captcha_id: str
    image: str
    expires_in: int


class SignupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)
    captcha_id: str = Field(..., min_length=10, max_length=64)
    captcha_answer: str = Field(..., min_length=1, max_length=20)


class SignupResponse(BaseModel):
    message: str
    username: str
    status: str


class LoginRequest(BaseModel):
    username: Optional[str] = Field(None, max_length=100)
    email: Optional[str] = Field(None, max_length=100)
    password: str = Field(..., min_length=1, max_length=128)
    captcha_id: Optional[str] = Field(None, max_length=64)
    captcha_answer: Optional[str] = Field(None, max_length=20)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=128)
    new_password: str = Field(..., min_length=8, max_length=128)
    confirm_password: str = Field(..., min_length=8, max_length=128)


class ChangePasswordResponse(BaseModel):
    message: str
    session_token: str


class LogoutResponse(BaseModel):
    message: str


def _extract_client_metadata(request: Request) -> tuple[str, Optional[str]]:
    client_ip = get_client_ip(request)
    return client_ip, request.headers.get("user-agent")


# ---------------------------------------------------------------------------
# 1. CAPTCHA Endpoint (Rate Limited to 30/min)
# ---------------------------------------------------------------------------

@router.get(
    "/captcha",
    response_model=CaptchaResponse,
    summary="Generate self-hosted visual CAPTCHA",
    description="Returns a short-lived, signed visual CAPTCHA challenge without third-party dependencies.",
    dependencies=[Depends(rate_limiter(action="captcha", max_requests=30, window_seconds=60))],
)
def get_captcha() -> CaptchaResponse:
    """Generate and return a self-hosted text/image CAPTCHA challenge."""
    challenge = create_captcha(expires_in=300)
    return CaptchaResponse(
        captcha_id=str(challenge["captcha_id"]),
        image=str(challenge["image"]),
        expires_in=int(challenge["expires_in"]),
    )


# ---------------------------------------------------------------------------
# 2. Signup Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/signup",
    response_model=SignupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description="Registers an account in PENDING status with strict reserved name checks and password policies.",
    dependencies=[Depends(rate_limiter(action="signup", max_requests=10, window_seconds=60))],
)
def signup(payload: SignupRequest, request: Request) -> SignupResponse:
    """Handle new user self-service signup."""
    client_ip, user_agent = _extract_client_metadata(request)

    # 1. Password confirmation check
    if payload.password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match",
        )

    # 2. Username format and reserved name validation
    un_valid, un_err = validate_username(payload.username, is_signup=True)
    if not un_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=un_err,
        )

    # 3. Password strength and username collision check
    pw_valid, pw_err = validate_password_strength(payload.password, username=payload.username)
    if not pw_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=pw_err,
        )

    # 4. CAPTCHA verification & single-use consumption
    captcha_valid, captcha_err = verify_and_consume_captcha(
        captcha_id=payload.captcha_id,
        user_answer=payload.captcha_answer,
    )
    if not captcha_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"CAPTCHA verification failed: {captcha_err}",
        )

    clean_username = normalize_username(payload.username)

    # 5. Check case-insensitive username uniqueness
    existing = get_user_by_username(clean_username)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{clean_username}' is already taken",
        )

    # 6. Securely hash password using Argon2id
    pwd_hash = hash_password(payload.password)

    # 7. Create user with status=PENDING, is_active=False, role=ANALYST
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
                    must_change_password,
                    created_at,
                    updated_at
                ) VALUES (%s, %s, %s, NULL, 'ANALYST', 'PENDING', false, false, NOW(), NOW())
                RETURNING id;
                """,
                (clean_username, f"{clean_username}@dnsnetra.local", pwd_hash),
            )
            user_id = cur.fetchone()[0]
            conn.commit()

    # 8. Record audit event
    log_audit_event(
        action=AuditAction.SIGNUP,
        user_id=user_id,
        target_user_id=user_id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"username": clean_username, "role": "ANALYST", "status": "PENDING"},
    )

    return SignupResponse(
        message="Account created successfully. Awaiting administrator approval.",
        username=clean_username,
        status="PENDING",
    )


# ---------------------------------------------------------------------------
# 3. Login Endpoint (JSON credentials + HttpOnly Session Cookie)
# ---------------------------------------------------------------------------

@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login with username/password credentials",
    description="Authenticates active user credentials, verifies CAPTCHA if provided, sets HttpOnly session cookie, and returns session token.",
    dependencies=[Depends(rate_limiter(action="login", max_requests=15, window_seconds=60))],
)
def login(payload: LoginRequest, request: Request, response: Response) -> TokenResponse:
    """Authenticate user with username and password, returning server-side session."""
    client_ip, user_agent = _extract_client_metadata(request)
    identifier = (payload.username or payload.email or "").strip()

    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is required",
        )

    # If CAPTCHA challenge is provided, verify and consume it
    if payload.captcha_id or payload.captcha_answer:
        captcha_valid, captcha_err = verify_and_consume_captcha(
            captcha_id=payload.captcha_id,
            user_answer=payload.captcha_answer,
        )
        if not captcha_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"CAPTCHA verification failed: {captcha_err}",
            )

    # Authenticate credentials and verify ACTIVE status
    user = authenticate_user(identifier, payload.password)
    if not user:
        log_audit_event(
            action=AuditAction.LOGIN_FAILURE,
            user_id=None,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"identifier": identifier},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Create server-side session
    raw_session_token, expires_at = create_session(
        user_id=user["id"],
        ip_address=client_ip,
        user_agent=user_agent,
    )

    # Set canonical HttpOnly browser session cookie
    response.set_cookie(
        key=CANONICAL_COOKIE_NAME,
        value=raw_session_token,
        httponly=True,
        secure=_is_cookie_secure(),
        samesite="lax",
        max_age=86400,
        path="/",
    )

    # Record login audit event
    log_audit_event(
        action=AuditAction.LOGIN_SUCCESS,
        user_id=user["id"],
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"username": user["username"], "role": user["role"]},
    )

    return TokenResponse(
        session_token=raw_session_token,
        access_token=raw_session_token,
        token_type="bearer",
        expires_in=86400,
        user={
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "status": user["status"],
            "must_change_password": user.get("must_change_password", False),
        },
    )


# ---------------------------------------------------------------------------
# 4. Canonical OAuth2 Form Token Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Obtain OAuth2 session token",
    description="Authenticate with username and password via standard form-data for OpenAPI docs / curl.",
    dependencies=[Depends(rate_limiter(action="login", max_requests=15, window_seconds=60))],
)
def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> TokenResponse:
    """Canonical OAuth2 form password login."""
    client_ip, user_agent = _extract_client_metadata(request)
    user = authenticate_user(form_data.username, form_data.password)

    if not user:
        log_audit_event(
            action=AuditAction.LOGIN_FAILURE,
            user_id=None,
            ip_address=client_ip,
            user_agent=user_agent,
            metadata={"identifier": form_data.username},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_session_token, _ = create_session(
        user_id=user["id"],
        ip_address=client_ip,
        user_agent=user_agent,
    )

    response.set_cookie(
        key=CANONICAL_COOKIE_NAME,
        value=raw_session_token,
        httponly=True,
        secure=_is_cookie_secure(),
        samesite="lax",
        max_age=86400,
        path="/",
    )

    log_audit_event(
        action=AuditAction.LOGIN_SUCCESS,
        user_id=user["id"],
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"username": user["username"], "role": user["role"]},
    )

    return TokenResponse(
        session_token=raw_session_token,
        access_token=raw_session_token,
        token_type="bearer",
        expires_in=86400,
        user={
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "status": user["status"],
            "must_change_password": user.get("must_change_password", False),
        },
    )


# ---------------------------------------------------------------------------
# 5. User Change Password Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/change-password",
    response_model=ChangePasswordResponse,
    summary="Change user password",
    description="Allows authenticated user to update their password. Clears must_change_password flag and issues new session.",
)
def user_change_password(
    payload: ChangePasswordRequest,
    request: Request,
    response: Response,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> ChangePasswordResponse:
    """Handle user password change."""
    client_ip, user_agent = _extract_client_metadata(request)

    # Verify confirmation match
    if payload.new_password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password and confirmation do not match",
        )

    # Verify current password
    user_record = get_user_by_username(current_user["username"])
    if not user_record or not verify_password(payload.current_password, user_record.get("password_hash", "")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Disallow reusing the current password
    if payload.current_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password cannot be identical to current password",
        )

    # Validate new password strength
    pw_valid, pw_err = validate_password_strength(payload.new_password, username=current_user["username"])
    if not pw_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_err)

    # Update password and revoke old sessions
    change_user_password(current_user["id"], payload.new_password)

    # Create fresh session for caller
    new_session_token, _ = create_session(
        user_id=current_user["id"],
        ip_address=client_ip,
        user_agent=user_agent,
    )

    response.set_cookie(
        key=CANONICAL_COOKIE_NAME,
        value=new_session_token,
        httponly=True,
        secure=_is_cookie_secure(),
        samesite="lax",
        max_age=86400,
        path="/",
    )

    log_audit_event(
        action="PASSWORD_CHANGED",
        user_id=current_user["id"],
        target_user_id=current_user["id"],
        ip_address=client_ip,
        user_agent=user_agent,
    )

    return ChangePasswordResponse(
        message="Password updated successfully",
        session_token=new_session_token,
    )


# ---------------------------------------------------------------------------
# 6. Logout Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Invalidate active session",
    description="Revokes the caller's server-side session token and clears the session cookies.",
)
def logout(
    request: Request,
    response: Response,
    current_user: dict[str, Any] = Depends(get_current_user),
) -> LogoutResponse:
    """Revoke caller's current session and clear auth cookies."""
    client_ip, user_agent = _extract_client_metadata(request)

    token = getattr(request.state, "session_token", None)
    if token:
        revoke_session(token)

    # Clear canonical and legacy cookies
    response.delete_cookie(key=CANONICAL_COOKIE_NAME, path="/")
    response.delete_cookie(key=LEGACY_COOKIE_NAME, path="/")

    log_audit_event(
        action=AuditAction.LOGOUT,
        user_id=current_user["id"],
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"username": current_user["username"]},
    )

    return LogoutResponse(message="Logged out successfully")


# ---------------------------------------------------------------------------
# 7. Current User Profile Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/me",
    response_model=UserPayload,
    summary="Current authenticated user profile",
    description="Returns the profile of the currently authenticated user session. Never returns secrets or hashes.",
)
def get_current_user_profile(user: dict[str, Any] = Depends(get_current_user)) -> UserPayload:
    """Return currently authenticated user profile."""
    return UserPayload(
        id=user["id"],
        username=user.get("username", f"user_{user['id']}"),
        email=user.get("email"),
        role=user.get("role", "ANALYST"),
        status=user.get("status", "ACTIVE"),
        is_active=user.get("is_active", True),
        created_at=user.get("created_at"),
        last_login_at=user.get("last_login_at"),
        must_change_password=user.get("must_change_password", False),
    )
