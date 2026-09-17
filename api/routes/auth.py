"""
api/routes/auth.py
==================
Authentication endpoints for DNSNetra API:
- POST /api/v1/auth/token (canonical OAuth2 form)
- POST /api/v1/auth/login (JSON login alias)
- GET /api/v1/auth/me (authenticated user profile)
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

from ..auth import (
    TokenResponse,
    UserPayload,
    authenticate_user,
    create_access_token,
    get_current_user,
)

logger = logging.getLogger("api_auth_router")

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    """JSON credentials payload for login alias."""
    email: Optional[str] = None
    username: Optional[str] = None
    password: str = Field(..., min_length=1)


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Obtain OAuth2 JWT access token",
    description="Authenticate with username/email and password via form-data to obtain a signed JWT bearer token.",
)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()) -> TokenResponse:
    """Canonical OAuth2 password flow endpoint."""
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(data={"sub": user["email"], "role": user["role"]})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=86400,
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login with JSON credentials",
    description="JSON login alias for API clients; delegates to the canonical authentication engine.",
)
def login_json(payload: LoginRequest) -> TokenResponse:
    """JSON login alias for frontend and client compatibility."""
    identifier = payload.username or payload.email
    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email is required",
        )

    user = authenticate_user(identifier, payload.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(data={"sub": user["email"], "role": user["role"]})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=86400,
    )


@router.get(
    "/me",
    response_model=UserPayload,
    summary="Current authenticated user profile",
    description="Returns the profile of the currently authenticated bearer token user.",
)
def get_current_user_profile(user: dict[str, Any] = Depends(get_current_user)) -> UserPayload:
    """Return currently authenticated user profile."""
    return UserPayload(
        id=user["id"],
        email=user["email"],
        role=user["role"],
        is_active=user["is_active"],
    )
