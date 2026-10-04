"""
Admin User Management Endpoints for DNSNetra API
================================================
Provides administrative endpoints accessible strictly by ADMIN users:
- GET    /api/v1/users                      (List registered users with pagination & filtering)
- GET    /api/v1/users/{id}                 (Get user details)
- POST   /api/v1/users                      (Admin creates user with role & status)
- PATCH  /api/v1/users/{id}                 (Admin updates user role or active status)
- POST   /api/v1/users/{id}/approve         (Approve pending account and assign role)
- POST   /api/v1/users/{id}/disable         (Disable user account and revoke all sessions)
- POST   /api/v1/users/{id}/enable          (Enable disabled user account)
- POST   /api/v1/users/{id}/reset-password  (Admin sets new password; revokes all sessions)
- POST   /api/v1/users/{id}/revoke-sessions (Revoke all active sessions for a target user)
- GET    /api/v1/users/audit/logs           (List security audit logs)

Enforces strict Last Active Admin Protection using row-level locking (FOR UPDATE)
to prevent any single or concurrent transactions from reducing active administrators to zero.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field

from labeler.intel.reputation.connection import get_connection
from ..audit import AuditAction, get_audit_logs, log_audit_event
from ..auth import (
    get_user_by_id,
    get_user_by_username,
    hash_password,
    normalize_username,
    require_admin,
    validate_password_strength,
    validate_username,
)
from ..rbac import UserRole, UserStatus
from ..sessions import revoke_all_user_sessions
from ..trusted_proxy import get_client_ip

logger = logging.getLogger("api_users_router")

router = APIRouter(prefix="/api/v1/users", tags=["User Management"])


# ---------------------------------------------------------------------------
# Pydantic Schemas
# ---------------------------------------------------------------------------

class UserDetail(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    role: str
    status: str
    is_active: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    must_change_password: bool = False


class UserListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[UserDetail]


class AdminCreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = UserRole.ANALYST
    status: UserStatus = UserStatus.ACTIVE


class UpdateUserRequest(BaseModel):
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None
    is_active: Optional[bool] = None


class ApproveUserRequest(BaseModel):
    role: UserRole = UserRole.ANALYST


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(..., min_length=8, max_length=128)


class GenericMessageResponse(BaseModel):
    message: str
    user_id: int


class RevokeSessionsResponse(BaseModel):
    message: str
    user_id: int
    revoked_count: int


def _extract_client_meta(request: Request) -> tuple[str, Optional[str]]:
    client_ip = get_client_ip(request)
    return client_ip, request.headers.get("user-agent")


def _ensure_not_last_active_admin(cur, target_user_id: int) -> None:
    """
    Transaction-safe check ensuring an action does not leave zero active administrators.
    Acquires exclusive row-level locks on all active admin rows (FOR UPDATE)
    to serialize concurrent attempts and prevent race conditions.
    """
    cur.execute(
        """
        SELECT id FROM dashboard_users
        WHERE role = 'ADMIN' AND status = 'ACTIVE' AND is_active = true
        FOR UPDATE;
        """
    )
    active_admins = [row[0] for row in cur.fetchall()]
    if target_user_id in active_admins and len(active_admins) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Operation rejected: cannot disable or demote the last remaining active administrator.",
        )


# ---------------------------------------------------------------------------
# 1. List Users
# ---------------------------------------------------------------------------

@router.get(
    "",
    response_model=UserListResponse,
    summary="List users (Admin only)",
    description="Returns a paginated list of all registered users with optional role and status filtering.",
)
def list_users(
    role: Optional[str] = Query(None, description="Filter by role (ADMIN, ANALYST, SUPPORT)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (PENDING, ACTIVE, DISABLED)"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    admin: dict[str, Any] = Depends(require_admin),
) -> UserListResponse:
    conditions = []
    params: list[Any] = []

    if role:
        conditions.append("UPPER(role) = %s")
        params.append(role.strip().upper())

    if status_filter:
        conditions.append("UPPER(status) = %s")
        params.append(status_filter.strip().upper())

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(f"SELECT COUNT(*) FROM dashboard_users {where_clause};", tuple(params))
            total = cur.fetchone()[0]

            sql = f"""
                SELECT
                    id,
                    username,
                    email,
                    role,
                    status,
                    is_active,
                    created_at,
                    updated_at,
                    last_login_at,
                    must_change_password
                FROM dashboard_users
                {where_clause}
                ORDER BY id ASC
                LIMIT %s OFFSET %s;
            """
            cur.execute(sql, tuple(params + [limit, offset]))
            rows = cur.fetchall()

            items = [
                UserDetail(
                    id=r[0],
                    username=r[1] or r[2] or f"user_{r[0]}",
                    email=r[2],
                    role=r[3].upper() if r[3] else "ANALYST",
                    status=r[4] or ("ACTIVE" if r[5] else "PENDING"),
                    is_active=r[5],
                    created_at=r[6],
                    updated_at=r[7],
                    last_login_at=r[8],
                    must_change_password=r[9] if len(r) > 9 else False,
                )
                for r in rows
            ]

    return UserListResponse(
        total=total,
        limit=limit,
        offset=offset,
        items=items,
    )


# ---------------------------------------------------------------------------
# 2. Get User Detail
# ---------------------------------------------------------------------------

@router.get(
    "/{user_id}",
    response_model=UserDetail,
    summary="Get user by ID (Admin only)",
    description="Fetch comprehensive account details for a specific user ID.",
)
def get_user(
    user_id: int,
    admin: dict[str, Any] = Depends(require_admin),
) -> UserDetail:
    user = get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )
    return UserDetail(**user)


# ---------------------------------------------------------------------------
# 3. Admin Create User Directly
# ---------------------------------------------------------------------------

@router.post(
    "",
    response_model=UserDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create user (Admin only)",
    description="Directly creates a user account with assigned role and status without requiring CAPTCHA.",
)
def create_user(
    payload: AdminCreateUserRequest,
    request: Request,
    admin: dict[str, Any] = Depends(require_admin),
) -> UserDetail:
    client_ip, user_agent = _extract_client_meta(request)

    # Validate username
    un_valid, un_err = validate_username(payload.username, is_signup=False)
    if not un_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=un_err)

    # Validate password
    pw_valid, pw_err = validate_password_strength(payload.password, username=payload.username)
    if not pw_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_err)

    clean_username = normalize_username(payload.username)

    # Check case-insensitive uniqueness
    if get_user_by_username(clean_username):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Username '{clean_username}' already exists",
        )

    pwd_hash = hash_password(payload.password)
    is_active = (payload.status == UserStatus.ACTIVE)

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
                ) VALUES (%s, %s, %s, NULL, %s, %s, %s, false, NOW(), NOW())
                RETURNING id, created_at, updated_at;
                """,
                (
                    clean_username,
                    f"{clean_username}@dnsnetra.local",
                    pwd_hash,
                    payload.role.value,
                    payload.status.value,
                    is_active,
                ),
            )
            row = cur.fetchone()
            new_id, created_at, updated_at = row[0], row[1], row[2]
            conn.commit()

    # Audit log
    log_audit_event(
        action=AuditAction.USER_CREATED,
        user_id=admin["id"],
        target_user_id=new_id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"created_username": clean_username, "role": payload.role.value, "status": payload.status.value},
    )

    return UserDetail(
        id=new_id,
        username=clean_username,
        email=f"{clean_username}@dnsnetra.local",
        role=payload.role.value,
        status=payload.status.value,
        is_active=is_active,
        created_at=created_at,
        updated_at=updated_at,
        must_change_password=False,
    )


# ---------------------------------------------------------------------------
# 4. Patch User Role or Status
# ---------------------------------------------------------------------------

@router.patch(
    "/{user_id}",
    response_model=UserDetail,
    summary="Update user role or status (Admin only)",
    description="Updates role, status, or is_active flag of a target user with Last Active Admin Protection.",
)
def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    request: Request,
    admin: dict[str, Any] = Depends(require_admin),
) -> UserDetail:
    client_ip, user_agent = _extract_client_meta(request)

    target_user = get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    # Prevent self-demotion or self-disablement
    if user_id == admin["id"]:
        if payload.role is not None and payload.role != UserRole.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot demote their own account",
            )
        if (payload.status is not None and payload.status != UserStatus.ACTIVE) or payload.is_active is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Administrators cannot disable their own account",
            )

    updates = []
    params: list[Any] = []

    # Check if role demotion or deactivation
    will_demote = payload.role is not None and payload.role != UserRole.ADMIN
    will_deactivate = (payload.status is not None and payload.status != UserStatus.ACTIVE) or payload.is_active is False

    if payload.role is not None:
        updates.append("role = %s")
        params.append(payload.role.value)

    if payload.status is not None:
        updates.append("status = %s")
        params.append(payload.status.value)
        # Synchronize is_active flag to maintain database invariant
        if payload.is_active is None:
            updates.append("is_active = %s")
            params.append(payload.status == UserStatus.ACTIVE)

    if payload.is_active is not None:
        updates.append("is_active = %s")
        params.append(payload.is_active)
        if payload.status is None:
            updates.append("status = %s")
            params.append(UserStatus.ACTIVE.value if payload.is_active else UserStatus.DISABLED.value)

    if not updates:
        return UserDetail(**target_user)

    updates.append("updated_at = NOW()")
    params.append(user_id)

    with get_connection() as conn:
        with conn.cursor() as cur:
            # Transactional guard: ensure not leaving 0 active admins
            if will_demote or will_deactivate:
                _ensure_not_last_active_admin(cur, user_id)

            cur.execute(
                f"""
                UPDATE dashboard_users
                SET {', '.join(updates)}
                WHERE id = %s
                RETURNING id, username, email, role, status, is_active, created_at, updated_at, last_login_at, must_change_password;
                """,
                tuple(params),
            )
            row = cur.fetchone()
            conn.commit()

    # If user was deactivated or role changed, revoke active sessions
    if will_deactivate or will_demote:
        revoke_all_user_sessions(user_id)

    updated = UserDetail(
        id=row[0],
        username=row[1] or row[2] or f"user_{row[0]}",
        email=row[2],
        role=row[3],
        status=row[4],
        is_active=row[5],
        created_at=row[6],
        updated_at=row[7],
        last_login_at=row[8],
        must_change_password=row[9] if len(row) > 9 else False,
    )

    log_audit_event(
        action=AuditAction.ROLE_CHANGED if payload.role else "USER_UPDATED",
        user_id=admin["id"],
        target_user_id=user_id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"changes": payload.model_dump(exclude_unset=True)},
    )

    return updated


# ---------------------------------------------------------------------------
# 5. Approve User
# ---------------------------------------------------------------------------

@router.post(
    "/{user_id}/approve",
    response_model=GenericMessageResponse,
    summary="Approve pending account (Admin only)",
    description="Transitions an account from PENDING to ACTIVE and assigns an authorized role (ANALYST or SUPPORT).",
)
def approve_user(
    user_id: int,
    payload: ApproveUserRequest,
    request: Request,
    admin: dict[str, Any] = Depends(require_admin),
) -> GenericMessageResponse:
    client_ip, user_agent = _extract_client_meta(request)

    target_user = get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE dashboard_users
                SET status = 'ACTIVE',
                    is_active = true,
                    role = %s,
                    updated_at = NOW()
                WHERE id = %s;
                """,
                (payload.role.value, user_id),
            )
            conn.commit()

    log_audit_event(
        action=AuditAction.ACCOUNT_APPROVED,
        user_id=admin["id"],
        target_user_id=user_id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"assigned_role": payload.role.value},
    )

    return GenericMessageResponse(
        message=f"User '{target_user['username']}' approved with role '{payload.role.value}'",
        user_id=user_id,
    )


# ---------------------------------------------------------------------------
# 6. Disable User (with Last Active Admin Protection)
# ---------------------------------------------------------------------------

@router.post(
    "/{user_id}/disable",
    response_model=GenericMessageResponse,
    summary="Disable user account (Admin only)",
    description="Sets user status to DISABLED, deactivates account, and immediately invalidates all active sessions.",
)
def disable_user(
    user_id: int,
    request: Request,
    admin: dict[str, Any] = Depends(require_admin),
) -> GenericMessageResponse:
    client_ip, user_agent = _extract_client_meta(request)

    target_user = get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    # Prevent admin from disabling themselves to avoid lockout
    if user_id == admin["id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot disable their own account",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            # Enforce Last Active Admin Protection inside transaction
            _ensure_not_last_active_admin(cur, user_id)

            cur.execute(
                """
                UPDATE dashboard_users
                SET status = 'DISABLED',
                    is_active = false,
                    updated_at = NOW()
                WHERE id = %s;
                """,
                (user_id,),
            )
            conn.commit()

    # Invalidate all active sessions immediately
    revoke_all_user_sessions(user_id)

    log_audit_event(
        action=AuditAction.ACCOUNT_DISABLED,
        user_id=admin["id"],
        target_user_id=user_id,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    return GenericMessageResponse(
        message=f"User '{target_user['username']}' has been disabled and all sessions revoked",
        user_id=user_id,
    )


# ---------------------------------------------------------------------------
# 7. Enable User
# ---------------------------------------------------------------------------

@router.post(
    "/{user_id}/enable",
    response_model=GenericMessageResponse,
    summary="Enable user account (Admin only)",
    description="Restores user account status to ACTIVE and enables login.",
)
def enable_user(
    user_id: int,
    request: Request,
    admin: dict[str, Any] = Depends(require_admin),
) -> GenericMessageResponse:
    client_ip, user_agent = _extract_client_meta(request)

    target_user = get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE dashboard_users
                SET status = 'ACTIVE',
                    is_active = true,
                    updated_at = NOW()
                WHERE id = %s;
                """,
                (user_id,),
            )
            conn.commit()

    log_audit_event(
        action=AuditAction.ACCOUNT_ENABLED,
        user_id=admin["id"],
        target_user_id=user_id,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    return GenericMessageResponse(
        message=f"User '{target_user['username']}' has been re-enabled",
        user_id=user_id,
    )


# ---------------------------------------------------------------------------
# 8. Reset Password (with must_change_password)
# ---------------------------------------------------------------------------

@router.post(
    "/{user_id}/reset-password",
    response_model=GenericMessageResponse,
    summary="Reset user password (Admin only)",
    description="Sets a new Argon2id password for target user, marks must_change_password=true, and invalidates all existing sessions.",
)
def reset_password(
    user_id: int,
    payload: ResetPasswordRequest,
    request: Request,
    admin: dict[str, Any] = Depends(require_admin),
) -> GenericMessageResponse:
    client_ip, user_agent = _extract_client_meta(request)

    target_user = get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    pw_valid, pw_err = validate_password_strength(payload.new_password, username=target_user["username"])
    if not pw_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=pw_err)

    new_hash = hash_password(payload.new_password)

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE dashboard_users
                SET password_hash = %s,
                    hashed_password = NULL,
                    must_change_password = true,
                    updated_at = NOW()
                WHERE id = %s;
                """,
                (new_hash, user_id),
            )
            conn.commit()

    # Invalidate all active sessions for security
    revoke_all_user_sessions(user_id)

    log_audit_event(
        action=AuditAction.PASSWORD_RESET,
        user_id=admin["id"],
        target_user_id=user_id,
        ip_address=client_ip,
        user_agent=user_agent,
    )

    return GenericMessageResponse(
        message=f"Password for user '{target_user['username']}' was successfully reset. All active sessions invalidated.",
        user_id=user_id,
    )


# ---------------------------------------------------------------------------
# 9. Revoke Sessions
# ---------------------------------------------------------------------------

@router.post(
    "/{user_id}/revoke-sessions",
    response_model=RevokeSessionsResponse,
    summary="Revoke user sessions (Admin only)",
    description="Forces immediate logout of all active sessions for the target user ID.",
)
def revoke_sessions(
    user_id: int,
    request: Request,
    admin: dict[str, Any] = Depends(require_admin),
) -> RevokeSessionsResponse:
    client_ip, user_agent = _extract_client_meta(request)

    target_user = get_user_by_id(user_id)
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {user_id} not found",
        )

    revoked_count = revoke_all_user_sessions(user_id)

    log_audit_event(
        action=AuditAction.SESSION_REVOKED,
        user_id=admin["id"],
        target_user_id=user_id,
        ip_address=client_ip,
        user_agent=user_agent,
        metadata={"revoked_count": revoked_count},
    )

    return RevokeSessionsResponse(
        message=f"Successfully revoked {revoked_count} active sessions for '{target_user['username']}'",
        user_id=user_id,
        revoked_count=revoked_count,
    )


# ---------------------------------------------------------------------------
# 10. Audit Logs Query Endpoint
# ---------------------------------------------------------------------------

@router.get(
    "/audit/logs",
    summary="Retrieve security audit logs (Admin only)",
    description="Returns chronological security audit trail with filtering by action or user.",
)
def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action (e.g. LOGIN_SUCCESS, SIGNUP)"),
    user_id: Optional[int] = Query(None, description="Filter by actor or target user ID"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    admin: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    items, total = get_audit_logs(
        limit=limit,
        offset=offset,
        action=action,
        user_id=user_id,
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }
