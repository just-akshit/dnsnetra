"""
Centralized Role-Based Access Control (RBAC) for DNSNetra API
=============================================================
Defines system roles (ADMIN, ANALYST, SUPPORT), permission mappings,
and reusable FastAPI dependency guards.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Callable, Set

from fastapi import Depends, HTTPException, status


class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    SUPPORT = "SUPPORT"


class UserStatus(str, Enum):
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


# Authoritative role-to-permission mapping
ROLE_PERMISSIONS: dict[str, Set[str]] = {
    UserRole.ADMIN.value: {
        # User management (lifecycle operations: approve, enable, disable)
        "users:read",
        "users:create",
        "users:update",
        # Telemetry & Dossiers
        "domains:read",
        "domains:investigate",
        "clients:read",
        "clients:investigate",
        "queries:read",
        "queries:investigate",
        # Review Queue
        "daily_review:read",
        "daily_review:update",
        # Reports
        "reports:read",
        "reports:export",
        # System & Audit
        "settings:read",
        "settings:update",
        "audit_logs:read",
    },
    UserRole.ANALYST.value: {
        # Telemetry & Dossiers
        "domains:read",
        "domains:investigate",
        "clients:read",
        "clients:investigate",
        "queries:read",
        "queries:investigate",
        # Review Queue
        "daily_review:read",
        "daily_review:update",
        # Reports
        "reports:read",
        "reports:export",
    },
    UserRole.SUPPORT.value: {
        # Read-only operational views
        "domains:read",
        "clients:read",
        "queries:read",
        "reports:read",
    },
}


def get_role_permissions(role: str | UserRole) -> Set[str]:
    """Return the set of permissions associated with a role."""
    r_val = role.value if isinstance(role, UserRole) else str(role)
    return ROLE_PERMISSIONS.get(r_val.strip().upper(), set()).copy()


def has_permission(role: str, permission: str) -> bool:
    """Check if a given role possesses a specific permission."""
    clean_role = role.strip().upper() if role else ""
    allowed = ROLE_PERMISSIONS.get(clean_role, set())
    return permission in allowed


def require_permission(permission: str) -> Callable:
    """
    FastAPI dependency enforcing that the current authenticated user
    possesses the specified permission.
    """
    from .auth import get_current_user

    async def dependency(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        role = current_user.get("role", "")
        if not has_permission(role, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: role '{role}' lacks permission '{permission}'",
            )
        return current_user

    return dependency


def require_role(*allowed_roles: str | UserRole) -> Callable:
    """
    FastAPI dependency enforcing that the current authenticated user has
    at least one of the allowed roles.
    """
    from .auth import get_current_user

    target_roles = {
        (r.value if isinstance(r, UserRole) else str(r)).strip().upper()
        for r in allowed_roles
    }

    async def dependency(current_user: dict[str, Any] = Depends(get_current_user)) -> dict[str, Any]:
        user_role = current_user.get("role", "").strip().upper()
        if user_role not in target_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation requires one of the following roles: {', '.join(sorted(target_roles))}",
            )
        return current_user

    return dependency
