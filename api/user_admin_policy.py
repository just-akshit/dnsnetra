"""Actor-vs-target authorization for user management.

This is the single source of truth for the role hierarchy. Every
user-management route calls it; deny by default.
"""

from __future__ import annotations

from typing import Any, Mapping

from fastapi import HTTPException, Request, status

from .audit import AuditAction, log_audit_event
from .trusted_proxy import get_client_ip

# Higher rank may manage lower rank. ANALYST and SUPPORT are peers.
ROLE_RANK: dict[str, int] = {
    "SUPER_ADMIN": 3,
    "ADMIN": 2,
    "ANALYST": 1,
    "SUPPORT": 1,
}

# Roles each actor may manage (target role) and assign (new role).
MANAGEABLE_ROLES: dict[str, set[str]] = {
    "SUPER_ADMIN": {"SUPER_ADMIN", "ADMIN", "ANALYST", "SUPPORT"},
    "ADMIN": {"ANALYST", "SUPPORT"},
}


def _role(value: Any) -> str:
    if value is None:
        return ""
    return str(getattr(value, "value", value)).strip().upper()


def can_assign_role(actor_role: Any, new_role: Any) -> tuple[bool, str]:
    actor = _role(actor_role)
    target = _role(new_role)
    allowed = MANAGEABLE_ROLES.get(actor, set())
    if not allowed:
        return False, f"role '{actor}' cannot manage users"
    if target not in allowed:
        return False, f"role '{actor}' cannot assign role '{target}'"
    return True, "ok"


def can_manage(
    actor: Mapping[str, Any],
    target: Mapping[str, Any],
    new_role: Any = None,
) -> tuple[bool, str]:
    actor_role = _role(actor.get("role"))
    target_role = _role(target.get("role"))

    if actor_role not in MANAGEABLE_ROLES:
        return False, f"role '{actor_role}' cannot manage users"
    if actor.get("id") is not None and actor.get("id") == target.get("id"):
        return False, "cannot manage your own account"
    if target_role not in MANAGEABLE_ROLES[actor_role]:
        return False, f"role '{actor_role}' cannot manage role '{target_role}'"
    if new_role is not None:
        return can_assign_role(actor_role, new_role)
    return True, "ok"


def _deny(
    actor: Mapping[str, Any],
    target: Mapping[str, Any] | None,
    request: Request,
    attempted_action: str,
    reason: str,
) -> None:
    log_audit_event(
        action=AuditAction.AUTHORIZATION_DENIED,
        user_id=actor.get("id"),
        target_user_id=target.get("id") if target else None,
        ip_address=get_client_ip(request),
        user_agent=request.headers.get("user-agent"),
        metadata={
            "attempted_action": attempted_action,
            "actor_role": _role(actor.get("role")),
            "target_role": _role(target.get("role")) if target else None,
            "reason": reason,
            "outcome": "denied",
        },
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="You are not allowed to manage this account",
    )


def ensure_can_manage(
    actor: Mapping[str, Any],
    target: Mapping[str, Any],
    *,
    request: Request,
    attempted_action: str,
    new_role: Any = None,
) -> None:
    ok, reason = can_manage(actor, target, new_role)
    if not ok:
        _deny(actor, target, request, attempted_action, reason)


def ensure_can_assign_role(
    actor: Mapping[str, Any],
    new_role: Any,
    *,
    request: Request,
    attempted_action: str,
) -> None:
    ok, reason = can_assign_role(actor.get("role"), new_role)
    if not ok:
        _deny(actor, None, request, attempted_action, reason)
