"""Case lifecycle and timeline orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .repository import CaseRepository
from .schemas import CaseDetail, CasePriority, CaseResolution, CaseStatus


class InvalidTransition(ValueError):
    pass


class PermissionDenied(InvalidTransition, PermissionError):
    """The transition is valid but the actor lacks cases:manage."""


ALLOWED = {
    "open": {"triaged", "closed"},
    "triaged": {"investigating", "awaiting_info", "resolved", "closed"},
    "investigating": {"awaiting_info", "resolved", "closed"},
    "awaiting_info": {"investigating", "resolved", "closed"},
    "resolved": {"closed", "investigating"},
    "closed": {"investigating"},
}
MANAGE_ONLY_TARGETS = {"closed"}
MANAGE_ONLY_SOURCES = {"closed"}


class CaseService:
    def __init__(self, repository=None) -> None:
        self.repository = repository or CaseRepository()

    @staticmethod
    def validate_transition(*, current: str, next_status: str,
                            resolution: Optional[str], can_manage: bool) -> None:
        if next_status not in ALLOWED.get(current, set()):
            raise InvalidTransition(
                f"Cannot move case from '{current}' to '{next_status}'. "
                f"Allowed: {sorted(ALLOWED.get(current, set()))}."
            )
        if next_status == "resolved" and not resolution:
            raise ValueError("A resolution is required to resolve a case.")
        if next_status == "resolved" and resolution not in {r.value for r in CaseResolution}:
            raise ValueError(f"Invalid resolution '{resolution}'.")
        if next_status in MANAGE_ONLY_TARGETS or current in MANAGE_ONLY_SOURCES:
            if not can_manage:
                raise PermissionDenied("This transition requires cases:manage.")

    def create(self, *, title, description, priority, entity_type,
               entity_value, created_by, assigned_to=None) -> CaseDetail:
        if priority not in {p.value for p in CasePriority}:
            raise ValueError(f"Invalid priority '{priority}'.")
        return self.repository.create(
            title=title, description=description, priority=priority,
            entity_type=entity_type, entity_value=entity_value,
            created_by=created_by, assigned_to=assigned_to,
        )

    def get(self, public_id: str) -> Optional[CaseDetail]:
        return self.repository.get(public_id)

    def list(self, **filters):
        return self.repository.list(**filters)

    def update(self, public_id: str, *, actor_id: int, can_manage: bool,
               payload: dict[str, Any]) -> CaseDetail:
        case = self.repository.get(public_id)
        if not case:
            raise LookupError("Case not found.")

        next_status = payload.get("status", case.status)
        resolution = payload.get("resolution", case.resolution)

        if next_status != case.status:
            self.validate_transition(
                current=case.status, next_status=next_status,
                resolution=resolution, can_manage=can_manage,
            )

        fields = dict(payload)
        if next_status == "resolved":
            fields["resolved_by"] = actor_id
            fields["resolved_at"] = datetime.now(timezone.utc)
        if next_status == "closed":
            fields["closed_at"] = datetime.now(timezone.utc)
        if case.status in ("resolved", "closed") and next_status == "investigating":
            fields["closed_at"] = None

        updated = self.repository.update(public_id, fields)
        if not updated:
            raise LookupError("Case not found.")

        if next_status != case.status:
            self.repository.add_event(
                updated.id,
                actor_id=actor_id, kind="status_changed",
                metadata={"from": case.status, "to": next_status,
                          "resolution": resolution},
            )
        return updated

    def add_comment(self, public_id: str, *, actor_id: int, body: str) -> CaseDetail:
        case = self.repository.get(public_id)
        if not case:
            raise LookupError("Case not found.")
        self.repository.add_event(
            case.id, actor_id=actor_id, kind="comment", body=body
        )
        return self.repository.get(public_id)

    def link_report(self, public_id: str, *, report_id: int, actor_id: int) -> bool:
        case = self.repository.get(public_id)
        if not case:
            raise LookupError("Case not found.")
        linked = self.repository.link_report(case.id, report_id, actor_id)
        if linked:
            self.repository.add_event(
                case.id, actor_id=actor_id, kind="report_linked",
                metadata={"report_id": report_id},
            )
        return linked
