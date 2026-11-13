"""Case lifecycle and timeline orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .repository import CaseRepository
from .schemas import CaseDetail, CasePriority, CaseResolution, CaseStatus


class InvalidTransition(ValueError):
    pass


class PermissionDenied(InvalidTransition, PermissionError):
    """The transition is valid but the actor lacks ``cases:manage``.

    Multiple inheritance lets this satisfy both contracts at once: callers
    that treat any illegal move as ``InvalidTransition`` still catch it, and
    callers that gate on ``PermissionError`` do too. Because it subclasses
    ``ValueError``, route layers must catch ``PermissionDenied`` /
    ``PermissionError`` *before* ``ValueError`` or a permission failure will
    be reported as a validation error.
    """


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
ENTITY_TYPES = ("domain", "client", "query")
PRIORITIES = {p.value for p in CasePriority}
RESOLUTIONS = {r.value for r in CaseResolution}


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
        if next_status == "resolved" and resolution not in RESOLUTIONS:
            raise ValueError(f"Invalid resolution '{resolution}'.")
        if next_status in MANAGE_ONLY_TARGETS or current in MANAGE_ONLY_SOURCES:
            if not can_manage:
                raise PermissionDenied("This transition requires cases:manage.")

    def create(self, *, title, description, priority, entity_type,
               entity_value, created_by, assigned_to=None) -> CaseDetail:
        if priority not in PRIORITIES:
            raise ValueError(f"Invalid priority '{priority}'.")
        if entity_type is not None and entity_type not in ENTITY_TYPES:
            raise ValueError(f"Invalid entity type '{entity_type}'.")
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

        if "priority" in payload and payload["priority"] not in PRIORITIES:
            raise ValueError(f"Invalid priority '{payload['priority']}'.")
        if payload.get("resolution") is not None and payload["resolution"] not in RESOLUTIONS:
            raise ValueError(f"Invalid resolution '{payload['resolution']}'.")

        next_status = payload.get("status", case.status)
        resolution = payload.get("resolution", case.resolution)

        if next_status != case.status:
            self.validate_transition(
                current=case.status, next_status=next_status,
                resolution=resolution, can_manage=can_manage,
            )

        fields = dict(payload)
        if next_status == "resolved" and case.status != "resolved":
            fields["resolved_by"] = actor_id
            fields["resolved_at"] = datetime.now(timezone.utc)
        if next_status == "closed" and case.status != "closed":
            fields["closed_at"] = datetime.now(timezone.utc)
        if case.status in ("resolved", "closed") and next_status == "investigating":
            fields["closed_at"] = None
            fields["resolved_by"] = None
            fields["resolved_at"] = None

        events = []
        if next_status != case.status:
            events.append((
                "status_changed",
                {"from": case.status, "to": next_status, "resolution": resolution},
            ))
        if "assigned_to" in payload and payload["assigned_to"] != case.assigned_to:
            events.append((
                "assigned",
                {"from": case.assigned_to, "to": payload["assigned_to"]},
            ))
        if "priority" in payload and payload["priority"] != case.priority:
            events.append((
                "priority_changed",
                {"from": case.priority, "to": payload["priority"]},
            ))
        if "resolution" in payload and payload["resolution"] != case.resolution:
            events.append((
                "resolution_set",
                {"from": case.resolution, "to": payload["resolution"]},
            ))
        elif next_status == "resolved" and case.status != "resolved":
            events.append((
                "resolution_set",
                {"from": case.resolution, "to": resolution},
            ))

        if events:
            updated = self.repository.update_with_events(
                public_id, fields, actor_id=actor_id, events=events,
            )
        else:
            updated = self.repository.update(public_id, fields)
        if not updated:
            raise LookupError("Case not found.")
        return updated

    def add_comment(self, public_id: str, *, actor_id: int, body: str) -> CaseDetail:
        case = self.repository.get(public_id)
        if not case:
            raise LookupError("Case not found.")
        self.repository.add_event(
            case.id, actor_id=actor_id, kind="comment", body=body
        )
        return self.repository.get(public_id)

    def link_report(self, public_id: str, *, report_id: int, actor_id: int,
                    report_public_id: Optional[str] = None) -> bool:
        case = self.repository.get(public_id)
        if not case:
            raise LookupError("Case not found.")
        metadata = (
            {"report_public_id": report_public_id}
            if report_public_id is not None
            else {"report_id": report_id}
        )
        return self.repository.link_report_with_event(
            case.id, report_id, actor_id,
            actor_id=actor_id, metadata=metadata,
        )
