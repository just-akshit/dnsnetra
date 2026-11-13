"""Case lifecycle rules without a database."""

from datetime import datetime, timezone

import pytest

from dnsnetra.domains.cases.schemas import CaseDetail, CasePriority, CaseResolution, CaseStatus
from dnsnetra.domains.cases.service import InvalidTransition, PermissionDenied, CaseService


@pytest.mark.parametrize("current,next_status", [
    ("open", "triaged"),
    ("triaged", "investigating"),
    ("investigating", "awaiting_info"),
    ("awaiting_info", "resolved"),
    ("resolved", "closed"),
])
def test_allowed_transitions(current, next_status):
    CaseService.validate_transition(
        current=current,
        next_status=next_status,
        resolution="true_positive" if next_status == "resolved" else None,
        can_manage=True,
    )


@pytest.mark.parametrize("current,next_status", [
    ("open", "resolved"),
    ("closed", "investigating"),
    ("open", "awaiting_info"),
])
def test_invalid_transitions(current, next_status):
    with pytest.raises(InvalidTransition):
        CaseService.validate_transition(
            current=current,
            next_status=next_status,
            resolution="benign",
            can_manage=False,
        )


def test_resolving_requires_a_resolution():
    with pytest.raises(ValueError):
        CaseService.validate_transition(
            current="investigating", next_status="resolved",
            resolution=None, can_manage=True,
        )


def test_closing_requires_manage():
    with pytest.raises(PermissionError):
        CaseService.validate_transition(
            current="resolved", next_status="closed",
            resolution=None, can_manage=False,
        )


def test_reopening_closed_requires_manage():
    with pytest.raises(PermissionError):
        CaseService.validate_transition(
            current="closed", next_status="investigating",
            resolution=None, can_manage=False,
        )


def test_reopening_closed_is_allowed_with_manage():
    CaseService.validate_transition(
        current="closed", next_status="investigating",
        resolution=None, can_manage=True,
    )


def test_reopening_closed_without_manage_raises_permission_denied():
    with pytest.raises(PermissionDenied):
        CaseService.validate_transition(
            current="closed", next_status="investigating",
            resolution=None, can_manage=False,
        )


def _case(**overrides):
    now = datetime.now(timezone.utc)
    data = dict(
        id=1,
        public_id="CASE-2026-000001",
        title="Suspicious domain",
        status="open",
        priority="medium",
        created_at=now,
        updated_at=now,
    )
    data.update(overrides)
    return CaseDetail(**data)


class FakeRepository:
    def __init__(self, case):
        self.case = case
        self.calls = []

    def get(self, public_id):
        return self.case

    def update(self, public_id, fields):
        self.calls.append(("update", fields))
        return self.case

    def update_with_event(self, public_id, fields, *, actor_id, kind, metadata=None):
        self.calls.append(("update_with_event", fields, kind, metadata))
        return self.case

    def update_with_events(self, public_id, fields, *, actor_id, events):
        self.calls.append(("update_with_events", fields, events))
        return self.case

    def link_report_with_event(self, case_id, report_id, linked_by, *,
                               actor_id, metadata=None):
        self.calls.append(("link_report_with_event", report_id, metadata))
        return True


def test_priority_change_appends_an_event_without_status_change():
    case = _case(status="resolved")
    repository = FakeRepository(case)

    CaseService(repository).update(
        case.public_id, actor_id=2, can_manage=True,
        payload={"priority": "high"},
    )

    (call, fields, events), = repository.calls
    assert call == "update_with_events"
    assert fields == {"priority": "high"}
    assert events == [("priority_changed", {"from": "medium", "to": "high"})]


def test_reopening_clears_resolution_and_close_timestamps():
    now = datetime.now(timezone.utc)
    case = _case(status="closed", closed_at=now, resolved_at=now, resolved_by=3)
    repository = FakeRepository(case)

    CaseService(repository).update(
        case.public_id, actor_id=2, can_manage=True,
        payload={"status": "investigating"},
    )

    (call, fields, events), = repository.calls
    assert call == "update_with_events"
    assert fields == {
        "status": "investigating",
        "closed_at": None,
        "resolved_by": None,
        "resolved_at": None,
    }
    assert events == [(
        "status_changed",
        {"from": "closed", "to": "investigating", "resolution": None},
    )]


def test_create_rejects_unknown_entity_type():
    with pytest.raises(ValueError):
        CaseService(FakeRepository(_case())).create(
            title="t", description=None, priority="medium",
            entity_type="ip", entity_value="192.0.2.1", created_by=1,
        )


def test_update_rejects_unknown_priority():
    case = _case()
    with pytest.raises(ValueError):
        CaseService(FakeRepository(case)).update(
            case.public_id, actor_id=2, can_manage=True,
            payload={"priority": "urgent"},
        )


def test_link_report_uses_atomic_repository_call():
    case = _case()
    repository = FakeRepository(case)

    linked = CaseService(repository).link_report(
        case.public_id, report_id=9, actor_id=2,
        report_public_id="RPT-2026-000001",
    )

    assert linked is True
    assert repository.calls == [
        ("link_report_with_event", 9, {"report_public_id": "RPT-2026-000001"}),
    ]


def test_assignment_change_appends_an_assigned_event():
    case = _case(assigned_to=None)
    repository = FakeRepository(case)

    CaseService(repository).update(
        case.public_id, actor_id=2, can_manage=True,
        payload={"assigned_to": 9},
    )

    (call, fields, events), = repository.calls
    assert call == "update_with_events"
    assert fields == {"assigned_to": 9}
    assert events == [("assigned", {"from": None, "to": 9})]


def test_resolving_appends_status_and_resolution_events():
    case = _case(status="investigating")
    repository = FakeRepository(case)

    CaseService(repository).update(
        case.public_id, actor_id=2, can_manage=True,
        payload={"status": "resolved", "resolution": "true_positive"},
    )

    (call, fields, events), = repository.calls
    assert call == "update_with_events"
    assert fields["status"] == "resolved"
    assert fields["resolved_by"] == 2
    assert ("status_changed", {
        "from": "investigating", "to": "resolved", "resolution": "true_positive",
    }) in events
    assert ("resolution_set", {
        "from": None, "to": "true_positive",
    }) in events
