"""Case lifecycle rules without a database."""

import pytest

from cases.schemas import CasePriority, CaseResolution, CaseStatus
from cases.service import InvalidTransition, CaseService


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
