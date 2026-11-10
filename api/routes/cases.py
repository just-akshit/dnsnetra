"""Case/ticket API."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from api.audit import AuditAction, log_audit_event
from api.auth import get_user_by_id
from api.rbac import has_permission, require_permission
from api.schemas.cases import (
    CaseCommentRequest, CaseCreateRequest, CaseDetail, CaseReportLinkRequest,
    CaseSummary, CaseUpdateRequest,
)
from api.schemas.common import PaginatedResponse
from cases.repository import CaseRepository
from cases.service import CaseService, InvalidTransition, PermissionDenied
from reporting.report_repository import ReportRepository

router = APIRouter(prefix="/api/v1/cases", tags=["Cases"])


def _audit(action, request, user, public_id, **metadata):
    log_audit_event(
        action=action, user_id=user["id"],
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        target_type="case", target_id=public_id, metadata=metadata,
    )


@router.post("", response_model=CaseDetail, status_code=201)
def create_case(
    payload: CaseCreateRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("cases:write")),
):
    if payload.assigned_to is not None:
        if (payload.assigned_to != current_user["id"]
                and not has_permission(current_user["role"], "cases:manage")):
            raise HTTPException(
                status_code=403,
                detail="Assigning a case to another user requires cases:manage.",
            )
        if get_user_by_id(payload.assigned_to) is None:
            raise HTTPException(status_code=400, detail="Assignee not found.")

    report_id: Optional[int] = None
    if payload.report_id:
        report = ReportRepository().get(payload.report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="Report not found.")
        if report.case_public_id is not None:
            raise HTTPException(
                status_code=409, detail="Report is already linked to a case."
            )
        report_id = ReportRepository().get_db_id(payload.report_id)

    try:
        case = CaseService().create(
            title=payload.title, description=payload.description,
            priority=payload.priority, entity_type=payload.entity_type,
            entity_value=payload.entity_value, created_by=current_user["id"],
            assigned_to=payload.assigned_to,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Audit the created case before the optional link so a link failure cannot
    # leave an unaudited case behind.
    _audit(AuditAction.CASE_CREATED, request, current_user, case.public_id,
           entity=payload.entity_value, priority=payload.priority,
           report=payload.report_id)

    if report_id is not None:
        try:
            CaseService().link_report(
                case.public_id, report_id=report_id, actor_id=current_user["id"],
                report_public_id=payload.report_id,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        case = CaseRepository().get(case.public_id)

    return case


@router.get("", response_model=PaginatedResponse[CaseSummary])
def list_cases(
    status_filter: Optional[str] = Query(None, alias="status"),
    priority: Optional[str] = Query(None),
    entity: Optional[str] = Query(None),
    unassigned: bool = Query(False),
    assigned_to_me: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: dict[str, Any] = Depends(require_permission("cases:read")),
):
    total, items = CaseRepository().list(
        status=status_filter, priority=priority, entity=entity,
        unassigned=unassigned,
        assigned_to=current_user["id"] if assigned_to_me else None,
        limit=limit, offset=offset,
    )
    return PaginatedResponse[CaseSummary](
        total=total, limit=limit, offset=offset,
        has_more=offset + len(items) < total, items=items,
    )


@router.get("/{public_id}", response_model=CaseDetail)
def get_case(public_id: str,
             current_user: dict[str, Any] = Depends(require_permission("cases:read"))):
    case = CaseRepository().get(public_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


@router.patch("/{public_id}", response_model=CaseDetail)
def update_case(
    public_id: str,
    payload: CaseUpdateRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("cases:write")),
):
    can_manage = has_permission(current_user["role"], "cases:manage")
    case = CaseRepository().get(public_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    data = payload.model_dump(exclude_unset=True)
    if "assigned_to" in data and data["assigned_to"] not in (None, current_user["id"]) and not can_manage:
        raise HTTPException(status_code=403, detail="Reassigning a case requires cases:manage.")
    if case.assigned_to not in (None, current_user["id"]) and not can_manage:
        raise HTTPException(status_code=403, detail="Only the assignee can update this case.")
    if data.get("assigned_to") is not None and get_user_by_id(data["assigned_to"]) is None:
        raise HTTPException(status_code=400, detail="Assignee not found.")

    try:
        updated = CaseService().update(
            public_id, actor_id=current_user["id"], can_manage=can_manage, payload=data
        )
    except PermissionDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _audit(AuditAction.CASE_UPDATED, request, current_user, public_id,
           fields=list(data.keys()), status=updated.status)
    if "assigned_to" in data and data["assigned_to"] != case.assigned_to:
        _audit(AuditAction.CASE_ASSIGNED, request, current_user, public_id,
               **{"from": case.assigned_to, "to": data["assigned_to"]})
    resolution_changed = (
        "resolution" in data and data["resolution"] != case.resolution
    )
    if (updated.status == "resolved" and case.status != "resolved") or resolution_changed:
        _audit(AuditAction.CASE_RESOLVED, request, current_user, public_id,
               resolution=updated.resolution)
    if updated.status == "closed" and case.status != "closed":
        _audit(AuditAction.CASE_CLOSED, request, current_user, public_id)
    return updated


@router.post("/{public_id}/comments", response_model=CaseDetail)
def comment_case(
    public_id: str,
    payload: CaseCommentRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("cases:write")),
):
    try:
        case = CaseService().add_comment(public_id, actor_id=current_user["id"], body=payload.body)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    _audit(AuditAction.CASE_UPDATED, request, current_user, public_id, comment=True)
    return case


@router.post("/{public_id}/reports", response_model=CaseDetail)
def link_report(
    public_id: str,
    payload: CaseReportLinkRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("cases:write")),
):
    case = CaseRepository().get(public_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    report_id = ReportRepository().get_db_id(payload.report_public_id)
    if report_id is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    try:
        CaseService().link_report(
            public_id, report_id=report_id, actor_id=current_user["id"],
            report_public_id=payload.report_public_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    _audit(AuditAction.CASE_UPDATED, request, current_user, public_id,
           linked_report=payload.report_public_id)
    return CaseRepository().get(public_id)
