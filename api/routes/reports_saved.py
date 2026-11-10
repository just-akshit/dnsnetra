"""Saved reports: create, list, review, archive, link to a case."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from api.audit import AuditAction, log_audit_event
from api.rbac import require_permission
from api.schemas.reports_saved import (
    ReportCreateRequest, ReportListResponse, ReportReviewRequest,
    SavedReportDetail,
)
from investigation.schemas import InvalidEntityError
from reporting.exporters import build_xlsx, safe_filename_part, snapshot_csv_chunks
from reporting.report_schemas import ReportStatus
from reporting.report_service import ReportService
from reporting.schemas import ReportingValidationError
from time_engine import InvalidTimeRangeError, TimeEngineValidationError

router = APIRouter(prefix="/api/v1/reports/saved", tags=["Saved Reports"])

# Expected client-side validation failures; anything else is a server error.
_CREATE_VALIDATION_ERRORS = (
    InvalidEntityError,
    ReportingValidationError,
    InvalidTimeRangeError,
    TimeEngineValidationError,
    ValueError,
)


def _audit(action, request, user, public_id, **metadata):
    log_audit_event(
        action=action,
        user_id=user["id"],
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        target_type="report",
        target_id=public_id,
        metadata=metadata,
    )


@router.post("", response_model=SavedReportDetail, status_code=201)
def create_report(
    payload: ReportCreateRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("reports:write")),
):
    service = ReportService()
    try:
        report = service.create(
            kind=payload.kind.value,
            entity=payload.entity,
            window=payload.window,
            start_time=payload.start_time,
            end_time=payload.end_time,
            filters=payload.filters,
            title=payload.title,
            user_id=current_user["id"],
            refresh=payload.refresh,
        )
    except _CREATE_VALIDATION_ERRORS as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _audit(AuditAction.REPORT_CREATED, request, current_user, report.public_id,
           kind=report.kind, entity=report.entity_value)
    return report


@router.get("", response_model=ReportListResponse)
def list_reports(
    status_filter: Optional[str] = Query(None, alias="status"),
    kind: Optional[str] = Query(None),
    entity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: dict[str, Any] = Depends(require_permission("reports:read")),
):
    total, items = ReportService().list_reports(
        status=status_filter, kind=kind, entity=entity,
        limit=limit, offset=offset,
    )
    return ReportListResponse(total=total, limit=limit, offset=offset, items=items)


@router.get("/{public_id}", response_model=SavedReportDetail)
def get_report(
    public_id: str,
    current_user: dict[str, Any] = Depends(require_permission("reports:read")),
):
    report = ReportService().get_report(public_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@router.patch("/{public_id}/review", response_model=SavedReportDetail)
def review_report(
    public_id: str,
    payload: ReportReviewRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("reports:write")),
):
    service = ReportService()
    try:
        report = service.review_report(
            public_id,
            status=payload.status.value,
            verdict=payload.verdict,
            conclusion=payload.conclusion,
            reviewer_id=current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    _audit(AuditAction.REPORT_REVIEWED, request, current_user, public_id,
           status=payload.status.value, verdict=payload.verdict)
    return report


@router.post("/{public_id}/archive", status_code=204)
def archive_report(
    public_id: str,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("reports:write")),
):
    if not ReportService().archive_report(public_id):
        raise HTTPException(status_code=404, detail="Report not found.")
    _audit(AuditAction.REPORT_ARCHIVED, request, current_user, public_id)
    return None


@router.post("/{public_id}/export")
def export_report(
    public_id: str,
    request: Request,
    format: str = Query("csv", pattern="^(csv|xlsx)$"),
    current_user: dict[str, Any] = Depends(require_permission("reports:export")),
):
    """Export a saved report's snapshot as CSV or XLSX."""
    report = ReportService().get_report(public_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    _audit(AuditAction.REPORT_EXPORTED, request, current_user, public_id, format=format)

    filename = f"dnsnetra_{safe_filename_part(public_id)}.{format}"
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Cache-Control": "no-store",
    }
    if format == "xlsx":
        return Response(
            content=build_xlsx(report.snapshot),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers=headers,
        )
    return StreamingResponse(
        snapshot_csv_chunks(report.snapshot),
        media_type="text/csv",
        headers=headers,
    )
