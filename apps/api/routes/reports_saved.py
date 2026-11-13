"""Saved reports: create, list, review, archive, link to a case."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response, StreamingResponse

from dnsnetra.core.security.audit import AuditAction, log_audit_event
from dnsnetra.core.security.rate_limiter import enforce_search_rate_limit
from dnsnetra.core.security.rbac import has_permission, require_permission
from apps.api.schemas.reports_saved import (
    ReportCreateRequest, ReportListResponse, ReportReviewRequest,
    SavedReportDetail,
)
from dnsnetra.domains.investigations.schemas import InvalidEntityError
from dnsnetra.domains.reporting.exporters import (
    build_xlsx,
    export_filename,
    snapshot_csv_chunks,
)
from dnsnetra.domains.reporting.report_schemas import ReportStatus
from dnsnetra.domains.reporting.report_service import ReportService
from dnsnetra.domains.reporting.schemas import ReportingValidationError
from dnsnetra.domains.reporting.service import ReportingService
from dnsnetra.time_engine import InvalidTimeRangeError, TimeEngineValidationError

router = APIRouter(prefix="/api/v1/reports/saved", tags=["Saved Reports"])

# Event rows a query-set export may contain (same cap as the query-log export).
_EXPORT_ROW_CAP = 50_000
_QUERY_PAGE_SIZE = 1_000

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
    current = service.get_report(public_id)
    if not current:
        raise HTTPException(status_code=404, detail="Report not found.")

    # Only touch fields the caller actually supplied.
    updates = payload.model_dump(exclude_unset=True, mode="json")
    status = updates.get("status")

    # Reopening a reviewed report is a management action (spec 10.1).
    if (current.status == ReportStatus.REVIEWED.value
            and status is not None
            and status != ReportStatus.REVIEWED.value
            and not has_permission(current_user["role"], "cases:manage")):
        raise HTTPException(
            status_code=403,
            detail="Reopening a reviewed report requires cases:manage.",
        )

    try:
        report = service.review_report(
            public_id, updates=updates, reviewer_id=current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    _audit(AuditAction.REPORT_REVIEWED, request, current_user, public_id,
           status=status, verdict=updates.get("verdict"))
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


def _iso(value):
    return value.isoformat() if value else None


def _query_filters(report) -> dict:
    """Extract the stored query-set filters, dropping empty and 'all' verdicts."""
    filters = report.filters or {}
    verdict = filters.get("verdict")
    if verdict and str(verdict).strip().lower() in ("", "all"):
        verdict = None
    return {
        "client_ip": filters.get("client_ip") or None,
        "domain": filters.get("domain") or None,
        "verdict": verdict,
        "query_type": filters.get("query_type") or None,
        "search": filters.get("search") or None,
    }


def _report_metadata(report) -> dict:
    """Saved-report fields surfaced in the Summary and Assessment sheets."""
    return {
        "public_id": report.public_id,
        "title": report.title,
        "kind": report.kind,
        "status": report.status,
        "verdict": report.verdict,
        "conclusion": report.conclusion,
        "reviewed_by": report.reviewed_by,
        "reviewed_at": _iso(report.reviewed_at),
        "created_at": _iso(report.created_at),
        "window_start": _iso(report.window_start),
        "window_end": _iso(report.window_end),
        "row_count": report.row_count,
    }


def _collect_query_rows(service, query_filters, window_start, window_end) -> list[dict]:
    """Page through matching events up to the export cap for workbook output."""
    rows: list[dict] = []
    offset = 0
    while len(rows) < _EXPORT_ROW_CAP:
        page = service.get_queries(
            **query_filters,
            start_time=window_start,
            end_time=window_end,
            limit=min(_QUERY_PAGE_SIZE, _EXPORT_ROW_CAP - len(rows)),
            offset=offset,
        )
        for item in page.items:
            row = item.model_dump()
            row["verdict"] = row.pop("final_label", None)
            rows.append(row)
        if not page.has_more or not page.items:
            break
        offset += len(page.items)
    return rows


@router.post("/{public_id}/export")
def export_report(
    public_id: str,
    request: Request,
    format: str = Query("csv", pattern="^(csv|xlsx)$"),
    current_user: dict[str, Any] = Depends(require_permission("reports:export")),
):
    """Export a saved report as CSV or XLSX.

    Entity reports export their frozen snapshot; query-set reports re-run the
    stored filters against the live query log so the file contains real events.
    """
    enforce_search_rate_limit(request)

    report = ReportService().get_report(public_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    service = ReportingService()
    filters = report.filters or {}
    meta = _report_metadata(report)
    headers = {
        "Content-Disposition": f'attachment; filename="{export_filename(public_id, format)}"',
        "Cache-Control": "no-store",
    }
    xlsx_media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

    if report.kind == "query_set":
        query_filters = _query_filters(report)
        try:
            if format == "xlsx":
                rows = _collect_query_rows(
                    service, query_filters, report.window_start, report.window_end
                )
                exported = len(rows)
                _audit(
                    AuditAction.REPORT_EXPORTED, request, current_user, public_id,
                    format=format, row_count=report.row_count,
                    exported_rows=exported, filters=filters,
                )
                return Response(
                    content=build_xlsx(
                        report.snapshot, meta, queries=rows, exported_rows=exported
                    ),
                    media_type=xlsx_media_type,
                    headers=headers,
                )

            total = service.get_queries(
                **query_filters,
                start_time=report.window_start,
                end_time=report.window_end,
                limit=1,
            ).total
            exported = min(total, _EXPORT_ROW_CAP)
            stream = service.stream_queries_csv(
                **query_filters,
                start_time=report.window_start,
                end_time=report.window_end,
                limit=_EXPORT_ROW_CAP,
            )
        except ReportingValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        _audit(
            AuditAction.REPORT_EXPORTED, request, current_user, public_id,
            format=format, row_count=report.row_count,
            exported_rows=exported, filters=filters,
        )
        return StreamingResponse(stream, media_type="text/csv", headers=headers)

    # Entity snapshots are frozen at creation time.
    exported = len((report.snapshot.get("dossier") or {}).get("recent_queries") or [])
    _audit(
        AuditAction.REPORT_EXPORTED, request, current_user, public_id,
        format=format, row_count=report.row_count,
        exported_rows=exported, filters=filters,
    )
    if format == "xlsx":
        return Response(
            content=build_xlsx(report.snapshot, meta, exported_rows=exported),
            media_type=xlsx_media_type,
            headers=headers,
        )
    return StreamingResponse(
        snapshot_csv_chunks(report.snapshot, meta),
        media_type="text/csv",
        headers=headers,
    )
