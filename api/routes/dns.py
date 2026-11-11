"""DNS page: one row per queried domain."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.rbac import require_permission
from api.schemas import PaginatedResponse
from reporting.schemas import DnsDomainItem, ReportingValidationError
from reporting.service import ReportingService

router = APIRouter(prefix="/api/v1/dns", tags=["DNS"])


@router.get("/domains", response_model=PaginatedResponse[DnsDomainItem])
def list_dns_domains(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    search: Optional[str] = Query(None, description="Search full or registered domain"),
    sort: Optional[str] = Query(None),
    order: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(require_permission("queries:read")),
) -> PaginatedResponse[DnsDomainItem]:
    try:
        result = ReportingService().get_dns_domains(
            limit=limit,
            offset=offset,
            search=search.strip() if search and search.strip() else None,
            sort_by=sort or "last_seen",
            sort_order=order or "desc",
        )
    except ReportingValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    return PaginatedResponse[DnsDomainItem](
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        has_more=result.has_more,
        items=result.items,
    )
