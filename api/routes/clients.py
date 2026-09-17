"""
api/routes/clients.py
=====================
Client collection and detail endpoints:
- GET /api/v1/clients
- GET /api/v1/clients/{client_ip}
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import get_current_user
from api.schemas import (
    ClientSummaryItem,
    PaginatedResponse,
)
from investigation.schemas import (
    ClientDossier,
    EntityNotFoundError,
    InvalidEntityError,
)
from investigation.service import InvestigationService
from reporting.service import ReportingService
from time_engine import resolve_time_range

logger = logging.getLogger("api_clients")

router = APIRouter(prefix="/api/v1/clients", tags=["Clients"])


def _check_no_temporal_params(window: Optional[str], start_time: Optional[str], end_time: Optional[str]) -> None:
    """Reject unsupported temporal parameters on investigation/detail routes."""
    if any(p is not None for p in (window, start_time, end_time)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Client detail dossiers are lifetime profiles with recent query previews in Phase 2D. Temporal query parameters are not supported.",
        )


@router.get(
    "",
    response_model=PaginatedResponse[ClientSummaryItem],
    summary="List and rank clients",
    description="Paginated list of client IP endpoints ranked by query volume with canonical pagination and optional temporal filtering.",
)
def list_clients(
    limit: int = Query(50, ge=1, le=1000, description="Max items to return"),
    offset: int = Query(0, ge=0, description="Offset index"),
    page: Optional[int] = Query(None, ge=1, description="Legacy page number alias"),
    page_size: Optional[int] = Query(None, ge=1, le=1000, description="Legacy page size alias"),
    search: Optional[str] = Query(None, description="Filter by client IP substring"),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> PaginatedResponse[ClientSummaryItem]:
    """Thin adapter over ReportingService.get_top_clients."""
    eff_limit = page_size if (page_size is not None and page_size >= 1) else limit
    eff_offset = ((page - 1) * eff_limit) if (page is not None and page >= 1) else offset

    has_temporal = any(p is not None for p in (window, start_time, end_time))
    tr = None
    if has_temporal:
        try:
            tr = resolve_time_range(window=window, start_time=start_time, end_time=end_time)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    service = ReportingService()
    result = service.get_top_clients(
        limit=eff_limit,
        offset=eff_offset,
        time_range=tr,
    )

    items = result.items
    if search and search.strip():
        term = search.strip()
        items = [c for c in items if term in c.client_ip]

    return PaginatedResponse[ClientSummaryItem](
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        has_more=result.has_more,
        items=items,
    )


@router.get(
    "/{client_ip}",
    response_model=ClientDossier,
    summary="Get client forensic detail",
    description="360-degree client forensic dossier backed by authoritative PostgreSQL client profiles, top destinations, threat activity, and recent events.",
)
def get_client_detail(
    client_ip: str,
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> ClientDossier:
    """Thin adapter delegating to InvestigationService.get_client_dossier."""
    _check_no_temporal_params(window, start_time, end_time)

    service = InvestigationService()
    try:
        return service.get_client_dossier(client_ip)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidEntityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
