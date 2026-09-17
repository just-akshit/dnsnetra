"""
api/routes/domains.py
=====================
Domain collection and detail endpoints:
- GET /api/v1/domains
- GET /api/v1/domains/{domain}
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import get_current_user
from api.schemas import (
    CanonicalVerdict,
    DomainSummaryItem,
    PaginatedResponse,
)
from investigation.schemas import (
    DomainDossier,
    EntityNotFoundError,
    InvalidEntityError,
)
from investigation.service import InvestigationService
from reporting.service import ReportingService
from time_engine import resolve_time_range

logger = logging.getLogger("api_domains")

router = APIRouter(prefix="/api/v1/domains", tags=["Domains"])


def _check_no_temporal_params(window: Optional[str], start_time: Optional[str], end_time: Optional[str]) -> None:
    """Reject unsupported temporal parameters on investigation/detail routes."""
    if any(p is not None for p in (window, start_time, end_time)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Domain detail dossiers are lifetime profiles with recent query previews in Phase 2D. Temporal query parameters are not supported.",
        )


@router.get(
    "",
    response_model=PaginatedResponse[DomainSummaryItem],
    summary="List and rank domains",
    description="Paginated list of queried domains ranked by activity with optional canonical verdict filter and temporal window.",
)
def list_domains(
    limit: int = Query(50, ge=1, le=1000, description="Max items to return"),
    offset: int = Query(0, ge=0, description="Offset index"),
    page: Optional[int] = Query(None, ge=1, description="Legacy page number alias"),
    page_size: Optional[int] = Query(None, ge=1, le=1000, description="Legacy page size alias"),
    verdict: Optional[str] = Query(None, description="Canonical verdict filter (Benign, Malicious, Review Needed, Unknown)"),
    label: Optional[str] = Query(None, description="Verdict filter alias"),
    search: Optional[str] = Query(None, description="Domain name search prefix/substring"),
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> PaginatedResponse[DomainSummaryItem]:
    """Thin adapter over ReportingService.get_top_domains."""
    eff_limit = page_size if (page_size is not None and page_size >= 1) else limit
    eff_offset = ((page - 1) * eff_limit) if (page is not None and page >= 1) else offset

    verdict_param = verdict or label
    canon_verdict: Optional[str] = None
    if verdict_param and verdict_param.strip() and verdict_param.strip().lower() != "all":
        canon_verdict = CanonicalVerdict.from_str(verdict_param).value

    has_temporal = any(p is not None for p in (window, start_time, end_time))
    tr = None
    if has_temporal:
        try:
            tr = resolve_time_range(window=window, start_time=start_time, end_time=end_time)
        except Exception as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    service = ReportingService()
    result = service.get_top_domains(
        limit=eff_limit,
        offset=eff_offset,
        verdict_filter=canon_verdict,
        time_range=tr,
    )

    items = result.items
    if search and search.strip():
        term = search.strip().lower()
        items = [d for d in items if term in d.domain.lower()]

    return PaginatedResponse[DomainSummaryItem](
        total=result.total,
        limit=result.limit,
        offset=result.offset,
        has_more=result.has_more,
        items=items,
    )


@router.get(
    "/{domain}",
    response_model=DomainDossier,
    summary="Get domain forensic detail",
    description="360-degree domain forensic dossier backed by authoritative PostgreSQL domain profiles, TI context, and recent events.",
)
def get_domain_detail(
    domain: str,
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> DomainDossier:
    """Thin adapter delegating to InvestigationService.get_domain_dossier."""
    _check_no_temporal_params(window, start_time, end_time)

    service = InvestigationService()
    try:
        return service.get_domain_dossier(domain)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidEntityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
