"""
api/routes/investigation.py
===========================
Explicit investigation routes providing forensic dossiers:
- GET /api/v1/investigation/domains/{domain} (and /domain/{domain})
- GET /api/v1/investigation/clients/{client_ip} (and /client/{client_ip})
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from api.auth import get_current_user
from investigation.schemas import (
    ClientDossier,
    DomainDossier,
    EntityNotFoundError,
    InvalidEntityError,
)
from investigation.service import InvestigationService

logger = logging.getLogger("api_investigation")

router = APIRouter(prefix="/api/v1/investigation", tags=["Investigation"])


def _check_no_temporal_params(window: Optional[str], start_time: Optional[str], end_time: Optional[str]) -> None:
    """Reject unsupported temporal parameters on investigation routes."""
    if any(p is not None for p in (window, start_time, end_time)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Investigation dossiers are lifetime profile views with recent query previews in Phase 2D. Temporal query parameters are not supported.",
        )


# ---------------------------------------------------------------------------
# Domain Investigation
# ---------------------------------------------------------------------------

@router.get(
    "/domains/{domain}",
    response_model=DomainDossier,
    summary="Investigate domain entity (plural)",
    description="360-degree forensic dossier for a domain including profile, querying clients, local TI evidence, and recent events.",
)
def investigate_domain(
    domain: str,
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> DomainDossier:
    """Canonical domain investigation endpoint."""
    _check_no_temporal_params(window, start_time, end_time)

    service = InvestigationService()
    try:
        return service.get_domain_dossier(domain)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidEntityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/domain/{domain}",
    response_model=DomainDossier,
    summary="Investigate domain entity (singular alias)",
    description="Compatibility alias for domain investigation delegating to canonical implementation.",
    include_in_schema=False,
)
def investigate_domain_alias(
    domain: str,
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> DomainDossier:
    """Singular routing alias delegating to canonical domain investigation."""
    return investigate_domain(domain, window, start_time, end_time, current_user)


# ---------------------------------------------------------------------------
# Client Investigation
# ---------------------------------------------------------------------------

@router.get(
    "/clients/{client_ip}",
    response_model=ClientDossier,
    summary="Investigate client endpoint (plural)",
    description="360-degree forensic dossier for a client IP including profile, top destinations, threat activity, and recent events.",
)
def investigate_client(
    client_ip: str,
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> ClientDossier:
    """Canonical client investigation endpoint."""
    _check_no_temporal_params(window, start_time, end_time)

    service = InvestigationService()
    try:
        return service.get_client_dossier(client_ip)
    except EntityNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except InvalidEntityError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc


@router.get(
    "/client/{client_ip}",
    response_model=ClientDossier,
    summary="Investigate client endpoint (singular alias)",
    description="Compatibility alias for client investigation delegating to canonical implementation.",
    include_in_schema=False,
)
def investigate_client_alias(
    client_ip: str,
    window: Optional[str] = Query(None),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    current_user: dict[str, Any] = Depends(get_current_user),
) -> ClientDossier:
    """Singular routing alias delegating to canonical client investigation."""
    return investigate_client(client_ip, window, start_time, end_time, current_user)
