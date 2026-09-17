"""
Daily Review Queue API Routes
==============================
Endpoints for inspecting, querying, triggering, and overriding daily review domains.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from labeler.intel.daily_review import (
    DailyReviewWorker,
    ReviewStatus,
    get_review_domain,
    get_reviewed_clean_domain,
    get_daily_review_stats,
    list_daily_review_domains,
    promote_to_clean,
    promote_to_malicious,
)
from labeler.intel.database import normalize_domain
from labeler.intel.reputation import get_domain as get_reputation_domain
from ..auth import get_current_user, require_admin

logger = logging.getLogger("api_daily_review")

router = APIRouter(prefix="/api/v1/daily-review", tags=["Daily Review"])


class DomainListItem(BaseModel):
    id: int
    domain: str
    status: str
    reason: Optional[str] = None
    next_check_at: Optional[datetime] = None
    review_count: int
    last_seen_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    is_due: bool


class DailyReviewListResponse(BaseModel):
    total: int = Field(..., description="Total items matching filter criteria")
    limit: int = Field(..., ge=1, le=500, description="Max items requested")
    offset: int = Field(..., ge=0, description="Index offset of first item")
    has_more: bool = Field(..., description="Whether additional items exist beyond limit+offset")
    items: list[DomainListItem] = Field(default_factory=list, description="Canonical page items")
    domains: list[DomainListItem] = Field(default_factory=list, description="Compatibility alias for items")


class DailyReviewStatsResponse(BaseModel):
    total: int
    review_needed: int
    clean: int
    malicious: int
    processing: int
    due_for_review: int


class DomainDossierResponse(BaseModel):
    domain: str
    normalized_domain: str
    daily_review_record: Optional[dict[str, Any]] = None
    reviewed_clean_record: Optional[dict[str, Any]] = None
    reputation_record: Optional[dict[str, Any]] = None
    effective_status: str


class VerdictOverrideRequest(BaseModel):
    verdict: str = Field(..., description="Either 'clean' or 'malicious'")
    reason: str = Field(..., description="Explanation for admin verdict override")
    confidence: Optional[float] = Field(default=1.0, ge=0.0, le=1.0)


@router.get("", response_model=DailyReviewListResponse)
def list_domains(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (review_needed, clean, malicious, etc.)"),
    search: Optional[str] = Query(None, description="Domain prefix / substring search"),
    is_due: Optional[bool] = Query(None, description="Filter only domains currently due for check"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    page: Optional[int] = Query(None, ge=1, description="Legacy page number alias"),
    page_size: Optional[int] = Query(None, ge=1, le=500, description="Legacy page size alias"),
    user: dict[str, Any] = Depends(get_current_user),
):
    """List domains in the daily review system with filtering and canonical pagination."""
    eff_limit = page_size if (page_size is not None and page_size >= 1) else limit
    eff_offset = ((page - 1) * eff_limit) if (page is not None and page >= 1) else offset

    status_enum = None
    if status_filter:
        try:
            status_enum = ReviewStatus(status_filter.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status filter '{status_filter}'. Allowed: {[s.value for s in ReviewStatus]}",
            )

    records, total = list_daily_review_domains(
        status=status_enum,
        search=search,
        is_due=is_due,
        limit=eff_limit,
        offset=eff_offset,
    )

    items = [
        DomainListItem(
            id=r.id or 0,
            domain=r.domain,
            status=r.status.value if hasattr(r.status, "value") else str(r.status),
            reason=r.reason,
            next_check_at=r.next_check_at,
            review_count=r.review_count,
            last_seen_at=r.last_seen_at,
            created_at=r.created_at,
            is_due=r.is_due,
        )
        for r in records
    ]

    has_more = (eff_offset + len(items)) < total

    return DailyReviewListResponse(
        total=total,
        limit=eff_limit,
        offset=eff_offset,
        has_more=has_more,
        items=items,
        domains=items,
    )


@router.get("/stats", response_model=DailyReviewStatsResponse)
def get_stats(user: dict[str, Any] = Depends(get_current_user)):
    """Retrieve operational statistics of the daily review queue."""
    stats = get_daily_review_stats()
    return DailyReviewStatsResponse(
        total=stats["total"],
        review_needed=stats["review_needed"],
        clean=stats["clean"],
        malicious=stats["malicious"],
        processing=stats["processing"],
        due_for_review=stats["due_for_review"],
    )


@router.get("/{domain}", response_model=DomainDossierResponse)
def get_domain_dossier(domain: str, user: dict[str, Any] = Depends(get_current_user)):
    """Retrieve complete intelligence dossier for a domain across all tiers."""
    canonical = normalize_domain(domain)
    if not canonical:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain name '{domain}'",
        )

    # 1. Daily Review record
    dr_record = get_review_domain(canonical)
    dr_dict = None
    if dr_record:
        dr_status = dr_record.status.value if hasattr(dr_record.status, "value") else str(dr_record.status)
        dr_dict = {
            "id": dr_record.id,
            "domain": dr_record.domain,
            "status": dr_status,
            "reason": dr_record.reason,
            "last_checked_at": dr_record.last_checked_at.isoformat() if dr_record.last_checked_at else None,
            "next_check_at": dr_record.next_check_at.isoformat() if dr_record.next_check_at else None,
            "review_count": dr_record.review_count,
            "vt_result": dr_record.vt_result,
            "otx_result": dr_record.otx_result,
            "is_due": dr_record.is_due,
            "last_seen_at": dr_record.last_seen_at.isoformat() if dr_record.last_seen_at else None,
            "created_at": dr_record.created_at.isoformat() if dr_record.created_at else None,
        }

    # 2. Reviewed Clean record
    clean_record = get_reviewed_clean_domain(canonical)
    clean_dict = None
    if clean_record:
        clean_dict = {
            "id": clean_record.id,
            "domain": clean_record.domain,
            "verified_clean_at": clean_record.verified_clean_at.isoformat() if clean_record.verified_clean_at else None,
            "verification_source": clean_record.verification_source,
            "vt_summary": clean_record.vt_summary,
            "otx_summary": clean_record.otx_summary,
            "last_observed_at": clean_record.last_observed_at.isoformat() if clean_record.last_observed_at else None,
        }

    # 3. Reputation record
    rep_record = get_reputation_domain(canonical)

    # Determine effective status
    effective = "UNKNOWN"
    if rep_record:
        effective = "MALICIOUS (Reputation DB)"
    elif clean_record:
        effective = "CLEAN (Reviewed Clean DB)"
    elif dr_record:
        dr_st = dr_record.status.value if hasattr(dr_record.status, "value") else str(dr_record.status)
        effective = f"DAILY_REVIEW ({dr_st.upper()})"

    return DomainDossierResponse(
        domain=domain,
        normalized_domain=canonical,
        daily_review_record=dr_dict,
        reviewed_clean_record=clean_dict,
        reputation_record=rep_record,
        effective_status=effective,
    )


@router.post("/{domain}/verdict")
def set_manual_verdict(
    domain: str,
    payload: VerdictOverrideRequest,
    admin: dict[str, Any] = Depends(require_admin),
):
    """Admin manual override to mark a domain Clean or Malicious."""
    canonical = normalize_domain(domain)
    if not canonical:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain name '{domain}'",
        )

    verdict_choice = payload.verdict.strip().lower()
    admin_tag = f"admin_override:{admin.get('email', 'admin')}"

    if verdict_choice == "clean":
        promote_to_clean(
            canonical,
            source=admin_tag,
            vt_summary={"override_by": admin.get("email"), "reason": payload.reason},
            otx_summary=None,
        )
        logger.info("Admin %s marked %s as CLEAN (reason: %s)", admin.get("email"), canonical, payload.reason)
        return {
            "success": True,
            "domain": canonical,
            "verdict": "CLEAN",
            "message": f"Domain {canonical} promoted to reviewed_clean_domains by admin.",
        }

    elif verdict_choice == "malicious":
        promote_to_malicious(
            canonical,
            metadata={
                "source": admin_tag,
                "confidence": payload.confidence or 1.0,
                "admin_reason": payload.reason,
                "admin_email": admin.get("email"),
            },
            vt_result={"override_by": admin.get("email"), "reason": payload.reason},
            otx_result=None,
        )
        logger.info("Admin %s marked %s as MALICIOUS (reason: %s)", admin.get("email"), canonical, payload.reason)
        return {
            "success": True,
            "domain": canonical,
            "verdict": "MALICIOUS",
            "message": f"Domain {canonical} promoted to reputation_domains by admin.",
        }

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verdict must be either 'clean' or 'malicious'.",
        )


@router.post("/{domain}/trigger")
def trigger_domain_review(
    domain: str,
    admin: dict[str, Any] = Depends(require_admin),
):
    """Trigger immediate online re-investigation for a domain in the daily review queue."""
    canonical = normalize_domain(domain)
    if not canonical:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain name '{domain}'",
        )

    from labeler.intel.correlation.engine import CorrelationEngine
    from labeler.config import LabelingConfig
    from labeler.intel.reputation import store_malicious_domain, get_domain

    config = LabelingConfig()
    engine = CorrelationEngine(
        config=config.get_online_ti_config(),
        db_store=store_malicious_domain,
        db_getter=get_domain,
    )
    worker = DailyReviewWorker(correlation_engine=engine)
    result = worker.process_domain_investigation(canonical)

    return {
        "success": True,
        "domain": canonical,
        "investigation_result": result,
        "message": f"Triggered investigation for {canonical}: outcome={result}",
    }
