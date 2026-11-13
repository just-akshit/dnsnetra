"""
Daily Review and Reviewed Clean Domain Models
============================================
Data structures and enumerations for managing the lifecycle of unresolved
and reviewed-clean domains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class ReviewStatus(str, Enum):
    REVIEW_NEEDED = "review_needed"
    PROCESSING = "processing"
    MALICIOUS = "malicious"
    CLEAN = "clean"
    EXTERNAL_LOOKUP_FAILED = "external_lookup_failed"
    ERROR = "error"


class DecisionProvenance(str, Enum):
    L1_CACHE = "L1_CACHE"
    LOCAL_REPUTATION = "LOCAL_REPUTATION"
    LOCAL_TRUSTED = "LOCAL_TRUSTED"
    LOCAL_MALICIOUS_FEED = "LOCAL_MALICIOUS_FEED"
    LOCAL_REVIEWED_CLEAN = "LOCAL_REVIEWED_CLEAN"
    HEURISTIC = "HEURISTIC"
    VIRUSTOTAL = "VIRUSTOTAL"
    OTX = "OTX"
    VT_OTX_CORRELATION = "VT_OTX_CORRELATION"
    DAILY_REVIEW = "DAILY_REVIEW"
    ADMIN_REVIEW = "ADMIN_REVIEW"
    EXTERNAL_LOOKUP_FAILED = "EXTERNAL_LOOKUP_FAILED"


@dataclass(frozen=True)
class DailyReviewRecord:
    domain: str
    status: str = ReviewStatus.REVIEW_NEEDED.value
    first_seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_checked_at: Optional[datetime] = None
    next_check_at: Optional[datetime] = None
    review_count: int = 1
    review_reason: Optional[str] = None
    vt_result: Optional[dict[str, Any]] = None
    otx_result: Optional[dict[str, Any]] = None
    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @property
    def reason(self) -> Optional[str]:
        return self.review_reason

    @property
    def is_due(self) -> bool:
        """Check if this domain is currently due for re-investigation."""
        if self.next_check_at is None:
            return True
        now = datetime.now(timezone.utc)
        target = self.next_check_at
        if target.tzinfo is None:
            target = target.replace(tzinfo=timezone.utc)
        return target <= now


    @classmethod
    def from_row(cls, row: dict[str, Any]) -> DailyReviewRecord:
        """Create a DailyReviewRecord from a database row dictionary."""
        return cls(
            id=row.get("id"),
            domain=row["domain"],
            status=row["status"],
            first_seen_at=row["first_seen_at"],
            last_seen_at=row["last_seen_at"],
            last_checked_at=row.get("last_checked_at"),
            next_check_at=row.get("next_check_at"),
            review_count=row.get("review_count", 1),
            review_reason=row.get("review_reason"),
            vt_result=row.get("vt_result"),
            otx_result=row.get("otx_result"),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )


@dataclass(frozen=True)
class ReviewedCleanRecord:
    domain: str
    verification_source: str = "online_correlation"
    verified_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    review_count: int = 1
    vt_summary: Optional[dict[str, Any]] = None
    otx_summary: Optional[dict[str, Any]] = None
    status: str = "clean"
    id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    @property
    def verified_clean_at(self) -> datetime:
        return self.verified_at

    @property
    def last_observed_at(self) -> Optional[datetime]:
        return self.updated_at or self.verified_at

    @classmethod
    def from_row(cls, row: dict[str, Any]) -> ReviewedCleanRecord:
        """Create a ReviewedCleanRecord from a database row dictionary."""
        return cls(
            id=row.get("id"),
            domain=row["domain"],
            verification_source=row.get("verification_source", "online_correlation"),
            verified_at=row.get("verified_at", datetime.now(timezone.utc)),
            review_count=row.get("review_count", 1),
            vt_summary=row.get("vt_summary"),
            otx_summary=row.get("otx_summary"),
            status=row.get("status", "clean"),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )
