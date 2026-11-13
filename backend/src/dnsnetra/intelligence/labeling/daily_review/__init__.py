"""
Daily Review Subsystem
======================
Lifecycle tracking and re-investigation management for unresolved domains.
"""

from .models import DailyReviewRecord, DecisionProvenance, ReviewedCleanRecord, ReviewStatus
from .repository import (
    DEFAULT_REVIEW_INTERVAL_DAYS,
    DEFAULT_RETRY_INTERVAL_HOURS,
    claim_due_reviews_for_processing,
    fetch_due_reviews_for_update,
    get_review_domain,
    get_reviewed_clean_domain,
    get_stats,
    list_domains,
    promote_to_clean,
    promote_to_malicious,
    record_api_failure,
    record_daily_review_observation,
    recover_stale_processing,
    upsert_review_needed,
)
from .scheduler import DailyReviewWorker

get_daily_review_stats = get_stats
list_daily_review_domains = list_domains

__all__ = [
    "DailyReviewRecord",
    "ReviewedCleanRecord",
    "ReviewStatus",
    "DecisionProvenance",
    "DEFAULT_REVIEW_INTERVAL_DAYS",
    "DEFAULT_RETRY_INTERVAL_HOURS",
    "get_review_domain",
    "get_reviewed_clean_domain",
    "record_daily_review_observation",
    "upsert_review_needed",
    "promote_to_clean",
    "promote_to_malicious",
    "record_api_failure",
    "claim_due_reviews_for_processing",
    "recover_stale_processing",
    "fetch_due_reviews_for_update",
    "list_domains",
    "get_stats",
    "DailyReviewWorker",
]
