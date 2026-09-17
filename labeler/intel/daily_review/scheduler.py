"""
Daily Review Scheduler & Background Worker
=========================================
Identifies unresolved domains due for re-investigation:
    status = 'review_needed' AND next_check_at <= NOW()

Uses SELECT ... FOR UPDATE SKIP LOCKED for strict concurrency safety.
Bypasses heuristics on re-investigation (heuristics evaluate static lexical
features that do not change) and directly invokes Online Threat Intelligence
(VT + OTX via CorrelationEngine).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from ..correlation.engine import CorrelationEngine
from ..reputation.connection import get_connection
from .models import ReviewStatus
from .repository import (
    DEFAULT_REVIEW_INTERVAL_DAYS,
    DEFAULT_RETRY_INTERVAL_HOURS,
    claim_due_reviews_for_processing,
    fetch_due_reviews_for_update,
    promote_to_clean,
    promote_to_malicious,
    record_api_failure,
    recover_stale_processing,
    upsert_review_needed,
)

logger = logging.getLogger("daily_review_scheduler")

DEFAULT_STALE_TIMEOUT_MINUTES: int = 15


class DailyReviewWorker:
    """Processes due daily-review domains in safe, concurrent batches."""

    def __init__(
        self,
        correlation_engine: Optional[CorrelationEngine] = None,
        batch_size: int = 50,
        review_interval_days: int = DEFAULT_REVIEW_INTERVAL_DAYS,
        retry_interval_hours: int = DEFAULT_RETRY_INTERVAL_HOURS,
        stale_timeout_minutes: int = DEFAULT_STALE_TIMEOUT_MINUTES,
    ) -> None:
        self.engine = correlation_engine
        self.batch_size = batch_size
        self.review_interval_days = review_interval_days
        self.retry_interval_hours = retry_interval_hours
        self.stale_timeout_minutes = stale_timeout_minutes

    def process_domain_investigation(self, domain: str) -> str:
        """Run external online investigation (VT + OTX) for a due domain.

        Heuristics are explicitly bypassed here because lexical characteristics
        do not mutate over time.
        """
        logger.info("[DailyReview] Re-investigating due domain: %s", domain)

        if self.engine is None:
            raise RuntimeError("CorrelationEngine is not configured on DailyReviewWorker")

        try:
            decision = self.engine.evaluate(domain)
        except Exception as exc:
            logger.error("[DailyReview] API lookup failed for %s: %s", domain, exc)
            record_api_failure(domain, str(exc), retry_interval_hours=self.retry_interval_hours)
            return "api_failure"

        vt_res = None
        otx_res = None
        for pr in decision.provider_results:
            if "virustotal" in pr.provider.lower():
                vt_res = pr.raw_data or {"malicious": pr.malicious, "unavailable": pr.unavailable}
            elif "alienvault" in pr.provider.lower() or "otx" in pr.provider.lower():
                otx_res = pr.raw_data or {"malicious": pr.malicious, "unavailable": pr.unavailable}

        # Check if providers had API failures
        all_failed = (
            len(decision.provider_results) > 0
            and all(pr.unavailable for pr in decision.provider_results)
        )
        if all_failed:
            err = "; ".join(pr.error or "unavailable" for pr in decision.provider_results)
            logger.warning("[DailyReview] All providers failed for %s: %s", domain, err)
            record_api_failure(domain, err, retry_interval_hours=self.retry_interval_hours)
            return "api_failure"

        if decision.malicious:
            logger.info("[DailyReview] Domain %s confirmed MALICIOUS", domain)
            promote_to_malicious(
                domain,
                metadata={
                    "source": "daily_review_reinvestigation",
                    "confidence": decision.confidence,
                },
                vt_result=vt_res,
                otx_result=otx_res,
            )
            return "malicious"
        elif decision.has_intelligence:
            logger.info("[DailyReview] Domain %s confirmed CLEAN with evidence", domain)
            promote_to_clean(
                domain,
                source="daily_review_reinvestigation",
                vt_summary=vt_res,
                otx_summary=otx_res,
            )
            return "clean"
        else:
            logger.info(
                "[DailyReview] Domain %s still INCONCLUSIVE; postponing +%d days",
                domain,
                self.review_interval_days,
            )
            upsert_review_needed(
                domain,
                reason="Re-investigation inconclusive (no external threat intelligence)",
                vt_result=vt_res,
                otx_result=otx_res,
                interval_days=self.review_interval_days,
            )
            return "inconclusive"

    def run_once(self) -> int:
        """Fetch one batch of due domains, atomically claim them to 'processing',
        and process them outside the database transaction.

        Returns the number of processed domains.
        """
        claimed_records = claim_due_reviews_for_processing(
            batch_size=self.batch_size,
            stale_timeout_minutes=self.stale_timeout_minutes,
        )

        if not claimed_records:
            return 0

        logger.info("[DailyReview] Acquired %d due domains for review", len(claimed_records))
        processed = 0
        for record in claimed_records:
            domain = record.domain
            try:
                self.process_domain_investigation(domain)
                processed += 1
            except Exception as exc:
                logger.exception("[DailyReview] Error processing %s: %s", domain, exc)
                try:
                    record_api_failure(domain, str(exc), retry_interval_hours=self.retry_interval_hours)
                except Exception:
                    pass

        return processed

    def run_daemon(self, poll_interval_seconds: int = 60, max_iterations: Optional[int] = None) -> None:
        """Run as a continuous daemon polling for due reviews."""
        logger.info("[DailyReview] Daemon started (poll_interval=%ds)", poll_interval_seconds)
        iterations = 0
        while True:
            if max_iterations is not None and iterations >= max_iterations:
                break
            try:
                count = self.run_once()
                if count == 0:
                    time.sleep(poll_interval_seconds)
            except Exception as exc:
                logger.exception("[DailyReview] Daemon loop error: %s", exc)
                time.sleep(5)
            iterations += 1
