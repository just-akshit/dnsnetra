"""
Deterministic Multi-Tier DNS Threat Detection Pipeline
======================================================
Implements the 4-layer threat detection architecture and fundamental contract:
    DO NOT REPROCESS A DOMAIN THAT DNSNETRA ALREADY KNOWS.

Control Flow:
1. Normalize domain (RFC-compliant canonical identity)
2. L1 RAM Cache check -> if HIT, return immediately
3. L2 Local Intelligence (in strict deterministic order):
   - Step A: reputation_domains (PostgreSQL) -> MALICIOUS, update telemetry, populate L1, STOP
   - Step B: trusted_domains (SQLite Tranco) -> CLEAN, populate L1, STOP
   - Step C: malicious_domains (SQLite URLhaus) -> MALICIOUS, populate L1, STOP
   - Step D: reviewed_clean_domains (PostgreSQL) -> CLEAN, populate L1, STOP
   - Step E: daily_review_domains (PostgreSQL) -> if not due, REVIEW_NEEDED, update telemetry, STOP
4. Investigation Stage (all L2 miss OR daily_review is due):
   - If domain is NEW: run Heuristics Engine
   - If domain is existing daily_review: SKIP heuristics
   - Query Online Threat Intelligence (VT + OTX) via CorrelationEngine:
     - MALICIOUS -> store in reputation_domains, mark daily_review malicious, populate L1
     - CLEAN -> store in reviewed_clean_domains, mark daily_review clean, populate L1
     - INCONCLUSIVE -> upsert into daily_review_domains with 180-day next_check_at
     - API FAILURE -> record failure with 1-hour retry, do NOT mark clean
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from .config import LabelingConfig
from .heuristics import Heuristics
from .intel.cache import ThreatIntelCache
from .intel.correlation.engine import CorrelationEngine
from .intel.correlation.models import ThreatDecision
from .intel.daily_review import (
    DailyReviewWorker,
    DecisionProvenance,
    ReviewStatus,
    get_review_domain,
    get_reviewed_clean_domain,
    promote_to_clean,
    promote_to_malicious,
    record_api_failure,
    record_daily_review_observation,
    upsert_review_needed,
)
from .intel.database import normalize_domain
from .intel.malicious import is_malicious
from .intel.manager import is_trusted
from .intel.reputation import (
    get_domain as get_reputation_domain,
    record_observation as record_reputation_observation,
    store_malicious_domain,
)

logger = logging.getLogger("detection_pipeline")

# Lightweight canonical verdict constants
VERDICT_MALICIOUS = "MALICIOUS"
VERDICT_CLEAN = "CLEAN"
VERDICT_REVIEW_NEEDED = "REVIEW_NEEDED"
VERDICT_EXTERNAL_LOOKUP_FAILED = "EXTERNAL_LOOKUP_FAILED"


@dataclass(frozen=True)
class DetectionVerdict:
    """Canonical verdict returned by the DetectionPipeline."""
    domain: str
    normalized_domain: str
    verdict: str                  # "MALICIOUS", "CLEAN", "REVIEW_NEEDED", "EXTERNAL_LOOKUP_FAILED"
    label: str                    # "Malicious", "Benign", "Suspicious"
    threat_score: int             # -100 to 100
    confidence: int               # 0 to 100
    provenance: str               # DecisionProvenance string value
    reasons: list[str]
    ti_source: str                # "reputation", "trusted", "malicious_feed", "reviewed_clean", "daily_review", "online_ti", "heuristic"
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def as_labeller_tuple(self) -> tuple[int, str, int, str, str]:
        """Convert to legacy 5-tuple: (threat_score, label, confidence, reason, ti_source)."""
        reason_str = "; ".join(dict.fromkeys(self.reasons))
        return (self.threat_score, self.label, self.confidence, reason_str, self.ti_source)


class DetectionPipeline:
    """Deterministic threat detection pipeline for DNSNetra."""

    def __init__(
        self,
        config: Optional[LabelingConfig] = None,
        correlation_engine: Optional[CorrelationEngine] = None,
        review_interval_days: int = 180,
    ) -> None:
        self.config = config or LabelingConfig()
        self.review_interval_days = review_interval_days

        # L1 RAM Cache (Dual TTL: 24h malicious, 6h clean) - strictly RAM performance layer
        self.l1_cache = ThreatIntelCache(
            ttl_malicious_hours=self.config.CACHE_TTL_MALICIOUS,
            ttl_clean_hours=self.config.CACHE_TTL_CLEAN,
            db_getter=None,
        )

        # Heuristics Engine
        self.heuristics = Heuristics(self.config)

        # Online Threat Intelligence Correlation Engine
        self.correlation_engine = correlation_engine or CorrelationEngine(
            config=self.config.get_online_ti_config(),
            db_store=store_malicious_domain,
            db_getter=get_reputation_domain,
        )

        # Daily Review Worker
        self.review_worker = DailyReviewWorker(
            correlation_engine=self.correlation_engine,
            review_interval_days=self.review_interval_days,
        )

        logger.info("DetectionPipeline initialized successfully.")

    def evaluate(
        self,
        domain: str,
        registered_domain: Optional[str] = None,
        tld: Optional[str] = None,
        response_code: Optional[str] = None,
        client_ip: Optional[str] = None,
        query_type: Optional[str] = None,
    ) -> DetectionVerdict:
        """Evaluate a domain through the multi-tier detection architecture.

        Enforces the fundamental contract:
        DO NOT REPROCESS A DOMAIN THAT DNSNETRA ALREADY KNOWS.
        """
        # 1. Normalization
        canonical = normalize_domain(domain)
        if not canonical:
            return DetectionVerdict(
                domain=domain,
                normalized_domain="",
                verdict="CLEAN",
                label="Benign",
                threat_score=0,
                confidence=0,
                provenance=DecisionProvenance.LOCAL_TRUSTED.value,
                reasons=["Invalid or unnormalizable domain format"],
                ti_source="invalid",
            )

        # 2. L1 RAM Cache Check
        cached_decision = self.l1_cache.get(canonical)
        if cached_decision is not None:
            logger.debug("[Pipeline] L1 RAM Cache HIT: %s (malicious=%s)", canonical, cached_decision.malicious)
            if cached_decision.malicious:
                return DetectionVerdict(
                    domain=domain,
                    normalized_domain=canonical,
                    verdict="MALICIOUS",
                    label="Malicious",
                    threat_score=self.config.MAX_THREAT_SCORE,
                    confidence=int(cached_decision.confidence * 100) if cached_decision.confidence <= 1.0 else int(cached_decision.confidence),
                    provenance=DecisionProvenance.L1_CACHE.value,
                    reasons=["Cached Decision (RAM L1)"],
                    ti_source="cache",
                )
            else:
                return DetectionVerdict(
                    domain=domain,
                    normalized_domain=canonical,
                    verdict="CLEAN",
                    label="Benign",
                    threat_score=self.config.MIN_THREAT_SCORE,
                    confidence=int(cached_decision.confidence * 100) if cached_decision.confidence <= 1.0 else 95,
                    provenance=DecisionProvenance.L1_CACHE.value,
                    reasons=["Cached Decision (RAM L1)"],
                    ti_source="cache",
                )

        # 3. L2 Local Intelligence (in strict deterministic order)

        # ------------------------------------------------------------------
        # Step A: reputation_domains (PostgreSQL Persistent Malicious Store)
        # ------------------------------------------------------------------
        rep_record = get_reputation_domain(canonical)
        if rep_record is not None:
            logger.info("[Pipeline] Reputation DB HIT: %s", canonical)
            # Update telemetry (query_count++, times_seen++, last_seen=NOW())
            record_reputation_observation(canonical, client_ip=client_ip, query_type=query_type)

            confidence_val = rep_record.get("confidence") or 1.0
            verdict = DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="MALICIOUS",
                label="Malicious",
                threat_score=self.config.MAX_THREAT_SCORE,
                confidence=int(confidence_val * 100) if confidence_val <= 1.0 else int(confidence_val),
                provenance=DecisionProvenance.LOCAL_REPUTATION.value,
                reasons=[f"Known Malicious Domain (Reputation DB: {rep_record.get('source', 'reputation')})"],
                ti_source="reputation",
            )
            # Populate L1 RAM cache for immediate future queries
            self._populate_l1(canonical, is_malicious=True, confidence=confidence_val)
            return verdict

        # ------------------------------------------------------------------
        # Step B: trusted_domains (SQLite Tranco Top 1M Whitelist)
        # ------------------------------------------------------------------
        # Tranco stores apex/registered domains
        tranco_key = normalize_domain(registered_domain or canonical)
        if tranco_key and is_trusted(tranco_key):
            logger.info("[Pipeline] Trusted DB HIT: %s (tranco_key=%s)", canonical, tranco_key)
            verdict = DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="CLEAN",
                label="Benign",
                threat_score=self.config.WHITELIST_SCORE,
                confidence=95,
                provenance=DecisionProvenance.LOCAL_TRUSTED.value,
                reasons=["Trusted Tranco Domain"],
                ti_source="trusted",
            )
            self._populate_l1(canonical, is_malicious=False, confidence=0.95)
            return verdict

        # ------------------------------------------------------------------
        # Step C: malicious_domains (SQLite URLhaus Feed)
        # ------------------------------------------------------------------
        # URLhaus stores hostnames and registered domains
        is_mal_feed = is_malicious(canonical) or (tranco_key and tranco_key != canonical and is_malicious(tranco_key))
        if is_mal_feed:
            logger.info("[Pipeline] Malicious Feed HIT: %s", canonical)
            verdict = DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="MALICIOUS",
                label="Malicious",
                threat_score=self.config.MAX_THREAT_SCORE,
                confidence=98,
                provenance=DecisionProvenance.LOCAL_MALICIOUS_FEED.value,
                reasons=["Known Malicious Domain (URLhaus Feed)"],
                ti_source="malicious_feed",
            )
            # Populate L1 RAM cache (do NOT write to reputation_domains per correction #2)
            self._populate_l1(canonical, is_malicious=True, confidence=0.98)
            return verdict

        # ------------------------------------------------------------------
        # Step D: reviewed_clean_domains (PostgreSQL Verified Clean Store)
        # ------------------------------------------------------------------
        clean_record = get_reviewed_clean_domain(canonical)
        if clean_record is not None:
            logger.info("[Pipeline] Reviewed Clean DB HIT: %s", canonical)
            verdict = DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="CLEAN",
                label="Benign",
                threat_score=self.config.MIN_THREAT_SCORE,
                confidence=95,
                provenance=DecisionProvenance.LOCAL_REVIEWED_CLEAN.value,
                reasons=[f"Verified Clean Domain ({clean_record.verification_source})"],
                ti_source="reviewed_clean",
            )
            self._populate_l1(canonical, is_malicious=False, confidence=0.95)
            return verdict

        # ------------------------------------------------------------------
        # Step E: daily_review_domains (PostgreSQL Review State)
        # ------------------------------------------------------------------
        review_record = get_review_domain(canonical)
        if review_record is not None and not review_record.is_due:
            logger.info("[Pipeline] Daily Review HIT (not due): %s", canonical)
            # Update telemetry: mark last_seen_at = NOW()
            record_daily_review_observation(canonical)
            verdict = DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="REVIEW_NEEDED",
                label="Suspicious",
                threat_score=50,
                confidence=50,
                provenance=DecisionProvenance.DAILY_REVIEW.value,
                reasons=[f"Unresolved Domain Under Daily Review (Next check: {review_record.next_check_at})"],
                ti_source="daily_review",
            )
            # STOP. Do NOT run heuristics, VT, or OTX.
            return verdict

        # ------------------------------------------------------------------
        # 4. Investigation Stage
        # ------------------------------------------------------------------
        # Reached ONLY when:
        # A) Domain is completely NEW (review_record is None), OR
        # B) Domain is existing daily_review whose 180-day check is DUE.

        is_new_domain = review_record is None
        heuristic_score = 0
        heuristic_reasons: list[str] = []

        if is_new_domain:
            # Run heuristics for NEW domains only
            logger.info("[Pipeline] Running heuristics on new domain: %s", canonical)
            heuristic_score, heuristic_reasons = self.heuristics.evaluate(
                {
                    "domain": canonical,
                    "registered_domain": tranco_key or canonical,
                    "tld": tld or "",
                    "response_code": response_code or "NOERROR",
                },
                base_score=0,
                base_reasons=[],
            )
        else:
            # Existing daily_review due for recheck: SKIP heuristics! (Correction #3)
            logger.info("[Pipeline] Daily review DUE for %s: skipping heuristics, rechecking external intel", canonical)

        # Query Online Threat Intelligence (VT + OTX via CorrelationEngine)
        try:
            decision = self.correlation_engine.evaluate(
                canonical,
                client_ip=client_ip,
                query_type=query_type,
            )
        except Exception as exc:
            logger.error("[Pipeline] Online TI lookup threw unexpected error for %s: %s", canonical, exc)
            if not is_new_domain:
                record_api_failure(canonical, str(exc))
            return DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="EXTERNAL_LOOKUP_FAILED",
                label="Suspicious",
                threat_score=max(heuristic_score, 50),
                confidence=50,
                provenance=DecisionProvenance.EXTERNAL_LOOKUP_FAILED.value,
                reasons=["External Threat Intelligence lookup failed"] + heuristic_reasons,
                ti_source="error",
            )

        # Check for provider availability / API failure
        all_providers_failed = (
            len(decision.provider_results) > 0
            and all(pr.unavailable for pr in decision.provider_results)
        )
        if all_providers_failed:
            err_msg = "; ".join(pr.error or "unavailable" for pr in decision.provider_results)
            logger.warning("[Pipeline] Online TI providers unavailable for %s: %s", canonical, err_msg)
            if not is_new_domain:
                record_api_failure(canonical, err_msg)
            return DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="EXTERNAL_LOOKUP_FAILED",
                label="Suspicious",
                threat_score=max(heuristic_score, 50),
                confidence=50,
                provenance=DecisionProvenance.EXTERNAL_LOOKUP_FAILED.value,
                reasons=[f"External TI unavailable: {err_msg}"] + heuristic_reasons,
                ti_source="error",
            )

        # Process CorrelationEngine verdict
        if decision.malicious:
            logger.info("[Pipeline] CorrelationEngine verdict: MALICIOUS for %s", canonical)
            vt_res = self._extract_provider_raw(decision, "virustotal")
            otx_res = self._extract_provider_raw(decision, "alienvault")

            # Promote to reputation_domains
            promote_to_malicious(
                canonical,
                metadata={
                    "source": "virustotal+otx",
                    "confidence": decision.confidence,
                    "client_ip": client_ip,
                    "query_type": query_type,
                },
                vt_result=vt_res,
                otx_result=otx_res,
            )
            self._populate_l1(canonical, is_malicious=True, confidence=decision.confidence)
            return DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="MALICIOUS",
                label="Malicious",
                threat_score=self.config.MAX_THREAT_SCORE,
                confidence=int(decision.confidence * 100) if decision.confidence <= 1.0 else int(decision.confidence),
                provenance=DecisionProvenance.VT_OTX_CORRELATION.value,
                reasons=["Online TI Correlation Confirmed Malicious"] + heuristic_reasons,
                ti_source="online_ti",
            )

        elif decision.has_intelligence:
            # Providers answered and have intelligence on domain, none flagged malicious -> CLEAN
            logger.info("[Pipeline] CorrelationEngine verdict: CLEAN for %s", canonical)
            vt_res = self._extract_provider_raw(decision, "virustotal")
            otx_res = self._extract_provider_raw(decision, "alienvault")

            promote_to_clean(
                canonical,
                source="online_correlation",
                vt_summary=vt_res,
                otx_summary=otx_res,
            )
            self._populate_l1(canonical, is_malicious=False, confidence=0.90)
            return DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="CLEAN",
                label="Benign",
                threat_score=self.config.MIN_THREAT_SCORE,
                confidence=90,
                provenance=DecisionProvenance.VT_OTX_CORRELATION.value,
                reasons=["Online TI Correlation Verified Clean"] + heuristic_reasons,
                ti_source="reviewed_clean",
            )

        else:
            # Providers answered successfully, but NO intelligence found -> INCONCLUSIVE
            logger.info("[Pipeline] Online TI inconclusive for %s -> Daily Review", canonical)
            vt_res = self._extract_provider_raw(decision, "virustotal")
            otx_res = self._extract_provider_raw(decision, "alienvault")

            upsert_review_needed(
                canonical,
                reason="Inconclusive online intelligence (no provider records)",
                vt_result=vt_res,
                otx_result=otx_res,
                interval_days=self.review_interval_days,
            )
            return DetectionVerdict(
                domain=domain,
                normalized_domain=canonical,
                verdict="REVIEW_NEEDED",
                label="Suspicious" if heuristic_score >= self.config.SUSPICIOUS_THRESHOLD else "Benign",
                threat_score=heuristic_score if heuristic_score > 0 else 50,
                confidence=50,
                provenance=DecisionProvenance.DAILY_REVIEW.value,
                reasons=["Unresolved domain added to daily review queue"] + heuristic_reasons,
                ti_source="daily_review",
            )

    def _populate_l1(self, domain: str, is_malicious: bool, confidence: float) -> None:
        """Populate L1 RAM cache with decision."""
        decision = ThreatDecision(
            domain=domain,
            malicious=is_malicious,
            score=1.0 if is_malicious else 0.0,
            confidence=float(confidence),
            threshold=0.60,
            provider_results=[],
            source="DetectionPipeline",
        )
        self.l1_cache.set(domain, decision)

    def _extract_provider_raw(self, decision: ThreatDecision, name: str) -> Optional[dict[str, Any]]:
        for pr in decision.provider_results:
            if name in pr.provider.lower():
                return pr.raw_data or {"malicious": pr.malicious, "unavailable": pr.unavailable}
        return None

    def close(self) -> None:
        """Release pipeline resources."""
        if hasattr(self, "correlation_engine") and self.correlation_engine:
            self.correlation_engine.close_providers()
        logger.info("DetectionPipeline closed.")
