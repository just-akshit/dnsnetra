#!/usr/bin/env python3
"""
daily_recheck.py
================
Periodic daily recheck service for Daily Review subsystem.

Features:
  - Queries `daily_review_db.unknown_domains` for domains in `REVIEW_NEEDED` or `NEW`
    where `last_checked` is NULL or older than the configured threshold (default 24h).
  - Evaluates each domain with external intelligence (VirusTotal / AlienVault OTX).
  - Updates Daily Review with explicit state transitions:
      old status  -> previous_status
      new verdict -> status
      review_time -> last_checked
  - On transition to MALICIOUS: caches result into `reputation_db` via `store_malicious_domain`.
  - On transition to CLEAN: purges any stale malicious entry from `reputation_db` via `remove_malicious_domain`.
  - Does NOT modify `first_seen`, `last_seen`, or `query_count` (those belong strictly to DNS query observations).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Path setup
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

from labeler.config import LabelingConfig
from labeler.intel.threat_intelligence import ThreatIntelligence as OnlineThreatIntelligence
from labeler.intel.reputation import store_malicious_domain, get_domain, remove_malicious_domain
from unknown_domain_repository.unknown_domain_repository.config import load_config as load_udr_config
from unknown_domain_repository.unknown_domain_repository.logger import initialize_logger
from unknown_domain_repository.unknown_domain_repository.constants import DomainStatus
from unknown_domain_repository.unknown_domain_repository.database import DatabaseManager
from unknown_domain_repository.unknown_domain_repository.models import UnknownDomain
from unknown_domain_repository.unknown_domain_repository.repository import UnknownDomainRepository

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("daily_recheck")


def get_repository() -> UnknownDomainRepository:
    udr_config = load_udr_config()
    try:
        initialize_logger(udr_config.logging)
    except Exception:
        pass
    db_mgr = DatabaseManager(udr_config)
    db_mgr.initialize()
    return UnknownDomainRepository(db_mgr)


def run_recheck(
    batch_size: int = 100,
    recheck_hours: int = 24,
    limit: Optional[int] = None,
    dry_run: bool = False,
    override_evaluator: Optional[Any] = None,
    eligible_statuses: Tuple[str, ...] = ("clean", "review_needed", "new"),
) -> Dict[str, Any]:
    """
    Execute periodic recheck on eligible domains.

    Args:
        batch_size: Database fetch batch size.
        recheck_hours: Age in hours since last_checked to consider for recheck.
        limit: Max domains to recheck in this run (None for unlimited).
        dry_run: If True, do not persist DB updates.
        override_evaluator: Optional custom function or object with evaluate(domain) -> ThreatDecision.
        eligible_statuses: Tuple of statuses eligible for periodic recheck.

    Returns:
        Summary statistics dictionary.
    """
    repo = get_repository()
    label_config = LabelingConfig()
    online_ti = override_evaluator or OnlineThreatIntelligence(
        config=label_config.get_online_ti_config(),
        db_store=store_malicious_domain,
        db_getter=get_domain,
    )

    stats = {
        "total_eligible": 0,
        "processed": 0,
        "transitioned_clean": 0,
        "transitioned_malicious": 0,
        "kept_review_needed": 0,
        "errors": 0,
        "dry_run": dry_run,
    }

    try:
        domains_to_check: List[UnknownDomain] = repo.get_domains_for_recheck(
            batch_size=limit if limit else batch_size,
            older_than_hours=recheck_hours,
            eligible_statuses=eligible_statuses,
        )
        stats["total_eligible"] = len(domains_to_check)
        logger.info("Found %d domains eligible for recheck (older than %dh, statuses=%s)",
                    len(domains_to_check), recheck_hours, eligible_statuses)

        for domain_record in domains_to_check:
            domain_name = domain_record.domain
            old_status = domain_record.status
            review_time = datetime.now(timezone.utc)

            try:
                # 1. External TI Evaluation
                if hasattr(online_ti, "evaluate"):
                    decision = online_ti.evaluate(domain_name)
                    is_malicious = getattr(decision, "malicious", False)
                    has_intelligence = getattr(decision, "has_intelligence", False)
                elif callable(online_ti):
                    decision = online_ti(domain_name)
                    is_malicious = getattr(decision, "malicious", False)
                    has_intelligence = getattr(decision, "has_intelligence", False)
                else:
                    is_malicious = False
                    has_intelligence = False

                if is_malicious:
                    new_status = DomainStatus.MALICIOUS
                    stats["transitioned_malicious"] += 1
                elif has_intelligence:
                    new_status = DomainStatus.CLEAN
                    stats["transitioned_clean"] += 1
                else:
                    new_status = DomainStatus.REVIEW_NEEDED
                    stats["kept_review_needed"] += 1

                logger.info(
                    "Recheck [%s]: %s -> %s (last_checked: %s)",
                    domain_name,
                    old_status.value if isinstance(old_status, DomainStatus) else old_status,
                    new_status.value,
                    review_time.isoformat(),
                )

                if not dry_run:
                    # 2. Update Daily Review record
                    repo.update_external_review(
                        domain_name=domain_name,
                        new_status=new_status,
                        review_time=review_time,
                    )

                    # 3. Synchronize with Reputation DB cache
                    if new_status == DomainStatus.MALICIOUS:
                        store_malicious_domain(
                            domain=domain_name,
                            metadata={
                                "source": "DailyReviewRecheck",
                                "confidence": 95,
                                "match_scope": "EXACT_FQDN",
                                "recheck_time": review_time.isoformat(),
                            },
                        )
                    elif new_status == DomainStatus.CLEAN and old_status == DomainStatus.MALICIOUS:
                        # De-list stale reputation entry
                        remove_malicious_domain(domain_name)

                stats["processed"] += 1

            except Exception as exc:
                logger.error("Error rechecking %s: %s", domain_name, exc)
                stats["errors"] += 1

    finally:
        if hasattr(online_ti, "close") and callable(online_ti.close):
            online_ti.close()
        repo.db_manager.close()

    logger.info("Daily recheck finished. Stats: %s", stats)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Daily Review Periodic Recheck Service")
    parser.add_argument("--batch-size", type=int, default=100, help="Batch size for database queries")
    parser.add_argument("--recheck-hours", type=int, default=24, help="Eligibility age threshold in hours")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of domains to recheck")
    parser.add_argument("--dry-run", action="store_true", help="Run without persisting DB changes")
    args = parser.parse_args()

    results = run_recheck(
        batch_size=args.batch_size,
        recheck_hours=args.recheck_hours,
        limit=args.limit,
        dry_run=args.dry_run,
    )
    print("\nRecheck Execution Summary:")
    for k, v in results.items():
        print(f"  {k:25}: {v}")


if __name__ == "__main__":
    main()
