"""
Daily Review Repository
=======================
PostgreSQL persistence layer for daily_review_domains and reviewed_clean_domains.
Uses the thread-safe connection pool from labeler.intel.reputation.connection.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import psycopg2.extras

from ..reputation.connection import get_connection
from ..reputation.repository import store_malicious_domain
from .models import DailyReviewRecord, ReviewedCleanRecord, ReviewStatus

logger = logging.getLogger(__name__)

DEFAULT_REVIEW_INTERVAL_DAYS: int = 180
DEFAULT_RETRY_INTERVAL_HOURS: int = 1


def _to_jsonb(value: Optional[dict[str, Any]]) -> Optional[str]:
    return json.dumps(value) if value is not None else None


def get_review_domain(domain: str) -> Optional[DailyReviewRecord]:
    """Retrieve a domain's current review record if it exists."""
    sql = "SELECT * FROM daily_review_domains WHERE domain = %s;"
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (domain,))
            row = cur.fetchone()

    if not row:
        return None

    return DailyReviewRecord.from_row(row)


def get_reviewed_clean_domain(domain: str) -> Optional[ReviewedCleanRecord]:
    """Retrieve a domain's record from reviewed_clean_domains if it exists."""
    sql = "SELECT * FROM reviewed_clean_domains WHERE domain = %s;"
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (domain,))
            row = cur.fetchone()

    if not row:
        return None

    return ReviewedCleanRecord.from_row(row)


def record_daily_review_observation(domain: str) -> bool:
    """Update last_seen_at for a domain that exists in daily_review_domains."""
    sql = """
        UPDATE daily_review_domains
        SET last_seen_at = NOW(),
            updated_at   = NOW()
        WHERE domain = %s;
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (domain,))
            return cur.rowcount > 0


def upsert_review_needed(
    domain: str,
    reason: str = "Inconclusive threat intelligence",
    vt_result: Optional[dict[str, Any]] = None,
    otx_result: Optional[dict[str, Any]] = None,
    interval_days: int = DEFAULT_REVIEW_INTERVAL_DAYS,
) -> bool:
    """Insert or update a domain into daily_review_domains as review_needed.

    Sets next_check_at = NOW() + interval_days.
    """
    vt_json = _to_jsonb(vt_result)
    otx_json = _to_jsonb(otx_result)

    sql = """
        INSERT INTO daily_review_domains
            (domain, status, first_seen_at, last_seen_at, last_checked_at,
             next_check_at, review_count, review_reason, vt_result, otx_result,
             created_at, updated_at)
        VALUES
            (%s, %s, NOW(), NOW(), NOW(),
             NOW() + (%s || ' days')::INTERVAL, 1, %s, %s::jsonb, %s::jsonb,
             NOW(), NOW())
        ON CONFLICT (domain) DO UPDATE
            SET status          = EXCLUDED.status,
                last_seen_at    = NOW(),
                last_checked_at = NOW(),
                next_check_at   = NOW() + (%s || ' days')::INTERVAL,
                review_count    = daily_review_domains.review_count + 1,
                review_reason   = EXCLUDED.review_reason,
                vt_result       = COALESCE(EXCLUDED.vt_result, daily_review_domains.vt_result),
                otx_result      = COALESCE(EXCLUDED.otx_result, daily_review_domains.otx_result),
                updated_at      = NOW()
        RETURNING (xmax = 0) AS inserted;
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    domain,
                    ReviewStatus.REVIEW_NEEDED.value,
                    str(interval_days),
                    reason,
                    vt_json,
                    otx_json,
                    str(interval_days),
                ),
            )
            return cur.fetchone()[0]


def promote_to_clean(
    domain: str,
    source: str = "online_correlation",
    vt_summary: Optional[dict[str, Any]] = None,
    otx_summary: Optional[dict[str, Any]] = None,
) -> bool:
    """Promote an unresolved domain to reviewed_clean_domains and update review status."""
    vt_json = _to_jsonb(vt_summary)
    otx_json = _to_jsonb(otx_summary)

    insert_clean_sql = """
        INSERT INTO reviewed_clean_domains
            (domain, verification_source, verified_at, review_count,
             vt_summary, otx_summary, status, created_at, updated_at)
        VALUES
            (%s, %s, NOW(), 1, %s::jsonb, %s::jsonb, 'clean', NOW(), NOW())
        ON CONFLICT (domain) DO UPDATE
            SET verified_at         = NOW(),
                review_count        = reviewed_clean_domains.review_count + 1,
                vt_summary          = COALESCE(EXCLUDED.vt_summary, reviewed_clean_domains.vt_summary),
                otx_summary         = COALESCE(EXCLUDED.otx_summary, reviewed_clean_domains.otx_summary),
                verification_source = EXCLUDED.verification_source,
                updated_at          = NOW();
    """

    update_review_sql = """
        UPDATE daily_review_domains
        SET status          = %s,
            last_checked_at = NOW(),
            vt_result       = COALESCE(%s::jsonb, vt_result),
            otx_result      = COALESCE(%s::jsonb, otx_result),
            updated_at      = NOW()
        WHERE domain = %s;
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(insert_clean_sql, (domain, source, vt_json, otx_json))
            cur.execute(
                update_review_sql,
                (ReviewStatus.CLEAN.value, vt_json, otx_json, domain),
            )
            return True


def promote_to_malicious(
    domain: str,
    metadata: Optional[dict[str, Any]] = None,
    vt_result: Optional[dict[str, Any]] = None,
    otx_result: Optional[dict[str, Any]] = None,
) -> bool:
    """Promote an unresolved domain to reputation_domains and mark status = malicious."""
    metadata = metadata or {}
    vt_json = _to_jsonb(vt_result)
    otx_json = _to_jsonb(otx_result)

    # 1. Upsert into reputation_domains
    store_malicious_domain(domain, metadata=metadata)

    # 2. Update daily_review_domains status
    update_review_sql = """
        UPDATE daily_review_domains
        SET status          = %s,
            last_checked_at = NOW(),
            vt_result       = COALESCE(%s::jsonb, vt_result),
            otx_result      = COALESCE(%s::jsonb, otx_result),
            updated_at      = NOW()
        WHERE domain = %s;
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                update_review_sql,
                (ReviewStatus.MALICIOUS.value, vt_json, otx_json, domain),
            )
            return True


def record_api_failure(
    domain: str,
    error_detail: str,
    retry_interval_hours: int = DEFAULT_RETRY_INTERVAL_HOURS,
) -> bool:
    """Record an external API failure for a domain.

    Transitions status to external_lookup_failed with next_check_at in retry_interval_hours.
    """
    sql = """
        UPDATE daily_review_domains
        SET status          = %s,
            last_checked_at = NOW(),
            next_check_at   = NOW() + (%s || ' hours')::INTERVAL,
            review_reason   = %s,
            updated_at      = NOW()
        WHERE domain = %s;
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    ReviewStatus.EXTERNAL_LOOKUP_FAILED.value,
                    str(retry_interval_hours),
                    f"API Failure: {error_detail}",
                    domain,
                ),
            )
            return cur.rowcount > 0


def claim_due_reviews_for_processing(
    batch_size: int = 50,
    stale_timeout_minutes: int = 15,
) -> list[DailyReviewRecord]:
    """Atomically claim due domains using SELECT ... FOR UPDATE SKIP LOCKED
    and UPDATE to 'processing' within the same transaction.

    Also claims domains stuck in 'processing' beyond stale_timeout_minutes.
    """
    sql = """
        WITH due_domains AS (
            SELECT id
            FROM daily_review_domains
            WHERE (status IN (%s, %s) AND next_check_at <= NOW())
               OR (status = %s AND updated_at <= NOW() - (%s || ' minutes')::INTERVAL)
            ORDER BY next_check_at ASC
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        )
        UPDATE daily_review_domains
        SET status = %s,
            updated_at = NOW()
        WHERE id IN (SELECT id FROM due_domains)
        RETURNING *;
    """
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                sql,
                (
                    ReviewStatus.REVIEW_NEEDED.value,
                    ReviewStatus.EXTERNAL_LOOKUP_FAILED.value,
                    ReviewStatus.PROCESSING.value,
                    str(stale_timeout_minutes),
                    batch_size,
                    ReviewStatus.PROCESSING.value,
                ),
            )
            rows = cur.fetchall()

    return [DailyReviewRecord.from_row(r) for r in rows]


def recover_stale_processing(timeout_minutes: int = 15) -> int:
    """Reset domains stuck in 'processing' state back to 'review_needed'."""
    sql = """
        UPDATE daily_review_domains
        SET status = %s,
            updated_at = NOW()
        WHERE status = %s
          AND updated_at <= NOW() - (%s || ' minutes')::INTERVAL;
    """
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                sql,
                (
                    ReviewStatus.REVIEW_NEEDED.value,
                    ReviewStatus.PROCESSING.value,
                    str(timeout_minutes),
                ),
            )
            return cur.rowcount


def fetch_due_reviews_for_update(
    conn,
    batch_size: int = 50,
) -> list[DailyReviewRecord]:
    """Select domains due for review using SELECT ... FOR UPDATE SKIP LOCKED.

    Caller must provide an active connection within a transaction context.
    """
    sql = """
        SELECT *
        FROM daily_review_domains
        WHERE status IN (%s, %s)
          AND next_check_at <= NOW()
        ORDER BY next_check_at ASC
        LIMIT %s
        FOR UPDATE SKIP LOCKED;
    """
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            sql,
            (
                ReviewStatus.REVIEW_NEEDED.value,
                ReviewStatus.EXTERNAL_LOOKUP_FAILED.value,
                batch_size,
            ),
        )
        rows = cur.fetchall()

    return [DailyReviewRecord.from_row(r) for r in rows]


def list_domains(
    status: Optional[str | ReviewStatus] = None,
    search: Optional[str] = None,
    is_due: Optional[bool] = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[DailyReviewRecord], int]:
    """List and search daily review domains with pagination and due-date filtering."""
    clauses = []
    params: list[Any] = []

    if status:
        st_val = status.value if hasattr(status, "value") else str(status)
        clauses.append("status = %s")
        params.append(st_val)

    if search:
        clauses.append("domain ILIKE %s")
        params.append(f"%{search}%")

    if is_due is True:
        clauses.append("next_check_at <= NOW()")
    elif is_due is False:
        clauses.append("next_check_at > NOW()")

    where_str = f"WHERE {' AND '.join(clauses)}" if clauses else ""

    count_sql = f"SELECT COUNT(*) FROM daily_review_domains {where_str};"
    query_sql = f"""
        SELECT * FROM daily_review_domains
        {where_str}
        ORDER BY next_check_at ASC
        LIMIT %s OFFSET %s;
    """

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(count_sql, tuple(params))
            total_count = cur.fetchone()["count"]

            query_params = params + [limit, offset]
            cur.execute(query_sql, tuple(query_params))
            rows = cur.fetchall()

    records = [DailyReviewRecord.from_row(r) for r in rows]
    return records, total_count


def get_stats() -> dict[str, int]:
    """Return KPI metrics on the daily review and reviewed clean queues.

    Canonical contract:
    - total: total tracked in daily review queue
    - review_needed: domains in review_needed status
    - due_for_review: domains in review_needed status with next_check_at <= NOW()
    - clean: domains in clean status
    - malicious: domains in malicious status
    - processing: domains in processing status
    - total_verified_clean: total in reviewed_clean_domains
    """
    stats_sql = """
        SELECT
            COUNT(*) AS total,
            COUNT(*) FILTER (WHERE status = 'review_needed') AS review_needed,
            COUNT(*) FILTER (WHERE status = 'review_needed' AND next_check_at <= NOW()) AS due_for_review,
            COUNT(*) FILTER (WHERE status = 'clean') AS clean,
            COUNT(*) FILTER (WHERE status = 'malicious') AS malicious,
            COUNT(*) FILTER (WHERE status = 'processing') AS processing
        FROM daily_review_domains;
    """
    clean_sql = "SELECT COUNT(*) AS total_verified_clean FROM reviewed_clean_domains;"

    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(stats_sql)
            review_stats = dict(cur.fetchone())

            cur.execute(clean_sql)
            clean_stats = dict(cur.fetchone())

    return {
        "total": review_stats["total"],
        "review_needed": review_stats["review_needed"],
        "due_for_review": review_stats["due_for_review"],
        "clean": review_stats["clean"],
        "malicious": review_stats["malicious"],
        "processing": review_stats["processing"],
        "total_verified_clean": clean_stats["total_verified_clean"],
    }

