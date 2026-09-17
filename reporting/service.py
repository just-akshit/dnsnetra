"""
reporting/service.py
====================
Domain business logic and service layer for DNSNetra Reporting Engine.
Consumes authoritative ResolvedTimeRange domain models from time_engine.
Pure Python, zero HTTP / FastAPI dependencies, directly testable.
"""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from time_engine import (
    ResolvedBucket,
    ResolvedTimeRange,
    TemporalDefaultPolicy,
    format_iso8601_utc,
    resolve_time_range,
)
from .repository import ReportingRepository
from .schemas import (
    CanonicalVerdict,
    ClientSummaryItem,
    DomainSummaryItem,
    InvalidTimeRangeError,
    PaginatedResult,
    QueryEventItem,
    ReportingSummary,
    ReportingTimeseries,
    ReportingValidationError,
    TimeseriesBucket,
    VerdictBreakdown,
)

logger = logging.getLogger(__name__)


def _coerce_time_range(
    time_range: Optional[Union[ResolvedTimeRange, datetime, str]] = None,
    start_time: Optional[Union[datetime, str]] = None,
    end_time: Optional[Union[datetime, str]] = None,
    window: Optional[str] = None,
    bucket: Optional[str] = None,
    default_policy: TemporalDefaultPolicy = TemporalDefaultPolicy.ALL_TIME,
) -> ResolvedTimeRange:
    """
    Ensures input is transformed into an immutable ResolvedTimeRange object
    via the canonical time_engine.
    """
    if isinstance(time_range, ResolvedTimeRange):
        return time_range

    # Handle positional invocation where first arg was start_time
    if isinstance(time_range, (datetime, str)):
        return resolve_time_range(
            start_time=time_range,
            end_time=start_time,
            bucket=bucket,
            default_policy=default_policy,
        )

    return resolve_time_range(
        window=window,
        start_time=start_time,
        end_time=end_time,
        bucket=bucket,
        default_policy=default_policy,
    )


class ReportingService:
    """
    Core service coordinating business logic and derived metrics for DNSNetra reporting.
    Consumes ResolvedTimeRange domain models for all temporal querying.
    """

    def __init__(self, repository: Optional[ReportingRepository] = None) -> None:
        self.repository = repository or ReportingRepository()

    # -----------------------------------------------------------------------
    # 1. Summary
    # -----------------------------------------------------------------------

    def get_summary(
        self,
        time_range: Optional[Union[ResolvedTimeRange, datetime, str]] = None,
        start_time: Optional[Union[datetime, str]] = None,
        end_time: Optional[Union[datetime, str]] = None,
        window: Optional[str] = None,
    ) -> ReportingSummary:
        """
        Retrieves high-level summary KPIs and canonical verdict breakdown.
        Operates on an authoritative ResolvedTimeRange.
        """
        tr = _coerce_time_range(
            time_range=time_range,
            start_time=start_time,
            end_time=end_time,
            window=window,
            default_policy=TemporalDefaultPolicy.ALL_TIME,
        )

        # All-time view
        if tr.is_all_time:
            raw = self.repository.get_all_time_summary()
            total_q = raw["total_queries"]
            mal_q = raw["malicious_queries"]
            pct = round((mal_q * 100.0) / total_q, 2) if total_q > 0 else 0.0

            return ReportingSummary(
                time_window=None,
                total_queries=total_q,
                unique_clients=raw["unique_clients"],
                unique_domains=raw["unique_domains"],
                verdict_breakdown=VerdictBreakdown(
                    benign=raw["benign_queries"],
                    malicious=mal_q,
                    review_needed=raw["review_needed_queries"],
                    unknown=raw["unknown_queries"],
                ),
                malicious_query_percentage=pct,
            )

        time_win_dict = {
            "start": format_iso8601_utc(tr.start),
            "end": format_iso8601_utc(tr.end),
        }

        # Empty range (duration 0)
        if tr.is_empty:
            return ReportingSummary(
                time_window=time_win_dict,
                total_queries=0,
                unique_clients=0,
                unique_domains=0,
                verdict_breakdown=VerdictBreakdown(),
                malicious_query_percentage=0.0,
            )

        # Bounded query bounded by observable_end
        if tr.is_hour_aligned:
            raw = self.repository.get_aligned_window_summary(tr.start, tr.observable_end)
        else:
            raw = self.repository.get_raw_window_summary(tr.start, tr.observable_end)

        total_q = raw["total_queries"]
        mal_q = raw["malicious_queries"]
        pct = round((mal_q * 100.0) / total_q, 2) if total_q > 0 else 0.0

        return ReportingSummary(
            time_window=time_win_dict,
            total_queries=total_q,
            unique_clients=raw["unique_clients"],
            unique_domains=raw["unique_domains"],
            verdict_breakdown=VerdictBreakdown(
                benign=raw["benign_queries"],
                malicious=mal_q,
                review_needed=raw["review_needed_queries"],
                unknown=raw["unknown_queries"],
            ),
            malicious_query_percentage=pct,
        )

    # -----------------------------------------------------------------------
    # 2. Timeseries
    # -----------------------------------------------------------------------

    def get_timeseries(
        self,
        time_range: Optional[Union[ResolvedTimeRange, datetime, str]] = None,
        start_time: Optional[Union[datetime, str]] = None,
        end_time: Optional[Union[datetime, str]] = None,
        window: Optional[str] = None,
        bucket: Optional[str] = None,
        bucket_hours: Optional[int] = 1,
    ) -> ReportingTimeseries:
        """
        Generates continuous chronological buckets for the requested time range.
        Consumes ResolvedTimeRange and uses generate_buckets() for zero filling.
        """
        if bucket is None and bucket_hours is not None and not window and not isinstance(time_range, ResolvedTimeRange):
            bucket = f"{bucket_hours}h"

        tr = _coerce_time_range(
            time_range=time_range,
            start_time=start_time,
            end_time=end_time,
            window=window,
            bucket=bucket,
            default_policy=TemporalDefaultPolicy.ROLLING_24H,
        )

        if tr.is_all_time:
            raise InvalidTimeRangeError("All-time timeseries is not permitted.")

        s_iso = format_iso8601_utc(tr.start)
        e_iso = format_iso8601_utc(tr.end)
        b_label = tr.bucket_spec.bucket_label

        if tr.is_empty:
            return ReportingTimeseries(
                start_time=s_iso,
                end_time=e_iso,
                bucket_size=b_label,
                buckets=[],
            )

        # Generate exact intersecting grid buckets from time_engine
        resolved_buckets = tr.generate_buckets()
        buckets_map: Dict[str, Dict[str, Any]] = {}
        for b in resolved_buckets:
            b_key = format_iso8601_utc(b.bucket_start)
            buckets_map[b_key] = {
                "timestamp": b_key,
                "total_queries": 0,
                "benign_queries": 0,
                "malicious_queries": 0,
                "review_needed_queries": 0,
                "unknown_queries": 0,
            }

        # Query database rows bounded by observable_end
        # Note: Section 25 & 37: Route to exact raw history from domain_query_history
        # until historical telemetry_hourly_rollup rows are repaired and revalidated.
        width_sec = tr.bucket_spec.bucket_seconds
        db_rows = self.repository.get_raw_timeseries(tr.start, tr.observable_end, width_sec)

        for row in db_rows:
            bt = row["bucket_time"]
            if isinstance(bt, datetime):
                b_key = format_iso8601_utc(bt)
            else:
                b_key = str(bt)
            if b_key in buckets_map:
                buckets_map[b_key]["total_queries"] += row["total_queries"]
                buckets_map[b_key]["benign_queries"] += row["benign_queries"]
                buckets_map[b_key]["malicious_queries"] += row["malicious_queries"]
                buckets_map[b_key]["review_needed_queries"] += row["review_needed_queries"]
                buckets_map[b_key]["unknown_queries"] += row["unknown_queries"]

        sorted_buckets = [
            TimeseriesBucket(**data)
            for _, data in sorted(buckets_map.items(), key=lambda item: item[0])
        ]

        return ReportingTimeseries(
            start_time=s_iso,
            end_time=e_iso,
            bucket_size=b_label,
            buckets=sorted_buckets,
        )

    # -----------------------------------------------------------------------
    # 3. Top Clients
    # -----------------------------------------------------------------------

    def get_top_clients(
        self,
        limit: int = 50,
        offset: int = 0,
        time_range: Optional[Union[ResolvedTimeRange, datetime, str]] = None,
        start_time: Optional[Union[datetime, str]] = None,
        end_time: Optional[Union[datetime, str]] = None,
        window: Optional[str] = None,
    ) -> PaginatedResult[ClientSummaryItem]:
        """
        Retrieves ranked top clients ordered deterministically by total_queries DESC, client_ip ASC.
        """
        if limit < 1 or limit > 1000:
            raise ReportingValidationError("limit must be between 1 and 1000.")
        if offset < 0:
            raise ReportingValidationError("offset must be non-negative.")

        has_temporal = (
            time_range is not None
            or start_time is not None
            or end_time is not None
            or window is not None
        )

        if has_temporal:
            tr = _coerce_time_range(
                time_range=time_range,
                start_time=start_time,
                end_time=end_time,
                window=window,
                default_policy=TemporalDefaultPolicy.ALL_TIME,
            )
            if not tr.is_all_time:
                if tr.is_empty:
                    return PaginatedResult(total=0, limit=limit, offset=offset, has_more=False, items=[])
                total, rows = self.repository.get_windowed_top_clients(
                    tr.start, tr.observable_end, limit, offset
                )
            else:
                total, rows = self.repository.get_all_time_top_clients(limit, offset)
        else:
            total, rows = self.repository.get_all_time_top_clients(limit, offset)

        items = [ClientSummaryItem(**r) for r in rows]
        has_more = (offset + len(items)) < total

        return PaginatedResult(
            total=total,
            limit=limit,
            offset=offset,
            has_more=has_more,
            items=items,
        )

    # -----------------------------------------------------------------------
    # 4. Top Domains
    # -----------------------------------------------------------------------

    def get_top_domains(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict_filter: Optional[Any] = None,
        time_range: Optional[Union[ResolvedTimeRange, datetime, str]] = None,
        start_time: Optional[Union[datetime, str]] = None,
        end_time: Optional[Union[datetime, str]] = None,
        window: Optional[str] = None,
    ) -> PaginatedResult[DomainSummaryItem]:
        """
        Retrieves ranked top domains.
        When verdict_filter is provided, it operates strictly as an EVENT-POPULATION FILTER.
        """
        if limit < 1 or limit > 1000:
            raise ReportingValidationError("limit must be between 1 and 1000.")
        if offset < 0:
            raise ReportingValidationError("offset must be non-negative.")

        has_temporal = (
            time_range is not None
            or start_time is not None
            or end_time is not None
            or window is not None
        )

        tr = None
        if has_temporal:
            tr = _coerce_time_range(
                time_range=time_range,
                start_time=start_time,
                end_time=end_time,
                window=window,
                default_policy=TemporalDefaultPolicy.ALL_TIME,
            )
            if not tr.is_all_time and tr.is_empty:
                return PaginatedResult(total=0, limit=limit, offset=offset, has_more=False, items=[])

        q_start = tr.start if (tr and not tr.is_all_time) else None
        q_end = tr.observable_end if (tr and not tr.is_all_time) else None

        if verdict_filter:
            canon = CanonicalVerdict.from_str(verdict_filter).value
            total, rows = self.repository.get_filtered_top_domains(
                canon, q_start, q_end, limit, offset
            )
        elif q_start is not None and q_end is not None:
            total, rows = self.repository.get_windowed_top_domains(
                q_start, q_end, limit, offset
            )
        else:
            total, rows = self.repository.get_all_time_top_domains(limit, offset)

        items = [DomainSummaryItem(**r) for r in rows]
        has_more = (offset + len(items)) < total

        return PaginatedResult(
            total=total,
            limit=limit,
            offset=offset,
            has_more=has_more,
            items=items,
        )

    # -----------------------------------------------------------------------
    # 5. Query Event Log
    # -----------------------------------------------------------------------

    def get_queries(
        self,
        client_ip: Optional[str] = None,
        domain: Optional[str] = None,
        verdict: Optional[Any] = None,
        query_type: Optional[str] = None,
        time_range: Optional[Union[ResolvedTimeRange, datetime, str]] = None,
        start_time: Optional[Union[datetime, str]] = None,
        end_time: Optional[Union[datetime, str]] = None,
        window: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> PaginatedResult[QueryEventItem]:
        """
        Multi-criteria paginated search across authoritative domain_query_history.
        """
        if limit < 1 or limit > 1000:
            raise ReportingValidationError("limit must be between 1 and 1000.")
        if offset < 0:
            raise ReportingValidationError("offset must be non-negative.")

        # Parameter validation
        clean_ip = None
        if client_ip and str(client_ip).strip():
            raw_ip = str(client_ip).strip()
            try:
                ipaddress.ip_address(raw_ip)
                clean_ip = raw_ip
            except ValueError:
                raise ReportingValidationError(f"Invalid client IP address: {client_ip}")

        clean_dom = domain.strip().lower() if domain and domain.strip() else None

        canon_verdict = None
        if verdict:
            canon_verdict = CanonicalVerdict.from_str(verdict).value

        clean_qt = query_type.strip().upper() if query_type and query_type.strip() else None

        has_temporal = (
            time_range is not None
            or start_time is not None
            or end_time is not None
            or window is not None
        )

        tr = None
        if has_temporal:
            tr = _coerce_time_range(
                time_range=time_range,
                start_time=start_time,
                end_time=end_time,
                window=window,
                default_policy=TemporalDefaultPolicy.ALL_TIME,
            )
            if not tr.is_all_time and tr.is_empty:
                return PaginatedResult(total=0, limit=limit, offset=offset, has_more=False, items=[])

        q_start = tr.start if (tr and not tr.is_all_time) else None
        q_end = tr.observable_end if (tr and not tr.is_all_time) else None

        total, rows = self.repository.get_queries(
            client_ip=clean_ip,
            domain=clean_dom,
            verdict=canon_verdict,
            query_type=clean_qt,
            start_time=q_start,
            end_time=q_end,
            limit=limit,
            offset=offset,
        )

        items = [QueryEventItem(**r) for r in rows]
        has_more = (offset + len(items)) < total

        return PaginatedResult(
            total=total,
            limit=limit,
            offset=offset,
            has_more=has_more,
            items=items,
        )

    def stream_queries_csv(
        self,
        client_ip: Optional[str] = None,
        domain: Optional[str] = None,
        verdict: Optional[Any] = None,
        query_type: Optional[str] = None,
        time_range: Optional[Union[ResolvedTimeRange, datetime, str]] = None,
        start_time: Optional[Union[datetime, str]] = None,
        end_time: Optional[Union[datetime, str]] = None,
        window: Optional[str] = None,
        limit: int = 5000,
    ):
        """
        Validates criteria and streams RFC 4180 CSV chunks from the repository.
        """
        if limit < 1 or limit > 50000:
            raise ReportingValidationError("CSV export limit must be between 1 and 50,000.")

        clean_ip = None
        if client_ip and str(client_ip).strip():
            raw_ip = str(client_ip).strip()
            try:
                ipaddress.ip_address(raw_ip)
                clean_ip = raw_ip
            except ValueError:
                raise ReportingValidationError(f"Invalid client IP address: {client_ip}")

        clean_dom = domain.strip().lower() if domain and domain.strip() else None

        canon_verdict = None
        if verdict:
            canon_verdict = CanonicalVerdict.from_str(verdict).value

        clean_qt = query_type.strip().upper() if query_type and query_type.strip() else None

        has_temporal = (
            time_range is not None
            or start_time is not None
            or end_time is not None
            or window is not None
        )

        tr = None
        if has_temporal:
            tr = _coerce_time_range(
                time_range=time_range,
                start_time=start_time,
                end_time=end_time,
                window=window,
                default_policy=TemporalDefaultPolicy.ALL_TIME,
            )

        q_start = tr.start if (tr and not tr.is_all_time) else None
        q_end = tr.observable_end if (tr and not tr.is_all_time) else None

        return self.repository.stream_queries_csv(
            client_ip=clean_ip,
            domain=clean_dom,
            verdict=canon_verdict,
            query_type=clean_qt,
            start_time=q_start,
            end_time=q_end,
            limit=limit,
        )

