"""Report snapshot composition and lifecycle."""

from __future__ import annotations

import ipaddress
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from dnsnetra.domains.investigations.service import InvestigationService
from dnsnetra.domains.investigations.live.service import LiveIntelService
from dnsnetra.intelligence.trusted.database import normalize_domain
from dnsnetra.time_engine import (
    InvalidTimeRangeError,
    TemporalDefaultPolicy,
    TimeEngineValidationError,
    format_iso8601_utc,
    resolve_time_range,
)

from .report_repository import ReportRepository
from .report_schemas import ReportStatus, SavedReportDetail
from .service import ReportingService

logger = logging.getLogger(__name__)

RECENT_QUERY_CAP = 500

# Query-set filters the create guard recognises; unknown keys cannot satisfy it.
QUERY_SET_FILTER_KEYS = frozenset(
    {"client_ip", "domain", "verdict", "query_type", "search"}
)


def _has_query_filters(filters: dict[str, Any]) -> bool:
    """True when at least one recognised filter carries a non-blank value."""
    for key in QUERY_SET_FILTER_KEYS:
        value = filters.get(key)
        if isinstance(value, str):
            value = value.strip()
        if value not in (None, ""):
            return True
    return False


class ReportService:
    def __init__(self, repository=None, investigation_service=None,
                 reporting_service=None) -> None:
        self.repository = repository or ReportRepository()
        self.investigation = investigation_service or InvestigationService(
            live_intel_service=LiveIntelService()
        )
        self.reporting = reporting_service or ReportingService()

    def _window(self, window, start_time, end_time, time_range=None):
        if time_range is not None:
            return time_range
        tr = resolve_time_range(
            window=window,
            start_time=start_time,
            end_time=end_time,
            default_policy=TemporalDefaultPolicy.ALL_TIME,
        )
        return tr

    def build_snapshot(self, *, kind, entity, window, start_time, end_time,
                       filters, refresh=False, time_range=None) -> dict[str, Any]:
        filters = filters or {}
        tr = self._window(window, start_time, end_time, time_range=time_range)
        window_meta = {
            "start": format_iso8601_utc(tr.start) if tr.start else None,
            "end": format_iso8601_utc(tr.end) if tr.end else None,
            "label": window or ("all time" if tr.is_all_time else "custom"),
        }

        if kind in ("entity_domain", "entity_client"):
            if kind == "entity_domain":
                dossier = self.investigation.get_domain_dossier(
                    entity, refresh_live=refresh
                )
                entity_type = "domain"
            else:
                dossier = self.investigation.get_client_dossier(
                    entity, refresh_live=refresh
                )
                entity_type = "client"

            dossier_data = dossier.model_dump(mode="json")

            # The dossier caps recent queries at 25 (max 50). A report must
            # capture up to 500 for the entity and window, so query the event
            # log directly rather than reusing the dossier preview.
            # Exact equality: a substring match would pull in subdomains and
            # lookalikes (sub.example.com, notexample.com) into the snapshot.
            entity_filter = (
                {"domain_exact": entity} if entity_type == "domain"
                else {"client_ip": entity}
            )
            events = self.reporting.get_queries(
                **entity_filter,
                time_range=tr,
                limit=RECENT_QUERY_CAP,
                offset=0,
            )
            dossier_data["recent_queries"] = [
                query.model_dump(mode="json") for query in events.items
            ][:RECENT_QUERY_CAP]
            live = dossier_data.get("live_intel") or {}

            summary = self.reporting.get_entity_summary(
                entity_type, entity, time_range=tr
            )
            try:
                series = self.reporting.get_entity_timeseries(
                    entity_type, entity, time_range=tr
                )
                timeline = [bucket.model_dump(mode="json") for bucket in series.buckets]
            except (InvalidTimeRangeError, TimeEngineValidationError) as exc:
                # All-time entity reports have no valid timeseries; state it
                # rather than inventing an empty chart.
                logger.warning(
                    "Timeline unavailable for %s %r: %s", kind, entity, exc
                )
                timeline = []

            return {
                "schema_version": 1,
                "kind": kind,
                "entity": {"type": entity_type, "value": entity},
                "window": window_meta,
                "observed_in_network": dossier_data.get("observed_in_network", False),
                "row_count": int(summary.total_queries or 0),
                "summary": summary.model_dump(mode="json"),
                "timeline": timeline,
                "dossier": dossier_data,
                "provenance": {
                    "sources": [
                        "domain_query_history",
                        "profiles",
                        "reputation_domains",
                        "daily_review_domains",
                        "reviewed_clean_domains",
                        "live_intel",
                    ],
                    "live_intel_checked_at": live.get("checked_at"),
                    "timeline_available": bool(timeline),
                    "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                },
            }

        summary = self.reporting.get_summary(time_range=tr)
        preview = self.reporting.get_queries(
            verdict=filters.get("verdict"),
            search=filters.get("search"),
            client_ip=filters.get("client_ip"),
            domain=filters.get("domain"),
            query_type=filters.get("query_type"),
            time_range=tr,
            limit=RECENT_QUERY_CAP,
            offset=0,
        )
        return {
            "schema_version": 1,
            "kind": kind,
            "entity": None,
            "window": window_meta,
            "filters": filters,
            "row_count": int(getattr(preview, "total", 0) or 0),
            "summary": summary.model_dump(mode="json"),
            "preview_queries": [q.model_dump(mode="json") for q in preview.items],
            "provenance": {
                "sources": ["domain_query_history", "telemetry_hourly_rollup"],
                "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            },
        }

    def create(self, *, kind, entity, window, start_time, end_time, filters,
               title, user_id, refresh=False) -> SavedReportDetail:
        filters = filters or {}

        if kind in ("entity_domain", "entity_client"):
            entity = self._canonical_entity(kind, entity)
        elif kind == "query_set":
            if (not window and not start_time and not end_time
                    and not _has_query_filters(filters)):
                raise ValueError(
                    "A query-set report requires a window or at least one filter."
                )

        tr = self._window(window, start_time, end_time)
        snapshot = self.build_snapshot(
            kind=kind, entity=entity, window=window, start_time=start_time,
            end_time=end_time, filters=filters, refresh=refresh, time_range=tr,
        )
        entity_type = snapshot["entity"]["type"] if snapshot.get("entity") else None
        return self.repository.create(
            kind=kind,
            entity_type=entity_type,
            entity_value=entity,
            title=title or entity or "Query set report",
            window_start=tr.start,
            window_end=tr.end,
            filters=filters,
            snapshot=snapshot,
            row_count=snapshot["row_count"],
            created_by=user_id,
        )

    @staticmethod
    def _canonical_entity(kind: str, entity) -> str:
        """Normalize the stored entity value: domains lowercase, IPs compressed."""
        if entity is None or not str(entity).strip():
            raise ValueError("An entity is required for an entity report.")
        if kind == "entity_domain":
            normalized = normalize_domain(str(entity))
            if not normalized:
                raise ValueError(f"Malformed domain: {entity!r}")
            return normalized
        try:
            return str(ipaddress.ip_address(str(entity).strip()))
        except ValueError as exc:
            raise ValueError(f"Malformed IP address: {entity!r}") from exc

    def list_reports(self, **kwargs):
        return self.repository.list(**kwargs)

    def get_report(self, public_id: str) -> Optional[SavedReportDetail]:
        return self.repository.get(public_id)

    def review_report(self, public_id: str, *, updates: dict[str, Any],
                      reviewer_id: int) -> Optional[SavedReportDetail]:
        """Apply only the fields the caller supplied.

        A status-only PATCH must not erase an existing verdict or conclusion,
        and ``reviewed_by``/``reviewed_at`` are only stamped when the report is
        actually marked reviewed.
        """
        updates = dict(updates or {})
        if not updates:
            return self.repository.get(public_id)
        if "status" in updates and updates["status"] is None:
            raise ValueError("A report status cannot be null.")

        status = updates.get("status")
        if status == ReportStatus.REVIEWED.value:
            current = self.repository.get(public_id)
            if current is None:
                return None
            conclusion = updates.get("conclusion", current.conclusion)
            if not (conclusion or "").strip():
                raise ValueError("A conclusion is required to mark a report reviewed.")
            updates["reviewed_by"] = reviewer_id

        fields = {
            key: updates[key]
            for key in ("status", "verdict", "conclusion", "reviewed_by")
            if key in updates
        }
        return self.repository.review(
            public_id,
            fields=fields,
            stamp_reviewed=status == ReportStatus.REVIEWED.value,
        )

    def archive_report(self, public_id: str) -> bool:
        return self.repository.archive(public_id)
