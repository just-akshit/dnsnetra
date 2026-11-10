"""Export helpers shared by CSV and XLSX writers."""

from __future__ import annotations

import csv
import io
import re
from typing import Any, Iterator

from openpyxl import Workbook

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_CSV_FIELDS = ["section", "field", "value", "source", "checked_at"]


def sanitize_csv_cell(value: Any) -> Any:
    """Neutralize spreadsheet formula prefixes in text cells.

    Numbers are left alone: a negative numeric value is data, not a formula.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def safe_filename_part(value: Any, *, limit: int = 64) -> str:
    """Reduce a user-supplied identifier to a header-safe filename fragment."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(value or ""))[:limit]
    return cleaned or "entity"


def _csv_row(values) -> str:
    buffer = io.StringIO()
    csv.DictWriter(buffer, fieldnames=_CSV_FIELDS).writerow(
        {k: sanitize_csv_cell(v) for k, v in zip(_CSV_FIELDS, values)}
    )
    return buffer.getvalue()


def snapshot_csv_chunks(snapshot: dict) -> Iterator[str]:
    """Stream a saved-report snapshot as long-format CSV rows."""
    buffer = io.StringIO()
    csv.DictWriter(buffer, fieldnames=_CSV_FIELDS).writeheader()
    yield buffer.getvalue()

    entity = (snapshot.get("entity") or {}).get("value")
    window = snapshot.get("window") or {}
    dossier = snapshot.get("dossier") or {}
    live = dossier.get("live_intel") or {}

    rows = [
        ("summary", "entity", entity, "telemetry", window.get("start")),
        ("summary", "window", window.get("label"), "request", None),
        ("summary", "observed_in_network", snapshot.get("observed_in_network"), "telemetry", None),
    ]
    for key in ("total_queries", "unique_clients", "unique_domains"):
        rows.append((
            "profile", key, (dossier.get("profile") or {}).get(key),
            "domain_query_history", None,
        ))
    rows.append((
        "intelligence", "live_verdict", (live.get("verdict") or {}).get("state"),
        "live_intel", live.get("checked_at"),
    ))

    for row in rows:
        yield _csv_row(row)

    for query in dossier.get("recent_queries") or []:
        yield _csv_row((
            "queries",
            "event",
            f"{query.get('timestamp')} {query.get('client_ip')} {query.get('domain')}",
            query.get("ti_source"),
            query.get("timestamp"),
        ))


def build_xlsx(snapshot: dict) -> bytes:
    """Render a saved-report snapshot as a six-sheet workbook."""
    dossier = snapshot.get("dossier") or {}
    live = dossier.get("live_intel") or {}
    provenance = snapshot.get("provenance") or {}
    workbook = Workbook(write_only=True)

    summary = workbook.create_sheet("Summary")
    summary.append(["Field", "Value"])
    summary.append(["Entity", sanitize_csv_cell((snapshot.get("entity") or {}).get("value"))])
    summary.append(["Window", (snapshot.get("window") or {}).get("label")])
    summary.append(["Observed in network", snapshot.get("observed_in_network")])

    timeline = workbook.create_sheet("Timeline")
    timeline.append(["Timestamp", "Total", "Benign", "Malicious", "Review Needed", "Unknown"])
    for bucket in snapshot.get("timeline") or []:
        timeline.append([
            bucket.get("timestamp"), bucket.get("total_queries"),
            bucket.get("benign_queries"), bucket.get("malicious_queries"),
            bucket.get("review_needed_queries"), bucket.get("unknown_queries"),
        ])

    relationships = workbook.create_sheet("Relationships")
    relationships.append(["Entity", "Queries", "Last seen"])
    for item in (dossier.get("top_querying_clients")
                 or dossier.get("top_domains") or []):
        relationships.append([
            sanitize_csv_cell(item.get("client_ip") or item.get("domain")),
            item.get("total_queries") or item.get("visit_count"),
            item.get("last_seen"),
        ])

    queries = workbook.create_sheet("Queries")
    queries.append(["Timestamp", "Client IP", "Domain", "Type", "Verdict", "Source"])
    for query in dossier.get("recent_queries") or []:
        queries.append([
            query.get("timestamp"), sanitize_csv_cell(query.get("client_ip")),
            sanitize_csv_cell(query.get("domain")), query.get("query_type"),
            query.get("final_label"), sanitize_csv_cell(query.get("ti_source")),
        ])

    intelligence = workbook.create_sheet("Intelligence")
    intelligence.append(["Field", "Value", "Checked at"])
    intelligence.append([
        "Verdict", (live.get("verdict") or {}).get("state"), live.get("checked_at"),
    ])
    for provider in live.get("providers") or []:
        intelligence.append([
            sanitize_csv_cell(provider.get("provider")),
            provider.get("status"), live.get("checked_at"),
        ])

    assessment = workbook.create_sheet("Assessment")
    assessment.append(["Generated at", provenance.get("generated_at")])
    assessment.append(["Sources", ", ".join(provenance.get("sources") or [])])

    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()
