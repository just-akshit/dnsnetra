"""PostgreSQL persistence for saved reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2.extras

from dnsnetra.domains.domain_profiles.connection import get_db_connection
from .report_schemas import SavedReportDetail, SavedReportSummary


def format_public_id(prefix: str, year: int, seq: int) -> str:
    return f"{prefix}-{year}-{seq:06d}"


def _summary(row: dict[str, Any]) -> SavedReportSummary:
    return SavedReportSummary(**{k: row.get(k) for k in SavedReportSummary.model_fields})


def _detail(row: dict[str, Any]) -> SavedReportDetail:
    data = {k: row.get(k) for k in SavedReportDetail.model_fields}
    if isinstance(data.get("filters"), str):
        data["filters"] = json.loads(data["filters"])
    if isinstance(data.get("snapshot"), str):
        data["snapshot"] = json.loads(data["snapshot"])
    return SavedReportDetail(**data)


_BASE_SELECT = """
    SELECT r.*, c.public_id AS case_public_id
    FROM reports r
    LEFT JOIN cases c ON c.id = r.case_id
"""

_SUMMARY_SELECT = """
    SELECT r.id, r.public_id, r.kind, r.entity_type, r.entity_value, r.title,
           r.status, r.verdict, r.created_by, r.reviewed_at, r.created_at,
           c.public_id AS case_public_id
    FROM reports r
    LEFT JOIN cases c ON c.id = r.case_id
"""


class ReportRepository:
    def __init__(self, connection_factory=None) -> None:
        self._connection_factory = connection_factory or get_db_connection

    def _get_conn(self):
        return self._connection_factory()

    def create(self, *, kind, entity_type, entity_value, title,
               window_start, window_end, filters, snapshot, row_count,
               created_by) -> SavedReportDetail:
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT nextval('report_public_seq');")
                seq = cur.fetchone()["nextval"]
                public_id = format_public_id("RPT", datetime.now(timezone.utc).year, seq)
                cur.execute(
                    """
                    INSERT INTO reports
                        (public_id, kind, entity_type, entity_value, title,
                         window_start, window_end, filters, snapshot, row_count,
                         status, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s,
                            'draft', %s)
                    RETURNING *;
                    """,
                    (public_id, kind, entity_type, entity_value, title,
                     window_start, window_end, json.dumps(filters),
                     json.dumps(snapshot), row_count, created_by),
                )
                row = dict(cur.fetchone())
            conn.commit()
        return _detail(row)

    def list(self, *, status=None, kind=None, entity=None, created_by=None,
             limit=50, offset=0) -> tuple[int, list[SavedReportSummary]]:
        clauses, params = [], []
        if status:
            clauses.append("r.status = %s")
            params.append(status)
        if kind:
            clauses.append("r.kind = %s")
            params.append(kind)
        if entity:
            clauses.append("r.entity_value = %s")
            params.append(entity)
        if created_by is not None:
            clauses.append("r.created_by = %s")
            params.append(created_by)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT COUNT(*) AS count FROM reports r {where};", tuple(params))
                total = cur.fetchone()["count"]
                cur.execute(
                    f"{_SUMMARY_SELECT} {where} ORDER BY r.created_at DESC LIMIT %s OFFSET %s;",
                    tuple(params + [limit, offset]),
                )
                rows = [dict(r) for r in cur.fetchall()]
        return total, [_summary(r) for r in rows]

    def get(self, public_id: str) -> Optional[SavedReportDetail]:
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"{_BASE_SELECT} WHERE r.public_id = %s;", (public_id,))
                row = cur.fetchone()
        return _detail(dict(row)) if row else None

    def get_db_id(self, public_id: str) -> Optional[int]:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM reports WHERE public_id = %s;", (public_id,))
                row = cur.fetchone()
        return row[0] if row else None

    def review(self, public_id: str, *, fields: dict[str, Any],
               stamp_reviewed: bool = False) -> Optional[SavedReportDetail]:
        """Update only the supplied review fields.

        ``verdict``/``conclusion`` are left untouched when omitted, and
        ``reviewed_at`` is only stamped for an explicit review transition.
        """
        allowed = {"status", "verdict", "conclusion", "reviewed_by"}
        clean = {k: v for k, v in fields.items() if k in allowed}
        assignments = [f"{k} = %s" for k in clean]
        params: list[Any] = list(clean.values())
        if stamp_reviewed:
            assignments.append("reviewed_at = NOW()")
        if not assignments:
            return self.get(public_id)
        assignments.append("updated_at = NOW()")

        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    f"""
                    WITH updated AS (
                        UPDATE reports
                        SET {", ".join(assignments)}
                        WHERE public_id = %s
                        RETURNING *
                    )
                    SELECT u.*, c.public_id AS case_public_id
                    FROM updated u
                    LEFT JOIN cases c ON c.id = u.case_id;
                    """,
                    tuple(params + [public_id]),
                )
                row = cur.fetchone()
            conn.commit()
        return _detail(dict(row)) if row else None

    def archive(self, public_id: str) -> bool:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE reports SET status = 'archived', updated_at = NOW() "
                    "WHERE public_id = %s;",
                    (public_id,),
                )
                changed = cur.rowcount > 0
            conn.commit()
        return changed
