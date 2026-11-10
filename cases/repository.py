"""PostgreSQL persistence for cases and their timeline."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2.extras

from domain_profiling.connection import get_db_connection
from .schemas import CaseDetail, CaseEvent, CaseSummary


def format_case_id(year: int, seq: int) -> str:
    return f"CASE-{year}-{seq:06d}"


def _summary(row):
    return CaseSummary(**{k: row.get(k) for k in CaseSummary.model_fields})


class CaseRepository:
    def __init__(self, connection_factory=None) -> None:
        self._connection_factory = connection_factory or get_db_connection

    def _conn(self):
        return self._connection_factory()

    def create(self, *, title, description, priority, entity_type, entity_value,
               created_by, assigned_to=None) -> CaseDetail:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT nextval('case_public_seq');")
                seq = cur.fetchone()["nextval"]
                public_id = format_case_id(datetime.now(timezone.utc).year, seq)
                cur.execute(
                    """
                    INSERT INTO cases
                        (public_id, title, description, priority, entity_type,
                         entity_value, created_by, assigned_to)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING *;
                    """,
                    (public_id, title, description, priority, entity_type,
                     entity_value, created_by, assigned_to),
                )
                row = dict(cur.fetchone())
                cur.execute(
                    """
                    INSERT INTO case_events (case_id, actor_id, kind, body)
                    VALUES (%s, %s, 'created', %s);
                    """,
                    (row["id"], created_by, title),
                )
            conn.commit()
        return self.get(public_id)

    def get(self, public_id: str) -> Optional[CaseDetail]:
        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute("SELECT * FROM cases WHERE public_id = %s;", (public_id,))
                row = cur.fetchone()
                if not row:
                    return None
                case = dict(row)
                cur.execute(
                    "SELECT * FROM case_events WHERE case_id = %s ORDER BY created_at, id;",
                    (case["id"],),
                )
                events = [CaseEvent(**dict(e)) for e in cur.fetchall()]
                cur.execute(
                    """
                    SELECT r.public_id FROM case_reports cr
                    JOIN reports r ON r.id = cr.report_id
                    WHERE cr.case_id = %s ORDER BY cr.linked_at;
                    """,
                    (case["id"],),
                )
                reports = [r["public_id"] for r in cur.fetchall()]
        data = {k: case.get(k) for k in CaseDetail.model_fields}
        data["events"] = events
        data["reports"] = reports
        return CaseDetail(**data)

    def list(self, *, status=None, assigned_to=None, priority=None,
             entity=None, unassigned=False, limit=50, offset=0):
        clauses, params = [], []
        if status:
            clauses.append("status = %s")
            params.append(status)
        if assigned_to is not None:
            clauses.append("assigned_to = %s")
            params.append(assigned_to)
        if priority:
            clauses.append("priority = %s")
            params.append(priority)
        if entity:
            clauses.append("entity_value = %s")
            params.append(entity)
        if unassigned:
            clauses.append("assigned_to IS NULL")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        with self._conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(f"SELECT COUNT(*) AS count FROM cases {where};", tuple(params))
                total = cur.fetchone()["count"]
                cur.execute(
                    f"SELECT * FROM cases {where} ORDER BY created_at DESC LIMIT %s OFFSET %s;",
                    tuple(params + [limit, offset]),
                )
                rows = [dict(r) for r in cur.fetchall()]
        return total, [_summary(r) for r in rows]

    def update(self, public_id: str, fields: dict[str, Any]) -> Optional[CaseDetail]:
        if not fields:
            return self.get(public_id)
        allowed = {"status", "priority", "assigned_to", "resolution",
                   "resolved_by", "resolved_at", "closed_at", "title", "description"}
        clean = {k: v for k, v in fields.items() if k in allowed}
        if not clean:
            return self.get(public_id)
        assignments = ", ".join(f"{k} = %s" for k in clean)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE cases SET {assignments}, updated_at = NOW() "
                    "WHERE public_id = %s;",
                    tuple(clean.values()) + (public_id,),
                )
                changed = cur.rowcount > 0
            conn.commit()
        return self.get(public_id) if changed else None

    def update_with_event(self, public_id: str, fields: dict[str, Any], *,
                          actor_id, kind, metadata=None) -> Optional[CaseDetail]:
        """Update a case and append its timeline event in one transaction."""
        allowed = {"status", "priority", "assigned_to", "resolution",
                   "resolved_by", "resolved_at", "closed_at", "title", "description"}
        clean = {k: v for k, v in fields.items() if k in allowed}
        if not clean:
            return self.get(public_id)
        assignments = ", ".join(f"{k} = %s" for k in clean)
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"UPDATE cases SET {assignments}, updated_at = NOW() "
                    "WHERE public_id = %s RETURNING id;",
                    tuple(clean.values()) + (public_id,),
                )
                row = cur.fetchone()
                if row is None:
                    conn.rollback()
                    return None
                cur.execute(
                    """
                    INSERT INTO case_events (case_id, actor_id, kind, body, metadata)
                    VALUES (%s, %s, %s, %s, %s::jsonb);
                    """,
                    (row[0], actor_id, kind, None, json.dumps(metadata or {})),
                )
            conn.commit()
        return self.get(public_id)

    def add_event(self, case_id: int, *, actor_id, kind, body=None, metadata=None) -> None:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO case_events (case_id, actor_id, kind, body, metadata)
                    VALUES (%s, %s, %s, %s, %s::jsonb);
                    """,
                    (case_id, actor_id, kind, body, json.dumps(metadata or {})),
                )
            conn.commit()

    def link_report(self, case_id: int, report_id: int, linked_by: int) -> bool:
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO case_reports (case_id, report_id, linked_by)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (case_id, report_id) DO NOTHING;
                    """,
                    (case_id, report_id, linked_by),
                )
                inserted = cur.rowcount > 0
                cur.execute(
                    "UPDATE reports SET case_id = COALESCE(case_id, %s) WHERE id = %s;",
                    (case_id, report_id),
                )
            conn.commit()
        return inserted

    def link_report_with_event(self, case_id: int, report_id: int, linked_by: int,
                               *, actor_id, metadata=None) -> bool:
        """Link a report to a case, backfill it, and log the event atomically.

        The report row is locked so two concurrent links cannot race the
        one-case-per-report invariant. Linking an already-linked report to
        the same case is idempotent and does not duplicate the event.
        """
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT case_id FROM reports WHERE id = %s FOR UPDATE;",
                    (report_id,),
                )
                row = cur.fetchone()
                if row is None:
                    conn.rollback()
                    raise LookupError("Report not found.")
                existing = row[0]
                if existing is not None and existing != case_id:
                    conn.rollback()
                    raise ValueError("Report is already linked to another case.")

                cur.execute(
                    """
                    INSERT INTO case_reports (case_id, report_id, linked_by)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (case_id, report_id) DO NOTHING;
                    """,
                    (case_id, report_id, linked_by),
                )
                inserted = cur.rowcount > 0
                if existing is None:
                    cur.execute(
                        "UPDATE reports SET case_id = %s "
                        "WHERE id = %s AND case_id IS NULL;",
                        (case_id, report_id),
                    )
                if inserted:
                    cur.execute(
                        """
                        INSERT INTO case_events (case_id, actor_id, kind, body, metadata)
                        VALUES (%s, %s, 'report_linked', %s, %s::jsonb);
                        """,
                        (case_id, actor_id, None, json.dumps(metadata or {})),
                    )
            conn.commit()
        return inserted
