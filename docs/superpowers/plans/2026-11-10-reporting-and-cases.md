# Reporting, Exports, and Cases Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship durable domain/IP reports, CSV + XLSX exports, and a full case/ticket workflow on top of the existing telemetry reporting.

**Architecture:** Reports are immutable JSONB snapshots composed from existing investigation dossiers and reporting services. Cases are mutable work items linked to reports through `case_reports` and an append-only `case_events` timeline. Verdict authority stays with the existing daily-review override. Every mutation and export writes an audit row.

**Tech Stack:** Python 3.13, FastAPI, Pydantic v2, psycopg2, PostgreSQL, pytest; Next.js 16 + React 19 + Tailwind v4, Vitest + Testing Library.

**Spec:** `docs/superpowers/specs/2026-11-10-reporting-and-cases-design.md`

## Global Constraints

- Only one new dependency: `openpyxl>=3.1,<4`. No other package additions.
- Users live in `dashboard_users(id) INTEGER`; all actor FKs are INTEGER.
- `domain_profiling.connection.get_db_connection()` does **not** commit on success — call `conn.commit()` yourself.
- `labeler.intel.reputation.connection.get_connection()` **does** commit on context exit.
- All SQL is parameterized. All timestamps are UTC. Half-open `[start, end)` intervals.
- New migrations are additive and numbered `012_audit_target_columns.sql` and `013_reporting_and_cases.sql`.
- Every report/case mutation and every export writes `log_audit_event` with `target_type`/`target_id`.
- Permissions: add `reports:write`, `cases:read`, `cases:write`, `cases:manage` (matrix in spec section 5).
- UI follows `DESIGN.md`: verdict chips, hairline panels, mono IDs/timestamps, 28–32px controls, no decorative color.
- Commands: backend `.venv/bin/python -m pytest <path> -q`; frontend `cd frontend && pnpm vitest run <path>` and `cd frontend && npx tsc --noEmit`.
- Commit after every task.

---

## Phase 0 — Correctness and security

### Task 1: Audit targeting and export/override auditing

**Files:**
- Create: `database/migrations/012_audit_target_columns.sql`
- Modify: `api/audit.py:20-110`
- Modify: `api/routes/reports.py:544-600`
- Modify: `api/routes/daily_review.py:224-282`
- Test: `tests/test_reporting_audit.py`

**Interfaces:**
- Produces: `log_audit_event(..., target_type: str | None = None, target_id: str | None = None)`
- Produces: `AuditAction.REPORT_EXPORTED`, `REPORT_CREATED`, `REPORT_REVIEWED`, `REPORT_ARCHIVED`, `CASE_CREATED`, `CASE_UPDATED`, `CASE_ASSIGNED`, `CASE_RESOLVED`, `CASE_CLOSED`, `VERDICT_OVERRIDE`

- [ ] **Step 1: Write the failing test**

```python
"""Audit rows for exports and verdict overrides."""

from fastapi.testclient import TestClient

from api.audit import get_audit_logs
from api.main import app

client = TestClient(app)


def test_csv_export_writes_an_audit_row(admin_headers):
    res = client.get(
        "/api/v1/reports/export/csv",
        headers=admin_headers,
        params={"limit": 1, "search": "a"},
    )
    assert res.status_code == 200

    rows, _ = get_audit_logs(action="REPORT_EXPORTED", limit=1)
    assert rows[0]["action"] == "REPORT_EXPORTED"
    assert rows[0]["target_type"] == "export"
    assert rows[0]["metadata"]["format"] == "csv"


def test_verdict_override_writes_an_audit_row(admin_headers):
    payload = {"verdict": "clean", "reason": "audit-test"}
    res = client.post(
        "/api/v1/daily-review/audit-override.example/verdict",
        headers=admin_headers,
        json=payload,
    )
    assert res.status_code == 200

    rows, _ = get_audit_logs(action="VERDICT_OVERRIDE", limit=1)
    assert rows[0]["target_type"] == "domain"
    assert rows[0]["target_id"] == "audit-override.example"
    assert rows[0]["metadata"]["verdict"] == "CLEAN"
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_reporting_audit.py -q`
Expected: FAIL — `target_type` column/attribute missing.

- [ ] **Step 3: Add the migration and audit fields**

`database/migrations/012_audit_target_columns.sql`:

```sql
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS target_type TEXT NULL,
    ADD COLUMN IF NOT EXISTS target_id   TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_target
    ON audit_logs (target_type, target_id);
```

In `api/audit.py`, extend the action block and the function:

```python
class AuditAction:
    # ...existing values...
    REPORT_CREATED = "REPORT_CREATED"
    REPORT_REVIEWED = "REPORT_REVIEWED"
    REPORT_ARCHIVED = "REPORT_ARCHIVED"
    REPORT_EXPORTED = "REPORT_EXPORTED"
    CASE_CREATED = "CASE_CREATED"
    CASE_UPDATED = "CASE_UPDATED"
    CASE_ASSIGNED = "CASE_ASSIGNED"
    CASE_RESOLVED = "CASE_RESOLVED"
    CASE_CLOSED = "CASE_CLOSED"
    VERDICT_OVERRIDE = "VERDICT_OVERRIDE"


def log_audit_event(
    action: str,
    user_id: Optional[int] = None,
    target_user_id: Optional[int] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    target_type: Optional[str] = None,
    target_id: Optional[str] = None,
) -> Optional[int]:
    # ...existing sanitization...
    cur.execute(
        """
        INSERT INTO audit_logs
            (user_id, action, target_user_id, target_type, target_id,
             ip_address, user_agent, timestamp, metadata)
        VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), %s::jsonb)
        RETURNING id;
        """,
        (user_id, action, target_user_id, target_type, target_id,
         valid_ip, user_agent, clean_meta_json),
    )
```

Also add `target_type`/`target_id` to the `get_audit_logs` SELECT list and row dict.

- [ ] **Step 4: Audit the CSV export**

In `get_report_export_csv`, add `request: Request` and before returning:

```python
from api.audit import AuditAction, log_audit_event

log_audit_event(
    action=AuditAction.REPORT_EXPORTED,
    user_id=current_user["id"],
    ip_address=request.client.host if request.client else None,
    user_agent=request.headers.get("user-agent"),
    target_type="export",
    target_id=filter_dom or filter_ip or "all",
    metadata={
        "format": "csv",
        "limit": limit,
        "client_ip": filter_ip,
        "domain": filter_dom,
        "verdict": canon_verdict,
        "query_type": query_type,
        "window": window,
    },
)
```

- [ ] **Step 5: Audit the verdict override**

In `set_manual_verdict`, add `request: Request` and after the success branch:

```python
from api.audit import AuditAction, log_audit_event

log_audit_event(
    action=AuditAction.VERDICT_OVERRIDE,
    user_id=current_user["id"],
    ip_address=request.client.host if request.client else None,
    user_agent=request.headers.get("user-agent"),
    target_type="domain",
    target_id=canonical,
    metadata={
        "verdict": verdict_choice.upper(),
        "reason": payload.reason,
        "confidence": payload.confidence,
    },
)
```

- [ ] **Step 6: Apply the migration and run tests**

Run: `.venv/bin/python database/migrate.py`
Run: `.venv/bin/python -m pytest tests/test_reporting_audit.py tests/test_auth_security_audit.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add database/migrations/012_audit_target_columns.sql api/audit.py api/routes/reports.py api/routes/daily_review.py tests/test_reporting_audit.py
git commit -m "fix(audit): target reports and exports, log overrides"
```

---

### Task 2: CSV formula-injection protection and filter parity

**Files:**
- Create: `reporting/exporters.py`
- Modify: `reporting/repository.py:25-35, 560-600, 641-745`
- Modify: `reporting/service.py:487-555`
- Modify: `api/routes/reports.py:549-600`
- Test: `tests/test_reporting_exports.py`

**Interfaces:**
- Produces: `sanitize_csv_cell(value: Any) -> Any`
- Produces: `ReportingRepository.stream_queries_csv(..., search: Optional[str] = None)`
- Produces: `ReportingService.stream_queries_csv(..., search: Optional[str] = None)`

- [ ] **Step 1: Write the failing tests**

```python
"""CSV safety and filter parity."""

from reporting.exporters import sanitize_csv_cell
from reporting.repository import ReportingRepository, like_pattern


def test_formula_cells_are_neutralized():
    assert sanitize_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert sanitize_csv_cell("+1") == "'+1"
    assert sanitize_csv_cell("-1") == "'-1"
    assert sanitize_csv_cell("@SUM") == "'@SUM"
    assert sanitize_csv_cell("example.com") == "example.com"
    assert sanitize_csv_cell(42) == 42


def test_like_pattern_escapes_metacharacters():
    assert like_pattern("%_x") == "%\\%\\_x%"


class _FakeCursor:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.log.append((" ".join(sql.split()), params))

    def fetchmany(self, size):
        return []


class _FakeConn:
    def __init__(self):
        self.log = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self, *args, **kwargs):
        return _FakeCursor(self.log)


def test_export_uses_ilike_for_domain_and_search():
    conn = _FakeConn()
    repo = ReportingRepository(connection_factory=lambda: conn)
    list(repo.stream_queries_csv(domain="example", search="foo", limit=10))

    sql = conn.log[-1][0]
    params = conn.log[-1][1]
    assert "domain ILIKE" in sql
    assert "client_ip ILIKE" in sql
    assert "%example%" in params
    assert params.count("%foo%") == 2
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_reporting_exports.py -q`
Expected: FAIL — no `reporting.exporters`, no `like_pattern`.

- [ ] **Step 3: Create the sanitizer and rename the pattern helper**

`reporting/exporters.py`:

```python
"""Export helpers shared by CSV and XLSX writers."""

from __future__ import annotations

from typing import Any

_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_csv_cell(value: Any) -> Any:
    """Neutralize spreadsheet formula prefixes in text cells.

    Numbers are left alone: a negative numeric value is data, not a formula.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value
```

In `reporting/repository.py`, rename `_like_pattern` to `like_pattern` and update every call site (8 occurrences). Keep the docstring.

- [ ] **Step 4: Add `search` and ILIKE parity to the export**

In `ReportingRepository.stream_queries_csv`, add `search: Optional[str] = None` after `limit`, then:

```python
if domain:
    clauses.append("domain ILIKE %s")
    params.append(like_pattern(domain.strip().lower()))

if search and search.strip():
    term = like_pattern(search)
    clauses.append("(domain ILIKE %s OR client_ip ILIKE %s)")
    params.extend([term, term])
```

When writing rows, sanitize every value:

```python
for r in rows:
    chunk_writer.writerow({k: sanitize_csv_cell(v) for k, v in dict(r).items()})
```

Import `from .exporters import sanitize_csv_cell`.

In `ReportingService.stream_queries_csv`, add `search: Optional[str] = None` and pass it to the repository. In `api/routes/reports.py`, stop converting `search` into exact IP/domain filters and pass `search=stripped_search`; keep explicit `client_ip`/`domain` as-is.

- [ ] **Step 5: Run tests**

Run: `.venv/bin/python -m pytest tests/test_reporting_exports.py tests/test_reporting_service.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add reporting/exporters.py reporting/repository.py reporting/service.py api/routes/reports.py tests/test_reporting_exports.py
git commit -m "fix(reports): sanitize CSV cells and match list filters"
```

---

### Task 3: Live-only entity reports and permission alignment

**Files:**
- Modify: `api/routes/reports.py:472-541`
- Test: `tests/test_reporting_entity.py`

**Interfaces:**
- Produces: `/api/v1/reports/entity` returns 200 for valid unseen entities.
- Produces: entity-appropriate 403 for SUPPORT.

- [ ] **Step 1: Write the failing test**

```python
"""Entity reporting for unseen indicators and role gates."""

from fastapi.testclient import TestClient

from api.main import app
from investigation.live.models import IndicatorVerdict, LiveIntelReport

client = TestClient(app)


class _FakeLive:
    def lookup_domain(self, value, refresh=False):
        return LiveIntelReport(
            indicator=value,
            kind="domain",
            verdict=IndicatorVerdict(state="unknown", reasons=["no data"]),
            checked_at="2026-11-10T00:00:00Z",
        )

    def lookup_ip(self, value, refresh=False):
        return None


def test_unseen_domain_returns_a_live_dossier(monkeypatch, analyst_headers):
    from api.routes import reports as report_routes
    from investigation.service import InvestigationService

    monkeypatch.setattr(
        report_routes,
        "InvestigationService",
        lambda: InvestigationService(live_intel_service=_FakeLive()),
    )

    res = client.get(
        "/api/v1/reports/entity",
        headers=analyst_headers,
        params={"entity": "never-seen-report.example"},
    )
    assert res.status_code == 200
    body = res.json()
    assert body["entity_type"] == "domain"
    assert body["domain_dossier"]["observed_in_network"] is False


def test_support_cannot_read_entity_dossiers(support_headers):
    res = client.get(
        "/api/v1/reports/entity",
        headers=support_headers,
        params={"entity": "example.com", "entity_type": "domain"},
    )
    assert res.status_code == 403
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_reporting_entity.py -q`
Expected: first test FAIL with 404; second FAIL with 200.

- [ ] **Step 3: Remove the observed-only rejection and add the permission check**

In `get_report_entity`, after `eff_type` is resolved:

```python
from api.rbac import has_permission

required = "domains:investigate" if eff_type == "domain" else "clients:investigate"
if not has_permission(current_user.get("role", ""), required):
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Access denied: role '{current_user.get('role')}' lacks permission '{required}'",
    )
```

Delete both blocks:

```python
if not dossier.observed_in_network:
    raise HTTPException(status_code=404, ...)
```

Keep the existing `EntityNotFoundError`/`InvalidEntityError` handling.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_reporting_entity.py tests/test_api_v1.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/routes/reports.py tests/test_reporting_entity.py
git commit -m "fix(reports): serve live-only entities and gate dossiers by investigate"
```

---

### Task 4: Atomic malicious promotion, confidence, and escaped review search

**Files:**
- Modify: `labeler/intel/reputation/repository.py:65-135`
- Modify: `labeler/intel/daily_review/repository.py:160-205, 331-380`
- Modify: `api/routes/daily_review.py:224-282`
- Test: `tests/test_daily_review_hardening.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Daily-review hardening: atomic promote, confidence, search escaping."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_zero_confidence_is_preserved(admin_headers):
    res = client.post(
        "/api/v1/daily-review/zero-confidence.example/verdict",
        headers=admin_headers,
        json={"verdict": "malicious", "reason": "test", "confidence": 0.0},
    )
    assert res.status_code == 200

    from labeler.intel.reputation.repository import get_domain
    record = get_domain("zero-confidence.example")
    assert record["confidence"] == 0.0


def test_review_search_escapes_wildcards(admin_headers):
    res = client.get(
        "/api/v1/daily-review",
        headers=admin_headers,
        params={"search": "%", "status": "all"},
    )
    assert res.status_code == 200
    assert res.json()["total"] >= 0
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_daily_review_hardening.py -q`
Expected: first FAIL (confidence 1.0), second still passes but does a full scan.

- [ ] **Step 3: Make `store_malicious_domain` accept a caller connection**

In `labeler/intel/reputation/repository.py`:

```python
def store_malicious_domain(
    domain: str,
    metadata: Optional[dict[str, Any]] = None,
    source: Optional[str] = None,
    confidence: Optional[float] = None,
    conn: Optional[PgConnection] = None,
    **kwargs: Any,
) -> bool:
    # ...build upsert_sql and params unchanged...

    if conn is not None:
        with conn.cursor() as cur:
            cur.execute(upsert_sql, params)
            inserted = cur.fetchone()[0]
    else:
        with get_connection() as own_conn:
            with own_conn.cursor() as cur:
                cur.execute(upsert_sql, params)
                inserted = cur.fetchone()[0]
    # ...logging unchanged...
```

- [ ] **Step 4: Pass one connection through `promote_to_malicious`**

```python
def promote_to_malicious(domain, metadata=None, vt_result=None, otx_result=None) -> bool:
    metadata = metadata or {}
    vt_json = _to_jsonb(vt_result)
    otx_json = _to_jsonb(otx_result)

    with get_connection() as conn:
        store_malicious_domain(domain, metadata=metadata, conn=conn)
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE daily_review_domains
                SET status = %s, last_checked_at = NOW(),
                    vt_result = COALESCE(%s::jsonb, vt_result),
                    otx_result = COALESCE(%s::jsonb, otx_result),
                    updated_at = NOW()
                WHERE domain = %s;
                """,
                (ReviewStatus.MALICIOUS.value, vt_json, otx_json, domain),
            )
        return True
```

- [ ] **Step 5: Fix the confidence fallback**

In `set_manual_verdict`:

```python
confidence = payload.confidence if payload.confidence is not None else 1.0
```

Use `confidence` in the metadata dict.

- [ ] **Step 6: Escape the daily-review search**

In `labeler/intel/daily_review/repository.py`, import `like_pattern` from `reporting.repository` and replace:

```python
params.append(like_pattern(search))
```

- [ ] **Step 7: Run tests**

Run: `.venv/bin/python -m pytest tests/test_daily_review_hardening.py tests/test_auth_complete.py -q`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add labeler/intel/reputation/repository.py labeler/intel/daily_review/repository.py api/routes/daily_review.py tests/test_daily_review_hardening.py
git commit -m "fix(daily-review): atomic promote, zero confidence, escaped search"
```

---

### Task 5: Reconcile summary with timeseries

**Files:**
- Modify: `reporting/service.py:145-150`
- Test: `tests/test_reporting_service.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/test_reporting_service.py`:

```python
def test_bounded_summary_matches_timeseries_total(service):
    summary = service.get_summary(window="24h")
    series = service.get_timeseries(window="24h", bucket="1h")

    assert summary.total_queries == sum(b.total_queries for b in series.buckets)
    assert summary.verdict_breakdown.malicious == sum(
        b.malicious_queries for b in series.buckets
    )
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_reporting_service.py::test_bounded_summary_matches_timeseries_total -q`
Expected: FAIL when rollups and raw telemetry disagree.

- [ ] **Step 3: Use one source of truth for bounded summaries**

In `ReportingService.get_summary`, replace the aligned/unaligned branch with:

```python
# Bounded summaries use raw telemetry so they always reconcile with the
# timeseries endpoint. Rollups remain for all-time dashboard KPIs.
raw = self.repository.get_raw_window_summary(tr.start, tr.observable_end)
```

- [ ] **Step 4: Run the full reporting test file**

Run: `.venv/bin/python -m pytest tests/test_reporting_service.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add reporting/service.py tests/test_reporting_service.py
git commit -m "fix(reports): reconcile bounded summary with timeseries"
```

---

## Phase 1 — Durable reports

### Task 6: Migration for reports and cases

**Files:**
- Create: `database/migrations/013_reporting_and_cases.sql`
- Test: `tests/test_reporting_schema.py`

- [ ] **Step 1: Write the failing schema test**

```python
"""Reporting schema exists after migrations."""

from domain_profiling.connection import get_db_connection


def test_reporting_tables_and_indexes_exist():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name IN ('reports', 'cases', 'case_events', 'case_reports')
                ORDER BY table_name;
            """)
            assert [r[0] for r in cur.fetchall()] == [
                "case_events", "case_reports", "cases", "reports"
            ]

            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'audit_logs'
                  AND column_name IN ('target_type', 'target_id');
            """)
            assert len(cur.fetchall()) == 2
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_reporting_schema.py -q`
Expected: FAIL — tables missing.

- [ ] **Step 3: Write the migration**

`database/migrations/013_reporting_and_cases.sql`:

```sql
-- Reporting, exports, and case workflow.
-- Cases are created before reports because reports.case_id references cases.

CREATE TABLE IF NOT EXISTS cases (
    id              BIGSERIAL PRIMARY KEY,
    public_id       TEXT NOT NULL UNIQUE,
    title           TEXT NOT NULL,
    description     TEXT NULL,
    status          TEXT NOT NULL DEFAULT 'open'
                    CHECK (status IN ('open', 'triaged', 'investigating',
                                      'awaiting_info', 'resolved', 'closed')),
    priority        TEXT NOT NULL DEFAULT 'medium'
                    CHECK (priority IN ('low', 'medium', 'high', 'critical')),
    resolution      TEXT NULL
                    CHECK (resolution IN ('true_positive', 'false_positive',
                                          'benign', 'duplicate', 'no_action')),
    entity_type     TEXT NULL CHECK (entity_type IN ('domain', 'client', 'query')),
    entity_value    TEXT NULL,
    created_by      INTEGER NULL REFERENCES dashboard_users(id) ON DELETE SET NULL,
    assigned_to     INTEGER NULL REFERENCES dashboard_users(id) ON DELETE SET NULL,
    resolved_by     INTEGER NULL REFERENCES dashboard_users(id) ON DELETE SET NULL,
    resolved_at     TIMESTAMPTZ NULL,
    closed_at       TIMESTAMPTZ NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cases_status_assignee ON cases (status, assigned_to);
CREATE INDEX IF NOT EXISTS idx_cases_entity ON cases (entity_value);
CREATE INDEX IF NOT EXISTS idx_cases_created ON cases (created_at DESC);

CREATE TABLE IF NOT EXISTS reports (
    id              BIGSERIAL PRIMARY KEY,
    public_id       TEXT NOT NULL UNIQUE,
    kind            TEXT NOT NULL
                    CHECK (kind IN ('entity_domain', 'entity_client', 'query_set')),
    entity_type     TEXT NULL CHECK (entity_type IN ('domain', 'client')),
    entity_value    TEXT NULL,
    title           TEXT NOT NULL,
    window_start    TIMESTAMPTZ NULL,
    window_end      TIMESTAMPTZ NULL,
    filters         JSONB NOT NULL DEFAULT '{}'::jsonb,
    snapshot        JSONB NOT NULL,
    row_count       INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'draft'
                    CHECK (status IN ('draft', 'needs_review', 'reviewed', 'archived')),
    conclusion      TEXT NULL,
    verdict         TEXT NULL
                    CHECK (verdict IN ('Benign', 'Malicious', 'Review Needed', 'Unknown')),
    created_by      INTEGER NULL REFERENCES dashboard_users(id) ON DELETE SET NULL,
    reviewed_by     INTEGER NULL REFERENCES dashboard_users(id) ON DELETE SET NULL,
    reviewed_at     TIMESTAMPTZ NULL,
    case_id         BIGINT NULL REFERENCES cases(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_status_created ON reports (status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_entity ON reports (entity_value);
CREATE INDEX IF NOT EXISTS idx_reports_case ON reports (case_id);

CREATE SEQUENCE IF NOT EXISTS report_public_seq;
CREATE SEQUENCE IF NOT EXISTS case_public_seq;

CREATE TABLE IF NOT EXISTS case_events (
    id          BIGSERIAL PRIMARY KEY,
    case_id     BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    actor_id    INTEGER NULL REFERENCES dashboard_users(id) ON DELETE SET NULL,
    kind        TEXT NOT NULL
                CHECK (kind IN ('created', 'comment', 'status_changed', 'assigned',
                                'priority_changed', 'resolution_set', 'report_linked',
                                'report_unlinked')),
    body        TEXT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_case_events_case ON case_events (case_id, created_at);

CREATE TABLE IF NOT EXISTS case_reports (
    case_id     BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    report_id   BIGINT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    linked_by   INTEGER NULL REFERENCES dashboard_users(id) ON DELETE SET NULL,
    linked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, report_id)
);
```

- [ ] **Step 4: Apply and run**

Run: `.venv/bin/python database/migrate.py`
Run: `.venv/bin/python -m pytest tests/test_reporting_schema.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add database/migrations/013_reporting_and_cases.sql tests/test_reporting_schema.py
git commit -m "feat(db): add reports, cases, events, and links"
```

---

### Task 7: Report schemas and repository

**Files:**
- Create: `reporting/report_schemas.py`
- Create: `reporting/report_repository.py`
- Test: `tests/test_saved_reports_repository.py`

**Interfaces:**
- Produces: `format_public_id(prefix: str, year: int, seq: int) -> str`
- Produces: `ReportRepository.create(...)`, `.list(...)`, `.get(public_id)`, `.get_db_id(public_id)`, `.review(...)`, `.archive(...)`
- Produces: `SavedReportSummary`, `SavedReportDetail`

- [ ] **Step 1: Write the failing tests**

```python
"""Saved report schemas and SQL behavior."""

import json
from datetime import datetime, timezone

from reporting.report_repository import ReportRepository, format_public_id


def test_public_id_format():
    assert format_public_id("RPT", 2026, 7) == "RPT-2026-000007"


class _Cursor:
    def __init__(self, rows):
        self.rows = list(rows)
        self.executed = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.executed.append((" ".join(sql.split()), params))

    def fetchone(self):
        return self.rows.pop(0)


class _Conn:
    def __init__(self, rows):
        self._cursor = _Cursor(rows)
        self.committed = False

    def cursor(self, *args, **kwargs):
        return self._cursor

    def commit(self):
        self.committed = True


def test_create_inserts_a_snapshot_and_commits():
    row = {
        "id": 1,
        "public_id": "RPT-2026-000001",
        "kind": "entity_domain",
        "entity_type": "domain",
        "entity_value": "example.com",
        "title": "example.com",
        "window_start": None,
        "window_end": None,
        "filters": {},
        "snapshot": {"schema_version": 1},
        "row_count": 0,
        "status": "draft",
        "conclusion": None,
        "verdict": None,
        "created_by": 1,
        "reviewed_by": None,
        "reviewed_at": None,
        "case_id": None,
        "case_public_id": None,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    conn = _Conn([{"nextval": 1}, row])
    repo = ReportRepository(connection_factory=lambda: conn)

    report = repo.create(
        kind="entity_domain",
        entity_type="domain",
        entity_value="example.com",
        title="example.com",
        window_start=None,
        window_end=None,
        filters={},
        snapshot={"schema_version": 1},
        row_count=0,
        created_by=1,
    )

    assert report.public_id == "RPT-2026-000001"
    assert conn.committed is True
    assert "INSERT INTO reports" in conn._cursor.executed[1][0]
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_saved_reports_repository.py -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Write the schemas**

`reporting/report_schemas.py`:

```python
"""Domain models for saved reports."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class ReportKind(str, Enum):
    ENTITY_DOMAIN = "entity_domain"
    ENTITY_CLIENT = "entity_client"
    QUERY_SET = "query_set"


class ReportStatus(str, Enum):
    DRAFT = "draft"
    NEEDS_REVIEW = "needs_review"
    REVIEWED = "reviewed"
    ARCHIVED = "archived"


class SavedReportSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    public_id: str
    kind: str
    entity_type: Optional[str] = None
    entity_value: Optional[str] = None
    title: str
    status: str
    verdict: Optional[str] = None
    created_by: Optional[int] = None
    reviewed_at: Optional[datetime] = None
    case_public_id: Optional[str] = None
    created_at: datetime


class SavedReportDetail(SavedReportSummary):
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None
    filters: dict[str, Any] = Field(default_factory=dict)
    snapshot: dict[str, Any] = Field(default_factory=dict)
    conclusion: Optional[str] = None
    reviewed_by: Optional[int] = None
    row_count: int = 0
```

- [ ] **Step 4: Write the repository**

`reporting/report_repository.py`:

```python
"""PostgreSQL persistence for saved reports."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2.extras

from domain_profiling.connection import get_db_connection
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
        row["case_public_id"] = None
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
                    f"{_BASE_SELECT} {where} ORDER BY r.created_at DESC LIMIT %s OFFSET %s;",
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

    def review(self, public_id: str, *, status: str, verdict, conclusion,
               reviewer_id: int) -> Optional[SavedReportDetail]:
        with self._get_conn() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    UPDATE reports
                    SET status = %s, verdict = %s, conclusion = %s,
                        reviewed_by = %s, reviewed_at = NOW(), updated_at = NOW()
                    WHERE public_id = %s
                    RETURNING *;
                    """,
                    (status, verdict, conclusion, reviewer_id, public_id),
                )
                row = cur.fetchone()
            conn.commit()
        if not row:
            return None
        report = _detail(dict(row))
        return self.get(public_id) if report else None

    def archive(self, public_id: str) -> bool:
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE reports SET status = 'archived', updated_at = NOW() "
                    "WHERE public_id = %s AND status <> 'archived';",
                    (public_id,),
                )
                changed = cur.rowcount > 0
            conn.commit()
        return changed
```

- [ ] **Step 5: Run tests**

Run: `.venv/bin/python -m pytest tests/test_saved_reports_repository.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add reporting/report_schemas.py reporting/report_repository.py tests/test_saved_reports_repository.py
git commit -m "feat(reports): add saved report models and repository"
```

---

### Task 8: Snapshot builder and report service

**Files:**
- Create: `reporting/report_service.py`
- Test: `tests/test_report_service.py`

**Interfaces:**
- Produces: `ReportService(repository=None, investigation_service=None, reporting_service=None)`
- Produces: `ReportService.build_snapshot(kind, entity, window, start_time, end_time, filters, refresh=False) -> dict`
- Produces: `ReportService.create(...) -> SavedReportDetail`
- Produces: `ReportService.list_reports(...)`, `.get_report`, `.review_report`, `.archive_report`

- [ ] **Step 1: Write the failing tests**

```python
"""Snapshot composition without network or database."""

from types import SimpleNamespace

from reporting.report_service import ReportService


class _FakeInvestigation:
    def get_domain_dossier(self, domain, refresh_live=False):
        return SimpleNamespace(
            model_dump=lambda mode="json": {
                "domain": domain,
                "observed_in_network": False,
                "profile": None,
                "recent_queries": [],
                "live_intel": {"checked_at": "2026-11-10T00:00:00Z"},
            }
        )

    def get_client_dossier(self, client_ip, refresh_live=False):
        return SimpleNamespace(
            model_dump=lambda mode="json": {
                "client_ip": client_ip,
                "observed_in_network": True,
                "profile": None,
                "recent_queries": [],
                "live_intel": None,
            }
        )


class _FakeReporting:
    def get_summary(self, **kwargs):
        return SimpleNamespace(
            model_dump=lambda mode="json": {"total_queries": 0}
        )

    def get_timeseries(self, **kwargs):
        return SimpleNamespace(buckets=[])

    def get_queries(self, **kwargs):
        return SimpleNamespace(
            total=2,
            items=[SimpleNamespace(model_dump=lambda mode="json": {"id": 1})],
        )


def test_domain_snapshot_keeps_provenance_and_caps_rows():
    service = ReportService(
        investigation_service=_FakeInvestigation(),
        reporting_service=_FakeReporting(),
    )
    snapshot = service.build_snapshot(
        kind="entity_domain",
        entity="example.com",
        window=None,
        start_time=None,
        end_time=None,
        filters={},
    )

    assert snapshot["schema_version"] == 1
    assert snapshot["kind"] == "entity_domain"
    assert snapshot["entity"] == {"type": "domain", "value": "example.com"}
    assert snapshot["observed_in_network"] is False
    assert "live_intel" in snapshot["dossier"]
    assert snapshot["provenance"]["live_intel_checked_at"] == "2026-11-10T00:00:00Z"


def test_query_set_snapshot_records_filters_and_preview():
    service = ReportService(reporting_service=_FakeReporting())
    snapshot = service.build_snapshot(
        kind="query_set",
        entity=None,
        window="24h",
        start_time=None,
        end_time=None,
        filters={"verdict": "Malicious"},
    )

    assert snapshot["kind"] == "query_set"
    assert snapshot["filters"] == {"verdict": "Malicious"}
    assert snapshot["summary"]["total_queries"] == 0
    assert len(snapshot["preview_queries"]) == 1
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_report_service.py -q`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement the service**

`reporting/report_service.py`:

```python
"""Report snapshot composition and lifecycle."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from investigation.service import InvestigationService
from investigation.live.service import LiveIntelService
from time_engine import TemporalDefaultPolicy, format_iso8601_utc, resolve_time_range

from .report_repository import ReportRepository
from .report_schemas import ReportStatus, SavedReportDetail, SavedReportSummary
from .service import ReportingService

RECENT_QUERY_CAP = 500


class ReportService:
    def __init__(self, repository=None, investigation_service=None,
                 reporting_service=None) -> None:
        self.repository = repository or ReportRepository()
        self.investigation = investigation_service or InvestigationService(
            live_intel_service=LiveIntelService()
        )
        self.reporting = reporting_service or ReportingService()

    def _window(self, window, start_time, end_time):
        tr = resolve_time_range(
            window=window,
            start_time=start_time,
            end_time=end_time,
            default_policy=TemporalDefaultPolicy.ALL_TIME,
        )
        return tr

    def build_snapshot(self, *, kind, entity, window, start_time, end_time,
                       filters, refresh=False) -> dict[str, Any]:
        tr = self._window(window, start_time, end_time)
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
            recent = dossier_data.get("recent_queries") or []
            dossier_data["recent_queries"] = recent[:RECENT_QUERY_CAP]
            live = dossier_data.get("live_intel") or {}
            profile = dossier_data.get("profile") or {}

            summary = self.reporting.get_summary(
                window=window, start_time=start_time, end_time=end_time
            )
            try:
                series = self.reporting.get_timeseries(
                    window=window, start_time=start_time, end_time=end_time,
                    bucket="1h",
                )
                timeline = [bucket.model_dump(mode="json") for bucket in series.buckets]
            except Exception:
                # All-time entity reports have no valid timeseries; state it
                # rather than inventing an empty chart.
                timeline = []

            return {
                "schema_version": 1,
                "kind": kind,
                "entity": {"type": entity_type, "value": entity},
                "window": window_meta,
                "observed_in_network": dossier_data.get("observed_in_network", False),
                "row_count": int(profile.get("total_queries") or 0),
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

        summary = self.reporting.get_summary(
            window=window, start_time=start_time, end_time=end_time
        )
        preview = self.reporting.get_queries(
            verdict=filters.get("verdict"),
            search=filters.get("search"),
            client_ip=filters.get("client_ip"),
            domain=filters.get("domain"),
            query_type=filters.get("query_type"),
            window=window,
            start_time=start_time,
            end_time=end_time,
            limit=RECENT_QUERY_CAP,
            offset=0,
        )
        return {
            "schema_version": 1,
            "kind": "query_set",
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
        snapshot = self.build_snapshot(
            kind=kind, entity=entity, window=window, start_time=start_time,
            end_time=end_time, filters=filters, refresh=refresh,
        )
        entity_type = snapshot["entity"]["type"] if snapshot.get("entity") else None
        row_count = (
            snapshot["row_count"] if "row_count" in snapshot
            else len(snapshot.get("preview_queries", []))
        )
        tr = self._window(window, start_time, end_time)
        return self.repository.create(
            kind=kind,
            entity_type=entity_type,
            entity_value=entity,
            title=title or entity or "Query set report",
            window_start=tr.start,
            window_end=tr.end,
            filters=filters,
            snapshot=snapshot,
            row_count=row_count,
            created_by=user_id,
        )

    def list_reports(self, **kwargs):
        return self.repository.list(**kwargs)

    def get_report(self, public_id: str) -> Optional[SavedReportDetail]:
        return self.repository.get(public_id)

    def review_report(self, public_id: str, *, status: str, verdict,
                      conclusion, reviewer_id: int) -> Optional[SavedReportDetail]:
        if status == ReportStatus.REVIEWED.value and not (conclusion or "").strip():
            raise ValueError("A conclusion is required to mark a report reviewed.")
        return self.repository.review(
            public_id, status=status, verdict=verdict,
            conclusion=conclusion, reviewer_id=reviewer_id,
        )

    def archive_report(self, public_id: str) -> bool:
        return self.repository.archive(public_id)
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/python -m pytest tests/test_report_service.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add reporting/report_service.py tests/test_report_service.py
git commit -m "feat(reports): compose immutable report snapshots"
```

---

### Task 9: Saved-report routes, permissions, and audit

**Files:**
- Create: `api/schemas/reports_saved.py`
- Create: `api/routes/reports_saved.py`
- Modify: `api/schemas/__init__.py`
- Modify: `api/main.py:35-55, 160-170`
- Modify: `api/rbac.py:30-95`
- Test: `tests/test_saved_reports_api.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Saved report API behavior and role gates."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_analyst_can_create_and_review_a_report(analyst_headers):
    res = client.post(
        "/api/v1/reports/saved",
        headers=analyst_headers,
        json={"kind": "query_set", "window": "24h", "filters": {"search": "a"}},
    )
    assert res.status_code == 201
    public_id = res.json()["public_id"]
    assert public_id.startswith("RPT-")

    reviewed = client.patch(
        f"/api/v1/reports/saved/{public_id}/review",
        headers=analyst_headers,
        json={"status": "reviewed", "verdict": "Review Needed",
              "conclusion": "Needs follow-up."},
    )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "reviewed"


def test_review_requires_a_conclusion(analyst_headers):
    created = client.post(
        "/api/v1/reports/saved",
        headers=analyst_headers,
        json={"kind": "query_set", "window": "24h", "filters": {"search": "a"}},
    )
    public_id = created.json()["public_id"]
    res = client.patch(
        f"/api/v1/reports/saved/{public_id}/review",
        headers=analyst_headers,
        json={"status": "reviewed", "verdict": "Unknown", "conclusion": ""},
    )
    assert res.status_code == 400


def test_support_cannot_create_reports(support_headers):
    res = client.post(
        "/api/v1/reports/saved",
        headers=support_headers,
        json={"kind": "query_set", "window": "24h", "filters": {"search": "a"}},
    )
    assert res.status_code == 403
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_saved_reports_api.py -q`
Expected: FAIL — 404 (router not mounted).

- [ ] **Step 3: Add permissions**

In `api/rbac.py`, add `"reports:write"` to ADMIN and ANALYST, `"cases:read"` to all three, `"cases:write"` to ADMIN and ANALYST, `"cases:manage"` to ADMIN only. SUPER_ADMIN inherits ADMIN.

- [ ] **Step 4: Add request schemas**

`api/schemas/reports_saved.py`:

```python
"""HTTP contracts for saved reports."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from reporting.report_schemas import ReportKind, ReportStatus, SavedReportDetail, SavedReportSummary


class ReportCreateRequest(BaseModel):
    kind: ReportKind
    entity: Optional[str] = None
    window: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    filters: dict[str, Any] = Field(default_factory=dict)
    title: Optional[str] = None
    refresh: bool = False


class ReportReviewRequest(BaseModel):
    status: ReportStatus
    verdict: Optional[str] = None
    conclusion: Optional[str] = None


class ReportListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[SavedReportSummary]


__all__ = [
    "ReportCreateRequest", "ReportReviewRequest", "ReportListResponse",
    "SavedReportDetail", "SavedReportSummary",
]
```

Export it from `api/schemas/__init__.py`.

- [ ] **Step 5: Implement the routes**

`api/routes/reports_saved.py`:

```python
"""Saved reports: create, list, review, archive, link to a case."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from api.audit import AuditAction, log_audit_event
from api.rbac import require_permission
from api.schemas.reports_saved import (
    ReportCreateRequest, ReportListResponse, ReportReviewRequest,
    SavedReportDetail, SavedReportSummary,
)
from reporting.report_schemas import ReportStatus
from reporting.report_service import ReportService

router = APIRouter(prefix="/api/v1/reports/saved", tags=["Saved Reports"])


def _audit(action, request, user, public_id, **metadata):
    log_audit_event(
        action=action,
        user_id=user["id"],
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        target_type="report",
        target_id=public_id,
        metadata=metadata,
    )


@router.post("", response_model=SavedReportDetail, status_code=201)
def create_report(
    payload: ReportCreateRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("reports:write")),
):
    service = ReportService()
    try:
        report = service.create(
            kind=payload.kind.value,
            entity=payload.entity,
            window=payload.window,
            start_time=payload.start_time,
            end_time=payload.end_time,
            filters=payload.filters,
            title=payload.title,
            user_id=current_user["id"],
            refresh=payload.refresh,
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _audit(AuditAction.REPORT_CREATED, request, current_user, report.public_id,
           kind=report.kind, entity=report.entity_value)
    return report


@router.get("", response_model=ReportListResponse)
def list_reports(
    status_filter: Optional[str] = Query(None, alias="status"),
    kind: Optional[str] = Query(None),
    entity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: dict[str, Any] = Depends(require_permission("reports:read")),
):
    total, items = ReportService().list_reports(
        status=status_filter, kind=kind, entity=entity,
        limit=limit, offset=offset,
    )
    return ReportListResponse(total=total, limit=limit, offset=offset, items=items)


@router.get("/{public_id}", response_model=SavedReportDetail)
def get_report(
    public_id: str,
    current_user: dict[str, Any] = Depends(require_permission("reports:read")),
):
    report = ReportService().get_report(public_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")
    return report


@router.patch("/{public_id}/review", response_model=SavedReportDetail)
def review_report(
    public_id: str,
    payload: ReportReviewRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("reports:write")),
):
    service = ReportService()
    try:
        report = service.review_report(
            public_id,
            status=payload.status.value,
            verdict=payload.verdict,
            conclusion=payload.conclusion,
            reviewer_id=current_user["id"],
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    _audit(AuditAction.REPORT_REVIEWED, request, current_user, public_id,
           status=payload.status.value, verdict=payload.verdict)
    return report


@router.post("/{public_id}/archive", status_code=204)
def archive_report(
    public_id: str,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("reports:write")),
):
    if not ReportService().archive_report(public_id):
        raise HTTPException(status_code=404, detail="Report not found.")
    _audit(AuditAction.REPORT_ARCHIVED, request, current_user, public_id)
    return None
```

- [ ] **Step 6: Mount the router**

In `api/main.py`:

```python
from api.routes.reports_saved import router as reports_saved_router
...
app.include_router(reports_saved_router)
```

- [ ] **Step 7: Run tests**

Run: `.venv/bin/python -m pytest tests/test_saved_reports_api.py tests/test_auth_complete.py -q`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add api/schemas/reports_saved.py api/schemas/__init__.py api/routes/reports_saved.py api/main.py api/rbac.py tests/test_saved_reports_api.py
git commit -m "feat(api): add saved report routes and permissions"
```

---

## Phase 2 — Exports

### Task 10: CSV long format, XLSX writer, and export routes

**Files:**
- Modify: `reporting/exporters.py`
- Modify: `requirements.txt`
- Modify: `api/routes/reports_saved.py`
- Modify: `api/routes/reports.py`
- Test: `tests/test_reporting_exports.py`

**Interfaces:**
- Produces: `snapshot_csv_chunks(snapshot: dict) -> Iterator[str]`
- Produces: `build_xlsx(snapshot: dict) -> bytes`
- Produces: `POST /api/v1/reports/saved/{public_id}/export?format=csv|xlsx`
- Produces: `GET /api/v1/reports/entity/export?entity=...&format=csv|xlsx`

- [ ] **Step 1: Write the failing tests**

```python
"""Entity CSV/XLSX export shape."""

from io import BytesIO

from reporting.exporters import build_xlsx, snapshot_csv_chunks

SNAPSHOT = {
    "schema_version": 1,
    "kind": "entity_domain",
    "entity": {"type": "domain", "value": "=evil.example"},
    "window": {"start": None, "end": None, "label": "all time"},
    "observed_in_network": False,
    "dossier": {
        "domain": "=evil.example",
        "observed_in_network": False,
        "profile": {"total_queries": 7, "unique_clients": 2},
        "recent_queries": [
            {"timestamp": "2026-11-10T00:00:00Z", "client_ip": "10.0.0.5",
             "domain": "=evil.example", "query_type": "A",
             "final_label": "Malicious", "ti_source": "@feed"}
        ],
        "live_intel": {"checked_at": "2026-11-10T00:00:00Z", "verdict": {"state": "malicious"}},
    },
    "provenance": {"sources": ["domain_query_history"]},
}


def test_entity_csv_sanitizes_formula_cells():
    csv_text = "".join(snapshot_csv_chunks(SNAPSHOT))
    assert "'=evil.example" in csv_text
    assert "'@feed" in csv_text
    assert csv_text.startswith("section,field,value,source,checked_at")


def test_xlsx_has_the_six_sheets_and_safe_text():
    from openpyxl import load_workbook

    data = build_xlsx(SNAPSHOT)
    workbook = load_workbook(BytesIO(data))
    assert workbook.sheetnames == [
        "Summary", "Timeline", "Relationships", "Queries", "Intelligence", "Assessment"
    ]
    values = [cell.value for row in workbook["Queries"].iter_rows() for cell in row]
    assert "'=evil.example" in values
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_reporting_exports.py -q`
Expected: FAIL — `snapshot_csv_chunks`/`build_xlsx` missing.

- [ ] **Step 3: Add openpyxl**

`requirements.txt`: add `openpyxl>=3.1,<4`, then `.venv/bin/pip install "openpyxl>=3.1,<4"`.

- [ ] **Step 4: Implement the writers**

Append to `reporting/exporters.py`:

```python
import csv
import io
from typing import Iterator

from openpyxl import Workbook


def _safe(value):
    return sanitize_csv_cell(value)


def snapshot_csv_chunks(snapshot: dict) -> Iterator[str]:
    fields = ["section", "field", "value", "source", "checked_at"]
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields)
    writer.writeheader()
    yield buffer.getvalue()

    entity = (snapshot.get("entity") or {}).get("value")
    window = snapshot.get("window") or {}
    rows = [
        ("summary", "entity", entity, "telemetry", window.get("start")),
        ("summary", "window", window.get("label"), "request", None),
        ("summary", "observed_in_network", snapshot.get("observed_in_network"), "telemetry", None),
    ]
    dossier = snapshot.get("dossier") or {}
    for key in ("total_queries", "unique_clients", "unique_domains"):
        rows.append(("profile", key, (dossier.get("profile") or {}).get(key), "domain_query_history", None))
    live = dossier.get("live_intel") or {}
    rows.append(("intelligence", "live_verdict", (live.get("verdict") or {}).get("state"), "live_intel", live.get("checked_at")))

    for row in rows:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writerow({k: _safe(v) for k, v in zip(fields, row)})
        yield buffer.getvalue()

    for query in dossier.get("recent_queries") or []:
        values = (
            "queries",
            "event",
            f"{query.get('timestamp')} {query.get('client_ip')} {query.get('domain')}",
            query.get("ti_source"),
            query.get("timestamp"),
        )
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=fields)
        writer.writerow({k: _safe(v) for k, v in zip(fields, values)})
        yield buffer.getvalue()


def build_xlsx(snapshot: dict) -> bytes:
        dossier = snapshot.get("dossier") or {}
        live = dossier.get("live_intel") or {}
        workbook = Workbook(write_only=True)

        summary = workbook.create_sheet("Summary")
        summary.append(["Field", "Value"])
        summary.append(["Entity", _safe((snapshot.get("entity") or {}).get("value"))])
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
        for item in dossier.get("top_clients") or dossier.get("top_domains") or []:
            relationships.append([_safe(item.get("client_ip") or item.get("domain")),
                                  item.get("total_queries"), item.get("last_seen")])

        queries = workbook.create_sheet("Queries")
        queries.append(["Timestamp", "Client IP", "Domain", "Type", "Verdict", "Source"])
        for query in dossier.get("recent_queries") or []:
            queries.append([
                query.get("timestamp"), _safe(query.get("client_ip")),
                _safe(query.get("domain")), query.get("query_type"),
                query.get("final_label"), _safe(query.get("ti_source")),
            ])

        intelligence = workbook.create_sheet("Intelligence")
        intelligence.append(["Field", "Value", "Checked at"])
        intelligence.append(["Verdict", (live.get("verdict") or {}).get("state"), live.get("checked_at")])
        for provider in live.get("providers") or []:
            intelligence.append([_safe(provider.get("provider")),
                                 provider.get("status"), live.get("checked_at")])

        assessment = workbook.create_sheet("Assessment")
        assessment.append(["Generated at", (snapshot.get("provenance") or {}).get("generated_at")])
        assessment.append(["Sources", ", ".join((snapshot.get("provenance") or {}).get("sources") or [])])

        buffer = io.BytesIO()
        workbook.save(buffer)
        return buffer.getvalue()
```

- [ ] **Step 5: Add the saved-report export route**

In `api/routes/reports_saved.py`:

```python
from fastapi.responses import Response, StreamingResponse
from reporting.exporters import build_xlsx, snapshot_csv_chunks


@router.post("/{public_id}/export")
def export_report(
    public_id: str,
    request: Request,
    format: str = Query("csv", pattern="^(csv|xlsx)$"),
    current_user: dict[str, Any] = Depends(require_permission("reports:export")),
):
    report = ReportService().get_report(public_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found.")

    _audit(AuditAction.REPORT_EXPORTED, request, current_user, public_id, format=format)

    filename = f"dnsnetra_{public_id}.{format}"
    if format == "xlsx":
        data = build_xlsx(report.snapshot)
        return Response(
            content=data,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="{filename}"',
                     "Cache-Control": "no-store"},
        )
    return StreamingResponse(
        snapshot_csv_chunks(report.snapshot),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "Cache-Control": "no-store"},
    )
```

- [ ] **Step 6: Add the one-shot entity export**

In `api/routes/reports.py`:

```python
from reporting.exporters import build_xlsx, snapshot_csv_chunks
from reporting.report_service import ReportService


@router.get("/entity/export")
def export_entity_report(
    request: Request,
    entity: str = Query(..., min_length=1),
    entity_type: Optional[str] = Query(None),
    format: str = Query("csv", pattern="^(csv|xlsx)$"),
    current_user: dict[str, Any] = Depends(require_permission("reports:export")),
):
    effective = (entity_type or ("client" if _is_ip(entity) else "domain")).lower()
    required = "domains:investigate" if effective == "domain" else "clients:investigate"
    from api.rbac import has_permission
    if not has_permission(current_user["role"], required):
        raise HTTPException(status_code=403, detail=f"Missing permission '{required}'.")

    service = ReportService()
    snapshot = service.build_snapshot(
        kind=f"entity_{effective}", entity=entity.strip(),
        window=None, start_time=None, end_time=None, filters={},
    )
    log_audit_event(
        action=AuditAction.REPORT_EXPORTED, user_id=current_user["id"],
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        target_type="export", target_id=entity.strip(),
        metadata={"format": format, "one_shot": True},
    )
    filename = f"dnsnetra_{effective}_{entity.strip().replace('/', '_')}.{format}"
    if format == "xlsx":
        return Response(
            content=build_xlsx(snapshot),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": f'attachment; filename="{filename}"',
                     "Cache-Control": "no-store"},
        )
    return StreamingResponse(
        snapshot_csv_chunks(snapshot),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"',
                 "Cache-Control": "no-store"},
    )


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
```

Add the imports for `Response`, `AuditAction`, and `log_audit_event` at the top of `reports.py`.

- [ ] **Step 7: Run tests**

Run: `.venv/bin/python -m pytest tests/test_reporting_exports.py tests/test_saved_reports_api.py -q`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add reporting/exporters.py requirements.txt api/routes/reports_saved.py api/routes/reports.py tests/test_reporting_exports.py
git commit -m "feat(exports): add entity CSV and XLSX exports"
```

---

### Task 11: Frontend report types, API client, and report library

**Files:**
- Create: `frontend/lib/reporting/types.ts`
- Modify: `frontend/lib/data-table/api-client.ts`
- Create: `frontend/app/(dashboard)/reports/saved/page.tsx`
- Test: `frontend/tests/saved-reports.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
import { render, screen, waitFor } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import SavedReportsPage from "@/app/(dashboard)/reports/saved/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }))

describe("SavedReportsPage", () => {
  beforeEach(() => vi.restoreAllMocks())

  it("lists saved reports", async () => {
    vi.spyOn(dnsnetraApi, "listSavedReports").mockResolvedValue({
      total: 1,
      limit: 50,
      offset: 0,
      items: [{
        public_id: "RPT-2026-000001",
        kind: "entity_domain",
        entity_type: "domain",
        entity_value: "example.com",
        title: "example.com review",
        status: "reviewed",
        verdict: "Malicious",
        created_by: 1,
        reviewed_at: "2026-11-10T00:00:00Z",
        case_public_id: null,
        created_at: "2026-11-10T00:00:00Z",
      }],
    })

    render(<SavedReportsPage />)
    expect(await screen.findByText("example.com review")).toBeInTheDocument()
    expect(screen.getByText("RPT-2026-000001")).toBeInTheDocument()
    await waitFor(() => expect(dnsnetraApi.listSavedReports).toHaveBeenCalled())
  })

  it("shows an empty state", async () => {
    vi.spyOn(dnsnetraApi, "listSavedReports").mockResolvedValue({
      total: 0, limit: 50, offset: 0, items: [],
    })
    render(<SavedReportsPage />)
    expect(await screen.findByText("No saved reports yet.")).toBeInTheDocument()
  })
})
```

- [ ] **Step 2: Run it to verify failure**

Run: `cd frontend && pnpm vitest run tests/saved-reports.test.tsx`
Expected: FAIL — page and API method missing.

- [ ] **Step 3: Add types and API methods**

`frontend/lib/reporting/types.ts`:

```ts
export interface SavedReportSummary {
  public_id: string
  kind: string
  entity_type?: string | null
  entity_value?: string | null
  title: string
  status: string
  verdict?: string | null
  created_by?: number | null
  reviewed_at?: string | null
  case_public_id?: string | null
  created_at: string
}

export interface SavedReportDetail extends SavedReportSummary {
  window_start?: string | null
  window_end?: string | null
  filters: Record<string, unknown>
  snapshot: Record<string, any>
  conclusion?: string | null
  reviewed_by?: number | null
  row_count: number
}

export interface SavedReportList {
  total: number
  limit: number
  offset: number
  items: SavedReportSummary[]
}
```

Add to `dnsnetraApi` in `frontend/lib/data-table/api-client.ts`:

```ts
async listSavedReports(params: { status?: string; kind?: string; entity?: string; limit?: number; offset?: number } = {}): Promise<import("@/lib/reporting/types").SavedReportList> {
  return apiFetch("/api/v1/reports/saved", params)
},

async getSavedReport(publicId: string): Promise<import("@/lib/reporting/types").SavedReportDetail> {
  return apiFetch(`/api/v1/reports/saved/${encodeURIComponent(publicId)}`)
},

async createSavedReport(body: {
  kind: "entity_domain" | "entity_client" | "query_set"
  entity?: string
  window?: string
  start_time?: string
  end_time?: string
  filters?: Record<string, unknown>
  title?: string
  refresh?: boolean
}): Promise<import("@/lib/reporting/types").SavedReportDetail> {
  return apiFetch("/api/v1/reports/saved", {}, { method: "POST", body })
},

async reviewSavedReport(publicId: string, body: {
  status: "draft" | "needs_review" | "reviewed" | "archived"
  verdict?: string
  conclusion?: string
}): Promise<import("@/lib/reporting/types").SavedReportDetail> {
  return apiFetch(`/api/v1/reports/saved/${encodeURIComponent(publicId)}/review`, {}, { method: "PATCH", body })
},

async downloadSavedReport(publicId: string, format: "csv" | "xlsx"): Promise<void> {
  const url = new URL(`/api/v1/reports/saved/${encodeURIComponent(publicId)}/export`, currentApiBase)
  url.searchParams.set("format", format)
  const res = await fetch(url.toString(), { method: "POST", credentials: "include", cache: "no-store" })
  if (!res.ok) throw new ApiError(res.status, `Export failed (${res.status})`)
  const blob = await res.blob()
  const link = document.createElement("a")
  link.href = URL.createObjectURL(blob)
  link.download = `dnsnetra_${publicId}.${format}`
  link.click()
  URL.revokeObjectURL(link.href)
},
```

- [ ] **Step 4: Build the library page**

`frontend/app/(dashboard)/reports/saved/page.tsx`:

```tsx
"use client"

import * as React from "react"
import Link from "next/link"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { SavedReportSummary } from "@/lib/reporting/types"

export default function SavedReportsPage() {
  const [items, setItems] = React.useState<SavedReportSummary[]>([])
  const [loading, setLoading] = React.useState(true)

  React.useEffect(() => {
    dnsnetraApi
      .listSavedReports({ limit: 50 })
      .then((res) => setItems(res.items))
      .catch(() => toast.error("Failed to load saved reports."))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold tracking-tight">Saved Reports</h2>
          <p className="text-sm text-muted-foreground">
            Immutable snapshots created from dossiers and query sets.
          </p>
        </div>
        <Button variant="outline" size="sm" render={<Link href="/reports" />}>
          Back to telemetry
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Library</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <p className="p-4 text-sm text-muted-foreground">Loading reports…</p>
          ) : items.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No saved reports yet.</p>
          ) : (
            <div className="divide-y divide-border/60">
              {items.map((report) => (
                <Link
                  key={report.public_id}
                  href={`/reports/saved/${encodeURIComponent(report.public_id)}`}
                  className="flex items-center justify-between gap-3 p-3 transition-colors hover:bg-muted/50"
                >
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{report.title}</p>
                    <p className="font-mono text-[11px] text-muted-foreground">
                      {report.public_id} · {report.entity_value ?? report.kind}
                    </p>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {report.case_public_id && (
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {report.case_public_id}
                      </Badge>
                    )}
                    <Badge variant="outline">{report.status}</Badge>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
```

Base UI buttons take `render`, not `asChild`; the code above uses `render`.

- [ ] **Step 5: Run tests and typecheck**

Run: `cd frontend && pnpm vitest run tests/saved-reports.test.tsx && npx tsc --noEmit`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add frontend/lib/reporting/types.ts frontend/lib/data-table/api-client.ts "frontend/app/(dashboard)/reports/saved/page.tsx" frontend/tests/saved-reports.test.tsx
git commit -m "feat(ui): add saved report library"
```

---

### Task 12: Report detail, review, and export UI

**Files:**
- Create: `frontend/app/(dashboard)/reports/saved/[public_id]/page.tsx`
- Test: `frontend/tests/report-detail.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
import { fireEvent, render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import ReportDetailPage from "@/app/(dashboard)/reports/saved/[public_id]/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"

vi.mock("next/navigation", () => ({
  useParams: () => ({ public_id: "RPT-2026-000001" }),
}))

const report = {
  public_id: "RPT-2026-000001",
  kind: "entity_domain",
  entity_type: "domain",
  entity_value: "example.com",
  title: "example.com review",
  status: "draft",
  verdict: null,
  conclusion: null,
  row_count: 4,
  filters: {},
  snapshot: {
    schema_version: 1,
    kind: "entity_domain",
    entity: { type: "domain", value: "example.com" },
    observed_in_network: false,
    dossier: {
      domain: "example.com",
      profile: { total_queries: 7, unique_clients: 2 },
      recent_queries: [],
      live_intel: { verdict: { state: "unknown" }, checked_at: "2026-11-10T00:00:00Z" },
    },
    provenance: { sources: ["domain_query_history"] },
  },
  created_at: "2026-11-10T00:00:00Z",
}

describe("ReportDetailPage", () => {
  beforeEach(() => vi.restoreAllMocks())

  it("renders the snapshot and marks it reviewed", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue(report as any)
    vi.spyOn(dnsnetraApi, "reviewSavedReport").mockResolvedValue({
      ...report,
      status: "reviewed",
    } as any)

    render(<ReportDetailPage />)
    expect(await screen.findByText(/example\.com/)).toBeInTheDocument()
    expect(screen.getByText("No local telemetry for this window.")).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText("Conclusion"), {
      target: { value: "Not observed locally." },
    })
    fireEvent.click(screen.getByRole("button", { name: "Mark reviewed" }))

    expect(await screen.findByText("reviewed")).toBeInTheDocument()
  })

  it("exports XLSX", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue(report as any)
    const spy = vi.spyOn(dnsnetraApi, "downloadSavedReport").mockResolvedValue()
    render(<ReportDetailPage />)
    fireEvent.click(await screen.findByRole("button", { name: "Export XLSX" }))
    expect(spy).toHaveBeenCalledWith("RPT-2026-000001", "xlsx")
  })
})
```

- [ ] **Step 2: Run it to verify failure**

Run: `cd frontend && pnpm vitest run tests/report-detail.test.tsx`
Expected: FAIL — page missing.

- [ ] **Step 3: Build the detail page**

```tsx
"use client"

import * as React from "react"
import { useParams } from "next/navigation"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { SavedReportDetail } from "@/lib/reporting/types"

export default function ReportDetailPage() {
  const params = useParams<{ public_id: string }>()
  const publicId = decodeURIComponent(params.public_id)
  const [report, setReport] = React.useState<SavedReportDetail | null>(null)
  const [conclusion, setConclusion] = React.useState("")
  const [saving, setSaving] = React.useState(false)

  React.useEffect(() => {
    dnsnetraApi
      .getSavedReport(publicId)
      .then(setReport)
      .catch(() => toast.error("Failed to load report."))
  }, [publicId])

  async function markReviewed() {
    if (!report) return
    setSaving(true)
    try {
      const updated = await dnsnetraApi.reviewSavedReport(publicId, {
        status: "reviewed",
        conclusion,
        verdict: report.verdict ?? undefined,
      })
      setReport(updated)
      toast.success("Report marked reviewed.")
    } catch {
      toast.error("Review failed.")
    } finally {
      setSaving(false)
    }
  }

  if (!report) {
    return <p className="p-6 text-sm text-muted-foreground">Loading report…</p>
  }

  const dossier = report.snapshot.dossier ?? {}
  const profile = dossier.profile ?? {}
  const live = dossier.live_intel ?? {}

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{report.title}</h1>
          <p className="font-mono text-[11px] text-muted-foreground">
            {report.public_id} · {report.kind} · {report.created_at}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => dnsnetraApi.downloadSavedReport(publicId, "csv")}>
            Export CSV
          </Button>
          <Button variant="outline" size="sm" onClick={() => dnsnetraApi.downloadSavedReport(publicId, "xlsx")}>
            Export XLSX
          </Button>
          <Badge variant="outline">{report.status}</Badge>
        </div>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader><CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">Total queries</CardTitle></CardHeader>
          <CardContent><p className="font-mono text-2xl font-semibold">{profile.total_queries ?? 0}</p></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">Unique clients</CardTitle></CardHeader>
          <CardContent><p className="font-mono text-2xl font-semibold">{profile.unique_clients ?? 0}</p></CardContent>
        </Card>
        <Card>
          <CardHeader><CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">Live verdict</CardTitle></CardHeader>
          <CardContent><p className="font-mono text-2xl font-semibold">{live.verdict?.state ?? "n/a"}</p></CardContent>
        </Card>
      </div>

      {report.snapshot.observed_in_network === false && (
        <p className="text-sm text-muted-foreground">No local telemetry for this window.</p>
      )}

      <Card>
        <CardHeader><CardTitle className="text-sm">Analyst assessment</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-3">
          <label htmlFor="conclusion" className="text-sm font-medium">Conclusion</label>
          <Input
            id="conclusion"
            value={conclusion}
            onChange={(event) => setConclusion(event.target.value)}
            placeholder="What did you conclude?"
          />
          <div>
            <Button size="sm" onClick={markReviewed} disabled={saving || !conclusion.trim()}>
              Mark reviewed
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `cd frontend && pnpm vitest run tests/report-detail.test.tsx && npx tsc --noEmit`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add "frontend/app/(dashboard)/reports/saved/[public_id]/page.tsx" frontend/tests/report-detail.test.tsx
git commit -m "feat(ui): add report detail, review, and export"
```

---

## Phase 3 — Cases

### Task 13: Case schemas, repository, and state machine

**Files:**
- Create: `cases/__init__.py`
- Create: `cases/schemas.py`
- Create: `cases/repository.py`
- Create: `cases/service.py`
- Test: `tests/test_cases_service.py`

**Interfaces:**
- Produces: `CaseStatus`, `CasePriority`, `CaseResolution`, `CaseEventKind`
- Produces: `CaseService.create/update/add_comment/link_report/get/list`
- Produces: `validate_transition(current, next_status, resolution, can_manage) -> None`

- [ ] **Step 1: Write the failing tests**

```python
"""Case lifecycle rules without a database."""

import pytest

from cases.schemas import CasePriority, CaseResolution, CaseStatus
from cases.service import InvalidTransition, CaseService


@pytest.mark.parametrize("current,next_status", [
    ("open", "triaged"),
    ("triaged", "investigating"),
    ("investigating", "awaiting_info"),
    ("awaiting_info", "resolved"),
    ("resolved", "closed"),
])
def test_allowed_transitions(current, next_status):
    CaseService.validate_transition(
        current=current,
        next_status=next_status,
        resolution="true_positive" if next_status == "resolved" else None,
        can_manage=True,
    )


@pytest.mark.parametrize("current,next_status", [
    ("open", "resolved"),
    ("closed", "investigating"),
    ("open", "awaiting_info"),
])
def test_invalid_transitions(current, next_status):
    with pytest.raises(InvalidTransition):
        CaseService.validate_transition(
            current=current,
            next_status=next_status,
            resolution="benign",
            can_manage=False,
        )


def test_resolving_requires_a_resolution():
    with pytest.raises(ValueError):
        CaseService.validate_transition(
            current="investigating", next_status="resolved",
            resolution=None, can_manage=True,
        )


def test_closing_requires_manage():
    with pytest.raises(PermissionError):
        CaseService.validate_transition(
            current="resolved", next_status="closed",
            resolution=None, can_manage=False,
        )


def test_reopening_closed_requires_manage():
    with pytest.raises(PermissionError):
        CaseService.validate_transition(
            current="closed", next_status="investigating",
            resolution=None, can_manage=False,
        )
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_cases_service.py -q`
Expected: FAIL — package missing.

- [ ] **Step 3: Write the schemas**

`cases/schemas.py`:

```python
"""Case and timeline contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


class CaseStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    AWAITING_INFO = "awaiting_info"
    RESOLVED = "resolved"
    CLOSED = "closed"


class CasePriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseResolution(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    DUPLICATE = "duplicate"
    NO_ACTION = "no_action"


class CaseEventKind(str, Enum):
    CREATED = "created"
    COMMENT = "comment"
    STATUS_CHANGED = "status_changed"
    ASSIGNED = "assigned"
    PRIORITY_CHANGED = "priority_changed"
    RESOLUTION_SET = "resolution_set"
    REPORT_LINKED = "report_linked"
    REPORT_UNLINKED = "report_unlinked"


class CaseEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    kind: str
    actor_id: Optional[int] = None
    body: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class CaseSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int = Field(exclude=True)
    public_id: str
    title: str
    status: str
    priority: str
    entity_type: Optional[str] = None
    entity_value: Optional[str] = None
    assigned_to: Optional[int] = None
    created_by: Optional[int] = None
    resolution: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CaseDetail(CaseSummary):
    description: Optional[str] = None
    resolved_by: Optional[int] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    events: list[CaseEvent] = Field(default_factory=list)
    reports: list[str] = Field(default_factory=list)
```

- [ ] **Step 4: Write the repository**

`cases/repository.py`:

```python
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
```

- [ ] **Step 5: Write the service and state machine**

`cases/service.py`:

```python
"""Case lifecycle and timeline orchestration."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .repository import CaseRepository
from .schemas import CaseDetail, CasePriority, CaseResolution, CaseStatus


class InvalidTransition(ValueError):
    pass


ALLOWED = {
    "open": {"triaged", "closed"},
    "triaged": {"investigating", "awaiting_info", "resolved", "closed"},
    "investigating": {"awaiting_info", "resolved", "closed"},
    "awaiting_info": {"investigating", "resolved", "closed"},
    "resolved": {"closed", "investigating"},
    "closed": {"investigating"},
}
MANAGE_ONLY_TARGETS = {"closed"}
MANAGE_ONLY_SOURCES = {"closed"}


class CaseService:
    def __init__(self, repository=None) -> None:
        self.repository = repository or CaseRepository()

    @staticmethod
    def validate_transition(*, current: str, next_status: str,
                            resolution: Optional[str], can_manage: bool) -> None:
        if next_status not in ALLOWED.get(current, set()):
            raise InvalidTransition(
                f"Cannot move case from '{current}' to '{next_status}'. "
                f"Allowed: {sorted(ALLOWED.get(current, set()))}."
            )
        if next_status == "resolved" and not resolution:
            raise ValueError("A resolution is required to resolve a case.")
        if next_status == "resolved" and resolution not in {r.value for r in CaseResolution}:
            raise ValueError(f"Invalid resolution '{resolution}'.")
        if next_status in MANAGE_ONLY_TARGETS or current in MANAGE_ONLY_SOURCES:
            if not can_manage:
                raise PermissionError("This transition requires cases:manage.")

    def create(self, *, title, description, priority, entity_type,
               entity_value, created_by, assigned_to=None) -> CaseDetail:
        if priority not in {p.value for p in CasePriority}:
            raise ValueError(f"Invalid priority '{priority}'.")
        return self.repository.create(
            title=title, description=description, priority=priority,
            entity_type=entity_type, entity_value=entity_value,
            created_by=created_by, assigned_to=assigned_to,
        )

    def update(self, public_id: str, *, actor_id: int, can_manage: bool,
               payload: dict[str, Any]) -> CaseDetail:
        case = self.repository.get(public_id)
        if not case:
            raise LookupError("Case not found.")

        next_status = payload.get("status", case.status)
        resolution = payload.get("resolution", case.resolution)

        if next_status != case.status:
            self.validate_transition(
                current=case.status, next_status=next_status,
                resolution=resolution, can_manage=can_manage,
            )

        fields = dict(payload)
        if next_status == "resolved":
            fields["resolved_by"] = actor_id
            fields["resolved_at"] = datetime.now(timezone.utc)
        if next_status == "closed":
            fields["closed_at"] = datetime.now(timezone.utc)
        if case.status in ("resolved", "closed") and next_status == "investigating":
            fields["closed_at"] = None

        updated = self.repository.update(public_id, fields)
        if not updated:
            raise LookupError("Case not found.")

        if next_status != case.status:
            self.repository.add_event(
                updated.id,
                actor_id=actor_id, kind="status_changed",
                metadata={"from": case.status, "to": next_status,
                          "resolution": resolution},
            )
        return updated

    def add_comment(self, public_id: str, *, actor_id: int, body: str) -> CaseDetail:
        case = self.repository.get(public_id)
        if not case:
            raise LookupError("Case not found.")
        self.repository.add_event(
            case.id, actor_id=actor_id, kind="comment", body=body
        )
        return self.repository.get(public_id)
```

- [ ] **Step 6: Run tests**

Run: `.venv/bin/python -m pytest tests/test_cases_service.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add cases/__init__.py cases/schemas.py cases/repository.py cases/service.py tests/test_cases_service.py
git commit -m "feat(cases): add case lifecycle and repository"
```

---

### Task 14: Case routes, permissions, audit, and report linking

**Files:**
- Create: `api/schemas/cases.py`
- Create: `api/routes/cases.py`
- Modify: `api/main.py`
- Modify: `api/rbac.py` (already has permissions from Task 9)
- Test: `tests/test_cases_api.py`

- [ ] **Step 1: Write the failing tests**

```python
"""Case API workflow."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def _create(analyst_headers, **overrides):
    payload = {
        "title": "Investigate beacon.example",
        "priority": "high",
        "entity_type": "domain",
        "entity_value": "beacon.example",
    }
    payload.update(overrides)
    return client.post("/api/v1/cases", headers=analyst_headers, json=payload)


def test_analyst_creates_self_assigns_and_resolves(analyst_headers):
    created = _create(analyst_headers)
    assert created.status_code == 201
    public_id = created.json()["public_id"]
    assert public_id.startswith("CASE-")

    me = client.get("/api/v1/users/me", headers=analyst_headers).json()
    assigned = client.patch(
        f"/api/v1/cases/{public_id}",
        headers=analyst_headers,
        json={"status": "triaged", "assigned_to": me["id"]},
    )
    assert assigned.status_code == 200
    assert assigned.json()["assigned_to"] == me["id"]

    resolved = client.patch(
        f"/api/v1/cases/{public_id}",
        headers=analyst_headers,
        json={"status": "investigating"},
    )
    assert resolved.status_code == 200

    done = client.patch(
        f"/api/v1/cases/{public_id}",
        headers=analyst_headers,
        json={"status": "resolved", "resolution": "true_positive"},
    )
    assert done.status_code == 200
    assert done.json()["resolution"] == "true_positive"


def test_analyst_cannot_close_or_reassign(support_headers, analyst_headers):
    created = _create(analyst_headers)
    public_id = created.json()["public_id"]
    client.patch(f"/api/v1/cases/{public_id}", headers=analyst_headers,
                 json={"status": "triaged"})
    client.patch(f"/api/v1/cases/{public_id}", headers=analyst_headers,
                 json={"status": "investigating"})
    client.patch(f"/api/v1/cases/{public_id}", headers=analyst_headers,
                 json={"status": "resolved", "resolution": "benign"})

    closed = client.patch(f"/api/v1/cases/{public_id}", headers=analyst_headers,
                          json={"status": "closed"})
    assert closed.status_code == 403


def test_support_can_read_but_not_patch(support_headers, analyst_headers):
    created = _create(analyst_headers)
    public_id = created.json()["public_id"]
    assert client.get(f"/api/v1/cases/{public_id}", headers=support_headers).status_code == 200
    assert client.patch(f"/api/v1/cases/{public_id}", headers=support_headers,
                        json={"status": "triaged"}).status_code == 403
```

- [ ] **Step 2: Run it to verify failure**

Run: `.venv/bin/python -m pytest tests/test_cases_api.py -q`
Expected: FAIL — 404.

- [ ] **Step 3: Add request schemas**

`api/schemas/cases.py`:

```python
"""HTTP contracts for cases."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from cases.schemas import CaseDetail, CaseSummary


class CaseCreateRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    priority: str = "medium"
    entity_type: Optional[str] = None
    entity_value: Optional[str] = None
    assigned_to: Optional[int] = None
    report_id: Optional[str] = None


class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[int] = None
    resolution: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None


class CaseCommentRequest(BaseModel):
    body: str = Field(..., min_length=1, max_length=10_000)


class CaseListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[CaseSummary]


class CaseReportLinkRequest(BaseModel):
    report_public_id: str


__all__ = [
    "CaseCreateRequest", "CaseUpdateRequest", "CaseCommentRequest",
    "CaseListResponse", "CaseReportLinkRequest", "CaseDetail", "CaseSummary",
]
```

Export from `api/schemas/__init__.py`.

- [ ] **Step 4: Implement the routes**

`api/routes/cases.py`:

```python
"""Case/ticket API."""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from api.audit import AuditAction, log_audit_event
from api.rbac import require_permission
from api.schemas.cases import (
    CaseCommentRequest, CaseCreateRequest, CaseDetail, CaseListResponse,
    CaseReportLinkRequest, CaseUpdateRequest,
)
from cases.repository import CaseRepository
from cases.service import CaseService, InvalidTransition
from reporting.report_repository import ReportRepository

router = APIRouter(prefix="/api/v1/cases", tags=["Cases"])


def _audit(action, request, user, public_id, **metadata):
    log_audit_event(
        action=action, user_id=user["id"],
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        target_type="case", target_id=public_id, metadata=metadata,
    )


@router.post("", response_model=CaseDetail, status_code=201)
def create_case(
    payload: CaseCreateRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("cases:write")),
):
    report_id: Optional[int] = None
    if payload.report_id:
        report_id = ReportRepository().get_db_id(payload.report_id)
        if report_id is None:
            raise HTTPException(status_code=404, detail="Report not found.")

    case = CaseService().create(
        title=payload.title, description=payload.description,
        priority=payload.priority, entity_type=payload.entity_type,
        entity_value=payload.entity_value, created_by=current_user["id"],
        assigned_to=payload.assigned_to,
    )

    if report_id is not None:
        CaseRepository().link_report(case.id, report_id, current_user["id"])

    _audit(AuditAction.CASE_CREATED, request, current_user, case.public_id,
           entity=payload.entity_value, priority=payload.priority)
    return case
```

Continue routes:

```python
@router.get("", response_model=CaseListResponse)
def list_cases(
    status_filter: Optional[str] = Query(None, alias="status"),
    priority: Optional[str] = Query(None),
    entity: Optional[str] = Query(None),
    unassigned: bool = Query(False),
    assigned_to_me: bool = Query(False),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_user: dict[str, Any] = Depends(require_permission("cases:read")),
):
    total, items = CaseRepository().list(
        status=status_filter, priority=priority, entity=entity,
        unassigned=unassigned,
        assigned_to=current_user["id"] if assigned_to_me else None,
        limit=limit, offset=offset,
    )
    return CaseListResponse(total=total, limit=limit, offset=offset, items=items)


@router.get("/{public_id}", response_model=CaseDetail)
def get_case(public_id: str,
             current_user: dict[str, Any] = Depends(require_permission("cases:read"))):
    case = CaseRepository().get(public_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    return case


@router.patch("/{public_id}", response_model=CaseDetail)
def update_case(
    public_id: str,
    payload: CaseUpdateRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("cases:write")),
):
    from api.rbac import has_permission

    can_manage = has_permission(current_user["role"], "cases:manage")
    case = CaseRepository().get(public_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")

    data = payload.model_dump(exclude_unset=True)
    if "assigned_to" in data and data["assigned_to"] not in (None, current_user["id"]) and not can_manage:
        raise HTTPException(status_code=403, detail="Reassigning a case requires cases:manage.")
    if case.assigned_to not in (None, current_user["id"]) and not can_manage:
        raise HTTPException(status_code=403, detail="Only the assignee can update this case.")

    try:
        updated = CaseService().update(
            public_id, actor_id=current_user["id"], can_manage=can_manage, payload=data
        )
    except InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    _audit(AuditAction.CASE_UPDATED, request, current_user, public_id,
           fields=list(data.keys()), status=updated.status)
    return updated


@router.post("/{public_id}/comments", response_model=CaseDetail)
def comment_case(
    public_id: str,
    payload: CaseCommentRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("cases:write")),
):
    try:
        case = CaseService().add_comment(public_id, actor_id=current_user["id"], body=payload.body)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    _audit(AuditAction.CASE_UPDATED, request, current_user, public_id, comment=True)
    return case


@router.post("/{public_id}/reports", response_model=CaseDetail)
def link_report(
    public_id: str,
    payload: CaseReportLinkRequest,
    request: Request,
    current_user: dict[str, Any] = Depends(require_permission("cases:write")),
):
    case = CaseRepository().get(public_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    report_id = ReportRepository().get_db_id(payload.report_public_id)
    if report_id is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    CaseRepository().link_report(case.id, report_id, current_user["id"])
    _audit(AuditAction.CASE_UPDATED, request, current_user, public_id,
           linked_report=payload.report_public_id)
    return CaseRepository().get(public_id)
```

Fix the create route to use `get_db_id` and link after creation.

- [ ] **Step 5: Mount and run**

In `api/main.py`: `from api.routes.cases import router as cases_router` and `app.include_router(cases_router)`.

Run: `.venv/bin/python -m pytest tests/test_cases_api.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add api/schemas/cases.py api/schemas/__init__.py api/routes/cases.py api/main.py reporting/report_repository.py tests/test_cases_api.py
git commit -m "feat(api): add case routes, transitions, and audit"
```

---

### Task 15: Frontend cases list and detail

**Files:**
- Create: `frontend/app/(dashboard)/cases/page.tsx`
- Create: `frontend/app/(dashboard)/cases/[public_id]/page.tsx`
- Modify: `frontend/lib/reporting/types.ts`
- Modify: `frontend/lib/data-table/api-client.ts`
- Test: `frontend/tests/cases.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
import { fireEvent, render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import CasesPage from "@/app/(dashboard)/cases/page"
import CaseDetailPage from "@/app/(dashboard)/cases/[public_id]/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"

vi.mock("next/navigation", () => ({
  useParams: () => ({ public_id: "CASE-2026-000001" }),
}))

const caseSummary = {
  public_id: "CASE-2026-000001",
  title: "Investigate beacon.example",
  status: "open",
  priority: "high",
  entity_type: "domain",
  entity_value: "beacon.example",
  assigned_to: null,
  created_by: 1,
  resolution: null,
  created_at: "2026-11-10T00:00:00Z",
  updated_at: "2026-11-10T00:00:00Z",
}

describe("cases UI", () => {
  beforeEach(() => vi.restoreAllMocks())

  it("lists cases", async () => {
    vi.spyOn(dnsnetraApi, "listCases").mockResolvedValue({
      total: 1, limit: 50, offset: 0, items: [caseSummary],
    })
    render(<CasesPage />)
    expect(await screen.findByText("Investigate beacon.example")).toBeInTheDocument()
  })

  it("moves a case to triaged", async () => {
    vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue({
      ...caseSummary,
      description: null,
      events: [],
      reports: [],
    } as any)
    const update = vi.spyOn(dnsnetraApi, "updateCase").mockResolvedValue({
      ...caseSummary,
      status: "triaged",
      events: [],
      reports: [],
    } as any)

    render(<CaseDetailPage />)
    fireEvent.click(await screen.findByRole("button", { name: "Start triage" }))
    expect(update).toHaveBeenCalledWith("CASE-2026-000001", { status: "triaged" })
  })
})
```

- [ ] **Step 2: Run it to verify failure**

Run: `cd frontend && pnpm vitest run tests/cases.test.tsx`
Expected: FAIL — pages and methods missing.

- [ ] **Step 3: Add types and API methods**

In `frontend/lib/reporting/types.ts`:

```ts
export interface CaseSummary {
  public_id: string
  title: string
  status: string
  priority: string
  entity_type?: string | null
  entity_value?: string | null
  assigned_to?: number | null
  created_by?: number | null
  resolution?: string | null
  created_at: string
  updated_at: string
}

export interface CaseEvent {
  id: number
  kind: string
  actor_id?: number | null
  body?: string | null
  metadata: Record<string, unknown>
  created_at: string
}

export interface CaseDetail extends CaseSummary {
  description?: string | null
  resolved_by?: number | null
  resolved_at?: string | null
  closed_at?: string | null
  events: CaseEvent[]
  reports: string[]
}

export interface CaseList {
  total: number
  limit: number
  offset: number
  items: CaseSummary[]
}
```

In `dnsnetraApi`:

```ts
async listCases(params: { status?: string; priority?: string; unassigned?: boolean; assigned_to_me?: boolean; limit?: number; offset?: number } = {}): Promise<import("@/lib/reporting/types").CaseList> {
  return apiFetch("/api/v1/cases", params)
},
async getCase(publicId: string): Promise<import("@/lib/reporting/types").CaseDetail> {
  return apiFetch(`/api/v1/cases/${encodeURIComponent(publicId)}`)
},
async createCase(body: { title: string; description?: string; priority?: string; entity_type?: string; entity_value?: string; report_id?: string }): Promise<import("@/lib/reporting/types").CaseDetail> {
  return apiFetch("/api/v1/cases", {}, { method: "POST", body })
},
async updateCase(publicId: string, body: Record<string, unknown>): Promise<import("@/lib/reporting/types").CaseDetail> {
  return apiFetch(`/api/v1/cases/${encodeURIComponent(publicId)}`, {}, { method: "PATCH", body })
},
async commentCase(publicId: string, body: string): Promise<import("@/lib/reporting/types").CaseDetail> {
  return apiFetch(`/api/v1/cases/${encodeURIComponent(publicId)}/comments`, {}, { method: "POST", body: { body } })
},
```

- [ ] **Step 4: Build the list page**

```tsx
"use client"

import * as React from "react"
import Link from "next/link"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { CaseSummary } from "@/lib/reporting/types"

export default function CasesPage() {
  const [items, setItems] = React.useState<CaseSummary[]>([])
  const [loading, setLoading] = React.useState(true)

  React.useEffect(() => {
    dnsnetraApi.listCases({ limit: 50 })
      .then((res) => setItems(res.items))
      .catch(() => toast.error("Failed to load cases."))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div>
        <h2 className="text-xl font-semibold tracking-tight">Cases</h2>
        <p className="text-sm text-muted-foreground">Investigations, assignments, and resolutions.</p>
      </div>
      <Card>
        <CardHeader><CardTitle className="text-sm">Queue</CardTitle></CardHeader>
        <CardContent className="p-0">
          {loading ? (
            <p className="p-4 text-sm text-muted-foreground">Loading cases…</p>
          ) : items.length === 0 ? (
            <p className="p-4 text-sm text-muted-foreground">No cases yet.</p>
          ) : (
            <div className="divide-y divide-border/60">
              {items.map((item) => (
                <Link key={item.public_id} href={`/cases/${encodeURIComponent(item.public_id)}`}
                      className="flex items-center justify-between gap-3 p-3 hover:bg-muted/50">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium">{item.title}</p>
                    <p className="font-mono text-[11px] text-muted-foreground">
                      {item.public_id} · {item.entity_value ?? "no entity"}
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <Badge variant="outline">{item.priority}</Badge>
                    <Badge variant="outline">{item.status}</Badge>
                  </div>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
```

- [ ] **Step 5: Build the detail page**

```tsx
"use client"

import * as React from "react"
import { useParams } from "next/navigation"
import { toast } from "sonner"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { dnsnetraApi } from "@/lib/data-table/api-client"
import type { CaseDetail } from "@/lib/reporting/types"

const NEXT: Record<string, { label: string; status: string }[]> = {
  open: [{ label: "Start triage", status: "triaged" }],
  triaged: [{ label: "Start investigation", status: "investigating" }],
  investigating: [{ label: "Resolve", status: "resolved" }],
  awaiting_info: [{ label: "Resume", status: "investigating" }],
  resolved: [{ label: "Close", status: "closed" }],
  closed: [],
}

export default function CaseDetailPage() {
  const params = useParams<{ public_id: string }>()
  const publicId = decodeURIComponent(params.public_id)
  const [item, setItem] = React.useState<CaseDetail | null>(null)
  const [comment, setComment] = React.useState("")

  React.useEffect(() => {
    dnsnetraApi.getCase(publicId).then(setItem).catch(() => toast.error("Failed to load case."))
  }, [publicId])

  async function move(status: string) {
    try {
      const payload = status === "resolved"
        ? { status, resolution: "true_positive" }
        : { status }
      const updated = await dnsnetraApi.updateCase(publicId, payload)
      setItem(updated)
      toast.success(`Case moved to ${status}.`)
    } catch {
      toast.error("Case update failed.")
    }
  }

  async function addComment() {
    if (!comment.trim()) return
    try {
      setItem(await dnsnetraApi.commentCase(publicId, comment))
      setComment("")
    } catch {
      toast.error("Comment failed.")
    }
  }

  if (!item) return <p className="p-6 text-sm text-muted-foreground">Loading case…</p>

  return (
    <div className="flex flex-col gap-4 p-4 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{item.title}</h1>
          <p className="font-mono text-[11px] text-muted-foreground">
            {item.public_id} · {item.entity_value ?? "no entity"}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline">{item.priority}</Badge>
          <Badge variant="outline">{item.status}</Badge>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {(NEXT[item.status] ?? []).map((action) => (
          <Button key={action.status} size="sm" onClick={() => move(action.status)}>
            {action.label}
          </Button>
        ))}
      </div>

      <Card>
        <CardHeader><CardTitle className="text-sm">Timeline</CardTitle></CardHeader>
        <CardContent className="flex flex-col gap-3">
          {item.events.length === 0 ? (
            <p className="text-sm text-muted-foreground">No events yet.</p>
          ) : (
            <ol className="flex flex-col gap-2">
              {item.events.map((event) => (
                <li key={event.id} className="text-sm">
                  <span className="font-mono text-[11px] text-muted-foreground">{event.created_at}</span>
                  <span className="ml-2">{event.kind}</span>
                  {event.body && <span className="ml-2 text-muted-foreground">{event.body}</span>}
                </li>
              ))}
            </ol>
          )}
          <div className="flex gap-2">
            <Input value={comment} onChange={(e) => setComment(e.target.value)}
                   placeholder="Add a comment" aria-label="Comment" />
            <Button size="sm" onClick={addComment}>Comment</Button>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-sm">Linked reports</CardTitle></CardHeader>
        <CardContent>
          {item.reports.length === 0 ? (
            <p className="text-sm text-muted-foreground">No linked reports.</p>
          ) : (
            <ul className="flex flex-col gap-1">
              {item.reports.map((report) => (
                <li key={report} className="font-mono text-xs">{report}</li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
```

- [ ] **Step 6: Run tests and typecheck**

Run: `cd frontend && pnpm vitest run tests/cases.test.tsx && npx tsc --noEmit`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add "frontend/app/(dashboard)/cases" frontend/lib/reporting/types.ts frontend/lib/data-table/api-client.ts frontend/tests/cases.test.tsx
git commit -m "feat(ui): add case queue and detail"
```

---

## Phase 4 — Integration and polish

### Task 16: Dossier and daily-review actions, navigation, and report-to-case

**Files:**
- Modify: `frontend/components/app-sidebar.tsx`
- Modify: `frontend/components/site-header.tsx`
- Modify: `frontend/app/(dashboard)/domains/[domain]/page.tsx`
- Modify: `frontend/app/(dashboard)/clients/[client_ip]/page.tsx`
- Modify: `frontend/app/(dashboard)/daily-review/page.tsx`
- Modify: `frontend/app/(dashboard)/reports/saved/[public_id]/page.tsx`
- Test: `frontend/tests/integration-actions.test.tsx`

- [ ] **Step 1: Write the failing test**

```tsx
import { fireEvent, render, screen } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"

import ReportDetailPage from "@/app/(dashboard)/reports/saved/[public_id]/page"
import { dnsnetraApi } from "@/lib/data-table/api-client"

vi.mock("next/navigation", () => ({
  useParams: () => ({ public_id: "RPT-2026-000001" }),
}))

const report = {
  public_id: "RPT-2026-000001",
  kind: "entity_domain",
  entity_type: "domain",
  entity_value: "example.com",
  title: "example.com review",
  status: "draft",
  verdict: null,
  conclusion: null,
  row_count: 1,
  filters: {},
  snapshot: { schema_version: 1, kind: "entity_domain",
    entity: { type: "domain", value: "example.com" },
    observed_in_network: false,
    dossier: { profile: {}, recent_queries: [], live_intel: {} },
    provenance: { sources: [] } },
  created_at: "2026-11-10T00:00:00Z",
}

describe("report to case", () => {
  beforeEach(() => vi.restoreAllMocks())

  it("creates a case from a report", async () => {
    vi.spyOn(dnsnetraApi, "getSavedReport").mockResolvedValue(report as any)
    const create = vi.spyOn(dnsnetraApi, "createCase").mockResolvedValue({
      public_id: "CASE-2026-000001",
      title: "Investigate example.com",
      status: "open",
      priority: "medium",
      entity_type: "domain",
      entity_value: "example.com",
      assigned_to: null,
      created_by: 1,
      resolution: null,
      created_at: "2026-11-10T00:00:00Z",
      updated_at: "2026-11-10T00:00:00Z",
      events: [],
      reports: ["RPT-2026-000001"],
    } as any)

    render(<ReportDetailPage />)
    fireEvent.click(await screen.findByRole("button", { name: "Open case" }))
    expect(create).toHaveBeenCalledWith({
      title: "Investigate example.com",
      priority: "medium",
      entity_type: "domain",
      entity_value: "example.com",
      report_id: "RPT-2026-000001",
    })
  })
})
```

- [ ] **Step 2: Run it to verify failure**

Run: `cd frontend && pnpm vitest run tests/integration-actions.test.tsx`
Expected: FAIL — no "Open case".

- [ ] **Step 3: Add the action to the report page**

In the report detail header actions:

```tsx
<Button
  variant="outline"
  size="sm"
  onClick={async () => {
    try {
      const created = await dnsnetraApi.createCase({
        title: `Investigate ${report.entity_value ?? report.title}`,
        priority: "medium",
        entity_type: report.entity_type ?? undefined,
        entity_value: report.entity_value ?? undefined,
        report_id: report.public_id,
      })
      toast.success(`Case ${created.public_id} opened.`)
    } catch {
      toast.error("Could not open a case.")
    }
  }}
>
  Open case
</Button>
```

- [ ] **Step 4: Add navigation**

In `app-sidebar.tsx`, add to `navAnalysis`:

```tsx
{ title: "Saved Reports", url: "/reports/saved", icon: <FileTextIcon /> },
{ title: "Cases", url: "/cases", icon: <ShieldIcon /> },
```

In `site-header.tsx` `pageTitles`, add:

```tsx
"/reports/saved": "Saved Reports",
"/cases": "Cases",
```

and the dynamic prefixes:

```tsx
if (pathname.startsWith("/reports/saved/")) return "Saved Report"
if (pathname.startsWith("/cases/")) return "Case"
```

- [ ] **Step 5: Add dossier and daily-review create buttons**

In `domains/[domain]/page.tsx` and `clients/[client_ip]/page.tsx`, add a header action:

```tsx
<Button
  variant="outline"
  size="sm"
  onClick={async () => {
    try {
      const report = await dnsnetraApi.createSavedReport({
        kind: "entity_domain",           // entity_client on the client page
        entity: domain,                   // clientIp on the client page
        window: "7d",
        title: `${domain} — 7 day review`,
      })
      toast.success(`Report ${report.public_id} created.`)
    } catch {
      toast.error("Could not create a report.")
    }
  }}
>
  Create report
</Button>
```

In `daily-review/page.tsx`, add a per-row action that calls:

```tsx
await dnsnetraApi.createCase({
  title: `Review ${item.domain}`,
  priority: "medium",
  entity_type: "domain",
  entity_value: item.domain,
})
```

- [ ] **Step 6: Run tests and typecheck**

Run: `cd frontend && pnpm vitest run tests/integration-actions.test.tsx tests/saved-reports.test.tsx tests/cases.test.tsx`
Run: `cd frontend && npx tsc --noEmit`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add frontend/components/app-sidebar.tsx frontend/components/site-header.tsx "frontend/app/(dashboard)/domains/[domain]/page.tsx" "frontend/app/(dashboard)/clients/[client_ip]/page.tsx" "frontend/app/(dashboard)/daily-review/page.tsx" "frontend/app/(dashboard)/reports/saved/[public_id]/page.tsx" frontend/tests/integration-actions.test.tsx
git commit -m "feat(ui): connect reports and cases to dossiers and review"
```

---

### Task 17: Full verification and accessibility polish

**Files:**
- Modify: report/case pages for empty states and ARIA where missing
- Test: existing suites

- [ ] **Step 1: Add missing empty-state and ARIA assertions**

Add to `frontend/tests/cases.test.tsx`:

```tsx
it("announces an empty case detail timeline", async () => {
  vi.spyOn(dnsnetraApi, "getCase").mockResolvedValue({
    ...caseSummary,
    description: null,
    events: [],
    reports: [],
  } as any)
  render(<CaseDetailPage />)
  expect(await screen.findByText("No events yet.")).toBeInTheDocument()
})
```

- [ ] **Step 2: Fix any ARIA gaps the test reveals**

Ensure:
- the comment input has `aria-label="Comment"`,
- status is always rendered as text, never color-only,
- export buttons are real `<button>` elements with discernible names,
- empty states are plain text inside the card.

- [ ] **Step 3: Run the full backend suite**

Run: `.venv/bin/python -m pytest tests/test_reporting_audit.py tests/test_reporting_exports.py tests/test_reporting_entity.py tests/test_daily_review_hardening.py tests/test_reporting_service.py tests/test_reporting_schema.py tests/test_saved_reports_repository.py tests/test_report_service.py tests/test_saved_reports_api.py tests/test_cases_service.py tests/test_cases_api.py tests/test_api_v1.py tests/test_auth_complete.py -q`
Expected: PASS.

- [ ] **Step 4: Run the full frontend suite, typecheck, and build**

Run: `cd frontend && pnpm test`
Run: `cd frontend && npx tsc --noEmit`
Run: `cd frontend && pnpm build`
Expected: all pass; 16 routes or more, including `/reports/saved`, `/reports/saved/[public_id]`, `/cases`, `/cases/[public_id]`.

- [ ] **Step 5: Manual XLSX verification**

Generate a report for a known domain from the UI, export XLSX, open it in Excel or Numbers, and confirm:
- six sheets exist,
- the Queries sheet shows rows,
- a domain beginning with `=` is prefixed with `'` and is not evaluated.

- [ ] **Step 6: Commit**

```bash
git add frontend
git commit -m "test: verify reporting, exports, and cases end to end"
```

---

## Self-review notes

- **Spec coverage:** section 4 decisions → Tasks 6–16; section 5 permissions → Tasks 9 and 14; section 6 schema → Task 6; section 7 snapshot → Task 8; section 8 contents → Tasks 8, 10; section 9 exports → Task 10; section 10 API → Tasks 9, 10, 14; section 11 workflows → Tasks 9, 14, 16; section 12 frontend → Tasks 11, 12, 15, 16; section 13 errors → Tasks 9, 14; section 14 phase 0 → Tasks 1–5; section 15 testing → Task 17; section 16 phases → task order.
- **Known deviation:** `CaseSummary.id` is added as `Field(exclude=True)` so routes can link reports without exposing database IDs.
- **Known deviation:** the spec's snapshot fields are carried under `dossier` (the full investigation payload) plus top-level `summary`, `timeline`, `row_count`, and `provenance`; export readers use `snapshot["dossier"]`.
- **Known deviation:** `link_report` lives in the route, not `CaseService`, because it needs to resolve a report public ID to a DB ID; the service stays free of report persistence.
- **No placeholders:** every step above contains the command, test, or code it needs.
