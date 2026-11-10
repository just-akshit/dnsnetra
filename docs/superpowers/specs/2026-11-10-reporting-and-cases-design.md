# Reporting, Exports, and Cases — Design Spec

- **Date:** 2026-11-10
- **Status:** Awaiting user review
- **Scope:** DNSNetra web dashboard + FastAPI backend + PostgreSQL
- **Supersedes:** nothing
3.7 Build order
## 1. Summary

Add a durable reporting layer on top of the existing telemetry reports:

- **Reports** are immutable snapshots of an entity dossier or a filtered query set, created by an analyst, 3.7 Build orderreviewable, and exportable as CSV or XLSX.
- **Cases** are mutable work items (tickets) that track investigation from creation to closure, with assignment, comments, evidence links, and an append-only timeline.
- **Exports** cover entity dossiers and query sets in CSV and Excel, with the same filters as the screen, formula-injection protection, and an audit row per export.
- **Verdict authority stays where it is.** Marking a report reviewed or resolving a case never changes a label. Clean/malicious decisions still go through the existing daily-review override.

## 2. Goals

1. An analyst can turn a domain/IP dossier into a saved report in one action and share or export it.
2. An analyst can mark a report reviewed with a conclusion and an assessed verdict.
3. An analyst can open a case from a report, an entity, a daily-review row, or a flagged query; work it; resolve it; close it.
4. An admin can assign/reassign, close/reopen, and audit every report, export, marking, and case transition.
5. Every export is reproducible from the report's stored filters and snapshot.
6. The reporting surface is honest about missing data: provider failures and unseen entities are stated, never rendered as "clean" or "zero results".

## 3. Non-goals

- Email/Slack/Jira notifications or two-way ticket sync.
- SLA timers, escalation rules, or on-call routing.
- Scheduled/recurring reports.
- Multi-tenant isolation.
- Editing a report snapshot after creation or deleting reports (archive only).
- Per-field redaction or data-loss prevention beyond role checks.
- Case attachments (files); evidence is limited to reports and entity references.

## 4. Locked decisions

| # | Decision |
|---|---|
| 1 | Full case workflow ships in v1, alongside exports and report review. |
| 2 | CSV **and** XLSX are required. `openpyxl` is added as the single new dependency. |
| 3 | Reports are immutable snapshots; cases are mutable. Label changes happen only through `POST /api/v1/daily-review/{domain}/verdict`. |
| 4 | Analysts self-assign and progress their own cases; only `cases:manage` (ADMIN/SUPER_ADMIN) can reassign others, close, or reopen a closed case. |
| 5 | Report review is an assessment, not a label override. The UI may offer "Apply verdict" which calls the existing override endpoint with a required reason. |

## 5. Roles and permissions

Add four permissions and keep the existing two:

| Permission | SUPER_ADMIN | ADMIN | ANALYST | SUPPORT |
|---|---|---|---|---|
| `reports:read` (existing) | yes | yes | yes | yes |
| `reports:export` (existing) | yes | yes | yes | no |
| `reports:write` (new) | yes | yes | yes | no |
| `cases:read` (new) | yes | yes | yes | yes |
| `cases:write` (new) | yes | yes | yes | no |
| `cases:manage` (new) | yes | yes | no | no |

Rules:

- `reports:write` covers creating reports and marking them reviewed.
- `cases:write` covers creating a case, commenting, linking reports, self-assigning, and progressing a case the analyst owns or that is unassigned.
- `cases:manage` covers assigning another user, reassigning, closing, reopening, and editing others' cases.
- SUPPORT remains read-only: can list and open reports/cases, cannot export, mark, or mutate.
- `/api/v1/reports/entity` stops being a dossier bypass: it requires `domains:investigate` for domains and `clients:investigate` for clients, matching `/investigation/*`. SUPPORT loses dossier-level access there.

## 6. Data model

Migration `012_reporting_and_cases.sql` is additive. No existing table changes except two nullable audit columns. The migration creates `cases` before `reports` because `reports.case_id` references it.

### 6.1 `reports`

```sql
CREATE TABLE IF NOT EXISTS reports (
    id              BIGSERIAL PRIMARY KEY,
    public_id       TEXT NOT NULL UNIQUE,          -- RPT-2026-000123
    kind            TEXT NOT NULL
                    CHECK (kind IN ('entity_domain', 'entity_client', 'query_set')),
    entity_type     TEXT NULL CHECK (entity_type IN ('domain', 'client')),
    entity_value    TEXT NULL,
    title           TEXT NOT NULL,
    window_start    TIMESTAMPTZ NULL,
    window_end      TIMESTAMPTZ NULL,
    filters         JSONB NOT NULL DEFAULT '{}'::jsonb,
    snapshot        JSONB NOT NULL,
    row_count       INTEGER NOT NULL DEFAULT 0,     -- rows captured at creation
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

CREATE INDEX idx_reports_status_created ON reports (status, created_at DESC);
CREATE INDEX idx_reports_entity ON reports (entity_value);
CREATE INDEX idx_reports_case ON reports (case_id);
```

Notes:

- `snapshot` is the frozen dossier payload (section 7). It is never updated after insert.
- `status`, `conclusion`, `verdict`, `reviewed_by`, `reviewed_at` are the only mutable fields.
- `public_id` is generated from a database sequence: `RPT-<year>-<six digits>`, uniqueness enforced by the column, retried once on collision.
- `case_id` is a convenience pointer for the "one report belongs to at most one case" v1 rule. The authoritative link is `case_reports` (section 6.4); a report may be linked to multiple cases later without a schema change if `case_id` is treated as "primary case".

### 6.2 `cases`

```sql
CREATE TABLE IF NOT EXISTS cases (
    id              BIGSERIAL PRIMARY KEY,
    public_id       TEXT NOT NULL UNIQUE,          -- CASE-2026-000042
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

CREATE INDEX idx_cases_status_assignee ON cases (status, assigned_to);
CREATE INDEX idx_cases_entity ON cases (entity_value);
CREATE INDEX idx_cases_created ON cases (created_at DESC);
```

### 6.3 `case_events`

Append-only timeline. Comments are `kind = 'comment'`; system events carry metadata.

```sql
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

CREATE INDEX idx_case_events_case ON case_events (case_id, created_at);
```

### 6.4 `case_reports`

```sql
CREATE TABLE IF NOT EXISTS case_reports (
    case_id     BIGINT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    report_id   BIGINT NOT NULL REFERENCES reports(id) ON DELETE CASCADE,
    linked_by   INTEGER NULL REFERENCES dashboard_users(id) ON DELETE SET NULL,
    linked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, report_id)
);
```

### 6.5 Audit extension

```sql
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS target_type TEXT NULL,
    ADD COLUMN IF NOT EXISTS target_id   TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_target
    ON audit_logs (target_type, target_id);
```

New audit actions: `REPORT_CREATED`, `REPORT_REVIEWED`, `REPORT_ARCHIVED`, `REPORT_EXPORTED`, `CASE_CREATED`, `CASE_UPDATED`, `CASE_ASSIGNED`, `CASE_RESOLVED`, `CASE_CLOSED`, `VERDICT_OVERRIDE`.

Metadata carries the actor email, report/case `public_id`, entity, format, row count, and reason. Existing `sanitize_metadata` already strips secrets.

## 7. Report snapshot contract

`snapshot` is versioned JSON:

```json
{
  "schema_version": 1,
  "kind": "entity_domain",
  "entity": { "type": "domain", "value": "example.com" },
  "window": { "start": "...", "end": "...", "label": "last 7 days" },
  "observed_in_network": true,
  "summary": {
    "verdict": "Review Needed",
    "total_queries": 0,
    "unique_clients": 0,
    "unique_domains": 0,
    "verdict_breakdown": { "benign": 0, "malicious": 0, "review_needed": 0, "unknown": 0 },
    "malicious_query_percentage": 0.0
  },
  "profile": { },
  "timeline": [ ],
  "relationships": [ ],
  "recent_queries": [ ],
  "persisted_intel": { },
  "live_intel": { },
  "provenance": { }
}
```

Rules:

- `schema_version` lets future readers migrate old snapshots.
- `recent_queries` is capped at **500** rows at creation. `row_count` records the true count represented by the report filters.
- `live_intel` records every provider's status (`ok`, `error`, `not_configured`), `checked_at`, and whether the result was persisted. A failed provider is never collapsed into "clean".
- `provenance` lists each evidence source (local profile, query history, reputation, daily review, reviewed-clean, VT, OTX, DNS, RDAP) and its timestamp.
- For `query_set` reports, `snapshot` stores the filter definition, summary counts, and a 500-row preview. Full rows are regenerated at export time from the stored filters plus window; the export records both the creation-time count and the export-time count.

## 8. Report contents

### 8.1 Domain report

1. **Cover** — report `public_id`, entity, generated by/at (UTC), window, sources, classification.
2. **Assessment** — overall verdict, malicious query %, review status, provider states, top reasons.
3. **Identity and registration** — registered domain, TLD, RDAP registrar/created/expires/nameservers, live DNS records (A/AAAA/MX/NS/TXT).
4. **Local telemetry** — first/last seen, total queries, unique clients, 4-state breakdown and percentages, query-type distribution, hourly activity.
5. **Relationships** — top querying clients: IP, query count, verdict split, last seen.
6. **Recent events** — up to 500: timestamp, client IP, query type, response code, verdict, `ti_source`.
7. **Persisted intelligence and provenance** — `reputation_domains` state, daily-review status/review count/next check/VT-OTX summaries, reviewed-clean state, decision provenance.
8. **Live intelligence** — VT/OTX verdicts and detection ratios, DNS, RDAP, each with provider status and `checked_at`; explicit "external verdict not persisted" note.
9. **Analyst assessment** — conclusion, recommended action, tags, reviewer, linked case.
10. **Appendix** — filter definition and method notes.

### 8.2 Client IP report

1. Cover and assessment as above.
2. Profile — first/last seen, total queries, unique domains, 4-state breakdown, last domain, last query type.
3. Network class — public vs private. Private addresses skip VT/OTX and say so.
4. Top domains — domain, query count, verdict split, last seen.
5. Recent events — up to 500.
6. Persisted intelligence and provenance.
7. Live intelligence for public addresses only.
8. Analyst assessment and appendix.

No fabricated risk scores. Every number is either stored telemetry or a named provider response.

## 9. Exports

### 9.1 Formats

- **CSV (query set):** existing columns — `id, timestamp, client_ip, domain, query_type, response_code, verdict, ti_source, registered_domain, tld` — streamed, max 50,000 rows.
- **CSV (entity report):** long format — `section, field, value, source, checked_at` — one row per report field, plus one row per recent query.
- **XLSX (entity or query set):** one workbook with sheets:
  1. `Summary`
  2. `Timeline`
  3. `Relationships`
  4. `Queries` (max 50,000)
  5. `Intelligence` (provider, status, verdict, ratio, checked_at, persisted)
  6. `Assessment` (analyst conclusion, reviewer, audit references)

### 9.2 Rules

- **Formula injection:** any text cell beginning with `=`, `+`, `-`, `@`, tab, or CR is prefixed with a single quote in CSV output; XLSX writes typed values and sanitizes text cells the same way.
- **Filter parity:** export uses the same filter semantics as the on-screen list: `search` is `ILIKE` across domain or client IP; `domain` is a substring match; verdict is canonical.
- **Bounded:** 1–50,000 rows; a 429 response when the export throttle is exceeded.
- **Audited:** every export writes `REPORT_EXPORTED` with actor, format, entity/filters, and row count, including one-shot entity exports.
- **Headers:** `Content-Disposition: attachment; filename="dnsnetra_<entity>_<UTC>.{csv|xlsx}"`, filename sanitized to `[A-Za-z0-9._-]`; `Cache-Control: no-store`.
- **Snapshot fidelity:** an entity report exports its frozen snapshot. A query-set report exports a regenerated row stream from its stored filters plus window, and records both the creation-time `row_count` and the export-time count so the difference is visible.

### 9.3 Dependency

Add `openpyxl>=3.1,<4` to `requirements.txt`. Use `Workbook(write_only=True)` so a 50k-row export does not build the sheet in memory. No other new dependency.

## 10. API

All routes require authentication and the stated permission. Existing `/api/v1/reports/*` read routes are unchanged.

### 10.1 Reports

| Method | Path | Permission | Purpose |
|---|---|---|---|
| POST | `/api/v1/reports/saved` | `reports:write` | Create a report snapshot |
| GET | `/api/v1/reports/saved` | `reports:read` | List reports (`status`, `kind`, `entity`, `created_by`, date range) |
| GET | `/api/v1/reports/saved/{public_id}` | `reports:read` | Report detail |
| PATCH | `/api/v1/reports/saved/{public_id}/review` | `reports:write` | Mark reviewed / update conclusion |
| POST | `/api/v1/reports/saved/{public_id}/archive` | `reports:write` | Archive (no delete) |
| POST | `/api/v1/reports/saved/{public_id}/export` | `reports:export` | Export CSV/XLSX |
| POST | `/api/v1/reports/saved/{public_id}/case` | `cases:write` | Create and link a case |
| GET | `/api/v1/reports/entity/export` | `reports:export` + investigate | One-shot entity export, no persistence |

Create payload:

```json
{
  "kind": "entity_domain",
  "entity": "example.com",
  "window": "7d",
  "start_time": null,
  "end_time": null,
  "filters": {},
  "title": "example.com — 7 day review"
}
```

Validation:

- `kind=entity_domain|entity_client`: `entity` required; domain canonicalized with `normalize_domain`; client validated as an IP.
- `kind=query_set`: at least one filter or window required; `filters` accepts the `/reports/queries` filter set.
- Window resolution uses `time_engine`; all-time is allowed for entity reports, not for timeseries-backed sections (those use the resolved window or the last 24h with a note).
- Unseen but valid entities are accepted: `observed_in_network=false`, live intel included, local sections state "no local telemetry".
- Malformed entities return 400. Malformed windows return 400.

Review payload:

```json
{ "status": "reviewed", "verdict": "Malicious", "conclusion": "Confirmed C2 beacon." }
```

`status=reviewed` requires a non-empty `conclusion`; it sets `reviewed_by`/`reviewed_at`. Reopening a reviewed report (`status=needs_review`) requires `cases:manage`.

### 10.2 Cases

| Method | Path | Permission | Purpose |
|---|---|---|---|
| POST | `/api/v1/cases` | `cases:write` | Create a case |
| GET | `/api/v1/cases` | `cases:read` | List (`status`, `assigned_to=me`, `priority`, `entity`, `unassigned`) |
| GET | `/api/v1/cases/{public_id}` | `cases:read` | Detail + events + reports |
| PATCH | `/api/v1/cases/{public_id}` | `cases:write` / `cases:manage` | Status, priority, assignee, resolution |
| POST | `/api/v1/cases/{public_id}/comments` | `cases:write` | Append a comment |
| POST | `/api/v1/cases/{public_id}/reports` | `cases:write` | Link a report |

Create payload:

```json
{
  "title": "Investigate beacon.example",
  "description": "Repeated TXT queries from 10.0.0.5.",
  "priority": "high",
  "entity_type": "domain",
  "entity_value": "beacon.example",
  "report_id": 123
}
```

### 10.3 Case state machine

| From | Allowed next | Who |
|---|---|---|
| `open` | `triaged`, `closed` | `cases:write` / `cases:manage` for close |
| `triaged` | `investigating`, `awaiting_info`, `resolved`, `closed` | `cases:write` for progress; `cases:manage` for close |
| `investigating` | `awaiting_info`, `resolved`, `closed` | `cases:write`; `cases:manage` for close |
| `awaiting_info` | `investigating`, `resolved`, `closed` | `cases:write`; `cases:manage` for close |
| `resolved` | `closed`, `investigating` (reopen) | `cases:manage` |
| `closed` | `investigating` (reopen) | `cases:manage` |

- `resolved` requires a `resolution` and writes `resolved_by`/`resolved_at`.
- `closed` requires `cases:manage` and writes `closed_at`.
- Reopening `resolved`/`closed` clears `closed_at`; `resolution` is retained on the event history.
- Invalid transitions return 409 with the allowed next states.
- Every transition, assignment, priority change, and link appends `case_events` and an audit row.
- Concurrent edits are last-write-wins; the event log preserves both changes. No optimistic-lock token in v1.

## 11. Workflows

### 11.1 Analyst

1. Search or open a dossier.
2. **Create report** → choose window/scope → preview → save draft.
3. Read the report; add conclusion and assessed verdict; **Mark reviewed**.
4. If action is needed, **Open case** (report auto-linked) or create one from an entity.
5. Self-assign, move to triaged/investigating, comment, attach more reports.
6. Resolve with a resolution, then an admin closes.
7. Export CSV/XLSX when a downstream system needs it.

### 11.2 Admin

1. Cases list filtered to unassigned/high/critical; assign or reassign.
2. Close or reopen; correct priority.
3. Audit: exports, marks, overrides, case transitions.
4. No ability to edit a report snapshot.

### 11.3 Support

Read-only: list/open reports and cases, no export, no marking, no mutations.

### 11.4 Daily Review handoff

- A daily-review row gains **Create case**, prefilled with the domain and review reason.
- Resolving a case does **not** clear the review item.
- If the analyst's conclusion is clean/malicious, **Apply verdict** calls the existing `POST /daily-review/{domain}/verdict` with a required reason; that path is now audited.
- The daily-review queue remains the only place a domain label changes.

## 12. Frontend surfaces

- **`/reports/saved`** — report library: table (public ID, title, entity, kind, status, creator, created, linked case), filters, empty state.
- **`/reports/saved/[public_id]`** — report detail: sectioned snapshot, review panel (status, verdict, conclusion), export menu (CSV/XLSX), create-case action, linked case.
- **`/cases`** — tabs: My open, Unassigned, All; filters for status/priority/entity; create button.
- **`/cases/[public_id]`** — header (status, priority, assignee, entity), timeline, linked reports, comment composer, transition actions.
- **Dossier pages** — **Create report** and **Open case** actions in the header.
- **Daily Review** — **Create case** per row.
- **Nav** — `Cases` under Analysis; `Saved Reports` under Analysis. Badge counts are out of scope.
- Follow `DESIGN.md`: verdict chips, hairline panels, mono for IDs/timestamps, 28–32px controls, no decorative color.
- Accessibility: labeled forms, status text alongside color, keyboard-reachable menus, visible focus rings, `aria-live` for save/export results.

## 13. Error handling and edge cases

| Case | Behavior |
|---|---|
| Malformed domain/IP | 400 with the canonical validation message |
| Valid but unseen entity | Report created; local sections say "no local telemetry"; live intel included |
| Private client IP | Live VT/OTX skipped; report states "private address" |
| Provider failure | Provider status `error`; report still created; never "clean" |
| Live intel disabled | Provider status `not_configured`; report still created |
| Unknown report/case | 404 |
| Invalid case transition | 409 with allowed next states |
| Review without conclusion | 400 |
| Export over 50k | 400 |
| Export throttle | 429 with `Retry-After` |
| Report of archived entity | Snapshot still renders and exports |
| Deleted user | `created_by` becomes null; actor email remains in audit metadata |
| CSV hostile cell | Sanitized with a leading apostrophe; stored data unchanged |

## 14. Prerequisite fixes (phase 0)

These land before the new feature because the new surfaces depend on them:

1. CSV formula-injection sanitizer + tests (`reporting/repository.py`).
2. Audit rows for CSV/one-shot exports, verdict overrides, and review triggers.
3. Export filter parity with the list (`ILIKE`, substring domain).
4. `/api/v1/reports/entity`: return live-only dossiers instead of 404, and require entity-appropriate investigate permissions.
5. Atomic `promote_to_malicious` (single transaction/connection).
6. `payload.confidence or 1.0` → `payload.confidence if payload.confidence is not None else 1.0`.
7. `_like_pattern` for daily-review search and the reporting domain filter.
8. Reconciliation test: summary totals must equal the sum of timeseries buckets for the same bounded window; fix whichever source disagrees.

## 15. Testing

**Backend**

- Unit: snapshot composer for domain, client, and query-set reports; state machine transitions; CSV sanitizer; ID formatting; snapshot `schema_version` handling.
- API: create/list/detail/review/archive; permission matrix per role; unseen entity path; provider-failure path; export headers, filenames, row caps, audit rows; case create/patch/comment/link; 409 transitions.
- DB: migration 012 applies cleanly on a populated database; indexes exist; audit columns nullable.
- Regression: existing `test_reporting_*`, `test_api_v1`, `test_investigation_*` stay green.

**Frontend**

- RTL: create report from a dossier, mark reviewed, export menu, create case, assign/self-assign, resolve with required resolution, invalid transition message, empty states, keyboard access.
- Type check and production build.

**Manual**

- Open both an entity XLSX and a query-set XLSX in Excel/Numbers; verify six sheets, formatting, and that `=1+1` in a domain field is not evaluated.

## 16. Phases

| Phase | Deliverable |
|---|---|
| 0 | Prerequisite fixes (section 14) with tests |
| 1 | Migration 012, report composer, report CRUD/review routes, tests |
| 2 | XLSX writer, entity/report export routes, export audit |
| 3 | Cases routes/permissions/audit, state machine (tables ship in migration 012) |
| 4 | Frontend: saved reports, cases, dossier and daily-review actions |
| 5 | Accessibility/empty-state polish, manual XLSX verification |

Migrations are additive and backward compatible; no feature flag is required. `openpyxl` is pinned in `requirements.txt`.

## 17. Open questions

None blocking. Deferred until asked: SLA timers, notifications, external ticket sync, scheduled reports, case attachments.
