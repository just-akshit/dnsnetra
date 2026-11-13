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
