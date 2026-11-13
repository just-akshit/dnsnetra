-- =============================================================================
-- Migration 003: Daily Review Lifecycle & Local Intelligence Schema
-- =============================================================================

-- Ensure client encoding is UTF8
SET client_encoding = 'UTF8';

-- 1. Enhance reputation_domains with verification tracking
ALTER TABLE reputation_domains
    ADD COLUMN IF NOT EXISTS last_verified_at TIMESTAMPTZ DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS verification_count INTEGER DEFAULT 1;

-- 2. Create daily_review_domains table
CREATE TABLE IF NOT EXISTS daily_review_domains (
    id              BIGSERIAL PRIMARY KEY,
    domain          VARCHAR(253) UNIQUE NOT NULL,
    status          VARCHAR(30)  NOT NULL DEFAULT 'review_needed',
    first_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_checked_at TIMESTAMPTZ,
    next_check_at   TIMESTAMPTZ  NOT NULL DEFAULT (NOW() + INTERVAL '180 days'),
    review_count    INTEGER      NOT NULL DEFAULT 1,
    review_reason   TEXT,
    vt_result       JSONB,
    otx_result      JSONB,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Indexes for daily_review_domains
CREATE INDEX IF NOT EXISTS idx_daily_review_domain
    ON daily_review_domains(domain);

CREATE INDEX IF NOT EXISTS idx_daily_review_status
    ON daily_review_domains(status);

CREATE INDEX IF NOT EXISTS idx_daily_review_next_check
    ON daily_review_domains(next_check_at);

CREATE INDEX IF NOT EXISTS idx_daily_review_status_next_check
    ON daily_review_domains(status, next_check_at);

-- 3. Create reviewed_clean_domains table
CREATE TABLE IF NOT EXISTS reviewed_clean_domains (
    id                  BIGSERIAL PRIMARY KEY,
    domain              VARCHAR(253) UNIQUE NOT NULL,
    verification_source VARCHAR(50)  NOT NULL DEFAULT 'online_correlation',
    verified_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    review_count        INTEGER      NOT NULL DEFAULT 1,
    vt_summary          JSONB,
    otx_summary         JSONB,
    status              VARCHAR(20)  NOT NULL DEFAULT 'clean',
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Indexes for reviewed_clean_domains
CREATE INDEX IF NOT EXISTS idx_reviewed_clean_domain
    ON reviewed_clean_domains(domain);

CREATE INDEX IF NOT EXISTS idx_reviewed_clean_verified_at
    ON reviewed_clean_domains(verified_at);

-- 4. Automatic updated_at trigger for daily_review_domains & reviewed_clean_domains
CREATE OR REPLACE FUNCTION update_timestamp_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE 'plpgsql';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_daily_review_updated_at'
    ) THEN
        CREATE TRIGGER trg_daily_review_updated_at
            BEFORE UPDATE ON daily_review_domains
            FOR EACH ROW
            EXECUTE FUNCTION update_timestamp_column();
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'trg_reviewed_clean_updated_at'
    ) THEN
        CREATE TRIGGER trg_reviewed_clean_updated_at
            BEFORE UPDATE ON reviewed_clean_domains
            FOR EACH ROW
            EXECUTE FUNCTION update_timestamp_column();
    END IF;
END $$;

-- 5. Data migration from unknown_domains (if exists)
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.tables WHERE table_name = 'unknown_domains'
    ) THEN
        -- Migrate review_needed / new / processing / error domains
        INSERT INTO daily_review_domains (
            domain, status, first_seen_at, last_seen_at, last_checked_at,
            next_check_at, review_count, review_reason, created_at, updated_at
        )
        SELECT
            domain,
            CASE
                WHEN status::text = 'clean' THEN 'clean'
                WHEN status::text = 'malicious' THEN 'malicious'
                WHEN status::text = 'processing' THEN 'processing'
                ELSE 'review_needed'
            END AS status,
            first_seen,
            last_seen,
            updated_at,
            NOW() + INTERVAL '180 days',
            1,
            'Migrated from unknown_domains',
            created_at,
            updated_at
        FROM unknown_domains
        ON CONFLICT (domain) DO UPDATE SET
            last_seen_at = GREATEST(daily_review_domains.last_seen_at, EXCLUDED.last_seen_at),
            updated_at   = NOW();

        -- Promote clean domains to reviewed_clean_domains
        INSERT INTO reviewed_clean_domains (
            domain, verification_source, verified_at, review_count, status, created_at, updated_at
        )
        SELECT
            domain,
            'unknown_domains_migration',
            last_seen,
            1,
            'clean',
            created_at,
            updated_at
        FROM unknown_domains
        WHERE status::text = 'clean'
        ON CONFLICT (domain) DO NOTHING;

        -- Promote malicious domains to reputation_domains
        INSERT INTO reputation_domains (
            domain, status, source, confidence, first_seen, last_seen, times_seen, query_count, created_at, updated_at
        )
        SELECT
            domain,
            'malicious',
            'unknown_domains_migration',
            1.0,
            first_seen,
            last_seen,
            1,
            1,
            created_at,
            updated_at
        FROM unknown_domains
        WHERE status::text = 'malicious'
        ON CONFLICT (domain) DO UPDATE SET
            last_seen   = GREATEST(reputation_domains.last_seen, EXCLUDED.last_seen),
            times_seen  = reputation_domains.times_seen + 1,
            updated_at  = NOW();
    END IF;
END $$;
