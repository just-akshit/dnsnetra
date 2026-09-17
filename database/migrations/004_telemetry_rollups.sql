-- =============================================================================
-- Migration 004: Telemetry Rollups, Aggregation State & Analytics Indexes
-- =============================================================================

SET client_encoding = 'UTF8';

-- 1. Table: telemetry_hourly_rollup
-- Stores strictly additive counters per hourly bucket.
-- Safe for ON CONFLICT DO UPDATE additions.
CREATE TABLE IF NOT EXISTS telemetry_hourly_rollup (
    bucket_time        TIMESTAMPTZ PRIMARY KEY,
    total_queries      BIGINT NOT NULL DEFAULT 0,
    clean_queries      BIGINT NOT NULL DEFAULT 0,
    suspicious_queries BIGINT NOT NULL DEFAULT 0,
    malicious_queries  BIGINT NOT NULL DEFAULT 0,
    unknown_queries    BIGINT NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_thr_bucket_time
    ON telemetry_hourly_rollup (bucket_time DESC);

-- 2. Table: telemetry_aggregation_state
-- Tracks transactional watermarks (domain_query_history.id) for incremental aggregators.
CREATE TABLE IF NOT EXISTS telemetry_aggregation_state (
    job_name                 VARCHAR(50) PRIMARY KEY,
    last_processed_id        BIGINT NOT NULL DEFAULT 0,
    last_processed_timestamp TIMESTAMPTZ,
    last_run_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_events_processed   BIGINT NOT NULL DEFAULT 0,
    status                   VARCHAR(20) NOT NULL DEFAULT 'idle'
);

-- Initialize default state row if not present
INSERT INTO telemetry_aggregation_state (job_name, last_processed_id, total_events_processed, status)
VALUES ('dnsnetra_aggregator', 0, 0, 'idle')
ON CONFLICT (job_name) DO NOTHING;

-- 3. Table: telemetry_daily_domain_rollup
-- Read model for multi-day distinct domains and threat rankings.
-- PRIMARY KEY (bucket_date, domain, final_label) explicitly preserves domain verdicts over time.
CREATE TABLE IF NOT EXISTS telemetry_daily_domain_rollup (
    bucket_date DATE NOT NULL,
    domain      VARCHAR(253) NOT NULL,
    final_label VARCHAR(50) NOT NULL,
    query_count INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (bucket_date, domain, final_label)
);

CREATE INDEX IF NOT EXISTS idx_tddr_date_label 
    ON telemetry_daily_domain_rollup (bucket_date, final_label);

CREATE INDEX IF NOT EXISTS idx_tddr_domain 
    ON telemetry_daily_domain_rollup (domain);

-- 4. Composite Performance Indexes on domain_query_history
-- Crucial for fast windowed distinct counts and threat filtering without sequential heap scans.
CREATE INDEX IF NOT EXISTS idx_dqh_ts_domain 
    ON domain_query_history (timestamp, domain);

CREATE INDEX IF NOT EXISTS idx_dqh_ts_client 
    ON domain_query_history (timestamp, client_ip);

CREATE INDEX IF NOT EXISTS idx_dqh_ts_label_domain 
    ON domain_query_history (timestamp, final_label, domain);

CREATE INDEX IF NOT EXISTS idx_dqh_ts_final_label 
    ON domain_query_history (timestamp, final_label);
