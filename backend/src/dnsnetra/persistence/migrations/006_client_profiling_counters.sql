-- =============================================================================
-- Migration 006: Repair Client Profiling Schema, Add Counters, and Backfill
-- =============================================================================
-- Non-destructive, additive migration.
-- 1. Alters client_profiles to store 4-state verdict counters, unique domains,
--    last domain, last query type, and timestamps with time zone.
-- 2. Alters client_history to store 4-state verdict counters and timestamps with time zone.
-- 3. Drops redundant index on client_history(client_ip, domain).
-- 4. Reconstructs all client_profiles and client_history data from domain_query_history.
-- =============================================================================

SET client_encoding = 'UTF8';

-- 1. Standardize timestamps to TIMESTAMPTZ
ALTER TABLE client_profiles ALTER COLUMN first_seen TYPE TIMESTAMPTZ USING first_seen AT TIME ZONE 'UTC';
ALTER TABLE client_profiles ALTER COLUMN last_seen TYPE TIMESTAMPTZ USING last_seen AT TIME ZONE 'UTC';

-- 2. Add client_profiles columns
ALTER TABLE client_profiles 
ADD COLUMN IF NOT EXISTS total_queries BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS unique_domains INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS benign_queries BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS malicious_queries BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS review_needed_queries BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS unknown_queries BIGINT NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS last_domain VARCHAR(255),
ADD COLUMN IF NOT EXISTS last_query_type VARCHAR(20),
ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

-- 3. Add performance indexes on client_profiles
CREATE INDEX IF NOT EXISTS idx_client_profiles_last_seen ON client_profiles(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_client_profiles_total_queries ON client_profiles(total_queries DESC);

-- 4. Standardize client_history timestamps
ALTER TABLE client_history ALTER COLUMN first_seen TYPE TIMESTAMPTZ USING first_seen AT TIME ZONE 'UTC';
ALTER TABLE client_history ALTER COLUMN last_seen TYPE TIMESTAMPTZ USING last_seen AT TIME ZONE 'UTC';

-- 5. Add verdict breakdown columns to client_history
ALTER TABLE client_history 
ADD COLUMN IF NOT EXISTS benign_visits INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS malicious_visits INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS review_needed_visits INTEGER NOT NULL DEFAULT 0,
ADD COLUMN IF NOT EXISTS unknown_visits INTEGER NOT NULL DEFAULT 0;

-- 6. Drop redundant duplicate index on client_history
-- (unique_client_domain already enforces uniqueness and creates btree index on client_ip, domain)
DROP INDEX IF EXISTS idx_client_history_client_domain;

-- 7. Backfill & Reconcile client_profiles from authoritative domain_query_history
-- Captures all clients including missing client 192.168.10.51
INSERT INTO client_profiles (
    client_ip, first_seen, last_seen, total_queries, unique_domains,
    benign_queries, malicious_queries, review_needed_queries, unknown_queries,
    last_domain, last_query_type, created_at, updated_at
)
SELECT 
    sub.client_ip,
    sub.first_seen,
    sub.last_seen,
    sub.total_queries,
    sub.unique_domains,
    sub.benign_queries,
    sub.malicious_queries,
    sub.review_needed_queries,
    sub.unknown_queries,
    lat.last_domain,
    lat.last_query_type,
    sub.first_seen AS created_at,
    NOW() AS updated_at
FROM (
    SELECT 
        client_ip::inet AS client_ip,
        MIN(timestamp) AS first_seen,
        MAX(timestamp) AS last_seen,
        COUNT(*) AS total_queries,
        COUNT(DISTINCT domain) AS unique_domains,
        COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_queries,
        COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_queries,
        COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_queries,
        COUNT(*) FILTER (WHERE final_label = 'Unknown' OR final_label NOT IN ('Benign', 'Malicious', 'Review Needed')) AS unknown_queries
    FROM domain_query_history
    GROUP BY client_ip::inet
) sub
JOIN (
    SELECT DISTINCT ON (client_ip::inet)
        client_ip::inet AS client_ip,
        domain AS last_domain,
        query_type AS last_query_type
    FROM domain_query_history
    ORDER BY client_ip::inet, timestamp DESC, id DESC
) lat ON sub.client_ip = lat.client_ip
ON CONFLICT (client_ip) DO UPDATE SET
    first_seen = EXCLUDED.first_seen,
    last_seen = EXCLUDED.last_seen,
    total_queries = EXCLUDED.total_queries,
    unique_domains = EXCLUDED.unique_domains,
    benign_queries = EXCLUDED.benign_queries,
    malicious_queries = EXCLUDED.malicious_queries,
    review_needed_queries = EXCLUDED.review_needed_queries,
    unknown_queries = EXCLUDED.unknown_queries,
    last_domain = EXCLUDED.last_domain,
    last_query_type = EXCLUDED.last_query_type,
    updated_at = NOW();

-- 8. Backfill & Reconcile client_history from authoritative domain_query_history
INSERT INTO client_history (
    client_ip, domain, first_seen, last_seen, visit_count,
    benign_visits, malicious_visits, review_needed_visits, unknown_visits
)
SELECT 
    client_ip::inet,
    domain,
    MIN(timestamp) AS first_seen,
    MAX(timestamp) AS last_seen,
    COUNT(*) AS visit_count,
    COUNT(*) FILTER (WHERE final_label = 'Benign') AS benign_visits,
    COUNT(*) FILTER (WHERE final_label = 'Malicious') AS malicious_visits,
    COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS review_needed_visits,
    COUNT(*) FILTER (WHERE final_label = 'Unknown' OR final_label NOT IN ('Benign', 'Malicious', 'Review Needed')) AS unknown_visits
FROM domain_query_history
GROUP BY client_ip::inet, domain
ON CONFLICT (client_ip, domain) DO UPDATE SET
    first_seen = EXCLUDED.first_seen,
    last_seen = EXCLUDED.last_seen,
    visit_count = EXCLUDED.visit_count,
    benign_visits = EXCLUDED.benign_visits,
    malicious_visits = EXCLUDED.malicious_visits,
    review_needed_visits = EXCLUDED.review_needed_visits,
    unknown_visits = EXCLUDED.unknown_visits;
