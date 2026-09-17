-- =============================================================================
-- Migration 005: Add review_needed_queries to domain_profiles & Reconcile
-- =============================================================================
-- Safe, additive migration. Does not drop tables, alter existing types, or 
-- truncate data. Preserves historical telemetry integrity.

SET client_encoding = 'UTF8';

-- 1. Add review_needed_queries column to domain_profiles if not present
ALTER TABLE domain_profiles 
ADD COLUMN IF NOT EXISTS review_needed_queries BIGINT NOT NULL DEFAULT 0;

-- 2. Synchronize review_needed_queries and unknown_queries from authoritative domain_query_history
-- Review Needed queries (448) were previously grouped into unknown_queries because domain_profiles
-- lacked a dedicated review_needed_queries column.
UPDATE domain_profiles dp
SET 
    review_needed_queries = sub.rn_cnt,
    unknown_queries = sub.unk_cnt,
    updated_at = NOW()
FROM (
    SELECT 
        domain,
        COUNT(*) FILTER (WHERE final_label = 'Review Needed') AS rn_cnt,
        COUNT(*) FILTER (WHERE final_label = 'Unknown' OR final_label NOT IN ('Malicious', 'Benign', 'Clean', 'Trusted', 'Review Needed')) AS unk_cnt
    FROM domain_query_history
    GROUP BY domain
) sub
WHERE dp.domain = sub.domain;
