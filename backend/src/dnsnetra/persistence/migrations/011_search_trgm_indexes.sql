-- Migration 011: Trigram indexes for substring search
--
-- The reporting search endpoints build ILIKE '%term%' patterns, which a plain
-- btree index cannot serve. pg_trgm GIN indexes turn those into index scans.
--
-- Only domain_query_history is indexed: it is the large, growing table
-- (~64k rows today). domain_profiles and client_profiles are small profile
-- tables (tens of rows) where a sequential scan is already free — add trgm
-- indexes there only when they reach tens of thousands of rows.
--
-- CREATE INDEX CONCURRENTLY cannot run inside the migration runner's
-- transaction, so these are regular builds. At current size that is a
-- sub-second lock. Revisit (split into a manual CONCURRENTLY step) when the
-- table is large enough for the lock to matter.

CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_dqh_domain_trgm
    ON domain_query_history USING gin (domain gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_dqh_client_ip_trgm
    ON domain_query_history USING gin (client_ip gin_trgm_ops);
