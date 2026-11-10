ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS target_type TEXT NULL,
    ADD COLUMN IF NOT EXISTS target_id   TEXT NULL;

CREATE INDEX IF NOT EXISTS idx_audit_target
    ON audit_logs (target_type, target_id);
