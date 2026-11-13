-- ============================================================================
-- DNSNetra Migration 008: Comprehensive Authentication & Security Hardening
-- Adds case-insensitive username index, status/role constraints,
-- must_change_password column, and drops NOT NULL from legacy bcrypt column.
-- ============================================================================

-- 1. Ensure unique case-insensitive index on username
DROP INDEX IF EXISTS idx_dashboard_users_username_lower;
CREATE UNIQUE INDEX IF NOT EXISTS uq_dashboard_users_lower_username ON dashboard_users (LOWER(username));

-- 2. Add must_change_password flag for admin-mediated password resets
ALTER TABLE dashboard_users
    ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE;

-- 3. Allow legacy hashed_password to be NULL when migrated to Argon2id password_hash
ALTER TABLE dashboard_users
    ALTER COLUMN hashed_password DROP NOT NULL;

-- 4. Enforce valid roles via CHECK constraint
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_dashboard_users_role'
    ) THEN
        ALTER TABLE dashboard_users
            ADD CONSTRAINT chk_dashboard_users_role
            CHECK (role IN ('ADMIN', 'ANALYST', 'SUPPORT'));
    END IF;
END $$;

-- 5. Enforce valid statuses via CHECK constraint
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_dashboard_users_status'
    ) THEN
        ALTER TABLE dashboard_users
            ADD CONSTRAINT chk_dashboard_users_status
            CHECK (status IN ('PENDING', 'ACTIVE', 'DISABLED'));
    END IF;
END $$;

-- 6. Enforce status and is_active invariant
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_dashboard_users_status_active'
    ) THEN
        ALTER TABLE dashboard_users
            ADD CONSTRAINT chk_dashboard_users_status_active
            CHECK (
                (status = 'ACTIVE' AND is_active = true) OR
                (status != 'ACTIVE' AND is_active = false)
            );
    END IF;
END $$;
