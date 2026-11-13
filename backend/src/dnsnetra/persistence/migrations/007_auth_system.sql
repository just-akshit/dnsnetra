-- ============================================================================
-- DNSNetra Migration 007: Complete Authentication, Session & Audit System
-- Non-destructive additive migration extending dashboard_users and provisioning
-- server-side sessions and security audit logging.
-- ============================================================================

-- 1. Extend dashboard_users table for username-based authentication & RBAC status
ALTER TABLE dashboard_users
    ADD COLUMN IF NOT EXISTS username VARCHAR(100),
    ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255),
    ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ;

-- Backfill username and password_hash for existing admin rows
UPDATE dashboard_users
SET username = 'admin',
    password_hash = hashed_password,
    role = 'ADMIN',
    status = 'ACTIVE'
WHERE id = 2 AND (username IS NULL OR username = '');

UPDATE dashboard_users
SET username = 'admin_sec',
    password_hash = hashed_password,
    role = 'ADMIN',
    status = 'ACTIVE'
WHERE id = 1 AND (username IS NULL OR username = '');

-- Fallback for any other existing rows
UPDATE dashboard_users
SET username = SPLIT_PART(email, '@', 1),
    password_hash = hashed_password,
    role = UPPER(role),
    status = 'ACTIVE'
WHERE username IS NULL OR username = '';

-- Ensure unique constraint on username
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'uq_dashboard_users_username'
    ) THEN
        ALTER TABLE dashboard_users ADD CONSTRAINT uq_dashboard_users_username UNIQUE (username);
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_dashboard_users_username_lower ON dashboard_users (LOWER(username));
CREATE INDEX IF NOT EXISTS idx_dashboard_users_status ON dashboard_users (status);
CREATE INDEX IF NOT EXISTS idx_dashboard_users_role ON dashboard_users (role);

-- 2. Server-side sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES dashboard_users(id) ON DELETE CASCADE,
    session_token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions (session_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_revoked_at ON sessions (revoked_at);

-- 3. Security audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES dashboard_users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    target_user_id INTEGER REFERENCES dashboard_users(id) ON DELETE SET NULL,
    ip_address INET,
    user_agent TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_target_user_id ON audit_logs (target_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs (timestamp DESC);
