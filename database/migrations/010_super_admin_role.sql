ALTER TABLE dashboard_users
    DROP CONSTRAINT IF EXISTS chk_dashboard_users_role;

ALTER TABLE dashboard_users
    ADD CONSTRAINT chk_dashboard_users_role
    CHECK (role IN ('SUPER_ADMIN', 'ADMIN', 'ANALYST', 'SUPPORT'));
