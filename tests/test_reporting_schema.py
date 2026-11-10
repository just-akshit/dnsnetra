"""Reporting schema exists after migrations."""

from domain_profiling.connection import get_db_connection


def test_reporting_tables_and_indexes_exist():
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name IN ('reports', 'cases', 'case_events', 'case_reports')
                ORDER BY table_name;
            """)
            assert [r[0] for r in cur.fetchall()] == [
                "case_events", "case_reports", "cases", "reports"
            ]

            cur.execute("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'audit_logs'
                  AND column_name IN ('target_type', 'target_id');
            """)
            assert len(cur.fetchall()) == 2
