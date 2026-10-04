"""
tests/test_wipe_data.py
=======================
Safety and dry-run tests for DNSNetra Development Data Reset Tool.
"""

import pytest
from pathlib import Path
from scripts.wipe_data import (
    verify_target_safety,
    SafetyCheckError,
    TARGET_POSTGRES_TABLES,
    PROTECTED_POSTGRES_TABLES,
    run_wipe,
)


class TestWipeDataSafetyGuards:
    """Verify safety checks and dry-run guarantees."""

    def test_remote_host_rejected_without_override(self):
        remote_params = {
            "host": "production-db.internal.net",
            "port": "5432",
            "dbname": "dns_threat_detection",
        }
        with pytest.raises(SafetyCheckError) as exc_info:
            verify_target_safety(remote_params, allow_remote=False)
        assert "restricted to local development" in str(exc_info.value)

    def test_localhost_accepted(self):
        local_params = {"host": "localhost"}
        # Should not raise
        verify_target_safety(local_params, allow_remote=False)

        ip_params = {"host": "127.0.0.1"}
        verify_target_safety(ip_params, allow_remote=False)

    def test_protected_tables_not_in_target_list(self):
        for pt in PROTECTED_POSTGRES_TABLES:
            assert pt not in TARGET_POSTGRES_TABLES, f"Protected table {pt} found in target wipe list!"

    def test_dry_run_executes_safely_without_modification(self):
        res = run_wipe(dry_run=True)
        assert res["dry_run"] is True
        assert res["counts_before"] == res["counts_after"]
        assert res["counts_before"]["domain_query_history"] > 0
