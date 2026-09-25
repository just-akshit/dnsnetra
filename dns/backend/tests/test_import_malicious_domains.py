#!/usr/bin/env python3
"""
test_import_malicious_domains.py
================================
Unit and integration tests for the Malicious Domain Importer:
1. Normalization consistency (case, whitespace, trailing dots, protocols, www prefix)
2. Duplicate handling & Idempotency (multiple runs do not duplicate records)
3. Existing data preservation (existing URLhaus records are untouched)
4. New data presence (SQLite domains exist in PostgreSQL with 'sqlite_import' provenance)
5. Classification integration (ThreatIntelligence and is_malicious recognize imported domains)
"""

from __future__ import annotations

import os
import sqlite3
import sys
import unittest
from pathlib import Path

import psycopg2
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
load_dotenv(PROJECT_ROOT / ".env")

from scripts.import_malicious_domains import (
    canonicalize_domain,
    run_import,
    resolve_sqlite_path,
)
from labeler.intel.malicious import is_malicious
from labeler.threat_intelligence import ThreatIntelligence
from labeler.config import LabelingConfig

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
MALICIOUS_DB = os.getenv("MALICIOUS_DB_DATABASE", "malicious_db")


class TestDomainNormalization(unittest.TestCase):
    """Verifies domain normalization conforms to project standards."""

    def test_lowercase_conversion(self):
        self.assertEqual(canonicalize_domain("MALICIOUS-TEST.COM"), "malicious-test.com")

    def test_whitespace_and_trailing_dots(self):
        self.assertEqual(canonicalize_domain("  evil.com.  "), "evil.com")
        self.assertEqual(canonicalize_domain("bad-domain.net..."), "bad-domain.net")

    def test_url_prefix_and_path_stripping(self):
        self.assertEqual(canonicalize_domain("https://c2.attacker.com/payload.exe"), "c2.attacker.com")
        self.assertEqual(canonicalize_domain("http://phish.target.org/login?ref=1"), "phish.target.org")

    def test_www_prefix_stripping(self):
        self.assertEqual(canonicalize_domain("www.malware-dist.biz"), "malware-dist.biz")
        # Subdomains other than www must be preserved
        self.assertEqual(canonicalize_domain("login.sub.attacker.com"), "login.sub.attacker.com")

    def test_empty_and_malformed_domains(self):
        self.assertIsNone(canonicalize_domain(""))
        self.assertIsNone(canonicalize_domain(None))
        self.assertIsNone(canonicalize_domain("   "))
        self.assertIsNone(canonicalize_domain("a"))


class TestPostgreSQLImportAndIntegration(unittest.TestCase):
    """Verifies database-level properties: deduplication, preservation, and classification."""

    @classmethod
    def setUpClass(cls):
        cls.conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            dbname=MALICIOUS_DB,
            user=DB_USER,
            password=DB_PASSWORD,
        )
        cls.sqlite_path = resolve_sqlite_path()

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def test_1_sqlite_database_resolvable_and_valid(self):
        """Verify SQLite database exists and contains expected record volume."""
        self.assertTrue(self.sqlite_path.exists())
        self.assertGreater(self.sqlite_path.stat().st_size, 1_000_000)

        s_conn = sqlite3.connect(self.sqlite_path)
        cur = s_conn.cursor()
        cur.execute("SELECT COUNT(*) FROM malicious_domains;")
        count = cur.fetchone()[0]
        s_conn.close()
        self.assertGreaterEqual(count, 200_000)

    def test_2_existing_data_preserved(self):
        """Verify existing URLhaus records remain intact in PostgreSQL."""
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM malicious_domains WHERE source = 'urlhaus';")
        urlhaus_count = cur.fetchone()[0]
        cur.close()
        self.assertGreaterEqual(urlhaus_count, 1_000_000)

    def test_3_new_data_present_with_provenance(self):
        """Verify imported SQLite domains exist in PostgreSQL with 'sqlite_import' provenance."""
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM malicious_domains WHERE source = 'sqlite_import';")
        sqlite_count = cur.fetchone()[0]
        cur.close()
        self.assertGreaterEqual(sqlite_count, 190_000)

    def test_4_import_idempotency(self):
        """Verify running import again does not increase count or insert duplicates."""
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM malicious_domains;")
        baseline_count = cur.fetchone()[0]
        cur.close()

        stats = run_import(self.sqlite_path, dry_run=False, batch_size=20000)
        self.assertEqual(stats["newly_inserted"], 0)
        self.assertEqual(stats["final_pg_total"], baseline_count)

    def test_5_classification_integration(self):
        """Verify that newly imported domains are recognized by ThreatIntelligence and is_malicious."""
        cur = self.conn.cursor()
        cur.execute(
            "SELECT domain FROM malicious_domains WHERE source = 'sqlite_import' AND domain NOT LIKE '%%.%%.%%' LIMIT 5;"
        )
        sample_domains = [row[0] for row in cur.fetchall()]
        cur.close()

        self.assertTrue(len(sample_domains) > 0, "Expected at least 1 sample imported domain")

        ti = ThreatIntelligence(LabelingConfig())
        for d in sample_domains:
            self.assertTrue(is_malicious(d), f"Domain {d} must be detected as malicious by is_malicious()")
            score, reasons = ti.evaluate(domain=d)
            self.assertEqual(score, 100, f"Domain {d} must score 100 in ThreatIntelligence")
            self.assertIn("Known Malicious Domain (URLhaus)", reasons[0])

        # Clean domain check
        self.assertFalse(is_malicious("wikipedia.org"))
        clean_score, _ = ti.evaluate(domain="wikipedia.org")
        self.assertEqual(clean_score, -100)


if __name__ == "__main__":
    unittest.main()
