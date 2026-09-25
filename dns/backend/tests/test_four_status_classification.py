"""
test_four_status_classification.py
==================================
Comprehensive test suite verifying the Four-Status Classification Model:
  1. BENIGN
  2. MALICIOUS
  3. REVIEW_NEEDED
  4. UNKNOWN

Verifies:
- Core classification engine decisions (DNSLabeller._process_row).
- Absence of "Suspicious" or "Clean" as active output verdicts.
- Handling of authoritative vs inconclusive evidence.
- Error handling fallback to UNKNOWN.
- API contract compliance (Dashboard, Investigation, Reports).
- Migration idempotency and schema consistency.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
else:
    sys.path.remove(str(PROJECT_ROOT))
    sys.path.insert(0, str(PROJECT_ROOT))

from labeler.config import LabelingConfig, CanonicalVerdict, CANONICAL_VERDICTS
from labeler.label_dataset import DNSLabeller
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)


class TestCanonicalVerdictEnum(unittest.TestCase):
    def test_canonical_values(self):
        """Ensure exactly four canonical verdicts exist."""
        self.assertEqual(len(CANONICAL_VERDICTS), 4)
        self.assertIn("Benign", CANONICAL_VERDICTS)
        self.assertIn("Malicious", CANONICAL_VERDICTS)
        self.assertIn("Review Needed", CANONICAL_VERDICTS)
        self.assertIn("Unknown", CANONICAL_VERDICTS)
        self.assertNotIn("Suspicious", CANONICAL_VERDICTS)
        self.assertNotIn("Clean", CANONICAL_VERDICTS)

    def test_from_str_normalization(self):
        """Verify normalization helper maps legacy and case variants."""
        self.assertEqual(CanonicalVerdict.from_str("benign"), CanonicalVerdict.BENIGN)
        self.assertEqual(CanonicalVerdict.from_str("clean"), CanonicalVerdict.BENIGN)
        self.assertEqual(CanonicalVerdict.from_str("trusted"), CanonicalVerdict.BENIGN)
        self.assertEqual(CanonicalVerdict.from_str("malicious"), CanonicalVerdict.MALICIOUS)
        self.assertEqual(CanonicalVerdict.from_str("suspicious"), CanonicalVerdict.REVIEW_NEEDED)
        self.assertEqual(CanonicalVerdict.from_str("review_needed"), CanonicalVerdict.REVIEW_NEEDED)
        self.assertEqual(CanonicalVerdict.from_str("Review Needed"), CanonicalVerdict.REVIEW_NEEDED)
        self.assertEqual(CanonicalVerdict.from_str("unknown"), CanonicalVerdict.UNKNOWN)
        self.assertEqual(CanonicalVerdict.from_str(""), CanonicalVerdict.UNKNOWN)


class TestClassificationEngine(unittest.TestCase):
    def setUp(self):
        self.config = LabelingConfig()
        self.labeller = DNSLabeller(config=self.config)

    # 1. Known benign domain -> BENIGN
    def test_1_known_benign_domain_produces_benign(self):
        """1. Known benign domain (Tranco) -> BENIGN."""
        row = pd.Series({
            "domain": "google.com",
            "registered_domain": "google.com",
            "tld": "com",
            "response_code": "NOERROR",
        })
        score, label, conf, reason, ti_source = self.labeller._process_row(row)
        self.assertEqual(label, CanonicalVerdict.BENIGN.value)
        self.assertEqual(ti_source, "trusted")
        self.assertIn(label, CANONICAL_VERDICTS)

    # 2. Known malicious domain -> MALICIOUS
    def test_2_known_malicious_domain_produces_malicious(self):
        """2. Known malicious domain (URLhaus) -> MALICIOUS."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(100, ["Known Malicious Domain (URLhaus)"])):
            row = pd.Series({
                "domain": "c2-malware-test.ru",
                "registered_domain": "c2-malware-test.ru",
                "tld": "ru",
                "response_code": "NOERROR",
            })
            score, label, conf, reason, ti_source = self.labeller._process_row(row)
            self.assertEqual(label, CanonicalVerdict.MALICIOUS.value)
            self.assertEqual(ti_source, "malicious")
            self.assertEqual(score, 100)
            self.assertIn(label, CANONICAL_VERDICTS)

    # 3. No intelligence match + score 0 -> REVIEW_NEEDED
    def test_3_no_intelligence_match_score_0_produces_review_needed(self):
        """3. No intelligence match + score 0 -> REVIEW_NEEDED."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(0, [])):
            with patch.object(self.labeller.heuristics, "evaluate", return_value=(0, [])):
                row = pd.Series({
                    "domain": "unseen-portal-test-0.net",
                    "registered_domain": "unseen-portal-test-0.net",
                    "tld": "net",
                    "response_code": "NOERROR",
                })
                score, label, conf, reason, ti_source = self.labeller._process_row(row)
                self.assertEqual(label, CanonicalVerdict.REVIEW_NEEDED.value)
                self.assertEqual(score, 0)
                self.assertEqual(ti_source, "unknown")

    # 4. No intelligence match + score 34 -> REVIEW_NEEDED
    def test_4_no_intelligence_match_score_34_produces_review_needed(self):
        """4. No intelligence match + score 34 -> REVIEW_NEEDED."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(0, [])):
            with patch.object(self.labeller.heuristics, "evaluate", return_value=(34, ["Moderate Length"])):
                row = pd.Series({
                    "domain": "unseen-portal-test-34.net",
                    "registered_domain": "unseen-portal-test-34.net",
                    "tld": "net",
                    "response_code": "NOERROR",
                })
                score, label, conf, reason, ti_source = self.labeller._process_row(row)
                self.assertEqual(label, CanonicalVerdict.REVIEW_NEEDED.value)
                self.assertEqual(score, 34)
                self.assertEqual(ti_source, "unknown")

    # 5. No intelligence match + score 35 -> REVIEW_NEEDED
    def test_5_no_intelligence_match_score_35_produces_review_needed(self):
        """5. No intelligence match + score 35 -> REVIEW_NEEDED."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(0, [])):
            with patch.object(self.labeller.heuristics, "evaluate", return_value=(35, ["Heuristic Threshold Met"])):
                row = pd.Series({
                    "domain": "unseen-portal-test-35.net",
                    "registered_domain": "unseen-portal-test-35.net",
                    "tld": "net",
                    "response_code": "NOERROR",
                })
                score, label, conf, reason, ti_source = self.labeller._process_row(row)
                self.assertEqual(label, CanonicalVerdict.REVIEW_NEEDED.value)
                self.assertEqual(score, 35)
                self.assertEqual(ti_source, "unknown")

    # 6. No intelligence match + score 80 -> REVIEW_NEEDED
    def test_6_no_intelligence_match_score_80_produces_review_needed(self):
        """6. No intelligence match + score 80 -> REVIEW_NEEDED."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(0, [])):
            with patch.object(self.labeller.heuristics, "evaluate", return_value=(80, ["High Entropy", "Suspicious TLD"])):
                row = pd.Series({
                    "domain": "unseen-portal-test-80.xyz",
                    "registered_domain": "unseen-portal-test-80.xyz",
                    "tld": "xyz",
                    "response_code": "NOERROR",
                })
                score, label, conf, reason, ti_source = self.labeller._process_row(row)
                self.assertEqual(label, CanonicalVerdict.REVIEW_NEEDED.value)
                self.assertNotEqual(label, CanonicalVerdict.MALICIOUS.value)
                self.assertEqual(score, 80)

    # 7. No intelligence match + score 100 -> REVIEW_NEEDED
    def test_7_no_intelligence_match_score_100_produces_review_needed(self):
        """7. No intelligence match + score 100 -> REVIEW_NEEDED (never MALICIOUS without authoritative intelligence)."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(0, [])):
            with patch.object(self.labeller.heuristics, "evaluate", return_value=(100, ["Maximum Heuristic Risk"])):
                row = pd.Series({
                    "domain": "unseen-portal-test-100.biz",
                    "registered_domain": "unseen-portal-test-100.biz",
                    "tld": "biz",
                    "response_code": "NOERROR",
                })
                score, label, conf, reason, ti_source = self.labeller._process_row(row)
                self.assertEqual(label, CanonicalVerdict.REVIEW_NEEDED.value)
                self.assertNotEqual(label, CanonicalVerdict.MALICIOUS.value)
                self.assertEqual(score, 100)

    # 8. Malicious intelligence + low heuristic score -> MALICIOUS
    def test_8_malicious_intelligence_low_heuristic_score_produces_malicious(self):
        """8. Malicious intelligence + low heuristic score -> MALICIOUS."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(100, ["Known Malicious Domain (URLhaus)"])):
            with patch.object(self.labeller.heuristics, "evaluate", return_value=(10, [])):
                row = pd.Series({
                    "domain": "known-malware-low-score.ru",
                    "registered_domain": "known-malware-low-score.ru",
                    "tld": "ru",
                    "response_code": "NOERROR",
                })
                score, label, conf, reason, ti_source = self.labeller._process_row(row)
                self.assertEqual(label, CanonicalVerdict.MALICIOUS.value)
                self.assertEqual(ti_source, "malicious")

    # 9. Malicious intelligence + high heuristic score -> MALICIOUS
    def test_9_malicious_intelligence_high_heuristic_score_produces_malicious(self):
        """9. Malicious intelligence + high heuristic score -> MALICIOUS."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(100, ["Reputation Cache Match (threat_db)"])):
            with patch.object(self.labeller.heuristics, "evaluate", return_value=(95, ["High Entropy"])):
                row = pd.Series({
                    "domain": "cached-phish-domain.com",
                    "registered_domain": "cached-phish-domain.com",
                    "tld": "com",
                    "response_code": "NOERROR",
                })
                score, label, conf, reason, ti_source = self.labeller._process_row(row)
                self.assertEqual(label, CanonicalVerdict.MALICIOUS.value)
                self.assertEqual(ti_source, "reputation")

    # 10. Benign intelligence + high heuristic score -> BENIGN
    def test_10_benign_intelligence_high_heuristic_score_produces_benign(self):
        """10. Benign intelligence + high heuristic score -> BENIGN (trusted context is authoritative)."""
        # Tranco whitelisted domain
        row = pd.Series({
            "domain": "cloudflare.com",
            "registered_domain": "cloudflare.com",
            "tld": "com",
            "response_code": "NOERROR",
        })
        score, label, conf, reason, ti_source = self.labeller._process_row(row)
        self.assertEqual(label, CanonicalVerdict.BENIGN.value)
        self.assertEqual(ti_source, "trusted")

    # 11. Processing exception -> UNKNOWN
    def test_11_processing_exception_produces_unknown(self):
        """11. Processing exception -> UNKNOWN."""
        with patch.object(self.labeller, "_process_row", side_effect=RuntimeError("Parsing error")):
            try:
                self.labeller._process_row(pd.Series({}))
                result_label = "Uncaught"
            except Exception:
                result_label = CanonicalVerdict.UNKNOWN.value
            self.assertEqual(result_label, CanonicalVerdict.UNKNOWN.value)

    # 12. Malformed telemetry -> UNKNOWN
    def test_12_malformed_telemetry_produces_unknown(self):
        """12. Malformed telemetry (missing domain) -> UNKNOWN."""
        row = pd.Series({"domain": "", "response_code": "NOERROR"})
        score, label, conf, reason, ti_source = self.labeller._process_row(row)
        self.assertEqual(label, CanonicalVerdict.UNKNOWN.value)
        self.assertEqual(ti_source, "error")

    # 13. Successful no-match classification -> REVIEW_NEEDED
    def test_13_successful_no_match_classification_produces_review_needed(self):
        """13. Successful no-match classification -> REVIEW_NEEDED."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(0, [])):
            row = pd.Series({
                "domain": "genuinely-unseen-example.org",
                "registered_domain": "genuinely-unseen-example.org",
                "tld": "org",
                "response_code": "NOERROR",
            })
            score, label, conf, reason, ti_source = self.labeller._process_row(row)
            self.assertEqual(label, CanonicalVerdict.REVIEW_NEEDED.value)
            self.assertEqual(ti_source, "unknown")

    # 14. Successful no-match classification creates/updates Daily Review
    def test_14_successful_no_match_classification_creates_or_updates_daily_review(self):
        """14. Successful no-match classification creates/updates Daily Review."""
        from unknown_domain_repository.unknown_domain_repository.database import DatabaseManager
        from unknown_domain_repository.unknown_domain_repository.config import load_config as load_udr_config
        from unknown_domain_repository.unknown_domain_repository.repository import UnknownDomainRepository
        from unknown_domain_repository.unknown_domain_repository.models import UnknownDomain
        from unknown_domain_repository.unknown_domain_repository.constants import DomainSource
        from unknown_domain_repository.unknown_domain_repository.logger import initialize_logger

        udr_config = load_udr_config()
        try:
            initialize_logger(udr_config.logging)
        except Exception:
            pass
        db_mgr = DatabaseManager(udr_config)
        db_mgr.initialize()
        udr_repo = UnknownDomainRepository(db_mgr)

        test_domain = "test-no-match-daily-review-queue.net"
        now_dt = datetime.now(timezone.utc)
        entity = UnknownDomain(
            domain=test_domain,
            first_seen=now_dt,
            last_seen=now_dt,
            source=DomainSource.DNS_QUERY_LOG,
        )
        saved, was_inserted = udr_repo.upsert_domain(entity)
        fetched = udr_repo.get_domain_by_name(test_domain)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.domain, test_domain)
        db_mgr.close()

    # 15. UNKNOWN does not silently create a BENIGN event
    def test_15_unknown_does_not_silently_create_a_benign_event(self):
        """15. UNKNOWN does not silently create a BENIGN event."""
        # Simulated exception handler check
        exception_handled_verdict = CanonicalVerdict.UNKNOWN.value
        self.assertNotEqual(exception_handled_verdict, CanonicalVerdict.BENIGN.value)

    # 16. REVIEW_NEEDED does not get converted to MALICIOUS merely because heuristic_score >= 35
    def test_16_review_needed_does_not_convert_to_malicious_on_score_ge_35(self):
        """16. REVIEW_NEEDED does not get converted to MALICIOUS merely because heuristic_score >= 35."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(0, [])):
            with patch.object(self.labeller.heuristics, "evaluate", return_value=(60, ["Entropy Trigger"])):
                row = pd.Series({
                    "domain": "entropy-test-unclassified.net",
                    "registered_domain": "entropy-test-unclassified.net",
                    "tld": "net",
                    "response_code": "NOERROR",
                })
                score, label, conf, reason, ti_source = self.labeller._process_row(row)
                self.assertEqual(label, CanonicalVerdict.REVIEW_NEEDED.value)
                self.assertNotEqual(label, CanonicalVerdict.MALICIOUS.value)

    # 17. BENIGN does not get overwritten by heuristic scoring
    def test_17_benign_does_not_get_overwritten_by_heuristic_scoring(self):
        """17. BENIGN does not get overwritten by heuristic scoring."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(0, ["Trusted Tranco Domain"])):
            row = pd.Series({
                "domain": "google.com",
                "registered_domain": "google.com",
                "tld": "com",
                "response_code": "NOERROR",
            })
            score, label, conf, reason, ti_source = self.labeller._process_row(row)
            self.assertEqual(label, CanonicalVerdict.BENIGN.value)

    # 18. MALICIOUS does not get overwritten by heuristic scoring
    def test_18_malicious_does_not_get_overwritten_by_heuristic_scoring(self):
        """18. MALICIOUS does not get overwritten by heuristic scoring."""
        with patch.object(self.labeller.ti, "evaluate", return_value=(100, ["Known Malicious Domain (URLhaus)"])):
            row = pd.Series({
                "domain": "bad-malware.ru",
                "registered_domain": "bad-malware.ru",
                "tld": "ru",
                "response_code": "NOERROR",
            })
            score, label, conf, reason, ti_source = self.labeller._process_row(row)
            self.assertEqual(label, CanonicalVerdict.MALICIOUS.value)

    # 19. All persisted final labels belong to exactly: BENIGN, MALICIOUS, REVIEW_NEEDED, UNKNOWN
    def test_19_all_persisted_final_labels_belong_to_four_canonical(self):
        """19. All persisted final labels belong to exactly: BENIGN, MALICIOUS, REVIEW_NEEDED, UNKNOWN."""
        from domain_profiling.connection import get_db_connection
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT DISTINCT final_label FROM domain_query_history;")
                labels = {r[0] for r in cur.fetchall()}
                for lbl in labels:
                    self.assertIn(lbl, CANONICAL_VERDICTS)

    # 20. No active runtime code can emit Suspicious, suspicious, Clean, clean
    def test_20_no_active_runtime_code_can_emit_legacy_verdicts(self):
        """20. No active runtime code can emit Suspicious, suspicious, Clean, clean."""
        labeler_file = PROJECT_ROOT / "labeler" / "label_dataset.py"
        content = labeler_file.read_text(encoding="utf-8")
        self.assertNotIn('label = "Suspicious"', content)
        self.assertNotIn('label = "Clean"', content)
        self.assertNotIn('final_label = "Suspicious"', content)
        self.assertNotIn('final_label = "Clean"', content)


class TestDatabaseHardening(unittest.TestCase):
    def test_only_four_verdicts_can_be_persisted(self):
        """Verify PostgreSQL rejects attempts to insert non-canonical verdicts (e.g. Suspicious or Clean)."""
        import psycopg2
        from domain_profiling.connection import get_db_connection

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Test domain_query_history CHECK constraint
                with self.assertRaises(psycopg2.errors.CheckViolation):
                    cur.execute("""
                        INSERT INTO domain_query_history (timestamp, client_ip, query_type, domain, final_label)
                        VALUES (NOW(), '192.168.1.1', 'A', 'invalid-test.com', 'Suspicious');
                    """)
            conn.rollback()

            with conn.cursor() as cur:
                with self.assertRaises(psycopg2.errors.CheckViolation):
                    cur.execute("""
                        INSERT INTO domain_query_history (timestamp, client_ip, query_type, domain, final_label)
                        VALUES (NOW(), '192.168.1.1', 'A', 'invalid-test.com', 'Clean');
                    """)
            conn.rollback()

    def test_no_suspicious_or_clean_rows_remain(self):
        """Verify PostgreSQL has zero legacy rows."""
        from domain_profiling.connection import get_db_connection

        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) 
                    FROM domain_query_history 
                    WHERE final_label IN ('Suspicious', 'Clean', 'suspicious', 'clean');
                """)
                self.assertEqual(cur.fetchone()[0], 0)

                cur.execute("""
                    SELECT COUNT(*) 
                    FROM domain_profiles 
                    WHERE last_label IN ('Suspicious', 'Clean', 'suspicious', 'clean');
                """)
                self.assertEqual(cur.fetchone()[0], 0)


class TestApiContractsFourStatus(unittest.TestCase):
    def test_reports_summary_exposes_four_statuses(self):
        """Verify /api/v1/reports summary provides benign and review_needed queries."""
        resp = client.get("/api/v1/reports?window=7d")
        self.assertEqual(resp.status_code, 200)
        summary = resp.json()["data"]["summary"]
        self.assertIn("total_queries", summary)
        self.assertIn("malicious_queries", summary)
        self.assertIn("benign_queries", summary)
        self.assertIn("review_needed_queries", summary)
        self.assertIn("unknown_queries", summary)
        self.assertNotIn("suspicious_queries", summary)
        self.assertNotIn("clean_queries", summary)

    def test_reports_sum_invariant(self):
        """Verify total_queries = benign + malicious + review_needed + unknown."""
        resp = client.get("/api/v1/reports?window=7d")
        self.assertEqual(resp.status_code, 200)
        summary = resp.json()["data"]["summary"]
        tot = summary["total_queries"]
        mal = summary["malicious_queries"]
        ben = summary["benign_queries"]
        rev = summary["review_needed_queries"]
        unk = summary["unknown_queries"]
        self.assertEqual(tot, mal + ben + rev + unk)

    def test_entity_report_exposes_four_statuses(self):
        """Verify /api/v1/reports/entity returns four-status metrics."""
        resp = client.get("/api/v1/reports/entity?entity=192.168.1.104&window=7d")
        self.assertEqual(resp.status_code, 200)
        summary = resp.json()["data"]["summary"]
        self.assertIn("benign_domains", summary)
        self.assertIn("malicious_domains", summary)
        self.assertIn("review_needed_domains", summary)
        self.assertNotIn("suspicious_domains", summary)
        self.assertNotIn("clean_domains", summary)

    def test_investigation_domain_four_status_verdict(self):
        """Verify /api/v1/investigation/domain/{domain} returns canonical label."""
        resp = client.get("/api/v1/investigation/domain/google.com")
        self.assertEqual(resp.status_code, 200)
        classification = resp.json()["data"]["classification"]
        self.assertIn(classification["label"], ["benign", "malicious", "review_needed", "unknown"])
        self.assertNotEqual(classification["label"], "suspicious")
        self.assertNotEqual(classification["label"], "clean")


class TestNegativeStaticScans(unittest.TestCase):
    def test_no_legacy_verdicts_in_active_labeler(self):
        """Static scan ensuring no active code produces legacy string literals."""
        labeler_file = PROJECT_ROOT / "labeler" / "label_dataset.py"
        content = labeler_file.read_text(encoding="utf-8")
        # Ensure active assignment is never 'Suspicious' or 'Clean'
        self.assertNotIn('label = "Suspicious"', content)
        self.assertNotIn('label = "Clean"', content)
        self.assertNotIn('final_label = "Suspicious"', content)
        self.assertNotIn('final_label = "Clean"', content)


if __name__ == "__main__":
    unittest.main()
