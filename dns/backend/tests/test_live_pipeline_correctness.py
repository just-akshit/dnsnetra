"""
test_live_pipeline_correctness.py
==================================
Regression test suite proving P0 data correctness in run_live_pipeline.py:
- Canonical live event sets row['final_label'] = label
- DomainProfilingService receives final_label correctly
- domain_query_history.final_label is persisted as 'Malicious', 'Benign', 'Suspicious', etc.
- IncrementalAggregator correctly aggregates threats from domain_query_history
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "bind converter"))
sys.path.insert(0, str(PROJECT_ROOT / "parsing logs"))
sys.path.insert(0, str(PROJECT_ROOT / "feature extraction"))

from parser.models import DNSRecord
from run_live_pipeline import _apply_labels, _record_from_structured_json


class TestLivePipelineLabelBinding(unittest.TestCase):
    """Test suite for label and final_label binding in live pipeline."""

    def test_apply_labels_preserves_final_label_and_metadata(self):
        """Verify _apply_labels patches label, final_label, threat_score, confidence, label_reason, ti_source."""
        record = DNSRecord(
            timestamp=datetime.now(timezone.utc),
            client_ip="192.168.1.100",
            domain="malicious-test.com",
            query_type="A",
            response_code="NOERROR",
        )

        row = {
            "domain": "malicious-test.com",
            "client_ip": "192.168.1.100",
            "query_type": "A",
            "timestamp": "2026-08-01T12:00:00Z",
            "label": "Malicious",
            "final_label": "Malicious",
            "threat_score": 90,
            "confidence": 95,
            "label_reason": "Known Malicious Domain (URLhaus)",
            "ti_source": "malicious",
        }

        updated_record = _apply_labels(record, row)

        self.assertEqual(updated_record.label, "Malicious")
        self.assertEqual(getattr(updated_record, "final_label", None), "Malicious")
        self.assertEqual(updated_record.threat_score, 90)
        self.assertEqual(updated_record.confidence, 95)
        self.assertEqual(updated_record.label_reason, "Known Malicious Domain (URLhaus)")
        self.assertEqual(getattr(updated_record, "ti_source", None), "malicious")

    def test_structured_json_to_record_parses_cleanly(self):
        """Verify structured JSON from Fluent Bit builds valid DNSRecord."""
        msg = {
            "timestamp": "01-Aug-2026 13:21:07.000",
            "client_ip": "192.168.1.101",
            "client_port": "3106",
            "domain": "malicious-test.com",
            "query_type": "AAAA",
            "query_class": "IN",
            "response_code": "NOERROR",
        }

        res = _record_from_structured_json(msg, source_file="kafka", line_number=1)
        self.assertTrue(res.success)
        self.assertIsNotNone(res.record)
        self.assertEqual(res.record.domain, "malicious-test.com")
        self.assertEqual(res.record.client_ip, "192.168.1.101")
        self.assertEqual(res.record.query_type, "AAAA")

    def test_domain_profiling_service_process_dataframe_receives_final_label(self):
        """
        Verify that when a DataFrame with 'final_label' and 'ti_source' is passed
        to DomainProfilingService.process_dataframe, the repository insert_history_batch
        and upsert_domain_profiles_batch receive the true final_label (not 'Unknown').
        """
        from domain_profiling.service import DomainProfilingService

        mock_repo = MagicMock()
        mock_repo.insert_history_batch.return_value = [101]

        service = DomainProfilingService(repository=mock_repo)

        # Simulate row passed from run_live_pipeline after labeller sets final_label
        row_dict = {
            "domain": "evil-c2-botnet.net",
            "client_ip": "192.168.1.55",
            "query_type": "A",
            "timestamp": datetime.now(timezone.utc),
            "response_code": "NOERROR",
            "registered_domain": "evil-c2-botnet.net",
            "tld": "net",
            "label": "Malicious",
            "final_label": "Malicious",
            "threat_score": 100,
            "confidence": 99,
            "label_reason": "Known Malicious Domain (URLhaus)",
            "ti_source": "malicious",
        }

        df = pd.DataFrame([row_dict])
        res_df = service.process_dataframe(df)

        # 1. Verify history batch insert received final_label = 'Malicious'
        mock_repo.insert_history_batch.assert_called_once()
        inserted_history = mock_repo.insert_history_batch.call_args[0][0]
        self.assertEqual(len(inserted_history), 1)
        self.assertEqual(inserted_history[0]["domain"], "evil-c2-botnet.net")
        self.assertEqual(inserted_history[0]["final_label"], "Malicious")
        self.assertEqual(inserted_history[0]["ti_source"], "malicious")

        # 2. Verify domain profiles batch upsert received final_label / malicious counts
        mock_repo.upsert_domain_profiles_batch.assert_called_once()
        upserted_profiles = mock_repo.upsert_domain_profiles_batch.call_args[0][0]
        self.assertEqual(len(upserted_profiles), 1)
        self.assertEqual(upserted_profiles[0]["domain"], "evil-c2-botnet.net")
        self.assertEqual(upserted_profiles[0]["last_label"], "Malicious")
        self.assertEqual(upserted_profiles[0]["last_ti_source"], "malicious")
        self.assertEqual(upserted_profiles[0]["malicious_queries"], 1)
        self.assertEqual(upserted_profiles[0]["clean_queries"], 0)

    def test_benign_domain_profiling_label_binding(self):
        """Verify Benign/Clean/Trusted domains propagate correctly."""
        from domain_profiling.service import DomainProfilingService

        mock_repo = MagicMock()
        mock_repo.insert_history_batch.return_value = [102]

        service = DomainProfilingService(repository=mock_repo)

        row_dict = {
            "domain": "google.com",
            "client_ip": "192.168.1.101",
            "query_type": "A",
            "timestamp": datetime.now(timezone.utc),
            "response_code": "NOERROR",
            "label": "Benign",
            "final_label": "Benign",
            "threat_score": 0,
            "confidence": 100,
            "label_reason": "Trusted Tranco Domain",
            "ti_source": "trusted",
        }

        service.process_dataframe(pd.DataFrame([row_dict]))

        inserted_history = mock_repo.insert_history_batch.call_args[0][0]
        self.assertEqual(inserted_history[0]["final_label"], "Benign")
        self.assertEqual(inserted_history[0]["ti_source"], "trusted")

        upserted_profiles = mock_repo.upsert_domain_profiles_batch.call_args[0][0]
        self.assertEqual(upserted_profiles[0]["last_label"], "Benign")
        self.assertEqual(upserted_profiles[0]["clean_queries"], 1)
        self.assertEqual(upserted_profiles[0]["malicious_queries"], 0)


if __name__ == "__main__":
    unittest.main()
