# Phase 3 — Verification Report & Test Execution
**DNS Threat Detection System — Reconciled Verification Deliverable**  
**Status**: GREEN (ALL FUNCTIONAL AND CONTRACT VERIFICATIONS PASSED)  
**Date**: August 2026  

---

## 1. Automated Test Suite Execution

### Command:
```bash
backend/.venv/bin/pytest backend/tests -v
```

### Result:
```
============================= test session starts ==============================
platform darwin -- Python 3.11.15, pytest-9.1.1, pluggy-1.6.0 -- /Users/akshit/Developer/dns/backend/.venv/bin/python3
cachedir: .pytest_cache
rootdir: /Users/akshit/Developer/dns/backend
configfile: pytest.ini
plugins: anyio-4.14.2
collected 79 items

backend/tests/test_dashboard_aggregation.py::TestDomainDetail::test_domain_counts PASSED [  1%]
backend/tests/test_dashboard_aggregation.py::TestDomainDetail::test_domain_query_type_breakdown PASSED [  2%]
backend/tests/test_dashboard_aggregation.py::TestClientDetail::test_client_counts PASSED [  3%]
backend/tests/test_dashboard_aggregation.py::TestClientDetail::test_client_malicious_count PASSED [  5%]
backend/tests/test_dashboard_aggregation.py::TestIdempotency::test_double_run_identical PASSED [  6%]
backend/tests/test_dashboard_aggregation.py::TestAtomicity::test_failure_leaves_prior_snapshot PASSED [  7%]
backend/tests/test_dashboard_aggregation.py::TestAPI::test_dashboard_bundle PASSED [  8%]
backend/tests/test_dashboard_aggregation.py::TestAPI::test_domain_list_pagination PASSED [ 10%]
backend/tests/test_dashboard_aggregation.py::TestAPI::test_domain_detail PASSED [ 11%]
backend/tests/test_dashboard_aggregation.py::TestAPI::test_client_detail PASSED [ 12%]
backend/tests/test_dashboard_aggregation.py::TestAPI::test_status PASSED [ 13%]
backend/tests/test_dashboard_aggregation.py::TestAPI::test_domain_filter PASSED [ 15%]
backend/tests/test_incremental_aggregator.py::TestBasicEventProcessing::test_01_empty_database PASSED [ 16%]
backend/tests/test_incremental_aggregator.py::TestBasicEventProcessing::test_02_first_incremental_run PASSED [ 17%]
backend/tests/test_incremental_aggregator.py::TestBasicEventProcessing::test_03_second_run_no_new_events PASSED [ 18%]
backend/tests/test_incremental_aggregator.py::TestBasicEventProcessing::test_04_second_run_with_new_events PASSED [ 20%]
backend/tests/test_incremental_aggregator.py::TestBasicEventProcessing::test_05_same_timestamp_different_ids PASSED [ 21%]
backend/tests/test_incremental_aggregator.py::TestMultiEntityProcessing::test_06_multiple_domains PASSED [ 22%]
backend/tests/test_incremental_aggregator.py::TestMultiEntityProcessing::test_07_multiple_clients PASSED [ 24%]
backend/tests/test_incremental_aggregator.py::TestMultiEntityProcessing::test_08_same_client_multiple_domains PASSED [ 25%]
backend/tests/test_incremental_aggregator.py::TestMultiEntityProcessing::test_09_same_domain_multiple_clients PASSED [ 26%]
backend/tests/test_incremental_aggregator.py::TestMultiEntityProcessing::test_10_duplicate_replayed_batch PASSED [ 27%]
backend/tests/test_incremental_aggregator.py::TestTransactionGuarantees::test_11_failure_before_commit_dashboard_unchanged PASSED [ 29%]
backend/tests/test_incremental_aggregator.py::TestTransactionGuarantees::test_12_failure_during_dashboard_update_rollback PASSED [ 30%]
backend/tests/test_incremental_aggregator.py::TestTransactionGuarantees::test_13_failure_before_watermark_update PASSED [ 31%]
backend/tests/test_incremental_aggregator.py::TestTransactionGuarantees::test_14_successful_watermark_update PASSED [ 32%]
backend/tests/test_incremental_aggregator.py::TestAggregationRuns::test_15_aggregation_runs_success PASSED [ 34%]
backend/tests/test_incremental_aggregator.py::TestAggregationRuns::test_16_aggregation_runs_failure PASSED [ 35%]
backend/tests/test_incremental_aggregator.py::TestAggregationRuns::test_17_stale_running_run_recovery PASSED [ 36%]
backend/tests/test_incremental_aggregator.py::TestDetailCorrectness::test_18_domain_details_correctness PASSED [ 37%]
backend/tests/test_incremental_aggregator.py::TestDetailCorrectness::test_19_client_details_correctness PASSED [ 39%]
backend/tests/test_incremental_aggregator.py::TestDetailCorrectness::test_20_threat_category_correctness PASSED [ 40%]
backend/tests/test_incremental_aggregator.py::TestDetailCorrectness::test_21_timeseries_correctness PASSED [ 41%]
backend/tests/test_incremental_aggregator.py::TestDetailCorrectness::test_22_top_domain_correctness PASSED [ 43%]
backend/tests/test_incremental_aggregator.py::TestDetailCorrectness::test_23_top_client_correctness PASSED [ 44%]
backend/tests/test_incremental_aggregator.py::TestRebuild::test_24_rebuild_correctness PASSED [ 45%]
backend/tests/test_incremental_aggregator.py::TestRebuild::test_25_rebuild_incremental_equivalence PASSED [ 46%]
backend/tests/test_incremental_aggregator.py::TestEdgeCases::test_26_dry_run_does_not_modify_db PASSED [ 48%]
backend/tests/test_incremental_aggregator.py::TestEdgeCases::test_27_concurrent_aggregator_protection PASSED [ 49%]
backend/tests/test_incremental_aggregator.py::TestEdgeCases::test_28_missing_enrichment_fields_null PASSED [ 50%]
backend/tests/test_incremental_aggregator.py::TestEdgeCases::test_29_empty_source PASSED [ 51%]
backend/tests/test_incremental_aggregator.py::TestEdgeCases::test_30_malformed_source_row PASSED [ 53%]
backend/tests/test_incremental_aggregator.py::TestLabelSemantics::test_clean_label PASSED [ 54%]
backend/tests/test_incremental_aggregator.py::TestLabelSemantics::test_empty_label PASSED [ 55%]
backend/tests/test_incremental_aggregator.py::TestLabelSemantics::test_malicious_label PASSED [ 56%]
backend/tests/test_incremental_aggregator.py::TestLabelSemantics::test_none_label PASSED [ 58%]
backend/tests/test_incremental_aggregator.py::TestLabelSemantics::test_trusted_label PASSED [ 59%]
backend/tests/test_incremental_aggregator.py::TestLabelSemantics::test_unknown_label PASSED [ 60%]
backend/tests/test_live_pipeline_correctness.py::TestLivePipelineLabelBinding::test_apply_labels_preserves_final_label_and_metadata PASSED [ 62%]
backend/tests/test_live_pipeline_correctness.py::TestLivePipelineLabelBinding::test_benign_domain_profiling_label_binding PASSED [ 63%]
backend/tests/test_live_pipeline_correctness.py::TestLivePipelineLabelBinding::test_domain_profiling_service_process_dataframe_receives_final_label PASSED [ 64%]
backend/tests/test_live_pipeline_correctness.py::TestLivePipelineLabelBinding::test_structured_json_to_record_parses_cleanly PASSED [ 65%]
backend/tests/test_performance.py::PerformanceTest::test_perf_100k_events PASSED [ 67%]
backend/tests/test_performance.py::PerformanceTest::test_perf_10k_events PASSED [ 68%]
backend/tests/test_performance.py::PerformanceTest::test_perf_1k_events PASSED [ 69%]
backend/tests/test_phase3_investigation.py::TestDomainInvestigation::test_d1_google_com_tranco_context PASSED [ 70%]
backend/tests/test_phase3_investigation.py::TestDomainInvestigation::test_d2_mail_google_com_subdomain_context PASSED [ 72%]
backend/tests/test_phase3_investigation.py::TestDomainInvestigation::test_d3_imccj_gobgem_com_urlhaus_exact PASSED [ 73%]
backend/tests/test_phase3_investigation.py::TestDomainInvestigation::test_d4_evil_google_com_subdomain_override PASSED [ 74%]
backend/tests/test_phase3_investigation.py::TestDomainInvestigation::test_d5_secure_update_net_correlated_malicious PASSED [ 75%]
backend/tests/test_phase3_investigation.py::TestDomainInvestigation::test_d6_unknown_test_domain_honest_handling PASSED [ 77%]
backend/tests/test_phase3_investigation.py::TestClientInvestigation::test_c1_known_client_investigation PASSED [ 78%]
backend/tests/test_phase3_investigation.py::TestClientInvestigation::test_c2_client_with_malicious_activity PASSED [ 79%]
backend/tests/test_phase3_investigation.py::TestClientInvestigation::test_c3_unobserved_client_not_found PASSED [ 81%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p1_persisted_evidence_not_reported_as_live PASSED [ 82%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p2_no_data_is_not_benign PASSED [ 83%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p3_not_configured_is_not_benign PASSED [ 84%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p4_provider_failure_is_not_benign PASSED [ 86%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p5_persisted_provider_evidence_provenance PASSED [ 87%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p6_live_provider_evidence_provenance PASSED [ 88%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p7_threat_traffic_ratio_calculation PASSED [ 89%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p8_threat_domain_ratio_calculation PASSED [ 91%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p9_suspicious_classification_honest_source PASSED [ 92%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p10_unknown_domain_remains_200_and_not_observed PASSED [ 93%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p11_unknown_client_remains_404 PASSED [ 94%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p12_exact_malicious_subdomain_overrides_trusted_parent PASSED [ 96%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p13_golden_payload_consistency PASSED [ 97%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p14_normalization_case_and_trailing_dot PASSED [ 98%]
backend/tests/test_phase3_investigation.py::TestPhase3HardenedInvariants::test_p15_legacy_route_compatibility PASSED [100%]

============================= 79 passed in 22.60s ==============================
```

---

## 2. Phase 2.7 Threat Intelligence Acceptance Matrix

### Canonical Terminology:
- **10 / 10 Top-Level Test Groups Passed**
- **14 / 14 Individual Assertions Passed**

```
====================================================================
 MATRIX SUMMARY: ALL TESTS PASSED (GREEN)
====================================================================
  [TEST A] Tranco Whitelist Integration (SQLite Read Model)       | PASS
  [TEST B] URLhaus Malicious Integration (Exact & Apex Scope)     | PASS
  [TEST C] Real External Provider Live Lookup (VirusTotal + OTX)  | PASS
  [TEST D] Correlation Engine Live Decision (Weighted Model)      | PASS
  [TEST E] Exact Malicious Subdomain Overrides Tranco Apex        | PASS
  [TEST F] Provider NO_DATA (Explicit Invariant Verification)     | PASS
  [TEST G] Provider Failure (Timeout / 429 != Clean)              | PASS
  [TEST H] The Golden Investigation & Dashboard Acceptance Test   | PASS
  [TEST I] Missing / Absent Credentials Path                      | PASS
  [TEST J] Explicit Evidence Scope & Precedence Matrix:
     [J.1] google.com (Tranco Apex + URLhaus Root Artifact)       | PASS
     [J.2] mail.google.com (Subdomain of Tranco Apex)             | PASS
     [J.3] GoOgLe.CoM (Case-Insensitive Normalization)            | PASS
     [J.4] google.com. (Trailing-Dot Normalization)               | PASS
     [J.5] imccj.gobgem.com (Exact Subdomain Malicious)           | PASS
     [J.6] secure-update.net (Correlated External Threat)         | PASS
====================================================================
```

---

## 3. Frontend Production Build

```bash
cd frontend && npm run build
```
- **Result**: Built successfully in 633ms without TypeScript errors or broken imports.

---

## 4. Latency Benchmark Measurements (Cold vs Warm Reporting)

| Latency Class | Benchmark Target | Cold Measurement | Warm P50 | Warm P95 | Samples | Verdict |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Local Benign TI** (`google.com`) | P95 < 100 ms | 484.02 ms | **11.73 ms** | **15.03 ms** | 20 | Cold: **NOT MET** / Warm: **PASS** |
| **Local Malicious TI** (`imccj.gobgem.com`) | P95 < 100 ms | 28.12 ms | **10.14 ms** | **15.97 ms** | 20 | Cold: **PASS** / Warm: **PASS** |
| **Persisted Reputation** (`secure-update.net`) | P95 < 100 ms | 31.40 ms | **10.06 ms** | **17.19 ms** | 20 | Cold: **PASS** / Warm: **PASS** |
| **Client Endpoint** (`192.168.1.100`) | P95 < 100 ms | 29.50 ms | **9.12 ms** | **18.18 ms** | 20 | Cold: **PASS** / Warm: **PASS** |
| **External TI Live Lookup** (`completely-unindexed-sample-456.biz`) | P95 < 3,000 ms | 1,703.83 ms | — | **1,703.83 ms** | Live HTTP | **PASS** |

*\*Cold latency reflects initial Python module imports and SQLite connection pool initialization on startup.*

---

## 5. Manual Frontend & API-Level End-to-End Acceptance

| Test ID | User Workflow / Navigation | Expected Verification | Observed Result | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| **E2E-1** | Header Search → `google.com` | Domain Investigation view loads | `POPULAR_BENIGN_CONTEXT`, Tranco match, 9 DNS queries | **PASS** |
| **E2E-2** | Header Search → `GoOgLe.CoM.` | Normalizes to `google.com` | Canonical FQDN `google.com`, Tranco match | **PASS** |
| **E2E-3** | Search → `secure-update.net` | Malicious investigation view loads | `KNOWN_MALICIOUS`, VT/OTX `AVAILABLE` (`PERSISTED`), active rep | **PASS** |
| **E2E-4** | Domain → Client `192.168.1.100` link | Client Investigation view loads | Shows `192.168.1.100`, RFC 1918 Private, 70 total queries | **PASS** |
| **E2E-5** | Client → `secure-update.net` link | Domain Investigation view loads | Bi-directional navigation opens domain detail | **PASS** |
| **E2E-6** | Search → `completely-unindexed-sample-456.biz` | No 404 error; investigation object | `REVIEW_NEEDED`, DNS `NOT_OBSERVED`, query count = 0 | **PASS** |
| **E2E-7** | Search → `imccj.gobgem.com` | Exact URLhaus malicious result | `KNOWN_MALICIOUS`, Scope: `EXACT_FQDN`, risk score 100.0 | **PASS** |
| **E2E-8** | Search → `evil.google.com` | Exact malicious overrides parent Tranco | `KNOWN_MALICIOUS`, exact subdomain precedence | **PASS** |
| **E2E-9** | Client Search → `not-an-ip` | HTTP 400 Bad Request error state | UI renders "Invalid IP format" error cleanly | **PASS** |
| **E2E-10**| Client Search → `10.254.254.254` | HTTP 404 Not Found error state | UI renders "Client IP not found in telemetry" cleanly | **PASS** |
