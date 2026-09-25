# PHASE 2.7 — RUN 0.16: CURRENT THREAT INTELLIGENCE PIPELINE MAP

**Document Version:** 1.0.0  
**Phase:** Phase 2.7 (Functional Threat Intelligence Validation)  
**Run:** Run 0.16 (Real Output / Dashboard Readiness Test)  
**Status:** VALIDATED AGAINST SOURCE CODE

---

## 1. Executive Summary & Pipeline Topology

This document details the **exact, currently implemented** Threat Intelligence (TI) execution flow in the codebase. It traces every function call, data transformation, database interaction, read-model update, API response, and frontend UI binding.

```
DNS Query (Log/Stream)
       ↓
Domain Extraction (DNSLogParser)
       ↓
Domain Normalization (TLDExtract / Lowercase)
       ↓
Local Threat Intelligence (ThreatIntelligence.evaluate)
       ├── Tranco SQLite (trusted_domains.db)  → Context / Popularity Flag
       └── URLhaus SQLite (malicious_domains.db) → Local Malicious Verdict
       ↓
Classification & Unknown Domain Decision (DNSLabeller)
       ├── "trusted"   → Score: -100, Skip Online TI
       ├── "malicious" → Score: +100, PostgreSQL reputation_domains (UPSERT), Skip Online TI
       └── "unknown"   → Heuristics, PostgreSQL unknown_domains (INSERT new)
                              ↓
                      UnknownDomainProcessor.process()
                              ↓
                      CorrelationEngine.evaluate()
                              ├── Layer-1 Memory Cache & Layer-2 PostgreSQL (reputation_domains)
                              ├── VirusTotalProvider.lookup() (Multi-key / Round-robin)
                              └── AlienVaultOTXProvider.lookup() (General & Analysis)
                              ↓
                      WeightedScorer.calculate()
                              ↓
                      ThreatDecision (Verdict, Score, Confidence, Evidence)
                              ├── If Malicious: PostgreSQL reputation_domains (UPSERT)
                              └── Status in unknown_domains: MALICIOUS / CLEAN / REVIEW_NEEDED
       ↓
Event Log Persistence (domain_query_history)
       ↓
Incremental Aggregator (IncrementalAggregator.run_incremental())
       ↓
SQLite Read Model (dashboard.db)
       ↓
FastAPI Backend (/api/v1/domains/{domain}, /api/v1/dashboard)
       ↓
React Dashboard Frontend (DomainDetailPage.tsx)
```

---

## 2. Transition-by-Transition Analysis

For each stage in the actual pipeline, the 10 standard architectural questions are answered below based on the runtime implementation.

---

### Stage 1: DNS Query Ingestion & Domain Extraction

1. **What function is called?**
   - Stream mode: `LivePipelineProcessor._process_line(line, line_number)` in [`backend/run_live_pipeline.py`](file:///Users/akshit/Developer/dns/backend/run_live_pipeline.py).
   - Batch mode: `DNSLogParser.parse_line(line)` in [`backend/parsing logs/parser.py`](file:///Users/akshit/Developer/dns/backend/parsing%20logs/parser.py).
2. **What object is returned?**
   - `DNSLogEntry` dataclass instance containing raw query fields (`query_name`, `client_ip`, `query_type`, `response_code`, `timestamp`, etc.).
3. **What fields exist?**
   - `query_name`, `client_ip`, `query_type`, `response_code`, `timestamp`, `country`, `asn`, `resolved_ips`.
4. **Where is the result stored?**
   - Stored in-memory as a row dict/Series during batch or stream processing.
5. **What happens if NO_DATA / Malformed line?**
   - Log parsing error is caught; line is skipped or marked invalid; does not crash the pipeline.
6. **What happens if provider fails?**
   - N/A (Local log parser).
7. **What happens if MALICIOUS?**
   - Raw query has no verdict yet.
8. **What happens if BENIGN?**
   - Raw query has no verdict yet.
9. **What happens if multiple records respond?**
   - Handled line-by-line sequentially.
10. **Does the result reach the dashboard?**
    - Feeds downstream extraction and persistence.

---

### Stage 2: Domain Normalization

1. **What function is called?**
   - `DatasetGenerator._extract_domain_features()` in [`backend/parsing logs/dataset_generator.py`](file:///Users/akshit/Developer/dns/backend/parsing%20logs/dataset_generator.py) using `tldextract`.
2. **What object is returned?**
   - Normalized dictionary with separate domain components.
3. **What fields exist?**
   - `domain` (lowercased, trailing dot removed, e.g. `"sub.example.com"`), `registered_domain` (e.g. `"example.com"`), `tld` (e.g. `"com"`), `subdomain` (e.g. `"sub"`).
4. **Where is the result stored?**
   - Transformed into `pd.Series` / row dictionary.
5. **What happens if NO_DATA / empty domain?**
   - If empty, discarded with warning.
6. **What happens if provider fails?**
   - N/A.
7. **What happens if MALICIOUS?**
   - Normalization is neutral.
8. **What happens if BENIGN?**
   - Normalization is neutral.
9. **What happens if multiple domains?**
   - Evaluated individually per record.
10. **Does the result reach the dashboard?**
    - Yes, `domain` is the primary key and display identifier.

---

### Stage 3: Local Threat Intelligence (Tranco & URLhaus)

1. **What function is called?**
   - `ThreatIntelligence.evaluate(domain, registered_domain, tld, response_code, client_ip, query_type)` in [`backend/labeler/threat_intelligence.py`](file:///Users/akshit/Developer/dns/backend/labeler/threat_intelligence.py).
   - Tranco lookup: `is_trusted(tranco_lookup)` via [`backend/labeler/intel/manager.py`](file:///Users/akshit/Developer/dns/backend/labeler/intel/manager.py) querying SQLite `trusted_domains.db`.
   - URLhaus lookup: `is_malicious(full_domain)` and `is_malicious(rd_lookup)` via [`backend/labeler/intel/malicious/manager.py`](file:///Users/akshit/Developer/dns/backend/labeler/intel/malicious/manager.py) querying SQLite `malicious_domains.db`.
2. **What object is returned?**
   - `tuple[int, list[str]]` -> `(score, reasons)`.
3. **What fields exist?**
   - `score` (int, e.g. -100, 100, or 0..100), `reasons` (list of strings, e.g. `["Trusted Tranco Domain"]`, `["Known Malicious Domain (URLhaus)"]`).
4. **Where is the result stored?**
   - If URLhaus matches, immediately invokes `store_malicious_domain(malicious_domain, {"source": "URLHaus", "confidence": 1.0, "client_ip": client_ip, "query_type": query_type})` which inserts/upserts into PostgreSQL `reputation_domains`.
5. **What happens if NO_DATA?**
   - If absent from both Tranco and URLhaus, returns `score = 0` and reasons based on suspicious TLDs or response codes; downstream classifies `ti_source = "unknown"`.
6. **What happens if provider fails?**
   - SQLite query error is caught and logged; falls through safely to heuristics/unknown.
7. **What happens if MALICIOUS (URLhaus hit)?**
   - Returns score 100, reasons `["Known Malicious Domain (URLhaus)"]`; persisted immediately to PostgreSQL `reputation_domains`.
8. **What happens if BENIGN / POPULAR (Tranco hit)?**
   - Returns score -100, reasons `["Trusted Tranco Domain"]`. Classified as `ti_source = "trusted"`.
9. **What happens if multiple sources match?**
   - Tranco is checked first. If matched, returns early. URLhaus checked second.
10. **Does the result reach the dashboard?**
    - Yes, `ti_source` and `label_reason` are saved to query history and aggregated.

---

### Stage 4: Classification & Unknown Domain Routing

1. **What function is called?**
   - `DNSLabeller._process_row(row)` in [`backend/labeler/label_dataset.py`](file:///Users/akshit/Developer/dns/backend/labeler/label_dataset.py).
   - In `run_live_pipeline.py` (lines 739–768):
     - `ti_source == "malicious"`: Skips online TI (already written to `reputation_domains`).
     - `ti_source == "trusted"`: Skips online TI (whitelist).
     - `ti_source == "unknown"`: Calls `DomainPersistenceManager.process_final_dataset()` then `UnknownDomainProcessor.process()`.
2. **What object is returned?**
   - `DNSLabeller._process_row` returns `(threat_score, label, confidence, reason, ti_source)`.
   - `DomainPersistenceManager.process_final_dataset()` returns `ProcessingStats`.
3. **What fields exist?**
   - `threat_score`, `label` ("Malicious", "Suspicious", "Benign"), `confidence`, `reason`, `ti_source` ("trusted", "malicious", "unknown").
4. **Where is the result stored?**
   - Unknown domains are inserted into PostgreSQL `unknown_domains` with `status = 'new'`, preserving `client_ip` and `query_type`.
5. **What happens if NO_DATA?**
   - Domain is marked `unknown` and enqueued in `unknown_domains`.
6. **What happens if provider fails?**
   - Database errors log warning and continue without crashing the stream.
7. **What happens if MALICIOUS?**
   - `ti_source = "malicious"`, labeled "Malicious", `threat_score = 100`, `confidence = 98`.
8. **What happens if BENIGN?**
   - `ti_source = "trusted"`, labeled "Benign", `threat_score = 0`, `confidence = 95`.
9. **What happens if multiple events?**
   - Deduplicated per batch in `domain_persistence.py`.
10. **Does the result reach the dashboard?**
    - Yes, stored in raw query log / `domain_query_history`.

---

### Stage 5: Unknown Domain Processor & Online TI Dispatch

1. **What function is called?**
   - `UnknownDomainProcessor.process()` in [`backend/labeler/intel/unknown_domain_processor.py`](file:///Users/akshit/Developer/dns/backend/labeler/intel/unknown_domain_processor.py).
2. **What object is returned?**
   - Fetches `UnknownDomain` entities via `persistence.get_pending_domains()` (status `'new'`).
   - Updates status to `DomainStatus.PROCESSING`.
   - Calls `OnlineThreatIntelligence.evaluate(domain_name, client_ip=..., query_type=...)`.
3. **What fields exist?**
   - `domain_name`, `client_ip`, `query_type`.
4. **Where is the result stored?**
   - Status in `unknown_domains` is updated to `DomainStatus.MALICIOUS`, `DomainStatus.CLEAN`, `DomainStatus.REVIEW_NEEDED`, or `DomainStatus.ERROR`.
5. **What happens if NO_DATA?**
   - `decision.has_intelligence` is `False` -> status becomes `DomainStatus.REVIEW_NEEDED` (never falsely marked `CLEAN`).
6. **What happens if provider fails?**
   - Returns `decision.has_intelligence = False` or raises exception -> caught and status set to `DomainStatus.ERROR` or `DomainStatus.REVIEW_NEEDED`.
7. **What happens if MALICIOUS?**
   - `decision.malicious` is `True` -> status updated to `DomainStatus.MALICIOUS`.
8. **What happens if BENIGN?**
   - `decision.has_intelligence` is `True` and `decision.malicious` is `False` -> status updated to `DomainStatus.CLEAN`.
9. **What happens if multiple domains?**
   - Iterates through all pending domains sequentially in the batch.
10. **Does the result reach the dashboard?**
    - Malicious outcomes are inserted into `reputation_domains` and updated in `unknown_domains`.

---

### Stage 6: VirusTotal & AlienVault OTX Providers

1. **What function is called?**
   - `VirusTotalProvider.lookup(domain)` in [`backend/labeler/intel/providers/virustotal.py`](file:///Users/akshit/Developer/dns/backend/labeler/intel/providers/virustotal.py).
   - `AlienVaultOTXProvider.lookup(domain)` in [`backend/labeler/intel/providers/alienvault.py`](file:///Users/akshit/Developer/dns/backend/labeler/intel/providers/alienvault.py).
2. **What object is returned?**
   - `ThreatProviderResult` dataclass.
3. **What fields exist?**
   - `provider`: "VirusTotal" / "AlienVault OTX"
   - `malicious`: bool
   - `confidence`: float (0.0 to 1.0)
   - `malicious_count`: int
   - `harmless_count`: int
   - `suspicious_count`: int
   - `unavailable`: bool
   - `error`: Optional[str]
   - `found`: bool
   - `raw_data`: dict (raw API response)
4. **Where is the result stored?**
   - Returned in-memory to `CorrelationEngine`.
5. **What happens if NO_DATA?**
   - VT HTTP 404 -> `ThreatProviderResult(malicious=False, confidence=0.0, found=False, unavailable=False)`.
   - OTX HTTP 404 / 0 pulses -> `ThreatProviderResult(malicious=False, confidence=0.0, found=False, unavailable=False)`.
6. **What happens if provider fails / times out / 429?**
   - Multi-key rotation via `APIKeyManager` attempts next key.
   - If exhausted, returns `ThreatProviderResult(unavailable=True, error=...)`.
   - `unavailable=True` contributes 0 weight to scoring.
7. **What happens if MALICIOUS?**
   - VT detections > 0 -> `malicious=True`, `confidence = malicious / total`, counts populated.
   - OTX pulses > 0 -> `malicious=True`, `confidence = min(pulses / 3.0, 1.0)`, `malicious_count = pulses`.
8. **What happens if BENIGN?**
   - VT detections == 0 and harmless > 0 -> `malicious=False`, `found=True`.
9. **What happens if multiple providers respond?**
   - Queried concurrently in `CorrelationEngine` via `ThreadPoolExecutor(max_workers=2)`.
10. **Does the result reach the dashboard?**
    - Preserved inside `ThreatDecision.provider_results` and formatted into `reputation_domains.metadata`.

---

### Stage 7: Correlation Engine & Weighted Scoring

1. **What function is called?**
   - `CorrelationEngine.evaluate(domain, client_ip, query_type)` in [`backend/labeler/intel/correlation/engine.py`](file:///Users/akshit/Developer/dns/backend/labeler/intel/correlation/engine.py).
   - `WeightedScorer.calculate(results)` in [`backend/labeler/intel/correlation/scoring.py`](file:///Users/akshit/Developer/dns/backend/labeler/intel/correlation/scoring.py).
2. **What object is returned?**
   - `ThreatDecision` dataclass.
3. **What fields exist?**
   - `domain`: str
   - `malicious`: bool (score >= threshold)
   - `score`: float (sum of malicious provider weights)
   - `confidence`: float (mean confidence of malicious providers)
   - `threshold`: float (default 0.60)
   - `provider_results`: list[ThreatProviderResult]
   - `checked_at`: datetime (UTC)
   - `source`: "Threat Correlation Engine"
   - Property `has_intelligence`: bool (True if at least one provider was reachable and found data)
   - Property `metadata`: dict (structured provider breakdown)
4. **Where is the result stored?**
   - Cached in Layer-1 (memory with dual TTL: 24h malicious, 6h clean).
   - If `malicious=True`, calls `CorrelationEngine._persist()` -> `store_malicious_domain()`.
5. **What happens if NO_DATA?**
   - Score = 0.0, Confidence = 0.0, `has_intelligence = False`, `malicious = False`.
6. **What happens if provider fails?**
   - Failed provider has `unavailable=True`, contributes 0 weight. Remaining provider votes determine score.
7. **What happens if MALICIOUS?**
   - Score >= 0.60 -> `malicious=True`, persisted to `reputation_domains`.
8. **What happens if BENIGN?**
   - Score < 0.60 -> `malicious=False`, cached in memory.
9. **What happens if disagreement (VT=Malicious 0.60, OTX=Benign 0.0)?**
   - Total score = 0.60 >= 0.60 -> `malicious=True`. Both provider records preserved in `provider_results`.
10. **Does the result reach the dashboard?**
    - Yes, via `reputation_domains` and aggregator updates.

---

### Stage 8: PostgreSQL Persistence

1. **What function is called?**
   - `store_malicious_domain(domain, metadata)` in [`backend/labeler/intel/reputation/repository.py`](file:///Users/akshit/Developer/dns/backend/labeler/intel/reputation/repository.py).
   - `UnknownDomainRepository.update_domain_status()` in [`backend/unknown_domain_repository/unknown_domain_repository/repository.py`](file:///Users/akshit/Developer/dns/backend/unknown_domain_repository/unknown_domain_repository/repository.py).
2. **What object is returned?**
   - `bool` (True if inserted, False if updated).
3. **What fields exist?**
   - `reputation_domains`: `domain`, `status`, `source`, `confidence`, `first_seen`, `last_seen`, `times_seen`, `query_count`, `client_ip`, `query_type`, `created_at`, `updated_at`.
   - `unknown_domains`: `id`, `domain`, `status`, `source`, `observation_count`, `first_observed_at`, `last_observed_at`, `evaluated_at`, `details`, `client_ip`, `query_type`.
4. **Where is the result stored?**
   - PostgreSQL tables `reputation_domains` and `unknown_domains`.
5. **What happens if NO_DATA?**
   - `reputation_domains` is not inserted; `unknown_domains.status` set to `'review_needed'`.
6. **What happens if DB fails?**
   - Exception logged, transaction rolled back; retry on next batch.
7. **What happens if MALICIOUS?**
   - Atomically upserted into `reputation_domains` with `ON CONFLICT (domain) DO UPDATE`.
8. **What happens if BENIGN?**
   - `unknown_domains.status` set to `'clean'`.
9. **What happens if multiple writes?**
   - Deduplicated via PostgreSQL unique index on `domain`.
10. **Does the result reach the dashboard?**
    - Serves as the primary source of truth.

---

### Stage 9: Incremental Aggregator & SQLite Read Model

1. **What function is called?**
   - `IncrementalAggregator.run_incremental()` in [`backend/dashboard_aggregation/incremental_aggregator.py`](file:///Users/akshit/Developer/dns/backend/dashboard_aggregation/incremental_aggregator.py).
2. **What object is returned?**
   - `IncrementalRunResult` (batches, rows seen, rows processed, duration_ms, status).
3. **What fields exist?**
   - SQLite tables in `dashboard.db`:
     - `metrics_summary`: `total_queries`, `total_threats`, `threats_blocked_pct`, `unique_clients`, `unique_domains`, `last_pipeline_run_at`.
     - `domain_details`: `domain`, `total_queries`, `unique_clients`, `threat_count`, `malicious_count`, `suspicious_count`, `clean_count`, `last_label`, `threat_score`, `confidence`, `last_ti_source`, `label_reason`, `first_seen`, `last_seen`, `query_type_breakdown`, `response_code_breakdown`, `enrichment_json`.
     - `client_details`: `client_ip`, `total_queries`, `unique_domains`, `threat_count`, `malicious_count`, `suspicious_count`, `clean_count`, `top_domains`.
     - `queries_timeseries`: `time_bucket`, `total_queries`, `threat_queries`.
     - `threats_by_category`: `category`, `count`, `pct`.
     - `recent_flagged_domains`: `domain`, `label`, `label_reason`, `ti_source`, `confidence`, `flagged_at`.
     - `aggregation_state`: `last_processed_event_id`, `last_processed_event_timestamp`.
4. **Where is the result stored?**
   - Written atomically to `backend/dashboard.db`.
5. **What happens if NO_DATA?**
   - Aggregator handles 0 rows smoothly and preserves existing watermark.
6. **What happens if SQLite is locked/fails?**
   - Rolls back current batch transaction, writes failure to `aggregation_runs` log table.
7. **What happens if MALICIOUS?**
   - Increments `threat_count` and `malicious_count`, updates `recent_flagged_domains` and `threats_by_category`.
8. **What happens if BENIGN?**
   - Increments `clean_count` and `total_queries`.
9. **What happens if multiple events?**
   - Aggregated in batches of 10,000 with watermark tracking.
10. **Does the result reach the dashboard?**
    - Yes, this is the exact read model queried by FastAPI.

---

### Stage 10: API & Dashboard UI Presentation

1. **What function is called?**
   - `get_domain_detail(domain)` -> `GET /api/v1/domains/{domain}` in [`backend/api/routes/dashboard.py`](file:///Users/akshit/Developer/dns/backend/api/routes/dashboard.py).
   - `get_dashboard_bundle()` -> `GET /api/v1/dashboard`.
   - `get_domains()` -> `GET /api/v1/domains`.
2. **What object is returned?**
   - JSON response with `status: "success"` and typed `data` object matching frontend interface `DomainDetailResponse`.
3. **What fields exist?**
   - `domain`, `label`, `threat_score`, `confidence`, `stats` (`total_queries`, `threat_count`, `malicious`, `suspicious`, `clean`), `first_seen`, `last_seen`, `threat_intel` (`source`, `label_reason`), `network`, `dns` (`query_type_breakdown`, `response_code_breakdown`), `enrichment`, `source`.
4. **Where is the result stored?**
   - Delivered over HTTP to React frontend (`DomainDetailPage.tsx`, `DashboardOverview.tsx`).
5. **What happens if domain not found?**
   - Returns HTTP 404 with JSON detail `Domain '<domain>' not found in dashboard database`.
6. **What happens if backend down?**
   - Frontend error boundary / toast displays connection error.
7. **What happens if MALICIOUS?**
   - Dashboard shows red "Malicious" badge, threat score, confidence percentage, TI source, and breakdown.
8. **What happens if BENIGN / TRUSTED?**
   - Dashboard shows green "Benign" / "Trusted" badge with query statistics.
9. **What happens if multiple queries?**
   - Paginated table with search and filtering (`/api/v1/domains?page=1&page_size=50`).
10. **Does the result reach the dashboard display?**
    - Rendered in real-time in the browser UI.

---

## 3. Real Code Path Verification Summary

| Component | File Path | Primary Function / Class |
|---|---|---|
| Ingestion & Parser | `backend/parsing logs/parser.py` | `DNSLogParser.parse_line()` |
| Stream Ingestion | `backend/run_live_pipeline.py` | `LivePipelineProcessor._process_line()` |
| Local TI (Tranco) | `backend/labeler/intel/manager.py` | `is_trusted()` |
| Local TI (URLhaus) | `backend/labeler/intel/malicious/manager.py` | `is_malicious()` |
| Offline Scorer | `backend/labeler/label_dataset.py` | `DNSLabeller._process_row()` |
| Unknown Domain Mgr | `backend/domain_persistence.py` | `DomainPersistenceManager.process_final_dataset()` |
| Unknown Processor | `backend/labeler/intel/unknown_domain_processor.py` | `UnknownDomainProcessor.process()` |
| Correlation Engine | `backend/labeler/intel/correlation/engine.py` | `CorrelationEngine.evaluate()` |
| Weighted Scorer | `backend/labeler/intel/correlation/scoring.py` | `WeightedScorer.calculate()` |
| VirusTotal Provider | `backend/labeler/intel/providers/virustotal.py` | `VirusTotalProvider.lookup()` |
| OTX Provider | `backend/labeler/intel/providers/alienvault.py` | `AlienVaultOTXProvider.lookup()` |
| PostgreSQL Store | `backend/labeler/intel/reputation/repository.py` | `store_malicious_domain()` |
| Read Aggregator | `backend/dashboard_aggregation/incremental_aggregator.py` | `IncrementalAggregator.run_incremental()` |
| FastAPI Routes | `backend/api/routes/dashboard.py` | `get_domain_detail()`, `get_dashboard_bundle()` |
| React UI Page | `frontend/src/pages/DomainDetailPage.tsx` | `DomainDetailPage` component |
