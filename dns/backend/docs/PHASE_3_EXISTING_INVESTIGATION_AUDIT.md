# Phase 3 — Forensic Investigation Audit & Architecture Baseline
**DNS Threat Detection System — Client + Domain Investigation & Domain Intelligence Search**  
**Status**: COMPLETE & VERIFIED  
**Date**: August 2026  

---

## Executive Summary

This forensic audit evaluates the existing codebase across `backend/` and `frontend/` to establish the baseline for Phase 3 MVP product implementation.

Phase 2.7 (Threat Intelligence MVP) has been functionally verified and frozen. All 55 unit/integration tests and the 10-point Threat Intelligence verification matrix are passing (**GREEN**).

Phase 3 builds upon this frozen core to deliver analyst-facing investigation capabilities:
1. **Domain Intelligence Search & Investigation** (arbitrary domain search, normalization, local TI, external TI provenance, active reputation, DNS telemetry, and querying clients).
2. **Client Endpoint Investigation** (client summary, query volume, threat ratio, categorized destination domains, recent activity, and click-through navigation).
3. **Bi-Directional Investigation Graph** (Domain ↔ Client navigation using existing relational data).

---

## 1. Existing Domain Investigation Functionality

| Component / Layer | Implementation Location | Current State & Behavior | Reusable in Phase 3? |
| :--- | :--- | :--- | :--- |
| **API Endpoint** | `GET /api/v1/domains/{domain}` in `backend/api/routes/dashboard.py` | Reads from `dashboard.db` (`domain_details`), overlays active PostgreSQL reputation (`reputation_domains`) and Tranco check. Returns 404 if domain has no prior DNS traffic. | **YES** — Can be augmented or complemented by `GET /api/v1/investigation/domain/{domain}` to support arbitrary domain search. |
| **Domain Normalization** | `normalize_domain()` in `scripts/test_threat_intelligence.py`, `tldextract` across backend | Extracts `fqdn`, `registered_domain`, `tld`, and `subdomain`. Strips trailing dots, whitespace, and lowercases. | **YES** — Exact normalization logic can be directly reused. |
| **Local Threat Intel** | `labeler.intel.manager.is_trusted`, `labeler.intel.malicious.is_malicious` | SQLite-backed Tranco (1M top domains) and URLhaus databases. Enforces scope precedence: exact FQDN malicious overrides parent Tranco; Tranco apex suppresses root artifacts. | **YES** — Direct reuse. |
| **External Threat Intel** | `VirusTotalProvider`, `AlienVaultOTXProvider` in `labeler.intel.providers` | Safe API wrappers with API key validation, timeouts, 404 detection (`found=False`), error trapping (`unavailable=True`). | **YES** — Direct reuse. |
| **Correlation & Scoring** | `WeightedScorer`, `CorrelationEngine` in `labeler.intel.correlation` | Weighted voting model (VT 0.60, OTX 0.40, threshold 0.60). Emits `ThreatDecision` with structured provider evidence. | **YES** — FROZEN, direct reuse. |
| **Reputation Storage** | `reputation_domains` in PostgreSQL (`labeler.intel.reputation`) | Stores active malicious reputation records with explicit `match_scope` (`EXACT_FQDN`, `REGISTERED_DOMAIN`, `CORRELATED`, `EXTERNAL_PROVIDER`, `LEGACY`). | **YES** — Direct reuse. |
| **DNS Traffic Telemetry** | `domain_details` in `dashboard.db` & `domain_query_history` in PostgreSQL | Query count, unique clients, query types breakdown (`A`, `AAAA`, `MX`, etc.), response codes (`NOERROR`, `NXDOMAIN`), first/last seen. | **YES** — Direct reuse. |

---

## 2. Existing Client Investigation Functionality

| Component / Layer | Implementation Location | Current State & Behavior | Reusable in Phase 3? |
| :--- | :--- | :--- | :--- |
| **API Endpoint** | `GET /api/v1/clients/{client_ip}` in `backend/api/routes/dashboard.py` | Reads from `dashboard.db` (`client_details`). Returns total queries, unique domains, threat counts, first/last seen, top domains list. Returns 404 if unobserved. | **YES** — Can be enriched by `GET /api/v1/investigation/client/{client_ip}`. |
| **Client Profiling DB** | `client_profiles` & `client_history` in PostgreSQL | Maintains unique client IPs and (client_ip, domain) visit counts. | **YES** — Direct reuse. |
| **Client Domain Membership** | `client_domain_membership` in `dashboard.db` | Maintains exact (client_ip, domain) pairs for instant set lookups. | **YES** — Direct reuse. |
| **Historical Query Log** | `domain_query_history` in PostgreSQL | Detailed query logs with timestamps, response codes, labels, and TI sources per client. | **YES** — Direct reuse for recent client activity and timeline. |

---

## 3. Existing API Endpoints Audit

| Endpoint | Method | Source Data | Description |
| :--- | :--- | :--- | :--- |
| `/api/v1/dashboard` | `GET` | `dashboard.db` | Unified metrics bundle (summary, timeseries, categories, top entities, recent alerts). |
| `/api/v1/summary` | `GET` | `dashboard.db` | High-level pipeline metrics snapshot. |
| `/api/v1/threats/timeseries` | `GET` | `dashboard.db` | Query and threat timeseries buckets. |
| `/api/v1/threats/categories` | `GET` | `dashboard.db` | Threat count breakdown by category / TI source. |
| `/api/v1/threats/geo` | `GET` | `dashboard.db` | Geographic threat distribution. |
| `/api/v1/domains` | `GET` | `dashboard.db` | Paginated list of monitored domains with search and label filters. |
| `/api/v1/domains/top` | `GET` | `dashboard.db` | Top queried domains. |
| `/api/v1/domains/recent` | `GET` | `dashboard.db` | Recently flagged malicious domains. |
| `/api/v1/domains/{domain}` | `GET` | `dashboard.db` + PG | Single domain telemetry and reputation overlay. |
| `/api/v1/clients` | `GET` | `dashboard.db` | Paginated list of client IPs with query metrics. |
| `/api/v1/clients/top` | `GET` | `dashboard.db` | Top clients by query count. |
| `/api/v1/clients/{client_ip}` | `GET` | `dashboard.db` | Single client profiling record. |
| `/api/v1/status` | `GET` | `dashboard.db` | Aggregator run status and watermark timestamp. |
| `/health` | `GET` | In-memory | Service health check. |

---

## 4. Existing Database Tables Audit

### PostgreSQL (`pg_db`)
1. `domain_profiles`: Aggregated domain query counters, unique clients, query type distributions, last label, timestamps.
2. `domain_query_history`: Chronological DNS query events with `domain`, `client_ip`, `query_type`, `response_code`, `final_label`, `ti_source`, `timestamp`.
3. `reputation_domains`: Active threat reputation with `domain`, `status`, `source`, `confidence`, `match_scope`, `matched_domain`, `first_seen`, `last_seen`, `client_ip`.
4. `client_profiles`: Client IP tracking (`client_ip`, `first_seen`, `last_seen`).
5. `client_history`: `(client_ip, domain)` visit counts and timestamps.
6. `unknown_domains`: Repository for unknown domain processing.

### SQLite (`dashboard.db`)
1. `metrics_summary`: Single row KPI snapshot.
2. `threats_by_category`: Aggregated threat categories and percentages.
3. `queries_timeseries`: Time-bucketed query and threat volume.
4. `top_domains`: Top queried domains with threat scores and labels.
5. `top_clients`: Top client IPs with query counts.
6. `recent_flagged_domains`: Most recent malicious alerts.
7. `domain_details`: Comprehensive pre-computed domain view.
8. `client_details`: Comprehensive pre-computed client view.
9. `domain_client_membership`: Junction table mapping `(domain, client_ip)`.
10. `client_domain_membership`: Junction table mapping `(client_ip, domain)`.
11. `aggregation_state` & `aggregation_runs`: Aggregation watermarks and audit trail.

---

## 5. Existing Frontend Screens & Components

1. `OverviewPage.tsx`: Top-level dashboard summary cards, traffic charts, category breakdown, quick links.
2. `DomainsPage.tsx`: Searchable, filterable, paginated table of domains.
3. `DomainDetailPage.tsx`: Detailed telemetry view (KPIs, query types, response codes, classification, source, network metadata).
4. `ClientsPage.tsx`: Searchable, paginated table of client IP addresses.
5. `ClientDetailPage.tsx`: Client KPIs, target destination domains table with navigation links to domain detail.
6. `Header.tsx`: Global navigation header with search input.
7. `Sidebar.tsx`: App navigation drawer.

---

## 6. Existing Fields Reusable for Phase 3

- **Domain Normalization**: `fqdn`, `registered_domain`, `tld`, `subdomain`.
- **Classification Status**: `KNOWN_MALICIOUS`, `POPULAR_BENIGN_CONTEXT`, `UNKNOWN`, `REVIEW_NEEDED`, `KNOWN_CLEAN`.
- **Threat Score & Confidence**: `threat_score` (0-100 or 0.0-1.0), `confidence` (0.0-1.0), `reason`, `source`.
- **Local Intelligence**: Tranco rank/match status, URLhaus match status & match scope (`EXACT_FQDN`, `REGISTERED_DOMAIN`, `ROOT_ARTIFACT`).
- **External Intelligence**: VirusTotal detections (`malicious_count`, `harmless_count`, `suspicious_count`), AlienVault OTX pulses.
- **DNS Activity**: Total query count, unique clients count, first seen, last seen, query type breakdown, response code breakdown.
- **Client Activity**: Total queries, unique domains count, malicious query count, clean query count, top destinations.
- **Evidence Provenance Tags**: `LOCAL`, `REAL`, `MOCK / FIXTURE`, `NO_DATA`, `NOT_CONFIGURED`, `PROVIDER_FAILURE`, `COMPUTED`.

---

## 7. Missing Functionality

1. **On-Demand / Arbitrary Domain Intelligence Search**:
   - Currently, querying `GET /api/v1/domains/{domain}` returns 404 if the domain has never appeared in DNS traffic.
   - An analyst searching for any arbitrary domain (e.g. `google.com`, `imccj.gobgem.com`, `secure-update.net`, or an arbitrary unknown domain) needs immediate threat intelligence evaluation (local + external + active reputation + historical DNS telemetry if present).
2. **Unified Investigation Endpoints**:
   - `GET /api/v1/investigation/domain/{domain}`: Returns normalized domain info, classification, local TI, external TI, DNS telemetry, active reputation, querying clients, and explicit evidence provenance.
   - `GET /api/v1/investigation/client/{client_ip}`: Returns client identity, activity summary (total queries, unique domains, malicious, benign, unknown, threat ratio), categorized threats, top domains, recent query activity with timestamps.
3. **Bi-Directional Drilldown Navigation**:
   - On Domain Investigation View: List of querying clients linking directly to Client Investigation.
   - On Client Investigation View: Distinct categorized domain listings (Malicious, Review Needed / Unknown, Benign) with direct links to Domain Investigation.
4. **Prominent Search Experience**:
   - A dedicated Domain Intelligence Search bar in the UI that immediately accepts any domain and opens the rich investigation page.

---

## 8. Broken Functionality Identified & Resolved

1. **Syntax error in `backend/labeler/intel/reputation/__init__.py`**:
   - Line 1 had `w"""` instead of `"""`, causing pytest collection failure.
   - **Resolution**: Fixed docstring syntax. All 55 tests now pass cleanly.
2. **Unobserved Domain 404s**:
   - Searching for unobserved domains in `/api/v1/domains/{domain}` resulted in a dead-end 404 instead of a rich investigation record.
   - **Resolution**: Provide dedicated investigation handler that evaluates intelligence on arbitrary domains while transparently indicating `NOT_OBSERVED` for DNS traffic telemetry.

---

## 9. Minimal Changes Required for Phase 3

1. **Backend Investigation Service & API Routes**:
   - Implement `backend/api/routes/investigation.py` (or integrate into `dashboard.py` / `main.py`) exposing:
     - `GET /api/v1/investigation/domain/{domain}`
     - `GET /api/v1/investigation/client/{client_ip}`
   - Reuse `ThreatIntelligenceInvestigator` logic from `scripts/test_threat_intelligence.py`, `labeler.intel`, `reputation_domains`, `dashboard.db`, and PostgreSQL `domain_query_history`.
   - Ensure explicit NO_DATA / FAILURE states and zero secret leakage.
2. **Frontend UI Enhancements**:
   - Update `DomainDetailPage.tsx` to display full Phase 3 sections: Domain Header, Verdict/Summary, Threat Intelligence (Tranco, URLhaus, VT, OTX, Correlation), DNS Activity & Telemetry, Querying Clients list with click-through, and Evidence Provenance.
   - Update `ClientDetailPage.tsx` to display Client Summary (Unique domains, Malicious, Benign, Unknown, Threat Ratio), Threat Breakdown, Top Domains, Recent Query Activity, and click-through to Domain Investigation.
   - Add a prominent Domain Intelligence Search component to allow instant analyst lookup.
   - Update `api-client.ts` and `types/api.ts` to support the investigation API contracts.
3. **Verification & Golden Artifacts**:
   - Create Phase 3 verification test suite covering D1-D6, C1-C3, and N1-N5.
   - Generate golden artifacts: `PHASE_3_GOLDEN_DOMAIN_INVESTIGATION.md` and `PHASE_3_GOLDEN_CLIENT_INVESTIGATION.md`.

---

## 10. Explicitly Rejected Overengineering

- ❌ **NO replacement of WeightedScorer**: WeightedScorer is validated and frozen.
- ❌ **NO activation of CanonicalCorrelationEngine**: Keeps the production-tested correlation path.
- ❌ **NO new distributed infrastructure**: No Kafka, Redis, Celery, or worker pools.
- ❌ **NO database migrations / schema alterations**: Existing PostgreSQL tables (`domain_query_history`, `reputation_domains`, `client_history`) and SQLite tables (`domain_details`, `client_details`, `domain_client_membership`) already store all required fields.
- ❌ **NO second threat intelligence engine**: The investigation service orchestrates and presents existing intelligence rather than duplicating core logic.
- ❌ **NO unconstrained external API spam**: External API lookups respect local authoritative precedence (Tranco / URLhaus) and safe caching.
