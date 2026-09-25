# DNS Threat Detection System — Classification Architecture Diagrams
> **Visual Reference Document**  
> Formatted for live preview using code editor Markdown Preview extensions with Mermaid support.

---

## Quick Navigation

1. [Diagram 1: Complete Zoomed-Out Architecture](#1-complete-zoomed-out-architecture)
2. [Diagram 2: Classification Engine Internal Logic](#2-classification-engine-internal-logic)
3. [Diagram 3: Local & Online Threat Intelligence Architecture](#3-local--online-threat-intelligence-architecture)
4. [Diagram 4: Domain Hierarchy & Scope Routing (FQDN vs Apex vs TLD)](#4-domain-hierarchy--scope-routing-fqdn-vs-apex-vs-tld)
5. [Diagram 5: Four Canonical Verdicts Lifecycle & Data Loss](#5-four-canonical-verdicts-lifecycle--data-loss)
6. [Diagram 6: Unknown Domain & External TI Sequence Diagram](#6-unknown-domain--external-ti-sequence-diagram)
7. [Diagram 7: Relational Database Architecture (PostgreSQL & SQLite)](#7-relational-database-architecture-postgresql--sqlite)
8. [Diagram 8: Incremental Aggregator Read-Model Architecture](#8-incremental-aggregator-read-model-architecture)
9. [Diagram 9: FastAPI Backend Route & Database Dispatch](#9-fastapi-backend-route--database-dispatch)
10. [Diagram 10: Next.js Frontend Component & Badge Normalization](#10-nextjs-frontend-component--badge-normalization)
11. [Diagram 11: End-to-End Traces for 8 Golden Domain Cases](#11-end-to-end-traces-for-8-golden-domain-cases)

---

## 1. Complete Zoomed-Out Architecture

This top-level diagram traces a DNS query from wire ingress through parsing, classification, multi-database persistence, asynchronous intelligence enrichment, dual read-model aggregation, the FastAPI tier, and the Next.js frontend.

```mermaid
flowchart TD
    subgraph INGEST["1. Telemetry Ingestion Layer"]
        L_RAW["Raw BIND 9 Log Line<br/>(File / Syslog Stream)"] --> P_LEGACY["legacy_bind_parser.py<br/>parse_bind_line()"]
        L_KAFKA["Fluent Bit JSON Message<br/>(Kafka Consumer Topic)"] --> P_KAFKA["run_live_pipeline.py<br/>_record_from_structured_json()"]
        P_LEGACY --> D_REC["parser.models.DNSRecord<br/>(domain, client_ip, query_type, timestamp)"]
        P_KAFKA --> D_REC
    end

    subgraph ENGINE["2. Classification Engine"]
        D_REC --> LABELLER["DNSLabeller._process_row()<br/>(backend/labeler/label_dataset.py)"]
        LABELLER --> TI_EVAL["ThreatIntelligence.evaluate()<br/>(backend/labeler/threat_intelligence.py)"]
    end

    subgraph LOCAL_TI["3. Local Threat Intelligence Waterfall (Synchronous)"]
        TI_EVAL --> CHK_FQDN{"Step 1: URLhaus Exact FQDN?<br/>is_malicious(full_domain)"}
        CHK_FQDN -- Match --> R_MAL1["Score: 100 | Scope: EXACT_FQDN<br/>Reason: Known Malicious Domain (URLhaus)"]
        CHK_FQDN -- Miss --> CHK_TRANCO{"Step 2: Tranco Top 1M?<br/>is_trusted(rd) or is_trusted(fqdn)"}
        
        CHK_TRANCO -- Match --> R_BEN["Score: -100 | Scope: TRUSTED<br/>Reason: Trusted Tranco Domain"]
        CHK_TRANCO -- Miss --> CHK_APEX{"Step 3: URLhaus Untrusted Apex?<br/>rd and is_malicious(rd)"}
        
        CHK_APEX -- Match --> R_MAL2["Score: 100 | Scope: REGISTERED_DOMAIN<br/>Reason: Known Malicious Domain (URLhaus)"]
        CHK_APEX -- Miss --> CHK_REP{"Step 4: Reputation DB Cache?<br/>get_domain(fqdn) or get_domain(rd)"}
        
        CHK_REP -- Match --> R_MAL3["Score: 100 | Scope: REPUTATION<br/>Reason: Reputation Cache Match"]
        CHK_REP -- Miss --> CHK_DR{"Step 5: Daily Review DB?<br/>get_daily_review_verdict()"}
        
        CHK_DR -- "status == 'malicious'" --> R_MAL4["Score: 100 | Daily Review Match (malicious)"]
        CHK_DR -- "status == 'clean'" --> R_BEN2["Score: 0 | Daily Review Match (clean)"]
        CHK_DR -- "Miss / review_needed" --> HEUR_CALL["Step 6: Heuristics Evaluation"]
    end

    subgraph HEURISTICS["4. In-Memory Heuristics Subsystem"]
        HEUR_CALL --> HEUR_ENG["Heuristics.evaluate()<br/>(backend/labeler/heuristics.py)"]
        HEUR_ENG --> SCORER["ScoringEngine: Shannon Entropy,<br/>Length, Digit Ratio, Query Type"]
        SCORER --> SCORE_OUT["Calculated Threat Score (0–100)<br/>+ Heuristic Reasons List"]
    end

    subgraph VERDICT_RES["5. Canonical Verdict Resolution"]
        R_MAL1 & R_MAL2 & R_MAL3 & R_MAL4 --> V_MAL["MALICIOUS<br/>confidence: 98 | ti_source: malicious/reputation"]
        R_BEN & R_BEN2 --> V_BEN["BENIGN<br/>confidence: 95 | ti_source: trusted/daily_review"]
        SCORE_OUT --> V_REV["REVIEW_NEEDED<br/>confidence: 70–95 | ti_source: unknown"]
        D_REC -. Empty / Malformed .-> V_UNK["UNKNOWN<br/>confidence: 0 | ti_source: error"]
    end

    subgraph PERSIST["6. PostgreSQL Persistence Layer (dns_threat_detection)"]
        V_MAL & V_BEN & V_REV & V_UNK --> PROFILER["DomainProfilingService.process_dataframe()<br/>(backend/domain_profiling/service.py)"]
        PROFILER --> PG_HIST[("PostgreSQL: dns_threat_detection<br/>table: domain_query_history")]
        PROFILER --> PG_PROF[("PostgreSQL: dns_threat_detection<br/>table: domain_profiles")]
        PROFILER --> PG_CLIENT[("PostgreSQL: dns_threat_detection<br/>table: client_profiles")]
        
        R_MAL1 & R_MAL2 --> REP_STORE["store_malicious_domain()<br/>(backend/labeler/intel/reputation/)"]
        REP_STORE --> PG_REP[("PostgreSQL: reputation_db<br/>table: reputation_domains")]
    end

    subgraph ASYNC_TI["7. Unknown Domain & Online Intelligence Pipeline"]
        V_REV --> UDR_INS["DomainPersistenceManager.process_final_dataset()"]
        UDR_INS --> PG_UDR[("PostgreSQL: daily_review_db<br/>table: unknown_domains (status='new')")]
        PG_UDR --> UDP["UnknownDomainProcessor.process()<br/>(backend/labeler/intel/unknown_domain_processor.py)"]
        UDP --> EXT_PROV["External Threat Providers:<br/>VirusTotal v3 & AlienVault OTX v1"]
        EXT_PROV --> CORR["CorrelationEngine.evaluate()<br/>(WeightedScorer threshold=0.60)"]
        CORR -- "Score >= 0.60" --> PG_REP
        CORR -- "Score >= 0.60" --> UDR_UP_MAL["unknown_domains.status = 'malicious'"]
        CORR -- Clean Consensus --> UDR_UP_CLN["unknown_domains.status = 'clean'"]
        CORR -- Inconclusive --> UDR_UP_REV["unknown_domains.status = 'review_needed'"]
    end

    subgraph READ_MODELS["8. Dual Read-Model Layer"]
        PG_HIST --> AGG["IncrementalAggregator<br/>(backend/dashboard_aggregation/)"]
        AGG --> SQLITE[("SQLite: dashboard.db<br/>(domain_details, metrics_summary)")]
        
        PG_HIST --> API_PG["Direct PostgreSQL Read Pool<br/>(backend/domain_profiling/connection.py)"]
    end

    subgraph API_TIER["9. FastAPI Application Tier (backend/api/)"]
        API_PG --> ROUTE_DASH["api/routes/dashboard.py<br/>/api/v1/dashboard<br/>/api/v1/domains/recent"]
        API_PG --> ROUTE_REP["api/routes/reports.py<br/>/api/v1/reports/queries<br/>/api/v1/reports/entity"]
        API_PG --> ROUTE_INV["api/routes/investigation.py<br/>/api/v1/investigation/domain/{domain}"]
        API_PG --> ROUTE_ANA["api/routes/analytics.py<br/>/api/v1/analytics/domains"]
    end

    subgraph FRONTEND["10. Next.js Frontend Dashboard (frontend/src/)"]
        ROUTE_DASH & ROUTE_REP & ROUTE_INV & ROUTE_ANA --> API_CLIENT["frontend/src/lib/api-client.ts<br/>(Axios dedupedGet)"]
        API_CLIENT --> VIEW_DASH["OverviewPage.tsx / ReportsPage.tsx / DomainDetailPage.tsx"]
        VIEW_DASH --> BADGE["VerdictBadge.tsx / ClassificationBadge.tsx<br/>(Renders Red, Emerald, Amber, or Slate Badge)"]
    end
```

---

## 2. Classification Engine Internal Logic

Zoomed-in technical breakdown of `DNSLabeller._process_row()` showing exact inputs, branch conditions, scoring, and verdict resolution.

```mermaid
flowchart TD
    subgraph INGRESS["Input Row Serialization"]
        ROW["row: pd.Series or dict<br/>{domain, registered_domain, tld, response_code, client_ip, query_type}"]
    end

    subgraph SANITY["Sanity Check"]
        ROW --> CHK_EMPTY{"domain_raw is empty?"}
        CHK_EMPTY -- Yes --> RET_UNK["Return Early:<br/>threat_score = 0<br/>label = 'Unknown'<br/>confidence = 0<br/>reason = 'Missing domain telemetry'<br/>ti_source = 'error'"]
    end

    subgraph TI_EVAL["ThreatIntelligence.evaluate() (labeler/threat_intelligence.py:L72)"]
        CHK_EMPTY -- No --> EXT_RD["Extract Public Suffix:<br/>tldextract fallback if rd missing"]
        EXT_RD --> STEP1{"Step 1: URLhaus Exact FQDN?<br/>full_domain != rd and is_malicious(full_domain)"}
        
        STEP1 -- Yes --> S1_OUT["store_malicious_domain(full_domain, scope='EXACT_FQDN')<br/>Return: (100, ['Known Malicious Domain (URLhaus)'])"]
        STEP1 -- No --> STEP2{"Step 2: Tranco Context?<br/>is_trusted(rd) or is_trusted(full_domain)"}
        
        STEP2 -- Yes --> S2_OUT["Return: (-100, ['Trusted Tranco Domain'])"]
        STEP2 -- No --> STEP3{"Step 3: URLhaus Untrusted Apex?<br/>rd and is_malicious(rd)"}
        
        STEP3 -- Yes --> S3_OUT["store_malicious_domain(target, scope='REGISTERED_DOMAIN')<br/>Return: (100, ['Known Malicious Domain (URLhaus)'])"]
        STEP3 -- No --> STEP4{"Step 4: Reputation Cache?<br/>get_domain(full_domain) or get_domain(rd)"}
        
        STEP4 -- "status == 'malicious'" --> S4_OUT["Return: (100, ['Reputation Cache Match (...)'])"]
        STEP4 -- No Match --> STEP5{"Step 5: Daily Review DB?<br/>get_daily_review_verdict()"}
        
        STEP5 -- "status == 'malicious'" --> S5_MAL["Return: (100, ['Daily Review Match (malicious)'])"]
        STEP5 -- "status == 'clean'" --> S5_CLN["Return: (0, ['Daily Review Match (clean)'])"]
        STEP5 -- "review_needed or None" --> S5_REV["Return: (0, ['Daily Review Match (review_needed)']) or (0, [])"]
    end

    subgraph HEUR_BRANCH["Heuristic Evaluation Branch (label_dataset.py:L57)"]
        S1_OUT & S3_OUT & S4_OUT & S5_MAL --> SKIP_HEUR["Skip Heuristics<br/>threat_score = ti_score<br/>reasons = ti_reasons"]
        S2_OUT & S5_CLN --> SKIP_HEUR
        S5_REV --> RUN_HEUR["self.heuristics.evaluate(row, ti_score, ti_reasons)"]
        RUN_HEUR --> HEUR_CALC["ScoringEngine.evaluate():<br/>Entropy + Length + DigitRatio + Consonants + QueryType"]
        HEUR_CALC --> HEUR_CLAMP["Clamp threat_score between 0 and 100"]
    end

    subgraph VERDICT_MAP["Canonical Verdict Assignment (label_dataset.py:L89-119)"]
        SKIP_HEUR & HEUR_CLAMP --> CANON_CHK{"Inspect ti_reasons content"}
        
        CANON_CHK -- "'Known Malicious Domain' or 'Reputation Cache' or 'Daily Review Match (malicious)'" --> SET_MAL["label = CanonicalVerdict.MALICIOUS ('Malicious')<br/>confidence = 98"]
        CANON_CHK -- "'Trusted Tranco Domain' or 'Daily Review Match (clean)'" --> SET_BEN["label = CanonicalVerdict.BENIGN ('Benign')<br/>confidence = 95"]
        CANON_CHK -- Neither matched --> SET_REV["label = CanonicalVerdict.REVIEW_NEEDED ('Review Needed')"]
        
        SET_REV --> CONF_SCALE{"threat_score >= 35?"}
        CONF_SCALE -- Yes --> CONF_HIGH["confidence = min(95, 75 + (threat_score - 35)//3)"]
        CONF_SCALE -- No --> CONF_LOW["confidence = 70<br/>reasons.append('Unindexed domain awaiting review')"]
    end

    subgraph TI_SOURCE_MAP["Derive ti_source (label_dataset.py:L46-56)"]
        CANON_CHK --> DERIVE_SRC{"ti_reasons content"}
        DERIVE_SRC -- "'Trusted Tranco Domain'" --> SRC_TRU["ti_source = 'trusted'"]
        DERIVE_SRC -- "'Known Malicious Domain'" --> SRC_MAL["ti_source = 'malicious'"]
        DERIVE_SRC -- "'Reputation Cache Match'" --> SRC_REP["ti_source = 'reputation'"]
        DERIVE_SRC -- "'Daily Review Match'" --> SRC_DR["ti_source = 'daily_review'"]
        DERIVE_SRC -- None of the above --> SRC_UNK["ti_source = 'unknown'"]
    end

    SET_MAL & SET_BEN & CONF_HIGH & CONF_LOW & RET_UNK --> RET_TUPLE["Return 5-Tuple:<br/>(threat_score, label, confidence, label_reason, ti_source)"]
```

---

## 3. Local & Online Threat Intelligence Architecture

This diagram maps every threat intelligence source, database, updater, manager, and external provider.

```mermaid
flowchart LR
    subgraph TI_URLHAUS["1. URLhaus (PostgreSQL: malicious_db)"]
        UH_FEED["abuse.ch URLhaus CSV Feed"] --> UH_UP["updater.py / downloader.py<br/>(Batch execute_many_queries)"]
        UH_UP --> UH_PG[("table: malicious_domains<br/>(domain UNIQUE, source, updated_at)")]
        UH_PG --> UH_MGR["manager.py: is_malicious()<br/>SELECT 1 FROM malicious_domains WHERE domain = %s"]
    end

    subgraph TI_TRANCO["2. Tranco Top 1M (PostgreSQL: trusted_db)"]
        TR_FEED["Tranco Top 1M ZIP/CSV"] --> TR_DL["downloader.py / database.py<br/>(Batch INSERT)"]
        TR_DL --> TR_PG[("table: trusted_domains<br/>(domain UNIQUE, rank, created_at)")]
        TR_PG --> TR_MGR["manager.py: is_trusted()<br/>SELECT 1 FROM trusted_domains WHERE domain = %s"]
    end

    subgraph TI_REP["3. Reputation DB (PostgreSQL: reputation_db)"]
        UH_MATCH["URLhaus Matches (Steps 1 & 3)"] --> REP_WRITE["store_malicious_domain()<br/>(reputation/repository.py)"]
        CORR_MATCH["CorrelationEngine (Score >= 0.60)"] --> REP_WRITE
        REP_WRITE --> REP_PG[("table: reputation_domains<br/>(domain UNIQUE, status, source, confidence,<br/>match_scope, matched_domain, client_ip, query_type)")]
        REP_PG --> REP_READ["repository.py: get_domain()<br/>SELECT * FROM reputation_domains WHERE domain = %s"]
    end

    subgraph TI_DR["4. Daily Review DB (PostgreSQL: daily_review_db)"]
        PIPE_UNK["run_live_pipeline.py (Unindexed Events)"] --> UDR_SVC["DomainPersistenceManager<br/>(unknown_domain_repository/)"]
        UDR_SVC --> DR_PG[("table: unknown_domains<br/>(domain UNIQUE, status, previous_status,<br/>query_count, metadata JSONB)")]
        ANALYST["Analyst Triage / scripts/daily_recheck.py"] --> DR_PG
        DR_PG --> DR_READ["daily_review.py: get_daily_review_verdict()<br/>SELECT domain, status, query_count FROM unknown_domains"]
    end

    subgraph TI_ONLINE["5. External Correlated Intelligence"]
        UDP_CALL["UnknownDomainProcessor.process()"] --> PROV_VT["VirusTotalProvider (v3 API)<br/>GET /api/v3/domains/{domain}"]
        UDP_CALL --> PROV_OTX["AlienVaultOTXProvider (v1 API)<br/>GET /api/v1/indicators/domain/{domain}"]
        PROV_VT & PROV_OTX --> CORR_ENG["CorrelationEngine (WeightedScorer)<br/>weights: VT=0.6, OTX=0.4 | threshold=0.60"]
        CORR_ENG --> MEM_CACHE["ThreatIntelCache (2-Layer L1/L2)<br/>L1 Memory: 24h mal / 6h clean TTL<br/>L2: reputation_domains"]
    end

    UH_MGR & TR_MGR & REP_READ & DR_READ --> TI_EVAL_CORE["ThreatIntelligence.evaluate()<br/>(Waterfall Stages 1–5)"]
```

---

## 4. Domain Hierarchy & Scope Routing (FQDN vs Apex vs TLD)

How the system decomposes a domain and routes components to different intelligence databases.

```mermaid
flowchart TD
    RAW_NAME["Incoming Query: 'evil.sub.example.co.uk'"]
    
    subgraph EXTRACTION["Decomposition Layer"]
        RAW_NAME --> TLD_EXT["tldextract.extract()<br/>(parser/models.py & threat_intelligence.py)"]
        TLD_EXT --> FQDN["FQDN: 'evil.sub.example.co.uk'"]
        TLD_EXT --> RD["Registered Domain (Apex): 'example.co.uk'"]
        TLD_EXT --> TLD["Public Suffix / TLD: 'co.uk'"]
        TLD_EXT --> SUB["Subdomain: 'evil.sub'"]
    end

    subgraph SCOPE_ROUTING["Intelligence Routing by Scope"]
        FQDN --> S1_LOOKUP["Step 1: is_malicious(FQDN)<br/>[Scope: EXACT_FQDN]<br/>Checked in malicious_domains"]
        RD --> S2_LOOKUP["Step 2: is_trusted(RD)<br/>[Scope: TRANCO_APEX]<br/>Checked in trusted_domains"]
        RD --> S3_LOOKUP["Step 3: is_malicious(RD)<br/>[Scope: REGISTERED_DOMAIN]<br/>Checked in malicious_domains"]
        FQDN --> S4_FQDN["Step 4a: get_domain(FQDN)<br/>Checked in reputation_domains"]
        RD --> S4_RD["Step 4b: get_domain(RD)<br/>Checked in reputation_domains"]
        FQDN --> S5_FQDN["Step 5a: get_daily_review(FQDN)<br/>Checked in unknown_domains"]
        RD --> S5_RD["Step 5b: get_daily_review(RD)<br/>Checked in unknown_domains"]
    end

    subgraph INHERIT_RULES["Inheritance & Non-Inheritance Invariants"]
        S3_LOOKUP -- "Apex is Malicious" --> INH_TRUE["Subdomains INHERIT Maliciousness<br/>Target: evil.sub.example.co.uk -> MALICIOUS<br/>Scope recorded: REGISTERED_DOMAIN"]
        S1_LOOKUP -- "Only FQDN is Malicious" --> INH_FALSE["Siblings DO NOT Inherit Maliciousness<br/>Target: safe.sub.example.co.uk -> REVIEW_NEEDED"]
        S2_LOOKUP -- "Apex is in Tranco" --> INH_PROT["Popular Apex Protects Subdomains<br/>Target: mail.google.com -> BENIGN<br/>Prevents URLhaus root scraping artifacts"]
    end

    subgraph HEUR_SPLIT["ccTLD Heuristics Divergence (Defect)"]
        RAW_NAME --> STR_SPLIT["heuristics.py: domain.split('.')[-2]"]
        STR_SPLIT --> BROKEN_SLD["Extracts: 'co' instead of 'example'<br/>Corrupts entropy & length on multi-part ccTLDs!"]
    end
```

---

## 5. Four Canonical Verdicts Lifecycle & Data Loss

Tracing how the four statuses are stored, rolled up, aggregated, served, and displayed—highlighting where data loss occurs.

```mermaid
flowchart LR
    subgraph ORIGIN["Verdict Origin (DNSLabeller)"]
        V_MAL["MALICIOUS"]
        V_BEN["BENIGN"]
        V_REV["REVIEW_NEEDED"]
        V_UNK["UNKNOWN"]
    end

    subgraph PG_HIST["PostgreSQL: domain_query_history"]
        V_MAL -->|final_label = 'Malicious'| H_M["final_label = 'Malicious'"]
        V_BEN -->|final_label = 'Benign'| H_B["final_label = 'Benign'"]
        V_REV -->|final_label = 'Review Needed'| H_R["final_label = 'Review Needed'"]
        V_UNK -->|final_label = 'Unknown'| H_U["final_label = 'Unknown'"]
    end

    subgraph PG_PROF["PostgreSQL: domain_profiles (Data Loss!)"]
        H_M -->|malicious_queries += 1| DP_M["malicious_queries"]
        H_B -->|clean_queries += 1| DP_C["clean_queries"]
        H_R -->|Merged into unknown!| DP_U["unknown_queries<br/>(review_needed_queries MISSING!)"]
        H_U -->|unknown_queries += 1| DP_U
    end

    subgraph AGG_SQLITE["SQLite: dashboard.db (IncrementalAggregator Loss!)"]
        H_M -->|is_malicious = True| SQ_M["threat_count / malicious_count"]
        H_B -->|is_clean = True| SQ_C["clean_count"]
        H_R -->|is_unknown = True| SQ_U["DROPPED FROM COUNTERS!<br/>(suspicious_count = 0 hardcoded)"]
        H_U -->|is_unknown = True| SQ_U
    end

    subgraph FASTAPI["FastAPI Tier (Reads domain_query_history Direct)"]
        H_M -->|Query Direct| API_M["'Malicious'"]
        H_B -->|Query Direct| API_B["'Benign'"]
        H_R -->|Query Direct| API_R["'Review Needed'"]
        H_U -->|Query Direct| API_U["'Unknown'"]
    end

    subgraph UI_BADGE["Next.js: VerdictBadge.tsx"]
        API_M --> B_M["<Badge variant='destructive'>Malicious</Badge><br/>(Red bg-red-500/15 + dot)"]
        API_B --> B_B["<Badge variant='success'>Benign</Badge><br/>(Emerald bg-emerald-500/15 + dot)"]
        API_R --> B_R["<Badge variant='warning'>Review Needed</Badge><br/>(Amber bg-amber-500/15 + dot)"]
        API_U --> B_U["<Badge variant='outline'>Unknown</Badge><br/>(Slate bg-secondary)"]
    end
```

---

## 6. Unknown Domain & External TI Sequence Diagram

The exact asynchronous lifecycle of an unindexed domain when processed by VirusTotal, AlienVault OTX, and the `CorrelationEngine`.

```mermaid
sequenceDiagram
    autonumber
    actor Client as DNS Client
    participant Ingestion as run_live_pipeline.py
    participant Labeller as DNSLabeller
    participant PG_Hist as domain_query_history
    participant UDR_Repo as unknown_domains (daily_review_db)
    participant UDP as UnknownDomainProcessor
    participant Cache as ThreatIntelCache (L1/L2)
    participant VT as VirusTotal API v3
    participant OTX as AlienVault OTX API v1
    participant Scorer as WeightedScorer
    participant RepDB as reputation_domains (reputation_db)

    Client->>Ingestion: DNS Query (unindexed domain)
    Ingestion->>Labeller: _process_row(row)
    Labeller-->>Ingestion: returns (score, 'Review Needed', 70, reason, 'unknown')
    Ingestion->>PG_Hist: INSERT query event (final_label='Review Needed')
    
    rect rgb(240, 245, 255)
        note over Ingestion,UDP: Synchronous Ingestion Step 8 (run_live_pipeline.py:L775-804)
        Ingestion->>UDR_Repo: process_final_dataset() -> INSERT (status='new')
        Ingestion->>UDP: process() [Blocks Ingestion Loop!]
    end

    UDP->>UDR_Repo: get_pending_domains()
    UDR_Repo-->>UDP: returns [UnknownDomain(status='new')]
    UDP->>UDR_Repo: update_status(domain, 'processing')
    
    UDP->>Cache: get(domain)
    alt L1 Cache Hit (In-Memory)
        Cache-->>UDP: return cached ThreatDecision
    else L2 Cache Hit (reputation_domains)
        Cache->>RepDB: get_domain(domain)
        RepDB-->>Cache: return record
        Cache-->>UDP: return ThreatDecision
    else Cache Miss
        par Query External Providers Concurrently (ThreadPoolExecutor)
            UDP->>VT: GET /api/v3/domains/{domain}
            UDP->>OTX: GET /api/v1/indicators/domain/{domain}/general
        end
        VT-->>UDP: ThreatProviderResult(found, malicious_count, harmless_count)
        OTX-->>UDP: ThreatProviderResult(found, pulse_count, tags)
        
        UDP->>Scorer: calculate(all_results)
        Scorer-->>UDP: return (score, confidence, is_malicious)
        UDP->>Cache: set(domain, decision) [TTL: 24h mal / 6h clean]
        
        alt Decision.is_malicious is True (score >= 0.60)
            UDP->>RepDB: store_malicious_domain(domain, metadata, scope='CORRELATED')
            UDP->>UDR_Repo: update_external_review(domain, 'malicious')
            note over PG_Hist: Note: Initial domain_query_history row<br/>is NOT retroactively updated!
        else Decision.has_intelligence is True (Clean Consensus)
            UDP->>UDR_Repo: update_external_review(domain, 'clean')
        else Inconclusive / Providers Unavailable
            UDP->>UDR_Repo: update_external_review(domain, 'review_needed')
        end
    end
```

---

## 7. Relational Database Architecture (PostgreSQL & SQLite)

Entity relationship diagram mapping all six active databases and tables across the system.

```mermaid
erDiagram
    %% PostgreSQL Database: dns_threat_detection
    domain_query_history {
        bigserial id PK
        varchar domain
        varchar client_ip
        varchar query_type
        timestamptz timestamp
        varchar response_code
        varchar registered_domain
        varchar tld
        varchar final_label
        varchar ti_source
    }

    domain_profiles {
        varchar domain PK
        timestamptz first_seen
        timestamptz last_seen
        bigint total_queries
        bigint unique_clients
        varchar last_client_ip
        bigint malicious_queries
        bigint clean_queries
        bigint unknown_queries
        varchar last_label
        varchar last_ti_source
    }

    client_profiles {
        varchar client_ip PK
        timestamptz first_seen
        timestamptz last_seen
        bigint total_queries
        bigint unique_domains
        bigint malicious_queries
    }

    %% PostgreSQL Database: malicious_db
    malicious_domains {
        serial id PK
        varchar domain UK
        varchar source
        timestamp downloaded_at
        timestamp updated_at
    }

    %% PostgreSQL Database: trusted_db
    trusted_domains {
        serial id PK
        varchar domain UK
        integer rank
        timestamp created_at
    }

    %% PostgreSQL Database: reputation_db
    reputation_domains {
        serial id PK
        varchar domain UK
        varchar status
        varchar source
        float confidence
        varchar match_scope
        varchar matched_domain
        int times_seen
        int query_count
        inet client_ip
        varchar query_type
        timestamp last_seen
    }

    %% PostgreSQL Database: daily_review_db
    unknown_domains {
        serial id PK
        varchar domain UK
        timestamptz first_seen
        timestamptz last_seen
        int query_count
        varchar source
        varchar status
        varchar previous_status
        timestamptz last_checked
        jsonb metadata
    }

    %% SQLite Database: dashboard.db
    domain_details {
        text domain PK
        integer total_queries
        integer unique_clients
        integer threat_count
        integer malicious_count
        integer suspicious_count
        integer clean_count
        text last_label
        text last_ti_source
    }

    aggregation_state {
        text aggregation_name PK
        integer last_processed_event_id
        text updated_at
    }

    %% Cross-Database Conceptual Relationships
    domain_query_history ||--o{ domain_profiles : "rolled up into by domain"
    domain_query_history ||--o{ client_profiles : "rolled up into by client_ip"
    domain_query_history ||--o{ domain_details : "replicated incrementally"
    malicious_domains ||--o{ reputation_domains : "seeds exact/apex hits"
    unknown_domains ||--o{ reputation_domains : "promoted on score >= 0.60"
```

---

## 8. Incremental Aggregator Read-Model Architecture

Detailing how `IncrementalAggregator` processes events from PostgreSQL and writes to SQLite `dashboard.db`.

```mermaid
flowchart TD
    subgraph PG_STREAM["PostgreSQL Event Source"]
        SQL_FETCH["SELECT * FROM domain_query_history<br/>WHERE id > watermark_id<br/>ORDER BY id ASC LIMIT 1000"]
    end

    subgraph AGG_PIPELINE["IncrementalAggregator Pipeline (incremental_aggregator.py)"]
        SQL_FETCH --> NORM["_normalize_event()<br/>Validates id, domain, client_ip, timestamp"]
        NORM --> LABEL_MAP["_classify_label(final_label)<br/>(incremental_aggregator.py:L155)"]
        
        LABEL_MAP -- "label == 'Malicious'" --> SET_M["is_malicious = True<br/>is_clean = False<br/>is_unknown = False"]
        LABEL_MAP -- "label in ('Clean','Trusted','Benign')" --> SET_C["is_malicious = False<br/>is_clean = True<br/>is_unknown = False"]
        LABEL_MAP -- "All other strings (Review Needed, Unknown)" --> SET_U["is_malicious = False<br/>is_clean = False<br/>is_unknown = True"]
    end

    subgraph SQLITE_WRITES["SQLite Batch Transactions (dashboard.db)"]
        SET_M --> U_SUM["metrics_summary: total_threats += 1"]
        SET_M --> U_FLAG["recent_flagged_domains: INSERT latest event"]
        SET_M --> U_DOM_M["domain_details: malicious_count += 1, threat_count += 1"]
        SET_C --> U_DOM_C["domain_details: clean_count += 1"]
        SET_U --> U_DOM_U["domain_details: DROPPED!<br/>(suspicious_count = 0; no review_needed column)"]
        
        SET_M & SET_C & SET_U --> U_TS["queries_timeseries: total_queries += 1"]
        SET_M & SET_C & SET_U --> U_CLI["client_details: total_queries += 1"]
        SET_M & SET_C & SET_U --> U_MEM["domain_client_membership: INSERT OR IGNORE"]
        
        U_SUM & U_FLAG & U_DOM_M & U_DOM_C & U_TS & U_CLI & U_MEM --> COMMIT_TX["COMMIT SQLite Transaction"]
        COMMIT_TX --> WM_ADV["aggregation_state: UPDATE last_processed_event_id"]
    end
```

---

## 9. FastAPI Backend Route & Database Dispatch

Mapping each API endpoint directly to the underlying database connection and SQL queries.

```mermaid
flowchart LR
    CLIENT_REQ["Incoming HTTP Request"] --> ROUTE_MATCH{"FastAPI Router Match"}
    
    subgraph ROUTE_DASH["Dashboard Routes (api/routes/dashboard.py)"]
        ROUTE_MATCH -- "GET /api/v1/dashboard" --> H_DASH["get_dashboard_bundle()<br/>Executes SQL across domain_query_history"]
        ROUTE_MATCH -- "GET /api/v1/summary" --> H_SUM["get_summary()"]
        ROUTE_MATCH -- "GET /api/v1/threats/timeseries" --> H_TS["get_threats_timeseries()"]
        ROUTE_MATCH -- "GET /api/v1/threats/categories" --> H_CAT["get_threat_categories()"]
        ROUTE_MATCH -- "GET /api/v1/domains/recent" --> H_REC["get_recent_flagged_domains()"]
        ROUTE_MATCH -- "GET /api/v1/domains/top" --> H_TOPD["get_top_domains()"]
        ROUTE_MATCH -- "GET /api/v1/clients/top" --> H_TOPC["get_top_clients()"]
    end

    subgraph ROUTE_REP["Reports Routes (api/routes/reports.py)"]
        ROUTE_MATCH -- "GET /api/v1/reports/queries" --> H_QUERIES["get_paginated_queries()<br/>Filters: label, search, window"]
        ROUTE_MATCH -- "GET /api/v1/reports/entity" --> H_ENTITY["get_entity_report()<br/>Domain or Client detailed history"]
    end

    subgraph ROUTE_INV["Investigation Routes (api/routes/investigation.py)"]
        ROUTE_MATCH -- "GET /api/v1/investigation/domain/{domain}" --> H_INVD["investigate_domain()<br/>Queries PG history, reputation_db, live VT/OTX"]
        ROUTE_MATCH -- "GET /api/v1/investigation/client/{client_ip}" --> H_INVC["investigate_client()"]
    end

    subgraph ROUTE_ANA["Analytics Routes (api/routes/analytics.py)"]
        ROUTE_MATCH -- "GET /api/v1/analytics/domains" --> H_ANA["get_domain_analytics()<br/>(analytics/domain_analytics.py)"]
    end

    subgraph DB_DISPATCH["Data Dispatch Layer"]
        H_DASH & H_SUM & H_TS & H_CAT & H_REC & H_TOPD & H_TOPC & H_QUERIES & H_ENTITY & H_INVD & H_INVC & H_ANA --> PG_POOL["domain_profiling.connection.get_db_connection()<br/>(Direct Threaded PostgreSQL Connection Pool)"]
        PG_POOL --> PG_MAIN[("PostgreSQL: dns_threat_detection")]
    end

    ROUTE_MATCH -- "GET /api/v1/metrics/*" --> NOT_PRESENT["NOT PRESENT (Returns 404)"]
```

---

## 10. Next.js Frontend Component & Badge Normalization

Tracing frontend data flow from API responses through Axios deduplication to UI views and badges.

```mermaid
flowchart TD
    API_JSON["FastAPI HTTP 200 JSON Response<br/>{ label: 'Malicious' | 'Benign' | 'Review Needed' | 'Unknown' }"]
    
    subgraph TRANSPORT["frontend/src/lib/api-client.ts"]
        API_JSON --> DEDUP["dedupedGet() in-flight Promise Map"]
        DEDUP --> AXIOS["api Axios Instance (baseURL = '/api/v1')"]
        AXIOS --> MODELS["Strongly Typed Interfaces (frontend/src/types/api.ts)"]
    end

    subgraph VIEWS["Frontend Page Views (frontend/src/views/)"]
        MODELS --> V_OVER["OverviewPage.tsx / DashboardPage.tsx<br/>(Top Domains, Recent Threats Tables)"]
        MODELS --> V_REP["ReportsPage.tsx<br/>(Paginated DNS Query Activity Log)"]
        MODELS --> V_DOM["DomainDetailPage.tsx / ThreatsPage.tsx<br/>(Domain Intelligence & Entity Cards)"]
    end

    subgraph BADGE_RENDER["Badge Normalization Component (VerdictBadge.tsx:L10-69)"]
        V_OVER & V_REP & V_DOM --> PROP_IN["<VerdictBadge verdict={item.final_label} />"]
        PROP_IN --> NORM["norm = (verdict || 'unknown').toLowerCase().trim()"]
        
        NORM -- "norm in ('malicious', 'known_malicious')" --> R_RED["Badge Destructive<br/>Class: bg-red-500/15 text-red-500 border-red-500/30<br/>Indicator: Red pulsing dot<br/>Text: 'Malicious'"]
        NORM -- "norm in ('review_needed', 'review needed', 'suspicious')" --> R_AMB["Badge Warning<br/>Class: bg-amber-500/15 text-amber-600 border-amber-500/30<br/>Indicator: Amber dot<br/>Text: 'Review Needed'"]
        NORM -- "norm in ('benign', 'clean', 'popular_benign_context', 'known_clean', 'trusted')" --> R_GRN["Badge Success<br/>Class: bg-emerald-500/15 text-emerald-600 border-emerald-500/30<br/>Indicator: Green dot<br/>Text: 'Benign'"]
        NORM -- "All other values" --> R_SLT["Badge Outline<br/>Class: bg-secondary text-muted-foreground border-border<br/>Text: 'Unknown'"]
    end
```

---

## 11. End-to-End Traces for 8 Golden Domain Cases

Comparing how eight test domains navigate the system from raw telemetry to the final UI badge.

```mermaid
flowchart TD
    subgraph CASES["8 Golden Test Domain Scenarios"]
        C1["Case 1: evil.c2-network.org<br/>(Exact FQDN in URLhaus)"]
        C2["Case 2: malwaredomain.com<br/>(Apex domain in URLhaus)"]
        C3["Case 3: google.com<br/>(Apex domain in Tranco Top 1M)"]
        C4["Case 4: brand-new-site.xyz<br/>(Unindexed domain; no TI records)"]
        C5["Case 5: cleansite.net<br/>(Daily Review status = 'clean')"]
        C6["Case 6: flagged.biz<br/>(Daily Review status = 'malicious')"]
        C7["Case 7: '' (Empty string)<br/>(Malformed telemetry)"]
        C8["Case 8: phish.google.com<br/>(Subdomain in Reputation DB under Tranco Apex)"]
    end

    subgraph ENGINE_ROUTING["Classification Engine Waterfall"]
        C1 -->|Step 1 Match| E_C1["Score: 100 | Scope: EXACT_FQDN<br/>Verdict: MALICIOUS (conf: 98)"]
        C2 -->|Step 3 Match| E_C2["Score: 100 | Scope: REGISTERED_DOMAIN<br/>Verdict: MALICIOUS (conf: 98)"]
        C3 -->|Step 2 Match| E_C3["Score: -100 | Scope: TRUSTED<br/>Verdict: BENIGN (conf: 95)"]
        C4 -->|Steps 1-5 Miss -> Heuristics| E_C4["Score: Heuristic (e.g. 78)<br/>Verdict: REVIEW_NEEDED (conf: 89)"]
        C5 -->|Step 5b Match| E_C5["Score: 0 | Daily Review Clean<br/>Verdict: BENIGN (conf: 95)"]
        C6 -->|Step 5a Match| E_C6["Score: 100 | Daily Review Malicious<br/>Verdict: MALICIOUS (conf: 98)"]
        C7 -->|Sanity Check Fail| E_C7["Score: 0 | Empty Telemetry<br/>Verdict: UNKNOWN (conf: 0)"]
        C8 -->|Step 2 Tranco Intercept!| E_C8["Score: -100 | Step 2 Tranco matches 'google.com'<br/>Verdict: BENIGN (Priority Inversion Defect!)"]
    end

    subgraph UI_DISPLAY["Final Displayed Badge on Frontend"]
        E_C1 --> D_C1["<VerdictBadge verdict='Malicious' /> (Red Badge)"]
        E_C2 --> D_C2["<VerdictBadge verdict='Malicious' /> (Red Badge)"]
        E_C3 --> D_C3["<VerdictBadge verdict='Benign' /> (Emerald Badge)"]
        E_C4 --> D_C4["<VerdictBadge verdict='Review Needed' /> (Amber Badge)"]
        E_C5 --> D_C5["<VerdictBadge verdict='Benign' /> (Emerald Badge)"]
        E_C6 --> D_C6["<VerdictBadge verdict='Malicious' /> (Red Badge)"]
        E_C7 --> D_C7["<VerdictBadge verdict='Unknown' /> (Slate Badge)"]
        E_C8 --> D_C8["<VerdictBadge verdict='Benign' /> (Emerald Badge - WRONG!)"]
    end
```
