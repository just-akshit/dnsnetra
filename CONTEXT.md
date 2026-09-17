# DNSNetra Domain Context & Glossary

This document defines the core domain model, canonical terminology, and boundary semantics for DNSNetra.

---

## 1. Domain Entities & Telemetry

### DNS Query Event
An authoritative record of a single DNS query processed by the pipeline, stored in `domain_query_history`. Carries packet metadata (`timestamp`, `client_ip`, `domain`, `query_type`, `response_code`, `registered_domain`, `tld`), the assigned `final_label`, and optional `ti_source`.

### Canonical Verdict
The authoritative 4-state classification assigned to a DNS query or domain:
1. **`Benign`**: Known safe or highly reputable domain activity with no malicious indicators.
2. **`Malicious`**: Confirmed malicious activity matched against threat intelligence (e.g. URLhaus, active reputation) or threat correlation.
3. **`Review Needed`**: Inconclusive or suspicious activity queued for ongoing 180-day telemetry evaluation.
4. **`Unknown`**: Unclassified activity without definitive evidence.

*Invariants:*
- The four states are mutually exclusive and collectively exhaustive.
- Verdict collapsing (such as `clean = !malicious`) is strictly prohibited.
- Legacy database column names (`clean_queries`, `suspicious_queries`) are internal implementation details and mapped to `benign` and `review_needed` respectively.

### Client Profile
A fast lifetime entity summary of an originating IP address, stored in `client_profiles`. Tracks lifetime queries, unique domains accessed, 4-state verdict counters, and latest activity timestamp.

### Domain Profile
A fast lifetime entity summary of a queried domain name, stored in `domain_profiles`. Tracks lifetime queries, unique clients, query type distribution, 4-state verdict counters, and latest threat intelligence state.

### Client History (Relationship)
A pre-aggregated client $\leftrightarrow$ domain relationship record, stored in `client_history`. Answers how often client $X$ queried domain $Y$ and the associated 4-state verdict breakdown.

### Telemetry Hourly Rollup
A pre-aggregated additive hourly summary, stored in `telemetry_hourly_rollup`. Contains additive counts (`total_queries`, `clean_queries`, `suspicious_queries`, `malicious_queries`, `unknown_queries`) keyed by `bucket_time` (`TIMESTAMPTZ`). Does NOT store entity cardinality (`unique_clients` or `unique_domains`).

---

## 2. Reporting Concepts

### Reporting Summary
Executive-level KPIs providing total queries, unique clients, unique domains, 4-state verdict breakdown, and `malicious_query_percentage`.

### Malicious Query Percentage
The derived ratio:
$$\text{malicious\_query\_percentage} = \frac{\text{malicious\_queries}}{\text{total\_queries}} \times 100$$
(Rounded to two decimal places; `0.0` if `total_queries == 0`).
*Note:* Replaces the deprecated `threats_blocked_pct`. DNSNetra does not record firewall blocking actions; malicious detections are not assumed to be blocked.

### Timeseries Bucket
An hourly calendar bucket $[T, T + 1\text{ hour})$ intersecting the requested interval $[start, end)$. Event inclusion is strictly bounded to the requested interval: events occurring before $start$ or after $end$ are excluded even if they fall within the bucket's calendar hour.

### Event-Population Filter (`verdict_filter`)
A semantic filter applied to query collections (e.g., top domains). Filters the underlying event population such that all returned metrics (`total_queries`, `unique_clients`, `first_seen`, `last_seen`) describe only events matching the selected verdict.

---

## 3. Boundary & Error Semantics

### Half-Open Intervals
All time boundaries follow the canonical half-open interval $[start\_time, end\_time)$. Implemented in SQL as `timestamp >= start_time AND timestamp < end_time`.

### Entity NotFound vs Empty Collection
- An entity lookup (`client_ip` or `domain`) for a non-existent entity raises `ClientNotFoundError` or `DomainNotFoundError`.
- A collection query that matches zero records returns an empty `PaginatedResult` (`total=0, items=[]`).

---

## 4. Investigation Concepts & Contracts (Phase 2B Frozen)

### Investigation Purpose
An on-demand, read-only, single-entity analyst dossier composed from authoritative PostgreSQL state (`client_profiles`, `client_history`, `domain_profiles`, `domain_query_history`, `reputation_domains`, `daily_review_domains`, `reviewed_clean_domains`). Investigation is not profiling, not reporting, not aggregation, and not live threat intelligence scanning.

### Canonical Four-Verdict Integrity
All entity profiles, relationship graphs, and query event previews preserve the canonical 4-state verdict model (`Benign`, `Malicious`, `Review Needed`, `Unknown`). Verdict collapsing is strictly forbidden. Database column `clean_queries` in `domain_profiles` is an internal column name that maps strictly to canonical `benign_queries`.

### Client Dossier Contract (`ClientDossier`)
An immutable document containing:
- `client_ip`: Validated IPv4 or IPv6 host address string.
- `profile`: Authoritative lifetime metrics (`total_queries`, `unique_domains`, 4 canonical verdict counters, `first_seen`, `last_seen`, `last_domain`, `last_query_type`) from `client_profiles`.
- `top_domains`: Bounded lifetime client-to-domain relationships from `client_history`.
- `threat_activity`: Bounded suspect/non-benign relationships from `client_history`.
- `recent_queries`: Bounded chronological preview of recent DNS query events from `ReportingRepository.get_queries()`.

### Domain Dossier Contract (`DomainDossier`)
An immutable document containing:
- `domain`: Normalized FQDN string.
- `profile`: Authoritative lifetime metrics (`total_queries`, `unique_clients`, 4 canonical verdict counters, `query_type_distribution`, `first_seen`, `last_seen`, `last_client_ip`, `last_label`, `last_ti_source`) from `domain_profiles`.
- `top_querying_clients`: Bounded reverse relationships from `client_history`. Benign clients remain visible.
- `threat_intel`: Three-context container of persisted local intelligence.
- `recent_queries`: Bounded chronological preview of recent DNS query events from `ReportingRepository.get_queries()`.

### Threat Activity Semantics & Activity Category
A client relationship belongs in `threat_activity` if and only if:
$$\text{malicious\_visits} > 0 \lor \text{review\_needed\_visits} > 0 \lor \text{unknown\_visits} > 0$$
Benign-only relationships (`benign > 0` and others `== 0`) are excluded.
Each item carries a factual, non-causal `activity_category`:
- **`MALICIOUS`**: Only malicious visits observed (`malicious > 0`, others `== 0`).
- **`REVIEW_NEEDED`**: Only review-needed visits observed (`review_needed > 0`, others `== 0`).
- **`UNKNOWN`**: Only unknown visits observed (`unknown > 0`, others `== 0`).
- **`MIXED`**: At least two verdict counters $> 0$, with at least one non-benign visit.
*Rule:* `activity_category` is a factual historical classification and never implies compromise, sinkholing, dynamic DNS reuse, domain takeover, or incident severity.

### Bounded Lists & Top-N Graph Semantics
The Investigation Engine never returns unbounded query results or claims to return the complete graph:
- `top_domains`: Default 20, Hard Maximum 100.
- `threat_activity`: Default 20, Hard Maximum 100.
- `top_querying_clients`: Default 20, Hard Maximum 100.
- `recent_queries`: Default 25, Hard Maximum 50.

### Deterministic Ordering Rules
1. `top_domains`: `ORDER BY visit_count DESC, last_seen DESC, domain ASC`
2. `threat_activity`: `ORDER BY malicious_visits DESC, review_needed_visits DESC, unknown_visits DESC, visit_count DESC, last_seen DESC, domain ASC`
3. `top_querying_clients`: `ORDER BY visit_count DESC, last_seen DESC, client_ip ASC`
4. `recent_queries`: `ORDER BY timestamp DESC, id DESC`

### Persisted Threat Intelligence (Three Independent Contexts)
`PersistedThreatIntel` preserves local intelligence records without artificial precedence:
1. `reputation` (`ReputationContext`): Populated from `reputation_domains` if present; otherwise `None`.
2. `daily_review` (`DailyReviewContext`): Populated from `daily_review_domains` if present; otherwise `None`.
3. `reviewed_clean` (`ReviewedCleanContext`): Populated from `reviewed_clean_domains` if present; otherwise `None`.
A domain can exist in multiple contexts concurrently.

### Evidence Summary Whitelist
`evidence_summary` in `DailyReviewContext` and `ReviewedCleanContext` strictly exposes whitelisted stable counters:
- VirusTotal: `{"provider": "VirusTotal", "malicious_count": int, "harmless_count": int, "suspicious_count": int}`
- AlienVault OTX: `{"provider": "AlienVault OTX", "pulse_count": int}`
Arbitrary provider keys, nested JSON dumps, and raw API responses are strictly excluded and never leaked. If payload is null, empty, or lacks whitelisted fields, `evidence_summary = None`.

### Entity Existence Semantics
- Primary existence is determined strictly by the profile tables (`client_profiles` / `domain_profiles`).
- Missing profile record $\to$ raises `EntityNotFoundError` (maps to future HTTP 404).
- Existence is never inferred from `domain_query_history`.
- Valid existing entity states include `threat_activity == []`, `top_querying_clients == []`, `recent_queries == []`, and empty threat intelligence contexts (valid 200 states).

### Input Validation Rules
- **Client IP**: Validated via Python standard library `ipaddress.ip_address()`. Rejects CIDR notations, hostnames, empty strings, and malformed characters with `InvalidEntityError`.
- **Domain**: Validated and normalized via `labeler.intel.database.normalize_domain()`. Strips whitespace, lowercases, removes trailing dot, and enforces RFC 1035 limits (length $\le 253$). Rejects malformed strings with `InvalidEntityError`. Punycode (`xn--*`) and valid private/internal domains are preserved.

### Mathematical Invariants
Every dossier returned enforces and preserves:
1. Client profile: $\text{benign} + \text{malicious} + \text{review\_needed} + \text{unknown} = \text{total\_queries}$
2. Domain profile: $\text{benign} + \text{malicious} + \text{review\_needed} + \text{unknown} = \text{total\_queries}$
3. Client relationship: $\text{benign\_visits} + \text{malicious\_visits} + \text{review\_needed\_visits} + \text{unknown\_visits} = \text{visit\_count}$
4. Domain reverse relationship: $\text{benign\_visits} + \text{malicious\_visits} + \text{review\_needed\_visits} + \text{unknown\_visits} = \text{visit\_count}$

### Architectural Decoupling & Read-Only Guarantees
- **Dependency Direction**: `InvestigationService` $\to$ `InvestigationRepository` and `ReportingRepository`. Zero dependencies on `ReportingService` or FastAPI. Reporting never depends on Investigation.
- **Read-Only Guarantee**: Investigation executes strictly `SELECT` SQL queries. Zero writes, zero migrations, zero table alterations.
- **No External Network Calls**: Investigation executes strictly against local PostgreSQL. Zero HTTP requests, DNS lookups, RDAP queries, or third-party TI provider calls.
- **Phase 2C Boundary**: Investigation maintains lifetime summaries and bounded recent previews. Zero time-window bucketing or timezone conversion abstractions.
- **Future API Boundary**: Frozen to `GET /api/v1/investigation/client/{client_ip}` and `GET /api/v1/investigation/domain/{domain}`. Full event drill-down belongs to `/reports/queries`.

---

## 5. Centralized Temporal Contract & Time Engine (Phase 2C Frozen)

### Purpose & Scope
The Centralized Temporal Engine (`time_engine`) is the single authoritative source of truth for all time-scoped analytics across DNSNetra, including Reporting, Investigation query drill-downs, Timeseries generation, Top Clients/Domains, and future CSV/JSON exports.

### Canonical Datatypes & Timezone Invariant
- **Internal Representation**: `datetime.datetime`, strictly timezone-aware, normalized to `timezone.utc`.
- **Strict Naive Datetime Policy**: Naive datetimes (`tzinfo is None`) are strictly rejected with `TimeEngineValidationError`. Zero silent coercion, zero guessing of machine local timezone.
- **Input ISO-8601 Strings**: Must explicitly include `'Z'`/`'z'` or an explicit offset (e.g. `+00:00`, `+05:30`). Converted to canonical UTC upon entry. Naive strings (e.g. `2026-09-16T12:00:00`) are rejected.
- **Microsecond Precision**: Microsecond precision ($10^{-6}\text{s}$) is strictly preserved across parsing, arithmetic, and SQL predicates. Internal timestamps are never rounded or truncated to whole seconds.

### Interval Mathematics $[start, end)$
- All temporal queries and event inclusion adhere strictly to canonical half-open interval semantics:
  $$\text{start} \le \text{event\_timestamp} < \text{end}$$
- SQL implementations use strictly `timestamp >= %s AND timestamp < %s`. `BETWEEN` and `<= end` are prohibited.
- **Boundary Disjointness**: For adjacent windows $[A, B)$ and $[B, C)$, $[A, B) \cap [B, C) = \emptyset$. An event occurring exactly at $B$ belongs strictly to the second window.
- **Empty Range ($start == end$)**: Valid empty interval. Returns total queries = 0, unique entities = 0, zero-filled or empty bucket list, and empty query events with HTTP 200 equivalent.
- **Inverted Range ($start > end$)**: Invalid interval. Strictly rejected with `InvalidTimeRangeError`.

### Single "NOW" Resolution
- Server time is resolved exactly once per request: `server_now = now_override or datetime.now(timezone.utc)`.
- Stored as `ResolvedTimeRange.resolved_now`. Downstream services and repositories are prohibited from calling `datetime.now()` or PostgreSQL `NOW()`.

### Preset Semantics & Preset-Bucket Precedence
1. **Rolling Presets**:
   - Strictly defined as $[now - \text{duration}, now)$.
   - Supported canonical presets: `15m` (default 1m), `1h` (default 5m), `6h` (default 15m), `24h` (default 1h), `7d` (default 6h), `30d` (default 1d).
   - Redundant or ambiguous aliases (`60m`, `6m`, `45m`) are permanently prohibited.
2. **Calendar Presets**:
   - `today`: $[today\_00:00:00\text{ UTC}, tomorrow\_00:00:00\text{ UTC})$ (default 1h).
   - `yesterday`: $[yesterday\_00:00:00\text{ UTC}, today\_00:00:00\text{ UTC})$ (default 1h).
   - Calendar boundaries are strictly evaluated in UTC. Local IANA timezone support is an explicit future extension point.
3. **Precedence Rule**:
   - `window` determines the **time range** $[start, end)$.
   - `bucket` determines the **bucket width**, overriding the preset's default.
   - e.g. `window=24h&bucket=15m` yields a 24-hour range with 15m buckets ($N=96$ or $97 \le 100$).
   - Explicit bucket remains subject to `MAX_TIMELINE_BUCKETS = 100` and is rejected if exceeded (e.g. `window=24h&bucket=1m` raises `InvalidTimeRangeError`).

### Partially Future Range Semantics
- We distinguish:
  1. `requested_range`: $[start, end)$
  2. `observable_range`: $[start, \min(end, resolved\_now))$
- **Observation Rule**: Telemetry queries strictly evaluate `timestamp < min(end, resolved_now)`. Database events with timestamps beyond `resolved_now` (from clock drift) are ignored.
- **Summary & KPI Metrics**: Computed strictly over the observable range $[start, \min(end, resolved\_now))$.
- **Timeseries Buckets**: Timeline generates all intersecting buckets up to $end$. Buckets covering $t \ge resolved\_now$ are zero-filled.
- **Boundaries**:
  - $end \le now$: Fully historical (allowed).
  - $start < now < end$: Partially future (allowed; future buckets zero-filled).
  - $start \ge now$: Entirely in future $\to$ **rejected** with `InvalidTimeRangeError`.

### All-Time State Model (`is_all_time`)
- `ResolvedTimeRange` supports exactly two mutually exclusive states:
  1. **Bounded Mode** (`is_all_time = False`): `start` and `end` are non-None UTC datetimes ($start \le end$); `bucket_spec` is populated; duration and bucket generation are valid.
  2. **All-Time Mode** (`is_all_time = True`): `start = None`, `end = None`, `preset = None`, `bucket_spec = None`. Methods `duration_seconds`, `generate_buckets()`, and `is_hour_aligned` are invalid (raise `InvalidTimeRangeError`). Lifetime summaries and profile lookups are valid.

### Centralized Default Temporal Policies
- Exposed via `TemporalDefaultPolicy`:
  - `ALL_TIME`: Defaults to `is_all_time = True` when no temporal parameters are provided (used by Summary, Top Clients, Top Domains).
  - `ROLLING_24H`: Defaults to rolling preset `"24h"` when no temporal parameters are provided (used by Reports Overview, Timeseries).
- The resolver centrally evaluates the policy; endpoints do not implement manual fallback branches.

### Bucket Grid & Partial Bucket Semantics
- **UTC Calendar/Epoch Grid**: All timeseries buckets align to canonical UTC calendar/epoch boundaries.
- **Intersecting Calendar Buckets**: An unaligned range (e.g. $[10:37, \text{next } 10:37)$) legitimately intersects 25 hourly calendar buckets. This is the correct mathematical behavior of grid intersection, not an off-by-one error.
- **Bucket Metadata (`ResolvedBucket`)**:
  - `bucket_start`: UTC grid floor.
  - `bucket_end`: UTC grid ceiling ($= \text{bucket\_start} + \text{bucket\_seconds}$).
  - `effective_start`: $\max(\text{bucket\_start}, \text{range\_start})$.
  - `effective_end`: $\min(\text{bucket\_end}, \text{range\_end})$.
  - `is_partial`: $\text{True}$ if $\text{effective\_start} \neq \text{bucket\_start} \lor \text{effective\_end} \neq \text{bucket\_end}$.
  - `covered_seconds`: $(\text{effective\_end} - \text{effective\_start}).\text{total\_seconds}()$.
- **Coverage Conservation Invariant**:
  $$\sum_{i=1}^N \text{covered\_seconds}_i == (\text{range\_end} - \text{range\_start}).\text{total\_seconds}()$$
- **Event Inclusion Rule**: Event at $t$ belongs to bucket $i$ iff $\text{effective\_start}_i \le t < \text{effective\_end}_i$. Events outside $[range\_start, range\_end)$ can never enter an edge bucket.

### Explicit Bucket Grammar & Auto-Bucketing Guarantee
- **Frozen Explicit Bucket Set**: `{"1s", "5s", "10s", "30s", "1m", "5m", "10m", "15m", "30m", "1h", "2h", "3h", "6h", "12h", "1d", "1w"}`.
  - Case-insensitive, whitespace-stripped.
  - Any width outside this set (e.g. `2m`, `7m`, `17m`, `90m`, `36h`) is strictly rejected with `TimeEngineValidationError`.
- **Auto-Bucketing Guarantee ($\le 100$ Buckets)**:
  1. Iterate candidate widths $W$ in ascending order.
  2. Compute exact intersecting bucket count $N = \text{count\_intersecting\_buckets}(start, end, W)$.
  3. First $W$ yielding $N \le 100$ is selected.
  4. Fallback for ranges $> 700\text{w}$: Compute $\text{days} = \max(8, \lceil D / (100 \times 86400) \rceil)$; increment $\text{days} += 1$ until $N \le 100$. Mathematically guarantees $N \le 100$ under all circumstances.

### Database Session & Rollup Contract
- **PostgreSQL Session Timezone**: Connection checkout must enforce `SET TIME ZONE 'UTC'`.
- **SQL String Formatting**: Must strictly use `AT TIME ZONE 'UTC'` when appending `'Z'`:
  `to_char(timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')`.
- **Legacy Rollup Verdict Mapping**:
  - `clean_queries` $\iff$ `Benign`
  - `suspicious_queries` $\iff$ `Review Needed`
  - `malicious_queries` $\iff$ `Malicious`
  - `unknown_queries` $\iff$ `Unknown`
  - Reconciles to $\text{clean} + \text{suspicious} + \text{malicious} + \text{unknown} == \text{total}$.
- **Rollup Eligibility**: `telemetry_hourly_rollup` is used ONLY if the window is UTC hourly-aligned, completely historical, and querying additive query counts. Unique clients and unique domains are NEVER summed from rollups and are ALWAYS computed via `COUNT(DISTINCT ...)` over raw history.
- **Rollup Repair Dependency**: Existing historical rollups contain local-floored timestamps and must be reconciled via a dedicated script before rollups can be treated as authoritative.

### Four-State Verdict Invariant
- Across all timeseries buckets and summary reports:
  $$\text{benign} + \text{malicious} + \text{review\_needed} + \text{unknown} == \text{total}$$
- Zero-filled buckets have all 4 verdict counts set to 0.



