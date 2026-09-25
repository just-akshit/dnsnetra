# Phase 4.2 — Time-Window DNS Analytics Specification

## Overview & Mission

Phase 4.2 implements a production-grade, observational **Time-Window DNS Analytics** capability on top of the append-only PostgreSQL telemetry (`domain_query_history`) and the overview dashboard.

The goal is to empower security analysts to query arbitrary rolling windows (`5m`, `10m`, `15m`, `30m`, `45m`, `60m`) or custom UTC date/time ranges to accurately observe how many domains, apex registrations, unique FQDNs, DNS queries, client endpoints, and malicious/suspicious domains were active.

> [!IMPORTANT]
> **Observational Analytics Foundation:**
> Phase 4.2 is strictly an observational analytics capability — NOT an alerting or case management engine. It does not alter Phase 2.7 threat intelligence rules, Phase 3 investigation contracts, Phase 4 enrichment, or Phase 4.1 evidence provenance contracts.

---

## 1. Metric Definitions & Semantics

| Metric | Definition & Formula | Interpretation |
| :--- | :--- | :--- |
| **Domains Observed (Primary KPI)** | `COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain))` | Unique registered apex domains (e.g. `evil-corp.com`) observed during the window. |
| **Unique FQDNs** | `COUNT(DISTINCT domain)` | Unique hostnames (e.g. `c2.evil-corp.com`, `vpn.evil-corp.com`). |
| **DNS Queries** | `COUNT(*)` | Total DNS query telemetry records logged in the window. |
| **Unique Clients** | `COUNT(DISTINCT client_ip)` | Total distinct IP endpoints originating DNS traffic. |
| **Malicious Domains** | `COUNT(DISTINCT CASE WHEN LOWER(final_label) = 'malicious' THEN COALESCE(NULLIF(registered_domain, ''), domain) END)` | Distinct registered domains observed with a historical `malicious` classification at query time. |
| **Suspicious Domains** | `COUNT(DISTINCT CASE WHEN LOWER(final_label) = 'suspicious' THEN COALESCE(NULLIF(registered_domain, ''), domain) END)` | Distinct registered domains observed with a historical `suspicious` classification at query time. |

### Historical Observational Integrity
The analytics layer strictly reflects what the system recorded at that moment (`final_label` in `domain_query_history`). It does **not** re-query live threat intelligence providers for past historical queries.

### Non-Additive Timeline Semantics
Timeline buckets report `unique_domains` observed within each specific interval $[t_i, t_{i+1})$. Because a domain may appear across multiple adjacent buckets:
$$\sum \text{bucket\_unique\_domains} \neq \text{window\_unique\_registered\_domains}$$
The primary headline KPI is computed from the window-level summary query.

---

## 2. API Contract Specification

### Endpoint
`GET /api/v1/analytics/domains`

### Query Parameters
| Parameter | Type | Required | Description | Example |
| :--- | :--- | :--- | :--- | :--- |
| `window` | `string` | Optional | Preset rolling window ending at server UTC now (`5m`, `10m`, `15m`, `30m`, `45m`, `60m`). | `window=15m` |
| `start` | `string` | Optional | Start timestamp in UTC ISO8601 format (inclusive). | `start=2026-08-24T00:00:00Z` |
| `end` | `string` | Optional | End timestamp in UTC ISO8601 format (exclusive). | `end=2026-08-24T00:15:00Z` |

### Validation Rules
1. `window` and custom (`start`/`end`) are mutually exclusive.
2. If `window` is specified, it must be one of `['5m', '10m', '15m', '30m', '45m', '60m']`.
3. If custom range is specified, both `start` and `end` are required and must be valid ISO8601 strings.
4. `start < end` is strictly enforced (returns HTTP 400 if `start >= end`).
5. Maximum historical duration is capped at 30 days (43,200 minutes).

### Response JSON Contract
```json
{
  "status": "success",
  "data": {
    "window": {
      "start": "2026-08-24T00:00:00Z",
      "end": "2026-08-24T00:15:00Z",
      "duration_minutes": 15.0
    },
    "metrics": {
      "total_queries": 2481,
      "unique_fqdns": 436,
      "unique_registered_domains": 182,
      "unique_clients": 27,
      "malicious_domains": 8,
      "suspicious_domains": 14
    },
    "timeline": [
      {
        "timestamp": "2026-08-24T00:00:00Z",
        "queries": 142,
        "unique_domains": 31
      }
    ]
  }
}
```

---

## 3. Database Architecture & Aggregation Queries

### Half-Open Time Bounds: `[start, end)`
All queries use canonical half-open time bounds `timestamp >= :start AND timestamp < :end` to eliminate boundary double-counting.

### Query 1: Summary Metrics
```sql
SELECT 
    COUNT(*) AS total_queries,
    COUNT(DISTINCT domain) AS unique_fqdns,
    COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_registered_domains,
    COUNT(DISTINCT client_ip) AS unique_clients,
    COUNT(DISTINCT CASE WHEN LOWER(COALESCE(final_label, '')) = 'malicious' THEN COALESCE(NULLIF(registered_domain, ''), domain) END) AS malicious_domains,
    COUNT(DISTINCT CASE WHEN LOWER(COALESCE(final_label, '')) = 'suspicious' THEN COALESCE(NULLIF(registered_domain, ''), domain) END) AS suspicious_domains
FROM domain_query_history
WHERE timestamp >= %(start)s AND timestamp < %(end)s;
```

### Query 2: Deterministic Timeline Bucketing
```sql
SELECT 
    to_timestamp(floor(extract(epoch from timestamp) / %(bucket_seconds)s) * %(bucket_seconds)s) AT TIME ZONE 'UTC' AS bucket_time,
    COUNT(*) AS queries,
    COUNT(DISTINCT COALESCE(NULLIF(registered_domain, ''), domain)) AS unique_domains
FROM domain_query_history
WHERE timestamp >= %(start)s AND timestamp < %(end)s
GROUP BY bucket_time
ORDER BY bucket_time ASC;
```

### Bucket Sizing & Invariant
- **5m, 10m, 15m:** 60s (1 min)
- **30m:** 120s (2 min)
- **45m:** 180s (3 min)
- **60m:** 300s (5 min)
- **Custom Range Invariant:** Bucket count is strictly $\le 100$ buckets.

---

## 4. Modular Package Structure

```text
backend/analytics/
├── __init__.py           # Package exports
├── time_window.py        # TimeWindow resolver, presets, half-open interval, bucket sizing
├── domain_analytics.py   # DomainAnalyticsService (database queries, bucket grid alignment)
└── models.py             # Pydantic response models
```

This modular foundation allows future Phase 5 services (Reporting, Alerting, Case Management) to consume identical time-window abstractions.
