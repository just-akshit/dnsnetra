# Phase 3 — Client Endpoint Investigation
**DNS Threat Detection System — Client Profiling & Triage Manual**  
**Status**: FUNCTIONALLY COMPLETE & FROZEN  
**Date**: August 2026  

---

## 1. Overview & Architecture

The **Client Endpoint Investigation** workflow allows security analysts to select or search any internal client IP address to inspect its DNS behavior, query volume, risk assessment, flagged destination contacts, and chronological telemetry log stream.

```
                  Analyst Client Search
                           │
                           ▼
                  IP Address Validation
                (IPv4 / IPv6 Format Check)
                           │
                           ▼
              Client Profiling & Telemetry
              ├── dashboard.db (client_details)
              ├── client_profiles (PostgreSQL)
              └── domain_query_history (PostgreSQL)
                           │
                           ▼
              Categorized Domain Partitioning
              ├── Threat Destinations (Malicious / Suspicious)
              ├── Benign / Trusted Destinations
              └── Unknown / Review-Needed Destinations
                           │
                           ▼
              Explicit Risk Metrics Calculation
              ├── Threat Traffic Ratio (% Malicious Queries)
              └── Threat Domain Ratio (% Unique Threat Domains)
                           │
                           ▼
              FastAPI /api/v1/investigation/client/{client_ip}
                           │
                           ▼
              React Client Investigation View
```

---

## 2. API Contract

### Endpoint:
```http
GET /api/v1/investigation/client/{client_ip}
```

### Parameters:
- `client_ip` (*path*, required): Target IP address string (e.g. `192.168.1.100`).

### Error Responses:
- `400 Bad Request`: Malformed IP address string.
- `404 Not Found`: Client IP has no recorded telemetry in the system.

### Response Structure:
```json
{
  "status": "success",
  "data": {
    "client": {
      "ip": "192.168.1.100",
      "network_type": "Private / RFC 1918 Internal Network",
      "first_seen": "2026-08-22T16:18:32Z",
      "last_seen": "2026-08-23T18:48:53Z",
      "total_queries": 70
    },
    "summary": {
      "total_queries": 70,
      "unique_domains": 46,
      "malicious_queries": 4,
      "malicious_domains": 4,
      "suspicious_queries": 3,
      "suspicious_domains": 3,
      "benign_queries": 63,
      "benign_domains": 42,
      "unknown_queries": 0,
      "unknown_domains": 0,
      "threat_traffic_ratio": 5.71,
      "threat_domain_ratio": 8.70,
      "threat_ratio": 5.71,
      "risk_status": "THREATS_DETECTED | CLEAN_TRAFFIC"
    },
    "threat_domains": [
      {
        "domain": "secure-update.net",
        "label": "malicious",
        "query_count": 1,
        "ti_source": "Threat Correlation Engine",
        "provenance": "COMPUTED",
        "last_seen": "2026-08-23T18:48:53Z"
      },
      {
        "domain": "software-update-check.com",
        "label": "suspicious",
        "query_count": 1,
        "ti_source": "heuristic_anomaly",
        "provenance": "COMPUTED",
        "last_seen": "2026-08-22T16:26:56Z"
      }
    ],
    "top_domains": [
      {
        "domain": "google.com",
        "label": "benign",
        "query_count": 3,
        "ti_source": "trusted",
        "provenance": "LOCAL",
        "last_seen": "2026-08-23T18:48:53Z"
      }
    ],
    "recent_activity": [
      {
        "timestamp": "2026-08-23T18:48:53Z",
        "domain": "secure-update.net",
        "query_type": "A",
        "response_code": "NOERROR",
        "final_label": "Malicious",
        "ti_source": "Threat Correlation Engine",
        "provenance": "COMPUTED"
      }
    ],
    "duration_ms": 9.12
  }
}
```

---

## 3. Threat Ratio Definitions

To avoid ambiguity, the system provides two distinct metrics:

1. **Threat Traffic Ratio (%)**:
   $$\text{Threat Traffic Ratio} = \frac{\text{Malicious Queries}}{\text{Total Queries}} \times 100$$
   Reflects the actual proportion of DNS query traffic directed to confirmed threats.

2. **Threat Domain Ratio (%)**:
   $$\text{Threat Domain Ratio} = \frac{\text{Unique Malicious Domains}}{\text{Unique Queried Domains}} \times 100$$
   Reflects the proportion of unique domain targets that are malicious.

---

## 4. UI Investigation Sections

The `ClientDetailPage.tsx` component provides 5 synchronized investigation sections:
1. **Client Header**: IP address, RFC 1918 Private vs Public network classification, risk badge (`THREATS_DETECTED` vs `CLEAN_TRAFFIC`), both Threat Traffic Ratio and Threat Domain Ratio.
2. **Summary KPIs**: Query-weighted threat traffic ratio, unique threat domain ratio, total queries, unique destinations.
3. **Flagged Threat Destinations Table**: Dedicated threat table highlighting malicious domains queried by this host, threat source, query volume, provenance tag, and direct link to `/domains/{domain}`.
4. **Top Destination Domains Table**: Highest volume destination domains queried with classifications and links to `/domains/{domain}`.
5. **Recent DNS Query Stream**: Chronological event log of query events with timestamp, query type (`A`, `AAAA`, `MX`, etc.), response code (`NOERROR`, `NXDOMAIN`), and threat labels.
