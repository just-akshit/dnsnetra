# Phase 3 — Golden Domain Investigation Artifact
**DNS Threat Detection System — Canonical Demonstration Investigation**  
**Target Domain**: `secure-update.net`  
**Classification**: `KNOWN_MALICIOUS` (Evidence Scope: `CORRELATED`)  
**Status**: VERIFIED & FROZEN  
**Date**: August 2026  

---

## 1. Domain Investigation Summary

| Attribute | Forensic Value |
| :--- | :--- |
| **Queried Domain** | `secure-update.net` |
| **Normalized FQDN** | `secure-update.net` |
| **Registered Domain** | `secure-update.net` |
| **TLD / Suffix** | `net` |
| **Verdict Status** | **`KNOWN_MALICIOUS`** |
| **Risk Score** | **100.0 / 100** |
| **Confidence** | **0.95 (High)** |
| **Primary Source** | **Threat Correlation Engine** |
| **Evidence Scope** | **`CORRELATED`** |
| **Tranco Status** | `NO_DATA` [`LOCAL`, Freshness: `NOT_APPLICABLE`] |
| **URLhaus Status** | `NO_DATA` [`LOCAL`, Freshness: `NOT_APPLICABLE`] |
| **External TI Aggregate** | `status: AVAILABLE`, `provenance: PERSISTED`, `freshness: ACTIVE_REPUTATION` |
| **VirusTotal Status** | `AVAILABLE` (1 Detections, Result: `MALICIOUS`) [`PERSISTED`, Freshness: `ACTIVE_REPUTATION`] |
| **AlienVault OTX Status** | `AVAILABLE` (1 Detections, Result: `MALICIOUS`) [`PERSISTED`, Freshness: `ACTIVE_REPUTATION`] |
| **PostgreSQL Reputation** | `reputation_domains` active record: **YES** (`CORRELATED`) |
| **DNS Query Volume** | **13 Queries** [`OBSERVED`] |
| **Querying Endpoints** | **5 Clients** (`192.168.1.100`, `192.168.1.103`, `192.168.1.102`, `192.168.1.104`, `10.0.0.6`) |

---

## 2. Canonical API Response Payload (Runtime-Extracted)

```json
{
  "status": "success",
  "data": {
    "domain": {
      "queried": "secure-update.net",
      "normalized": "secure-update.net",
      "fqdn": "secure-update.net",
      "registered_domain": "secure-update.net",
      "tld": "net",
      "subdomain": ""
    },
    "classification": {
      "status": "KNOWN_MALICIOUS",
      "label": "malicious",
      "risk_score": 100.0,
      "confidence": 0.95,
      "reason": "Flagged as malicious by Threat Correlation Engine (Persisted reputation scope: CORRELATED)",
      "source": "Threat Correlation Engine",
      "scope": "CORRELATED"
    },
    "local_intelligence": {
      "tranco": {
        "provider": "Tranco",
        "matched": false,
        "status": "NO_DATA",
        "result": null,
        "provenance": "LOCAL",
        "freshness": "NOT_APPLICABLE"
      },
      "urlhaus": {
        "provider": "URLhaus",
        "matched": false,
        "status": "NO_DATA",
        "result": null,
        "provenance": "LOCAL",
        "freshness": "NOT_APPLICABLE"
      }
    },
    "external_intelligence": {
      "status": "AVAILABLE",
      "provenance": "PERSISTED",
      "freshness": "ACTIVE_REPUTATION",
      "virustotal": {
        "provider": "VirusTotal",
        "status": "AVAILABLE",
        "result": "MALICIOUS",
        "malicious_count": 1,
        "harmless_count": 0,
        "suspicious_count": 0,
        "provenance": "PERSISTED",
        "freshness": "ACTIVE_REPUTATION",
        "confidence": 0.95,
        "observed_at": "2026-08-23 19:55:19.826365",
        "reason": "Active reputation record (Scope: CORRELATED)"
      },
      "otx": {
        "provider": "AlienVault OTX",
        "status": "AVAILABLE",
        "result": "MALICIOUS",
        "malicious_count": 1,
        "harmless_count": 0,
        "suspicious_count": 0,
        "provenance": "PERSISTED",
        "freshness": "ACTIVE_REPUTATION",
        "confidence": 0.95,
        "observed_at": "2026-08-23 19:55:19.826365",
        "reason": "Active reputation record (Scope: CORRELATED)"
      }
    },
    "correlation": {
      "engine": "Threat Correlation Engine",
      "score": 0.60,
      "threshold": 0.60,
      "confidence": 0.95,
      "verdict": "malicious",
      "provenance": "COMPUTED"
    },
    "dns_activity": {
      "status": "OBSERVED",
      "query_count": 13,
      "unique_clients": 5,
      "malicious_count": 1,
      "suspicious_count": 0,
      "clean_count": 0,
      "first_seen": "2026-08-22T16:16:20Z",
      "last_seen": "2026-08-23T18:48:53Z",
      "query_types": {
        "A": 8,
        "TXT": 2,
        "AAAA": 1,
        "NS": 1,
        "MX": 1
      },
      "response_codes": {
        "NOERROR": 13
      }
    },
    "reputation": {
      "active_record": true,
      "status": "malicious",
      "source": "Threat Correlation Engine",
      "confidence": 0.95,
      "match_scope": "CORRELATED",
      "matched_domain": "secure-update.net",
      "first_seen": "2026-08-22 16:16:21.158593",
      "last_seen": "2026-08-23 19:55:19.826365"
    },
    "querying_clients": [
      {
        "client_ip": "192.168.1.100",
        "query_count": 6,
        "last_seen": "2026-08-23 18:48:53.825449+05:30"
      },
      {
        "client_ip": "192.168.1.103",
        "query_count": 3,
        "last_seen": "2026-08-22 16:18:31.072274+05:30"
      },
      {
        "client_ip": "192.168.1.102",
        "query_count": 2,
        "last_seen": "2026-08-22 16:18:31.034510+05:30"
      },
      {
        "client_ip": "192.168.1.104",
        "query_count": 1,
        "last_seen": "2026-08-22 16:18:33.396472+05:30"
      },
      {
        "client_ip": "10.0.0.6",
        "query_count": 1,
        "last_seen": "2026-08-22 16:18:33.148012+05:30"
      }
    ],
    "investigation": {
      "known": true,
      "why": "Active malicious reputation record found in the reputation database.",
      "evidence": [
        {
          "provider": "Threat Correlation Engine",
          "result": "MALICIOUS",
          "scope": "CORRELATED",
          "provenance": "PERSISTED",
          "freshness": "ACTIVE_REPUTATION",
          "confidence": 0.95
        }
      ]
    },
    "duration_ms": 10.06
  }
}
```

---

## 3. Investigation Evidence Breakdown

```
====================================================================
                     GOLDEN DOMAIN INVESTIGATION
====================================================================
Domain: secure-update.net

Normalization
├── FQDN:              secure-update.net
├── Registered domain: secure-update.net
└── TLD / Subdomain:   .net (Sub: None)

Local Intelligence
├── URLhaus:           NO_DATA [LOCAL, Freshness: NOT_APPLICABLE]
└── Tranco:            NO_DATA [LOCAL, Freshness: NOT_APPLICABLE]

External Intelligence
├── Aggregate:         status: AVAILABLE, provenance: PERSISTED, freshness: ACTIVE_REPUTATION
├── VirusTotal:        1 Detections [PERSISTED, Freshness: ACTIVE_REPUTATION]
├── AlienVault OTX:    1 Detections [PERSISTED, Freshness: ACTIVE_REPUTATION]
└── Status:            AVAILABLE (Active Reputation Record Reused)

Correlation
├── Verdict:           KNOWN_MALICIOUS
├── Risk Score:        100.00 / 100
├── Confidence:        0.95
├── Scope:             CORRELATED
└── Reason:            Flagged as malicious by Threat Correlation Engine

Persistence & DNS Activity
├── PostgreSQL:        ✓ (reputation_domains match_scope: CORRELATED)
├── SQLite Read Model: ✓ (Observed in 13 Queries)
└── Querying Clients:  5 Endpoints (Top: 192.168.1.100, 6 hits)
====================================================================
```
