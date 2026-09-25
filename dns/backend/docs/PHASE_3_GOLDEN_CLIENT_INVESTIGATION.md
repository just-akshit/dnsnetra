# Phase 3 — Golden Client Investigation Artifact
**DNS Threat Detection System — Canonical Demonstration Investigation**  
**Target Client IP**: `192.168.1.100`  
**Network Segment**: `Private / RFC 1918 Internal Network`  
**Status**: VERIFIED & FROZEN  
**Date**: August 2026  

---

## 1. Client Investigation Summary

| Attribute | Forensic Value |
| :--- | :--- |
| **Client IP** | `192.168.1.100` |
| **Network Classification** | `Private / RFC 1918 Internal Network` |
| **Total Query Volume** | **70 Queries** |
| **Unique Destination Targets** | **46 Domains** |
| **Malicious Queries** | **4 Queries** (`secure-update.net`, `malicious-c2-test.net`, `trojan-download.org`, `ransomware-payload.biz`) |
| **Malicious Domains** | **4 Unique Domains** |
| **Suspicious Queries** | **3 Queries** (`software-update-check.com`, `apple-account-verify.net`, `bank-account-verification.com`) |
| **Suspicious Domains** | **3 Unique Domains** |
| **Benign Queries** | **63 Queries** |
| **Benign Domains** | **42 Unique Domains** |
| **Threat Traffic Ratio** | **5.71%** (4 malicious queries / 70 total queries) |
| **Threat Domain Ratio** | **8.70%** (4 malicious domains / 46 unique domains) |
| **Risk Status** | **`THREATS_DETECTED`** |
| **Activity Window** | First Seen: `2026-08-22 16:18:32` • Last Seen: `2026-08-23 18:48:53` |

---

## 2. Canonical API Response Payload (Runtime-Extracted)

```json
{
  "status": "success",
  "data": {
    "client": {
      "ip": "192.168.1.100",
      "network_type": "Private / RFC 1918 Internal Network",
      "first_seen": "2026-08-22 16:18:32.876715+05:30",
      "last_seen": "2026-08-23 18:48:53.825449+05:30",
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
      "threat_domain_ratio": 8.7,
      "threat_ratio": 5.71,
      "risk_status": "THREATS_DETECTED"
    },
    "threat_domains": [
      {
        "domain": "secure-update.net",
        "label": "malicious",
        "query_count": 1,
        "ti_source": "Threat Correlation Engine",
        "provenance": "COMPUTED",
        "last_seen": "2026-08-23 18:48:53.825449+05:30"
      },
      {
        "domain": "software-update-check.com",
        "label": "suspicious",
        "query_count": 1,
        "ti_source": "heuristic_anomaly",
        "provenance": "COMPUTED",
        "last_seen": "2026-08-22 16:26:56.610323+05:30"
      },
      {
        "domain": "apple-account-verify.net",
        "label": "suspicious",
        "query_count": 1,
        "ti_source": "heuristic_anomaly",
        "provenance": "COMPUTED",
        "last_seen": "2026-08-22 16:26:55.238253+05:30"
      },
      {
        "domain": "bank-account-verification.com",
        "label": "suspicious",
        "query_count": 1,
        "ti_source": "heuristic_anomaly",
        "provenance": "COMPUTED",
        "last_seen": "2026-08-22 16:22:00.947659+05:30"
      }
    ],
    "top_domains": [
      {
        "domain": "google.com",
        "label": "benign",
        "query_count": 3,
        "ti_source": "trusted",
        "provenance": "LOCAL",
        "last_seen": "2026-08-23 18:48:53.787281+05:30"
      },
      {
        "domain": "azure.microsoft.com",
        "label": "benign",
        "query_count": 2,
        "ti_source": "trusted",
        "provenance": "LOCAL",
        "last_seen": "2026-08-22 16:26:55.474772+05:30"
      },
      {
        "domain": "bitbucket.org",
        "label": "benign",
        "query_count": 2,
        "ti_source": "trusted",
        "provenance": "LOCAL",
        "last_seen": "2026-08-22 16:24:09.499205+05:30"
      },
      {
        "domain": "tensorflow.org",
        "label": "benign",
        "query_count": 2,
        "ti_source": "trusted",
        "provenance": "LOCAL",
        "last_seen": "2026-08-22 16:26:55.261396+05:30"
      }
    ],
    "recent_activity": [
      {
        "timestamp": "2026-08-23 18:48:53.825449+05:30",
        "domain": "secure-update.net",
        "query_type": "A",
        "response_code": "NOERROR",
        "final_label": "Malicious",
        "ti_source": "Threat Correlation Engine",
        "provenance": "COMPUTED"
      },
      {
        "timestamp": "2026-08-23 18:48:53.787281+05:30",
        "domain": "google.com",
        "query_type": "A",
        "response_code": "NOERROR",
        "final_label": "Benign",
        "ti_source": "trusted",
        "provenance": "LOCAL"
      },
      {
        "timestamp": "2026-08-22 16:26:56.693089+05:30",
        "domain": "notion.so",
        "query_type": "NS",
        "response_code": "NOERROR",
        "final_label": "Benign",
        "ti_source": "trusted",
        "provenance": "LOCAL"
      },
      {
        "timestamp": "2026-08-22 16:26:56.610323+05:30",
        "domain": "software-update-check.com",
        "query_type": "TXT",
        "response_code": "NOERROR",
        "final_label": "Suspicious",
        "ti_source": "heuristic_anomaly",
        "provenance": "COMPUTED"
      },
      {
        "timestamp": "2026-08-22 16:26:55.238253+05:30",
        "domain": "apple-account-verify.net",
        "query_type": "NS",
        "response_code": "NOERROR",
        "final_label": "Suspicious",
        "ti_source": "heuristic_anomaly",
        "provenance": "COMPUTED"
      }
    ],
    "duration_ms": 9.12
  }
}
```

---

## 3. Investigation Evidence Breakdown

```
====================================================================
                     GOLDEN CLIENT INVESTIGATION
====================================================================
Client IP: 192.168.1.100 (RFC 1918 Private Network)

Summary Metrics
├── Total Queries:          70
├── Unique Domains:         46
├── Threat Traffic Ratio:   5.71% (4 / 70 queries)
├── Threat Domain Ratio:    8.70% (4 / 46 domains)
└── Status:                 THREATS_DETECTED

Flagged Threat Destinations (Consistent Provenance)
├── secure-update.net          [MALICIOUS - Threat Correlation Engine, COMPUTED]
├── software-update-check.com  [SUSPICIOUS - heuristic_anomaly, COMPUTED]
├── apple-account-verify.net   [SUSPICIOUS - heuristic_anomaly, COMPUTED]
└── bank-account-verification  [SUSPICIOUS - heuristic_anomaly, COMPUTED]

Bi-Directional Investigation Link
└── Clicking any flagged destination opens the Domain Investigation view
====================================================================
```
