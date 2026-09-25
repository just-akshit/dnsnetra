# Phase 3 — Domain Investigation & Domain Intelligence Search
**DNS Threat Detection System — Analyst Investigation Manual**  
**Status**: FUNCTIONALLY COMPLETE & FROZEN  
**Date**: August 2026  

---

## 1. Overview & Architecture

The **Domain Intelligence Search & Investigation** workflow transforms the frozen Phase 2.7 Threat Intelligence core into an on-demand, analyst-facing search product.

Analysts can enter any arbitrary domain (e.g. `google.com`, `imccj.gobgem.com`, `secure-update.net`, or an arbitrary unknown domain) and receive a comprehensive, structured investigation record containing everything the system knows about that domain across local intelligence, external threat feeds, active reputation persistence, and DNS protocol traffic.

```
                  Analyst Domain Search
                           │
                           ▼
                  Domain Normalization
                 (FQDN, Apex, TLD, Sub)
                           │
                           ▼
               Local Threat Intelligence
              ├── Tranco Popularity Context
              └── URLhaus Malicious Feed
                           │
                           ▼
              Active PostgreSQL Reputation
             (reputation_domains & Scopes)
                           │
            Authoritative / Persisted Result?
                   ├── YES ──► External Lookup Skipped
                   └── NO  ──► Safe External TI (VT/OTX)
                           │
                           ▼
               DNS Protocol Activity / Logs
              ├── dashboard.db (Aggregated)
              ├── domain_query_history (PG)
              └── Querying Clients List
                           │
                           ▼
              FastAPI /api/v1/investigation/domain/{domain}
                           │
                           ▼
              React Domain Investigation View
```

---

## 2. Canonical Evidence Model & Enums

The system separates Provider, Status, Result, Provenance, and Freshness into distinct, explicit dimensions:

### Provider Enum:
- `VirusTotal`
- `AlienVault OTX`
- `Tranco`
- `URLhaus`
- `Threat Correlation Engine`

### Status Enum:
- `AVAILABLE`: Intelligence data returned.
- `NO_DATA`: Provider queried successfully, domain not indexed.
- `NOT_CONFIGURED`: API credentials absent.
- `PROVIDER_FAILURE`: Network timeout, 429 rate limit, or 5xx server error.
- `SKIPPED`: External query skipped due to local authoritative match.

### Provider Result Enum:
- `MALICIOUS`
- `CLEAN`
- `POPULAR_BENIGN_CONTEXT`
- `NO_MATCH`
- `null`

### Investigation Classification Enum:
- `KNOWN_MALICIOUS`: Authoritative malicious evidence.
- `KNOWN_CLEAN`: Explicit authoritative clean evidence from verified provider.
- `POPULAR_BENIGN_CONTEXT`: Tranco top-1M global domain context.
- `REVIEW_NEEDED`: Insufficient evidence / unindexed domain.
- `UNKNOWN`: No intelligence evidence.

### Provenance Enum:
- `LOCAL`: Resolved from local Tranco SQLite or URLhaus feed.
- `REAL`: Resolved from live external API provider.
- `PERSISTED`: Resolved from PostgreSQL `reputation_domains` active reputation.
- `COMPUTED`: Correlation Engine weighted score.
- `NO_DATA`: Provider queried; no threat record.

### Freshness Enum:
- `LIVE_LOOKUP`: Queried synchronously in real-time.
- `ACTIVE_REPUTATION`: Active record in PostgreSQL reputation table.
- `HISTORICAL`: Expired / historical record.
- `NOT_APPLICABLE`: Local static feed (Tranco/URLhaus) or unconfigured provider.

---

## 3. API Contract

### Endpoint:
```http
GET /api/v1/investigation/domain/{domain}
```

### Parameters:
- `domain` (*path*, required): Arbitrary domain string (case-insensitive, trailing dots stripped).
- `force_external` (*query*, optional, default `false`): Force external provider query even if local match is authoritative.

### Response Structure:
```json
{
  "status": "success",
  "data": {
    "domain": {
      "queried": "string",
      "normalized": "string",
      "fqdn": "string",
      "registered_domain": "string",
      "tld": "string",
      "subdomain": "string"
    },
    "classification": {
      "status": "KNOWN_MALICIOUS | POPULAR_BENIGN_CONTEXT | KNOWN_CLEAN | REVIEW_NEEDED | UNKNOWN",
      "label": "malicious | benign | clean | suspicious | unknown",
      "risk_score": 0.0,
      "confidence": 0.0,
      "reason": "string",
      "source": "string",
      "scope": "string"
    },
    "local_intelligence": {
      "tranco": {
        "provider": "Tranco",
        "matched": true,
        "status": "AVAILABLE | NO_DATA",
        "result": "POPULAR_BENIGN_CONTEXT | null",
        "provenance": "LOCAL",
        "freshness": "NOT_APPLICABLE"
      },
      "urlhaus": {
        "provider": "URLhaus",
        "matched": false,
        "status": "AVAILABLE | NO_DATA | SUPPRESSED_ROOT_ARTIFACT",
        "result": "MALICIOUS | null",
        "provenance": "LOCAL",
        "freshness": "NOT_APPLICABLE"
      }
    },
    "external_intelligence": {
      "status": "AVAILABLE | NO_DATA | NOT_CONFIGURED | PROVIDER_FAILURE | SKIPPED",
      "provenance": "PERSISTED | REAL | LOCAL | null",
      "freshness": "ACTIVE_REPUTATION | LIVE_LOOKUP | NOT_APPLICABLE",
      "virustotal": {
        "provider": "VirusTotal",
        "status": "AVAILABLE | NO_DATA | NOT_CONFIGURED | PROVIDER_FAILURE | SKIPPED",
        "result": "MALICIOUS | CLEAN | null",
        "malicious_count": 0,
        "harmless_count": 0,
        "suspicious_count": 0,
        "provenance": "PERSISTED | REAL | LOCAL | null",
        "freshness": "ACTIVE_REPUTATION | LIVE_LOOKUP | NOT_APPLICABLE",
        "confidence": 0.0,
        "observed_at": "ISO8601 | null",
        "reason": "string"
      },
      "otx": {
        "provider": "AlienVault OTX",
        "status": "AVAILABLE | NO_DATA | NOT_CONFIGURED | PROVIDER_FAILURE | SKIPPED",
        "result": "MALICIOUS | CLEAN | null",
        "malicious_count": 0,
        "harmless_count": 0,
        "suspicious_count": 0,
        "provenance": "PERSISTED | REAL | LOCAL | null",
        "freshness": "ACTIVE_REPUTATION | LIVE_LOOKUP | NOT_APPLICABLE",
        "confidence": 0.0,
        "observed_at": "ISO8601 | null",
        "reason": "string"
      }
    },
    "correlation": {
      "engine": "Threat Correlation Engine",
      "score": 0.0,
      "threshold": 0.60,
      "confidence": 0.0,
      "verdict": "malicious | benign",
      "provenance": "COMPUTED"
    },
    "dns_activity": {
      "status": "OBSERVED | NOT_OBSERVED",
      "query_count": 0,
      "unique_clients": 0,
      "malicious_count": 0,
      "suspicious_count": 0,
      "clean_count": 0,
      "first_seen": "ISO8601 | null",
      "last_seen": "ISO8601 | null",
      "query_types": {},
      "response_codes": {}
    },
    "reputation": {
      "active_record": false,
      "status": "string | null",
      "source": "string | null",
      "confidence": 0.0,
      "match_scope": "string | null",
      "matched_domain": "string | null",
      "first_seen": "ISO8601 | null",
      "last_seen": "ISO8601 | null"
    },
    "querying_clients": [
      {
        "client_ip": "string",
        "query_count": 0,
        "last_seen": "ISO8601 | null"
      }
    ],
    "investigation": {
      "known": true,
      "why": "string",
      "evidence": []
    },
    "duration_ms": 0.0
  }
}
```

---

## 4. UI Investigation Sections

The `DomainDetailPage.tsx` component provides 7 synchronized sections:
1. **Domain Header**: FQDN, registered apex, TLD, status pill, risk score gauge (0-100), confidence, primary source.
2. **Verdict / Summary Banner**: Clear forensic reason explaining why the system classified the domain this way.
3. **Threat Intelligence Grid**: Cards for Tranco, URLhaus, VirusTotal, AlienVault OTX, and Correlation Scorer with explicit Provenance and Freshness badges.
4. **DNS Protocol Telemetry**: Query volume, query type distribution (`A`, `AAAA`, `MX`, `TXT`, `NS`), response code breakdown (`NOERROR`, `NXDOMAIN`, `SERVFAIL`), and timestamps.
5. **Querying Clients Table**: Internal client IPs that queried this domain, query counts, last seen, with direct link to Client Investigation.
6. **Active Reputation & Persistence**: Table status, evidence match scope, confidence.
7. **Interactive Quick Search Bar**: Immediate re-search for other domains.
