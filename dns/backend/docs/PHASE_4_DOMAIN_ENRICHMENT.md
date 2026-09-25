# Phase 4 — Domain Enrichment Specification & Evidence Model

## 1. Domain Enrichment Scope

Domain enrichment is attached under `data.enrichment` in `GET /api/v1/investigation/domain/{domain}`. It provides infrastructure, network, geographic, and domain registration context.

```json
{
  "status": "success",
  "data": {
    "domain": { "fqdn": "example.com", ... },
    "classification": { ... },
    "enrichment": {
      "status": "AVAILABLE",
      "dns": {
        "status": "AVAILABLE",
        "a": ["93.184.216.34"],
        "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"],
        "cname": [],
        "ns": ["a.iana-servers.net", "b.iana-servers.net"],
        "mx": [{ "priority": 10, "exchange": "mail.example.com" }],
        "provider": "DNS Resolver",
        "provenance": "REAL",
        "freshness": "LIVE_LOOKUP"
      },
      "ips": [
        {
          "ip": "93.184.216.34",
          "ip_type": "PUBLIC",
          "geo": {
            "status": "AVAILABLE",
            "country": "United States",
            "country_code": "US",
            "region": "California",
            "city": "Los Angeles",
            "latitude": 34.0522,
            "longitude": -118.2437,
            "timezone": "America/Los_Angeles",
            "provider": "IPinfo",
            "provenance": "REAL",
            "freshness": "LIVE_LOOKUP"
          },
          "network": {
            "status": "AVAILABLE",
            "asn": "AS15133",
            "asn_organization": "EDGECAST",
            "isp": "MCI Communications Services, Inc. d/b/a Verizon Business",
            "organization": "AS15133 EDGECAST",
            "provider": "GeoLite2-ASN",
            "provenance": "LOCAL",
            "freshness": "LIVE_LOOKUP"
          }
        }
      ],
      "registration": {
        "status": "AVAILABLE",
        "source": "Authoritative RDAP",
        "registrar": "RESERVED-Internet Assigned Numbers Authority",
        "registrar_id": "376",
        "created_at": "1995-08-14T04:00:00Z",
        "updated_at": "2023-08-14T07:01:38Z",
        "expires_at": "2024-08-13T04:00:00Z",
        "domain_status": ["clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"],
        "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
        "provider": "Authoritative RDAP",
        "provenance": "REAL",
        "freshness": "LIVE_LOOKUP"
      },
      "duration_ms": 142.5
    }
  }
}
```

---

## 2. Component Specifications

### 2.1 Live DNS Infrastructure (`dns`)
- **Resolver Engine:** `dnspython` with a 2.0s per-query timeout.
- **RR Types:**
  - `A`: List of unique IPv4 addresses.
  - `AAAA`: List of unique IPv6 addresses.
  - `CNAME`: List of alias target hostnames.
  - `NS`: List of authoritative nameserver hostnames.
  - `MX`: List of structured objects containing `{ priority: int, exchange: str }`.
- **Status Semantics:**
  - `AVAILABLE`: At least one record type answered. (Absence of optional records like MX or AAAA does not downgrade status to `PARTIAL`).
  - `NO_DATA`: All queries answered with `NXDOMAIN` or `NoAnswer`.
  - `PROVIDER_FAILURE`: Resolver timeout or network error.

### 2.2 Resolved IP Infrastructure (`ips`)
- **Multi-IP Architecture:** Evaluates every unique IPv4 and IPv6 address resolved from A/AAAA records.
- **Deduplication:** Repeated identical IPs across multiple records are deduplicated prior to enrichment.
- **Independent Evidence Records:**
  - **ASN & Network:** Sourced locally from `GeoLite2-ASN.mmdb` (`provider: "GeoLite2-ASN"`, `provenance: "LOCAL"`).
  - **Geography:** Sourced live from `IPinfo` HTTP API (`provider: "IPinfo"`, `provenance: "REAL"`).
  - **Explicit Mapping:** `city`, `region`, `country_name` -> `country`, `country` -> `country_code`, `loc` -> `latitude`/`longitude`, `org` -> `organization`. Unsupported fields remain `null`.

### 2.3 Domain Registration Intelligence (`registration`)
- **Discovery Mechanism:** In-process caching of IANA RDAP TLD bootstrap endpoints (`https://data.iana.org/rdap/dns.json`).
- **Authoritative Resolution:** Queries the authoritative RDAP server directly (or falls back to `rdap.org`).
- **Fields Extracted:** Registrar name, IANA Registrar ID, ISO 8601 creation/update/expiration timestamps, registry EPP status codes, authoritative nameservers.
- **Redaction Handling:** Missing or redacted registrant/contact fields are stored as `null` and displayed honestly as "Redacted / Not Disclosed" without fabricating values.
