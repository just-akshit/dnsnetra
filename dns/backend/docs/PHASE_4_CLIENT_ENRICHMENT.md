# Phase 4 — Client Enrichment Specification & Private IP Guard

## 1. Client IP Classification & Private IP Guard

Client enrichment is attached under `data.enrichment` in `GET /api/v1/investigation/client/{client_ip}`.

### IP Classification Hierarchy
Every IP address is strictly classified using Python's `ipaddress` module before any lookup occurs:
1. `PRIVATE` (RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
2. `LOOPBACK` (`127.0.0.0/8`, `::1`)
3. `LINK_LOCAL` (`169.254.0.0/16`, `fe80::/10`)
4. `MULTICAST` (`224.0.0.0/4`, `ff00::/8`)
5. `UNSPECIFIED` (`0.0.0.0`, `::`)
6. `RESERVED` (IETF reserved ranges)
7. `PUBLIC` (Globally routable unicast)

### Private IP Guard Invariant
- If an IP is **non-public** (`PRIVATE`, `LOOPBACK`, `LINK_LOCAL`, etc.):
  - External GeoIP and ASN providers **are NEVER queried**.
  - `geo.status = "NOT_APPLICABLE"` with `provenance: "COMPUTED"`.
  - `network.status = "NOT_APPLICABLE"` with `provenance: "COMPUTED"`.
  - The UI displays a secure "Private / Internal Network Address" badge.
- If an IP is **PUBLIC**:
  - ASN is queried via local `GeoLite2-ASN.mmdb`.
  - Geolocation is queried via `IPinfo` HTTP API.

---

## 2. Client Enrichment Data Contract

```json
{
  "status": "success",
  "data": {
    "client": {
      "ip": "192.168.1.100",
      "network_type": "PRIVATE",
      "first_seen": "2026-08-20T10:00:00",
      "last_seen": "2026-08-23T12:00:00",
      "total_queries": 1500
    },
    "summary": { ... },
    "threat_domains": [ ... ],
    "enrichment": {
      "ip": "192.168.1.100",
      "ip_type": "PRIVATE",
      "status": "NOT_APPLICABLE",
      "geo": {
        "status": "NOT_APPLICABLE",
        "provider": "IPinfo",
        "provenance": "COMPUTED",
        "freshness": "NOT_APPLICABLE"
      },
      "network": {
        "status": "NOT_APPLICABLE",
        "provider": "GeoLite2-ASN",
        "provenance": "COMPUTED",
        "freshness": "NOT_APPLICABLE"
      },
      "duration_ms": 0.12
    }
  }
}
```
