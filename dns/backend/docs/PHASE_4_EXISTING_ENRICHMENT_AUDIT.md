# Phase 4 — Existing Enrichment Audit
**DNS Threat Detection System**
**Audit Date:** 2026-08-23

---

## Executive Summary

Before implementing the Phase 4 Domain & Client Enrichment layer, a forensic audit of the entire codebase was conducted across backend models, pipeline components, databases, routes, and frontend pages. 

The audit evaluated:
1. Where DNS query events currently contain resolved IP information.
2. Whether A/AAAA answers are already stored.
3. Whether DNS resolver functionality already exists.
4. Whether GeoIP libraries/databases already exist.
5. Whether ASN information already exists.
6. Whether WHOIS/RDAP functionality already exists.
7. Whether any enrichment functionality already exists elsewhere.
8. Which frontend components can be extended rather than duplicated.

---

## Forensic Findings Matrix

| Dimension | Existing Source / Location | Existing Data / Capability | Current Status in Live Investigation API | Missing Capability for Phase 4 | Recommended Minimal Implementation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. DNS Query Events & Resolved IP** | `domain_query_history` (PostgreSQL), `domain_profiles`, `dashboard.db` | Contains `(domain, client_ip, query_type, timestamp, response_code, registered_domain, tld, final_label, ti_source)`. `dashboard.db` `domain_details` has placeholder `resolved_ips` column (currently NULL). | No DNS answer RRsets or resolved IPs are recorded in telemetry tables. | Telemetry records only record query metadata, not live resolution infrastructure. | Perform lightweight live DNS resolution on-demand during domain investigation. |
| **2. A / AAAA Answers Storage** | Telemetry databases (`domain_query_history`, `dashboard.db`) | Only query type counts (`query_a_count`, `query_aaaa_count`) and JSON distributions (`{"A": 10}`). | Not stored in any read model. | No historical passive DNS or resolved IP lists exist. | Resolve live A and AAAA records on-demand with explicit availability semantics (`AVAILABLE`, `NO_DATA`, `PROVIDER_FAILURE`). |
| **3. DNS Resolver Functionality** | `backend/feature extraction/enrichment/dns_lookup.py` | Uses `dnspython` (`dns.resolver.Resolver`) with 2.0s timeout to resolve A, AAAA, CNAME, and check MX presence for offline CSV batches. | Not integrated with Phase 3/4 Investigation API. Missing NS resolution, MX record extraction, and canonical evidence model (`AVAILABLE`, `NO_DATA`, `PROVIDER_FAILURE`, `REAL`, `LIVE_LOOKUP`). | Missing structured record answers (A, AAAA, CNAME, NS, MX) with independent failure isolation. | Build a clean, decoupled `DNSResolverEnricher` conforming to Phase 4 contract with bounded timeouts (e.g. 2.0s) and structured outputs. |
| **4. GeoIP Libraries & Databases** | `backend/feature extraction/enrichment/geoip_lookup.py`, `backend/requirements.txt` | `geoip2>=5.0.0` and `maxminddb>=3.1.1` installed. `GeoLite2-ASN.mmdb` (12MB) present in `backend/feature extraction/enrichment/databases/`. `GeoLite2-City.mmdb` is NOT on disk. | GeoIP is disabled in aggregation pipeline (`enable_geoip=False`). | No local City MMDB file exists; missing provider abstraction for live GeoIP lookup. | Implement `IPEnrichmentProvider` abstraction supporting local MaxMind City DB if configured, with HTTP provider fallback (e.g. standard GeoIP API / RDAP) and explicit timeouts. |
| **5. ASN Information** | `backend/feature extraction/enrichment/asn_lookup.py`, `GeoLite2-ASN.mmdb` | `GeoLite2-ASN.mmdb` is active on disk. `ASNLookup` queries `geoip2.database.Reader` and falls back to `ipwhois.IPWhois`. | Not integrated into Phase 3 Investigation API. | Missing normalized ASN schema (`asn`, `asn_organization`, `isp`, `organization`, `connection_type`) linked to resolved IPs. | Integrate local `GeoLite2-ASN.mmdb` and provider abstraction into IP enrichment with <5ms local latency. |
| **6. WHOIS / RDAP Functionality** | `backend/feature extraction/enrichment/whois_lookup.py`, `backend/requirements.txt` | `python-whois>=0.9.6` and `ipwhois>=1.3.0` installed. `WhoisLookup` performs regex-based legacy WHOIS parsing for batch extraction. | Not integrated into Investigation API. Missing RDAP bootstrap, registrar ID parsing, domain status codes, and honest redaction semantics. | Legacy WHOIS scraping is brittle, lacks structured RDAP JSON, lacks registrar ID, and lacks domain status. | Implement clean `RDAPEnricher` querying authoritative RDAP endpoints (via `rdap.org` / IANA bootstrap) with ISO8601 date parsing, registrar name/ID, status array, and nameserver array. |
| **7. Cross-Cutting Enrichment Architecture** | `backend/feature extraction/enrichment/enrichment_manager.py` | `EnrichmentManager` exists for offline batch CSV transformation with `ThreadPoolExecutor`. | Completely disconnected from FastAPI `investigation.py` routes. | Missing per-request async/isolated execution, timeout boundaries, provenance tracking, and partial availability semantics. | Create modular `backend/enrichment/` package containing decoupled enrichers: `dns.py`, `ip.py`, `rdap.py`, and orchestrator `manager.py`. |
| **8. Frontend Extensibility** | `DomainDetailPage.tsx`, `ClientDetailPage.tsx`, `frontend/src/types/api.ts` | Complete Phase 3 investigation UI with KPI summary, Evidence Matrix, DNS telemetry breakdown, querying clients list, and active reputation card. | Phase 3 UI displays threat intelligence and DNS telemetry, but has no infrastructure, GeoIP, or registration cards. | Frontend needs infrastructure intelligence cards without replacing or modifying frozen Phase 3 sections. | Extend `DomainDetailPage.tsx` with "Infrastructure Intelligence", "Resolved IP Infrastructure", and "Registration Intelligence" sections. Extend `ClientDetailPage.tsx` with client IP network/geo card. |

---

## Detailed Gap Analysis

### 1. DNS Resolution
- **Current State:** `dnspython` is installed and functioning. The legacy `DNSLookup` class was tailored for Pandas DataFrames and CSV feature engineering.
- **Required State:** A lightweight, thread-safe, or async-safe DNS enricher that resolves:
  - `A` records (IPv4 list)
  - `AAAA` records (IPv6 list)
  - `CNAME` records (canonical target alias)
  - `NS` records (authoritative nameservers)
  - `MX` records (mail exchange servers with priority)
- **Failure Model:** NXDOMAIN or NoAnswer -> `NO_DATA`; DNS timeout/server failure -> `PROVIDER_FAILURE`.

### 2. Multi-IP Architecture & Geolocation / Network Enrichment
- **Current State:** The legacy system assumed 1 IP per record in CSVs.
- **Required State:** Support 1-to-many domain-to-IP resolutions (`resolved_ips: [...]`). Each resolved IP is enriched individually with:
  - `geo`: `country`, `country_code`, `region`, `city`, `latitude`, `longitude`, `timezone`
  - `network`: `asn`, `asn_organization`, `isp`, `organization`, `connection_type`
- **Private IP Isolation:** Client IPs in RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) must NOT be queried against external GeoIP providers; they are marked `network_type = PRIVATE` and `status = NOT_APPLICABLE`.

### 3. Domain Registration (RDAP)
- **Current State:** `python-whois` was used for legacy text scraping.
- **Required State:** Modern RDAP over HTTPS query with standard JSON parsing:
  - `registrar` (e.g. "MarkMonitor Inc.")
  - `registrar_id` (e.g. "292")
  - `created_at` (ISO8601 string)
  - `updated_at` (ISO8601 string)
  - `expires_at` (ISO8601 string)
  - `domain_status` (array of EPP status strings, e.g. `["clientTransferProhibited", "clientDeleteProhibited"]`)
  - `nameservers` (array of FQDNs)
- **Honesty Guarantee:** Redacted fields remain `null`; missing domains return `NO_DATA`; timeouts return `PROVIDER_FAILURE`.

---

## Architectural Recommendations

1. **Decoupled Package Structure:**
   Create a clean, dedicated `backend/enrichment/` package:
   - `backend/enrichment/__init__.py`
   - `backend/enrichment/models.py` (Pydantic / dataclass response models)
   - `backend/enrichment/dns.py` (DNS resolver for A, AAAA, CNAME, NS, MX)
   - `backend/enrichment/ip.py` (IP Geolocation & ASN resolver with local MMDB + provider fallback + RFC1918 guard)
   - `backend/enrichment/rdap.py` (RDAP client with ISO8601 parsing & redaction handling)
   - `backend/enrichment/manager.py` (Parallel orchestrator with independent timeouts and partial failure aggregation)

2. **Integration without Breaking Phase 2.7 or Phase 3:**
   - In `backend/api/routes/investigation.py`, call the enrichment orchestrator in `investigate_domain()` and attach `"enrichment"` to the existing JSON response.
   - In `investigate_client()`, call the IP enricher for public client IPs and attach `"enrichment"` to the client response.
   - Preserve all existing fields, classification logic, threat ratios, and evidence taxonomy.

3. **Frontend Presentation:**
   - Extend `frontend/src/types/api.ts` with type definitions for `EnrichmentData`.
   - Update `DomainDetailPage.tsx` and `ClientDetailPage.tsx` to render rich, responsive visual cards for Infrastructure, Resolved IPs, and Domain Registration, with status badges for `AVAILABLE`, `NO_DATA`, `PROVIDER_FAILURE`, and `NOT_APPLICABLE`.
