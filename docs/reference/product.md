# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

SOC analysts and administrators on an internal corporate network.

- **Analysts** triage domains, client IPs, and query events; work the daily-review queue; and need to reach a defensible verdict quickly, including for indicators the network has never seen.
- **Administrators** manage users and roles, review audit logs, and own the self-hosted deployment.
- Access is role-gated (`SUPER_ADMIN`, `ADMIN`, `ANALYST`, `SUPPORT`); support users get read-only operational views.

## Product Purpose

DNSNetra ingests DNS telemetry, profiles the clients and domains seen on the network, and labels query activity as malicious, suspicious, clean, or unknown. It exists so an internal team can understand what a domain or client did on their network and whether it is dangerous, without stitching together separate DNS logs and threat-intel consoles. Success means an analyst can answer "what is this indicator, and should I act?" in one place, with local telemetry and external reputation side by side.

## Positioning

On-prem DNS telemetry plus live external threat intelligence in one entity dossier.

Local query history, client/domain profiles, review state, and labels are the authoritative record. Live VirusTotal, AlienVault OTX, DNS, and RDAP lookups fill the gap for never-seen indicators without persisting external verdicts. A neighboring DNS tool can copy either half, but not the combination of authoritative internal behavior and on-demand external reputation in the same investigation surface.

## Operating Context

- Self-hosted on Ubuntu 24.04 behind nginx, with systemd-managed API and web services.
- PostgreSQL is the authoritative store for raw query history, profiles, labels, reviews, users, sessions, and audit logs.
- Deployed on a single host with a single API worker; no cloud dependency. External intelligence is optional via a kill switch.
- Analysts use a web dashboard with dark and light themes during incident triage, review, and reporting.
- Reports and entity dossiers are read in the browser; exports and audit trails support later review.

## Capabilities and Constraints

- Ingest DNS query telemetry and maintain domain and client profiles with four-state verdict counters.
- Investigate a domain or client IP as a 360-degree dossier: local profile, querying clients or top destinations, recent events, persisted threat-intel context, and live external intelligence.
- Search the dashboard globally across domains, clients, and query events; open a full dossier for any valid domain or IP, even with no recorded telemetry.
- Live intelligence combines VirusTotal and AlienVault OTX with DNS resolution and RDAP registration data. External verdicts are composed per request and are never written into local reputation tables.
- Maintain a daily-review queue for domains needing human judgment, and keep an audit trail of privileged actions.
- Local threat-intel data includes a Tranco-derived trusted-domain database (`data/intelligence/trusted_domains.db`) and a URLhaus-based malicious-domain pipeline.
- Single-node, single-worker deployment today. Scaling beyond one worker requires a shared cache and rate-limit store.
- Terminology: "observed in network" distinguishes local telemetry from live external-only results; verdict states are `malicious`, `suspicious`, `clean`, `unknown`.

## Brand Commitments

- Product name is **DNSNetra**; the browser title is "DNSNetra — DNS Threat Detection" and the description is "Real-time DNS threat detection and network intelligence platform."
- The existing dashboard identity, typography (Geist / Geist Mono / DM Sans), and dark/light theming are incumbent and should be preserved in refinements.
- No logo or formal brand guideline asset is present in the repository.

## Evidence on Hand

- Working ingestion, profiling, labeling, reporting, review, auth, and audit code paths, with PostgreSQL schemas and migrations under `backend/src/dnsnetra/persistence/`.
- Domain, client, daily-review, queries, reports, settings, and auth surfaces under `apps/web/app/(dashboard)/` and `apps/web/app/(auth)/`.
- Real local Tranco database at `data/intelligence/trusted_domains.db` (82 MB) and the URLhaus ingestion pipeline under `backend/src/dnsnetra/intelligence/malicious/`.
- Test suites exercising API seams, investigation dossiers, live verdicts, and the search bar.
- No customer testimonials, case studies, benchmarks, pricing, or public customer names exist; future work must not invent them.

## Product Principles

1. Local telemetry is the source of truth; external intelligence annotates, it does not overwrite.
2. One indicator, one dossier: the answer should not require switching tools.
3. Never-seen indicators still deserve a verdict path; absence of local data is not absence of signal.
4. Show provenance. Analysts must be able to tell local observation, provider evidence, and inference apart.
5. Degrade honestly. A provider outage or partial result is surfaced, never rendered as "clean" or as zero results.
