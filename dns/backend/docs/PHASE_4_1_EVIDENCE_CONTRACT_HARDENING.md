# PHASE 4.1 — EVIDENCE CONTRACT & PROVENANCE HARDENING

## Executive Summary

Phase 4.1 performed a forensic hardening of the DNS Threat Detection System's intelligence, correlation, persistence, and classification contracts.

This hardening eliminates:
1. **Correlation Semantic Contradictions:** `score = 0.0, verdict = "benign"` coexisting with `classification = "KNOWN_MALICIOUS"`.
2. **Fabricated Provider Evidence:** Synthesizing `VirusTotal = MALICIOUS` or `OTX = MALICIOUS` from a persisted `Threat Correlation Engine` record.
3. **Absence of Malicious Signal != Clean:** Treating 0 detections or unrated domains as `KNOWN_CLEAN`.
4. **Invalid Confidence & Provenance Propagation:** Non-traceable confidence scores and conflating provenance taxonomies.
5. **Classification Inversion:** Ensuring local malicious matches (both exact and registered-domain) strictly precede Tranco popularity context.

---

## The Three Independent Evidence Planes

```
                          INVESTIGATION TARGET
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         ▼                         ▼                         ▼
   [PLANE 1: EVIDENCE]    [PLANE 2: COMPUTATION]   [PLANE 3: PERSISTENCE]
         │                         │                         │
  • URLhaus (LOCAL)         • WeightedScorer (COMPUTED)• reputation_domains
  • Tranco (LOCAL)          • CorrelationEngine       (PostgreSQL)
  • VirusTotal (REAL)       • Status: EVALUATED /     • Source attribution
  • AlienVault OTX (REAL)     NOT_EVALUATED /           (TCE / VT / OTX)
  • DNS Resolver (REAL)       NOT_APPLICABLE / FAILED • Status: malicious
  • RDAP / GeoIP (REAL)     • Scores: numeric or null • Scope: CORRELATED
```

---

## Canonical Taxonomy Reference

### 1. External Provider Status & Availability
- `AVAILABLE`: Provider lookup completed with actionable data.
- `NO_DATA`: Provider queried successfully but has no record/pulses, OR evidence is not available from a persisted aggregate record.
  - When persisted record does not store individual engine scan results: `availability_reason = "NOT_RECORDED_IN_PERSISTED_REPUTATION"`.
- `NOT_CONFIGURED`: API credentials are not configured in `api.env`.
- `PROVIDER_FAILURE`: Upstream provider returned HTTP 429/5xx, network error, or timeout.
- `SKIPPED`: External query was skipped due to local authoritative ground truth.

### 2. Correlation Engine State
- `EVALUATED`: Computed weighted threat score across live external providers (`score`, `threshold`, `confidence`, `verdict`).
- `NOT_EVALUATED`: Correlation computation was skipped because an authoritative persisted reputation record or unconfigured state exists (`score = null`, `confidence = null`, `verdict = null`, `provenance = null`).
- `NOT_APPLICABLE`: Correlation is not applicable because local ground truth (URLhaus / Tranco) is authoritative (`score = null`, `confidence = null`, `verdict = null`, `provenance = null`).
- `FAILED`: Correlation evaluation failed due to upstream provider errors (`score = null`, `confidence = null`, `verdict = null`, `provenance = "COMPUTED"`).

### 3. Strict Provenance Taxonomy
- `LOCAL`: Local file/in-memory ground truth databases (`URLhaus`, `Tranco`, `System`).
- `REAL`: Real live network API responses (`VirusTotal`, `AlienVault OTX`, `RDAP`, `IPinfo`).
- `PERSISTED`: Historical records stored in PostgreSQL (`reputation_domains`).
- `COMPUTED`: Real-time computations performed by our engines (`Threat Correlation Engine`).
- `null`: When an engine/provider did not execute or produce data.

---

## Exact Classification Precedence Matrix (Phase 2.7 Ground Truth)

1. **Exact Local Malicious Match (`URLhaus EXACT_FQDN`)**
   - Result: `status = KNOWN_MALICIOUS`, `risk_score = 100.0`, `confidence = 1.0`, `source = URLhaus`.
2. **Registered-Domain Local Malicious Match (`URLhaus REGISTERED_DOMAIN`)**
   - Result: `status = KNOWN_MALICIOUS`, `risk_score = 100.0`, `confidence = 1.0`, `source = URLhaus`.
3. **Active Persisted Malicious Reputation (`reputation_domains`)**
   - Result: `status = KNOWN_MALICIOUS`, `risk_score = 100.0`, `confidence = pg_rep.confidence`, `source = pg_rep.source`.
4. **Live Computed Malicious Correlation (`decision.malicious == True`)**
   - Result: `status = KNOWN_MALICIOUS`, `risk_score = score * 100.0`, `confidence = decision.confidence`, `source = Threat Correlation Engine`.
5. **Local Tranco Popularity Context (`POPULAR_BENIGN_CONTEXT`)**
   - Result: `status = POPULAR_BENIGN_CONTEXT`, `risk_score = 0.0`, `confidence = 0.0`, `source = Tranco`.
6. **Live Multi-Engine Clean Consensus (`harmless_count >= 5` & `malicious == 0` & `suspicious == 0`)**
   - Result: `status = KNOWN_CLEAN`, `risk_score = 0.0`, `confidence = clean_conf`, `source = External Threat Intelligence`.
7. **Unknown / Inconclusive (`REVIEW_NEEDED`)**
   - Result: `status = REVIEW_NEEDED`, `label = unknown`, `risk_score = 0.0`, `confidence = 0.0`, `source = NO_DATA`.

---

## Verification Results

- **Unit & Hardened Invariant Suite:** 20/20 PASSED (`backend/tests/test_phase4_1_evidence_hardening.py`)
- **Full Backend Pytest Suite:** 124/124 PASSED (`backend/tests/`)
- **Threat Intelligence Reference Matrix:** 100% GREEN (`backend/scripts/test_threat_intelligence.py --matrix`)
- **Frontend Production Bundle:** Built successfully in 2.02s (`frontend/src/`)
