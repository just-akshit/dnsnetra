# PHASE 4.1.1 — PRODUCTION HARDENING & PERFORMANCE SPECIFICATION
## DNS Threat Detection System
### Correlation Semantics & End-to-End Investigation Deadline Enforcement

---

## 1. Executive Summary

Phase 4.1.1 represents a forensic production-hardening pass over the DNS Threat Detection System's investigation and enrichment layers. It fundamentally resolves two core architectural risks:
1. **Semantic Ambiguity in Threat Correlation:** Decoupled `CorrelationEngine` evaluation from VirusTotal clean thresholds. On zero-signal / unindexed domains, the system reports `correlation.verdict = "INCONCLUSIVE"` rather than asserting a false `BENIGN` claim on negative evidence. The global classification layer independently determines `KNOWN_CLEAN` when multi-engine clean consensus exists.
2. **Pathological Tail Latencies & Provider Isolation:** Implemented a unified monotonic deadline model (`INVESTIGATION_DEADLINE_SECONDS = 5.0`), parallelized DNS record resolution across RR types (`A`, `AAAA`, `CNAME`, `NS`, `MX`), and parallelized live external threat queries (`VirusTotal`, `AlienVault OTX`). Replaced per-request thread pools with a managed executor, cutting unindexed domain investigation latency from **~17.5s down to < 2.8s** (an **84% latency reduction**).

---

## 2. Invariant & Contract Matrix

| ID | Hardened Guarantee | Enforcement Mechanism |
|---|---|---|
| **INV-H01** | **No False Clean on Zero Signal** | Zero threat detections produce `correlation.verdict = "INCONCLUSIVE"` and `classification.status = "REVIEW_NEEDED"`. |
| **INV-H02** | **Decoupled Consensus** | `CorrelationEngine` only computes malicious threat weights. Clean consensus (`harmless >= 5`, 0 mal/susp) is evaluated at the classification layer. |
| **INV-H03** | **Active Persisted Isolation** | Persisted reputation matches report `correlation.status = "NOT_EVALUATED"` with `verdict = null` and `score = null`. |
| **INV-H04** | **Local Ground Truth Isolation** | Local Tranco / URLhaus root artifact matches report `correlation.status = "NOT_APPLICABLE"` with `verdict = null`. |
| **INV-H05** | **Monotonic Deadline Propagation** | Outer `deadline = time.monotonic() + 5.0` is passed down to all TI providers and enrichment sub-engines, bounding sub-request socket timeouts. |
| **INV-H06** | **DNS Parallel Record Resolution** | `A`, `AAAA`, `CNAME`, `NS`, and `MX` records are queried concurrently with bounded query timeouts $\le 0.8$s. |
| **INV-H07** | **TI Parallel Execution** | VirusTotal and AlienVault OTX live lookups run concurrently with budget bounded by $\min(3.0, \text{remaining})$. |
| **INV-H08** | **Concurrency Invariant** | Multiple slow providers delayed simultaneously (e.g. 5 $\times$ 5.0s) do not stack sequentially ($5 \times 5.0\text{s} \neq 25\text{s}$); request strictly terminates at $\approx 5.0\text{s}$. |
| **INV-H09** | **Partial Result Resilience** | Provider failures and deadline timeouts return partial telemetry without throwing HTTP 500 exceptions. |
| **INV-H10** | **Non-Blocking Thread Management** | Managed `ThreadPoolExecutor(max_workers=16)` prevents context manager join deadlocks and background worker leakage. |

---

## 3. Architecture & Deadline Budgeting

```text
                     INVESTIGATION REQUEST
                               │
                    GLOBAL DEADLINE (5.0s)
                               │
            ┌──────────────────┴──────────────────┐
            │                                     │
   THREAT INTELLIGENCE (Max 3.0s)        ENRICHMENT (Max 3.5s)
            │                                     │
      ┌─────┴─────┐                         ┌─────┼─────┐
      │           │                         │     │     │
     VT          OTX                       DNS   RDAP  IP
  (Parallel)  (Parallel)               (Parallel)
      │           │                         │     │     │
      └─────┬─────┘                         └─────┼─────┘
            │                                     │
            └──────────────────┬──────────────────┘
                               │
                               ▼
                   PARTIAL RESULT COMPOSITION
```

### Monotonic Budget Allocation
- **DNS Resolver:** Query timeout $\le \min(0.8\text{s}, \max(0.1\text{s}, \text{remaining}))$. All RR types executed concurrently.
- **RDAP Registry:** HTTP timeout $\le \min(2.0\text{s}, \max(0.1\text{s}, \text{remaining}))$.
- **IPinfo Geolocation:** HTTP timeout $\le \min(2.0\text{s}, \max(0.1\text{s}, \text{remaining}))$.
- **VirusTotal / OTX:** API request timeout $\le \min(3.0\text{s}, \max(0.1\text{s}, \text{remaining}))$.

---

## 4. Verification & Golden Benchmarks

### Pytest Verification
- **Total Backend Tests:** 139 passed, 0 failed (100% green).
- **Threat Intelligence Reference Matrix:** 100% green.
- **Frontend Build:** Succeeded with zero type errors.

### Real Endpoint Latency & Verdict Audit

| Domain | Historical Latency | Hardened Latency | Classification | Correlation Verdict | Status |
|---|---|---|---|---|---|
| `google.com` | ~1.4s | **1.36s** | `POPULAR_BENIGN_CONTEXT` | `null` (`NOT_APPLICABLE`) | PASS |
| `secure-update.net` | ~300ms | **243ms** | `KNOWN_MALICIOUS` | `null` (`NOT_EVALUATED`) | PASS |
| `imccj.gobgem.com` | ~300ms | **255ms** | `KNOWN_MALICIOUS` | `null` (`NOT_APPLICABLE`) | PASS |
| `completely-unindexed-random-domain.biz` | ~17,500ms | **2,783ms** | `REVIEW_NEEDED` | `"INCONCLUSIVE"` | PASS |

---

## 5. Artifact Compatibility

- **Backend:** Fully backward-compatible with Phase 2.7, Phase 3, and Phase 4 API contracts.
- **Frontend:** `DomainDetailPage.tsx` and TypeScript models in `api.ts` accurately render `INCONCLUSIVE`, `NOT_EVALUATED`, and `NOT_APPLICABLE` states.
