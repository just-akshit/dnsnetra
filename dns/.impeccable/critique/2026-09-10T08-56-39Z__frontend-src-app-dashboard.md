---
target: frontend/src/app/(dashboard)
total_score: 19
max_score: 40
na_heuristics: 
p0_count: 1
p1_count: 2
target_identity: "file:/Users/akshit/Developer/dns/frontend/src/app/(dashboard)"
timestamp: 2026-09-10T08-56-39Z
slug: frontend-src-app-dashboard
---
# Design Health Score

| # | Heuristic | Score | Key Issue |
|---|-----------|-------|-----------|
| 1 | Visibility of System Status | 2 | Hardcoded fallback telemetry (`|| 14280`) masks zero-state; desynchronized time pickers |
| 2 | Match System / Real World | 3 | Solid DNS terminology, but confusing routing hierarchy ("Command Hub" vs "Overview") |
| 3 | User Control and Freedom | 2 | `select-none` blocks analysts from copying IOCs/IPs/domains; empty drawer navigation trap |
| 4 | Consistency and Standards | 1 | 400px dual-rail sidebar with 1 link per pane; Recharts vs Visx chart split; hardcoded hex codes |
| 5 | Error Prevention | 2 | Search inputs lack FQDN/CIDR validation syntax; unconstrained input ranges |
| 6 | Recognition Rather Than Recall | 2 | Severe text truncation on KPI cards (`Total Que...`, `Threat R... 100....`) and table cells |
| 7 | Flexibility and Efficiency | 2 | No inline pivot actions (e.g. "Pivot to WHOIS", "Block Domain"); missing keyboard shortcuts |
| 8 | Aesthetic and Minimalist Design | 2 | Huge empty side panel wastes 340px; dot-matrix chart clutter; generic SaaS styling lacking SOC authority |
| 9 | Error Recovery | 2 | Raw API error strings leaked to UI; no actionable troubleshooting steps on failure |
| 10 | Help and Documentation | 1 | Zero contextual tooltips for DGA confidence, entropy scoring, or threat classification tiers |
| **Total** | | **19/40** | **Poor (Major UX overhaul required)** |

---

# Design Specificity Verdict

**LLM assessment**:
The application currently suffers from **structural sameness and category-generic execution**. Rather than feeling like a purpose-built, mission-critical Security Operations Center (SOC) and DNS threat intelligence system (such as CrowdStrike Falcon, Cloudflare Radar, or Cisco Umbrella), it presents like an assembled generic SaaS dashboard kit.
Key specificity failures:
1. **The Dual Sidebar Trap**: A 64px icon rail paired with a 340px expandable drawer creates a massive 400px navigation bar where entire sections (Overview, Reports, Analytics) contain only *one single navigation link*, leaving 85% of the drawer completely vacant while suffocating tables and charts.
2. **Text Clipping & Density Mismatch**: Critical security metrics are truncated into illegibility (`Total Que...`, `100....`, `live-report-verification-te...`). Analysts cannot perform rapid visual triage when numbers and FQDNs are clipped.
3. **Impeded Forensics (`select-none`)**: Core pages apply `select-none`, actively blocking incident responders from highlighting, double-clicking, and copying domains or IPs into terminal tools or ticketing systems.
4. **Fragmented Visual Language**: Recharts in `AnalyticsPage`, Visx in `OverviewPage`, custom SVG bars in `DNSAnalyticsPage`, and raw un-tokenized hex colors (`#2F6FED`, `#121826`) in `ReportsPage` create an inconsistent visual experience.

**Deterministic scan**:
Automated scan (`impeccable detect`) executed across `frontend/src`:
- **1 warning finding**: `bounce-easing` (`animate-bounce`) detected at `frontend/src/views/ReportsPage.tsx:590` on the CSV export download icon. Bouncy physics feel amateurish in a mission-critical cybersecurity tool.

**Visual overlays**:
Browser subagent encountered Playwright driver installation issues (fallback signal recorded). Visual inspection completed via committed high-resolution desktop visual regression goldens (`reports_page.png`, `client_detail_desktop.png`, `tables_section.png`, `client_detail_bottom.png`), source code AST, and backend database schema inspection.

---

# Overall Impression
The underlying threat detection engine and data pipeline are robust, but the frontend currently feels like an early, generic admin template. The dual-pane navigation wastes critical horizontal space, metric cards truncate essential values, charts lack coherent visual language, and the interface fails to deliver the high-density, authoritative SOC ergonomics needed for fast security triage.

---

# What's Working
1. **Deep Data Infrastructure & Schema**: The backend aggregation schema (`metrics_summary`, `threats_by_category`, `domain_details`, `client_details`, `recent_flagged_domains`) is rich and well-structured, providing a solid foundation for enterprise-grade visualizations.
2. **TanStack Table Implementation on Investigation Pages**: `DomainsPage` and `QueriesPage` feature solid column helpers, selection checkboxes, and preset filters (`All`, `Malicious`, `Review Needed`), proving that high-density data tables can work effectively here.
3. **Global Command Palette**: The ⌘K search dialog (`GlobalSearchDialog`) provides a strong foundation for rapid keyboard-driven navigation across entities and pages.

---

# Priority Issues

### [P0] Wasted Viewport & Fragile Navigation (Dual Rail + Empty Drawer)
- **Why it matters**: The 64px icon rail plus 340px drawer consumes 400px of screen real estate. On 1440px displays, this forces tables and KPI cards into cramped widths where labels and numbers truncate (`Total Que...`, `Threat R... 100....`). Sections like "Reports", "Home", and "Analytics" host only 1 link in a 340px empty drawer.
- **Fix**: Replace the cumbersome dual-pane drawer with a clean, single-rail collapsible sidebar (compact 56px icon rail expanding to 240px with inline sub-items) or a top-tier SOC header with sub-tabs. Free up 200px+ of horizontal space for data density.
- **Suggested command**: `/impeccable layout`

### [P1] Blocked Forensic Operations & Text Selection
- **Why it matters**: `ThreatsPage.tsx` and `AppSidebar.tsx` apply `select-none` to root containers. Security analysts must be able to highlight, double-click, and copy IP addresses, hashes, and domain names without encountering locked selection or clumsy buttons.
- **Fix**: Remove `select-none` across all data views. Add 1-click copy icons with subtle toast confirmation and keyboard shortcuts (e.g. `C` on focused row) for IOC copying.
- **Suggested command**: `/impeccable polish`

### [P1] Phantom / Hardcoded Telemetry Values
- **Why it matters**: `ThreatsPage.tsx` falls back to `summary?.total_threats || 14280`, which displays 14,280 threats even when true threat count is 0. Similarly, `ThreatIntelligencePage.tsx` hardcodes static mock feed cards instead of reading from `threat_intel_feeds` in SQLite. This destroys credibility and operational trust.
- **Fix**: Remove all truthy fallback defaults (`|| 14280` -> `?? 0`). Connect `ThreatIntelligencePage` to real backend API endpoints or explicit zero-state / loading skeletons.
- **Suggested command**: `/impeccable harden`

### [P2] Incoherent Chart Architecture & Noise
- **Why it matters**: The dashboard splits charting across Visx (`DNSQueriesOverTimeChart`), Recharts (`AnalyticsPage`), and custom SVG bars (`DNSDetectionBarChart`). The dot-matrix background on `OverviewPage` creates visual moiré noise rather than clarity. Time range pickers are desynchronized between global header and local preset buttons.
- **Fix**: Standardize on a single, high-performance chart system with unified dark-mode palette, clean subtle gridlines, synchronized crosshair tooltips, and strict connection to the global `TimeRangeContext`.
- **Suggested command**: `/impeccable typeset`

### [P2] Hardcoded Colors and Slop Animations
- **Why it matters**: `ReportsPage.tsx` contains raw hardcoded hex codes (`#2F6FED`, `#121826`, `#EBEBEB`) bypassing Tailwind theme tokens, plus `animate-bounce` on export buttons, giving an unpolished, prototype feel.
- **Fix**: Refactor `ReportsPage.tsx` into modular components using standard design tokens (`bg-primary`, `bg-card`, `border-border`) and replace bouncy keyframes with smooth exponential easing transitions.
- **Suggested command**: `/impeccable distill`

---

# Persona Red Flags

**Alex (Tier-2 SOC Analyst / Power User)**:
- Cannot copy domain names or IPs on `ThreatsPage` due to `select-none`.
- Forced to click through an empty 340px drawer just to reach "Threat Analytics".
- Key telemetry numbers are clipped (`100....`), forcing Alex to open DevTools or drill into individual pages to read actual alert totals.
- Abandons dashboard in favor of CLI or direct database queries within 2 minutes.

**Jordan (First-Time Incident Responder)**:
- Confused by conflicting navigation: "Home" opens `/overview`, but there is an orphaned `/home` "Command Hub".
- No tooltips explaining DGA confidence, entropy thresholds, or why a domain was flagged as malicious versus review-needed.
- Disoriented by different table behaviors and filter placements between `OverviewPage`, `DomainsPage`, and `ReportsPage`.

**Sam (Accessibility & Keyboard-First User)**:
- Dual-rail sidebar traps Tab navigation through invisible buttons and nested containers.
- Color alone is occasionally used to signify verdict state without high-contrast borders or screen-reader announcements.
- Brush timeline slider lacks keyboard ARIA slider attributes (`aria-valuenow`, `aria-valuemin`).

**Riley (Stress Tester)**:
- Empty states or 0-count queries display fallback numbers (`14280`) instead of clean zero-states.
- Resizing browser to 1280px causes metric card titles to truncate to 6 letters.
- Exporting CSV triggers `animate-bounce` rather than a standard indeterminate progress indicator or disabled spinner.

---

# Minor Observations
- Grammar error in `reports_page.png`: "1 events" instead of "1 event".
- Domain details tables lack quick pivot buttons (e.g., "Check VirusTotal", "Pivot to Client IP", "Add to Allowlist").
- The top bar title "DNS THREAT DETECTION" repeats the sidebar workspace name identically, wasting header height.
- `/analytics` route performs a client-side redirect rather than rendering a true unified analytics hub.

---

# Questions to Consider
- What if the navigation collapsed into a sleek, unified 220px SOC navigation rail with immediate one-click access to Alerts, Intelligence, Analytics, and Forensics?
- What would a true production SOC layout look like if density were increased by 30%, prioritizing live query streams, threat severity breakdown, and 1-click pivot investigations?
- Should the Overview page feature real-time streaming telemetry with live incident tickers rather than static wireframe cards?
