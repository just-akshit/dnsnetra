# Reporting, Cases & Audit Resources

## Knowledge

- [Design spec: Reporting, Exports, and Cases (local)](docs/superpowers/specs/2026-11-10-reporting-and-cases-design.md)
  Primary source for DNSNetra. Use for: table schemas, report/review states, case state machine, permissions, exports, audit actions.
- [NIST SP 800-61 Rev. 3 — Incident Response Recommendations and Considerations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
  Current NIST guidance, published April 2025 and framed around CSF 2.0. Use for: the incident-response lifecycle and why tracking/documentation exists, not for DNSNetra-specific design.
- [TheHive: About Cases](https://docs.strangebee.com/thehive/user-guides/analyst-corner/cases/about-cases/)
  Open-source SIRP documentation. Use for: a real-world model of cases, tasks, observables, linked elements, and closing cases.
- [TheHive: About Audit Logs](https://docs.strangebee.com/thehive/user-guides/organization/about-audit-logs/)
  Use for: key use cases and structure of an audit trail in a case-management tool.
- [TheHive: About Case Timelines](https://docs.strangebee.com/thehive/user-guides/analyst-corner/cases/case-timelines/about-case-timelines/)
  Use for: why case history is kept as a timeline of events rather than overwritten fields.

## Wisdom (Communities)

- [r/blueteamsec](https://reddit.com/r/blueteamsec)
  Practitioner-oriented security subreddit. Use for: how SOC/IR teams actually structure cases and reports.
- [TheHive community / StrangeBee discussions](https://github.com/StrangeBeeCorp)
  Use for: concrete questions about case workflow design in an open-source SIRP.

## Gaps

- No single canonical source on the exact "immutable report vs mutable case" split; the local spec is the authority for this design.
- Need a good, citable source on audit-log design (append-only, tamper-evidence) if a future lesson goes deeper.
