# Mission: Understand reports, cases (tickets), and the audit trail

## Why
I'm working in the DNSNetra codebase and want to understand the *concepts* behind the reporting-and-cases design — what each artifact is for, why some are immutable and others mutable, and how accountability is preserved — before I implement, review, or use any of it.

## Success looks like
- Explain the difference between a report, a case (ticket), and an audit record without looking at the spec
- Walk a case through its six states and say who is allowed to move it at each step
- Explain why a report snapshot is frozen while a case keeps changing
- Read the design spec and map each table and route to the concept it serves
- Spot when a proposed feature blurs the line between evidence, work, and accountability

## Constraints
- Concept-first; no implementation or deployment work in these lessons
- Short sessions, one tightly-scoped lesson at a time
- Ground every claim in the local spec or a high-trust external source
- The user prefers to learn the "why" before the "how"

## Out of scope
- Frontend styling and component implementation
- Notifications, Slack/Jira sync, SLA timers, scheduled reports
- Database migration mechanics and API coding details
