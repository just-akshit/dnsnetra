# DNSNetra Documentation

## Start here

- `../README.md` — repository layout, setup, local run, and test commands.
- `../AGENTS.md` — working conventions and placement rules.
- `../CONTRIBUTING.md` — development workflow.
- `deployment/production.md` — current production deployment procedure.
- `development/run-commands.md` — current local pipeline and test commands.

## Architecture

- `architecture/context.md` — domain glossary, entity model, verdict invariants, and time contract.
- `architecture/authentication.md` — hardened authentication and authorization design.
- `architecture/design.md` — system design notes.
- `architecture/super-admin-and-hardening.md` — SUPER_ADMIN rollout, live intelligence, and hardening history.
- `architecture/phase0-verification.md` — phase 0 verification record.
- `architecture/monorepo-migration.md` — migration table, validation results, and remaining risks.

## Development

- `development/notes.md` — implementation notes.
- `development/auth-hardening-week1.md` — current auth-hardening companion.
- `development/run-commands.md` — runnable commands for the current monorepo layout.
- `development/plans/` — historical executable implementation plans.
- `development/specs/` — frozen design specs.

## Reference

- `reference/mission.md`, `reference/product.md`, `reference/resources.md` — product context.
- `reference/parsing.md`, `reference/feature-extraction.md` — pipeline reference.
- `reference/unknown_domains/` — unknown-domain subsystem reference.
- `reference/auth-security-audit.md` — historical security audit.
- `reference/full-audit-report.md` — historical full-repository audit.
- `reference/dnsnetra_audit_and_blueprint.html`, `reference/dnsnetra_audit_dashboard.html` — historical audit dashboards.

## Historical documents

Documents under `development/plans/`, `development/specs/`, and the audit reports above were written before the monorepo migration. They intentionally retain the paths that were valid at the time (`frontend/`, `api/`, `database/`, `deploy/`, `labeler/intel/`). Use the mapping below when reading them:

| Historical path | Current path |
| --- | --- |
| `frontend/` | `apps/web/` |
| `api/` | `apps/api/` for routes/app; `backend/src/dnsnetra/core/security/` for auth/security |
| `aggregator/` | `backend/src/dnsnetra/aggregation/` |
| `cases/` | `backend/src/dnsnetra/domains/cases/` |
| `client_profiling/` | `backend/src/dnsnetra/domains/clients/` |
| `domain_profiling/` | `backend/src/dnsnetra/domains/domain_profiles/` |
| `investigation/` | `backend/src/dnsnetra/domains/investigations/` |
| `reporting/` | `backend/src/dnsnetra/domains/reporting/` |
| `unknown_domain_repository/` | `backend/src/dnsnetra/domains/unknown_domains/` |
| `labeler/intel/` | `backend/src/dnsnetra/intelligence/` |
| `bind converter/`, `parsing logs/` | `backend/src/dnsnetra/parsing/` |
| `feature extraction/` | `backend/src/dnsnetra/feature_extraction/` |
| `database/migrate.py` | `python -m dnsnetra.persistence.migrations.runner` |
| `database/migrations/` | `backend/src/dnsnetra/persistence/migrations/` |
| `deploy/` | `infrastructure/deployment/` |
| `fluent-bit.conf`, `parsers.conf` | `infrastructure/fluent-bit/` |
| `run_pipeline.py`, `run_live_pipeline.py` | `scripts/development/` |
| `tests/test_*.py` | `tests/unit/` or `tests/integration/` |
| `labeler/intel/trusted_domains.db` | `data/intelligence/trusted_domains.db` |
| `data/malicious_domains.db` | `data/intelligence/malicious_domains.db` |
