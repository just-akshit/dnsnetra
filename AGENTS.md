# AGENTS.md

Guidance for coding agents working in the DNSNetra monorepo.

## Source of truth

- Python backend packages: `backend/src/dnsnetra/`.
- FastAPI application surface: `apps/api/`.
- Next.js dashboard: `apps/web/`.
- SQL schema and migrations: `backend/src/dnsnetra/persistence/`.
- Canonical filesystem paths: `backend/src/dnsnetra/core/config/paths.py`.
- Historical pre-monorepo snapshot: `legacy/dns-snapshot/`. Do not import from it, edit it, or use it as a source for new code.

## Commands

Run from the repository root unless noted.

```bash
export PYTHONPATH="$PWD/backend/src:$PWD"

.venv/bin/python -m compileall -q backend/src apps/api tests scripts
.venv/bin/pytest
.venv/bin/pytest --run-legacy-udr tests/unit/unknown_domains   # opt-in subsystem suite

cd apps/web
pnpm test
pnpm build
pnpm lint
```

Apply migrations with:

```bash
.venv/bin/python -m dnsnetra.persistence.migrations.runner
```

Start the local stack with:

```bash
./scripts/development/start_all.sh
```

## Placement rules

- Business logic belongs in `backend/src/dnsnetra/<area>/`, not in `apps/api`.
- HTTP routing, request schemas, and the FastAPI app live in `apps/api/`.
- Security and auth primitives live in `backend/src/dnsnetra/core/security/`.
- Domain modules live under `dnsnetra.domains`; their implementation modules keep their existing file names.
- Shared path constants belong in `core/config/paths.py`. Do not hardcode `data/`, `logs/`, or `frontend/` paths in new code.
- Environment loading goes through `core/config/env.py` unless a process has a documented reason to load only one file.
- SQL migrations are append-only. Add a new numbered file; never rewrite an applied migration.
- Deployment assets belong in `infrastructure/`; operational helpers in `scripts/`.

## Environment and secrets

- `.env` is the canonical local configuration file; `api.env` holds provider keys.
- Never commit `.env`, `api.env`, credentials, tokens, or real database passwords.
- Keep existing environment variable names stable (`UDR_DB_*`, `DB_*`, `AUTH_*`, `VT_API_KEYS`, `OTX_API_KEYS`).
- There is one canonical virtualenv at `.venv/`.

## Testing expectations

- Run the smallest relevant test first, then the full backend suite before claiming completion.
- Real results only: report the command and its actual output. Do not describe tests as passing unless they were run.
- The default suite excludes `tests/unit/unknown_domains` for speed; it is opt-in via `--run-legacy-udr` and is expected to stay green.
- Integration tests use the live PostgreSQL database configured in `.env`. Do not point them at production.
- Dashboard tests use Vitest; production readiness also requires `pnpm build`.

## Change discipline

- Preserve public API routes, database schemas, aggregation semantics, and environment variable names unless the task explicitly changes them.
- Prefer targeted edits over broad rewrites. Keep import updates mechanical and reviewable.
- Add tests for behavior changes. Keep existing tests unless they are demonstrably obsolete; if a suite is stale, mark it opt-in and document why rather than deleting it silently.
- Do not delete or rewrite data files without a backup and explicit instruction.
- Do not modify `legacy/dns-snapshot/`.
