# Contributing

## Development setup

1. Create the canonical environment:

   ```bash
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   cp .env.example .env
   cp api.env.example api.env
   ```

2. Install the dashboard dependencies:

   ```bash
   cd apps/web
   pnpm install
   ```

3. Apply database migrations:

   ```bash
   PYTHONPATH=backend/src .venv/bin/python -m dnsnetra.persistence.migrations.runner
   ```

## Workflow

1. Branch from the current integration branch. Use a descriptive branch name.
2. Keep changes scoped. Do not mix refactors, schema changes, and behavior changes without a reason.
3. Update imports and configuration paths through the canonical modules; avoid new `sys.path` manipulation outside process entrypoints.
4. Add or update tests for every behavior change.
5. Run the relevant checks before opening a pull request.

```bash
PYTHONPATH=backend/src .venv/bin/python -m compileall -q backend/src apps/api tests scripts
.venv/bin/pytest
cd apps/web && pnpm test && pnpm build
```

## Backend conventions

- Python 3.11+ syntax, `from __future__ import annotations`, and type hints on public functions.
- Keep HTTP concerns in `apps/api/` and business logic in `backend/src/dnsnetra/`.
- Use `dnsnetra.core.config.paths` for repository and data locations.
- Import through `dnsnetra.*` and `apps.api.*`; do not import from the repository root or `legacy/`.
- Add SQL migrations as new numbered files in `backend/src/dnsnetra/persistence/migrations/`. Never edit an applied migration.
- Do not add hardcoded credentials or fallback passwords.

## Frontend conventions

- Next.js App Router under `apps/web/app/`, shared UI under `apps/web/components/`.
- Keep the existing Tailwind v4 setup and `@/*` path alias.
- Tests live in `apps/web/tests/` and run with Vitest.
- Run `pnpm build` when changing routing, server components, or Next.js configuration.

## Data

- `data/datasets/` contains curated and generated CSV data.
- `data/intelligence/` contains SQLite intelligence databases.
- `data/samples/` contains small fixtures for local runs.
- Do not commit runtime logs, SQLite WAL/SHM files, or provider credentials.
- Preserve existing data files when moving code. If a data path changes, update `core/config/paths.py` and all callers together.

## Documentation

- Current architecture and deployment docs are under `docs/`.
- Historical plans and audit reports keep their original paths as a record; do not rewrite them unless the task is explicitly a documentation migration.
- Update `docs/deployment/production.md` when deployment paths or service entrypoints change.
