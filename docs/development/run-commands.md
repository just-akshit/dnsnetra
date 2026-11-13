# Run Commands

All commands run from the repository root unless noted. Export the Python path once:

```bash
export PYTHONPATH="$PWD/backend/src:$PWD"
```

## Batch pipeline

Normalize a BIND log, extract features, label, and persist to PostgreSQL:

```bash
.venv/bin/python scripts/development/run_pipeline.py \
  --input data/samples/logs/query.log \
  --dataset data/datasets/normalized_dns_dataset.csv \
  --output data/datasets/feature_matrix.csv
```

Add `--recursive` when `--input` is a directory.

## Live pipeline

Read BIND logs and/or Kafka (`dns-logs`) and emit live features:

```bash
.venv/bin/python scripts/development/run_live_pipeline.py \
  --dataset data/datasets/live_dataset.csv \
  --output data/datasets/live_features.csv
```

The module entrypoint is also available:

```bash
.venv/bin/python -m dnsnetra.ingestion.pipelines.live \
  --dataset data/datasets/live_dataset.csv \
  --output data/datasets/live_features.csv \
  --kafka-topic dns-logs \
  --kafka-bootstrap localhost:9092
```

## Aggregation

```bash
# one-shot
.venv/bin/python scripts/development/run_aggregation.py --incremental

# continuous (what start_all.sh runs in the background)
.venv/bin/python scripts/development/run_aggregation.py --loop 60
```

## Database migrations

```bash
.venv/bin/python -m dnsnetra.persistence.migrations.runner
```

## API and dashboard

```bash
.venv/bin/python -m uvicorn apps.api.main:app --reload --port 8000

cd apps/web
pnpm dev
```

The entrypoint is `apps.api.main:app`. The pre-restructure `api.main:app` no
longer exists and fails with `ModuleNotFoundError: No module named 'api'`.

Two traps worth knowing:

- **A failed `--reload` run keeps the port.** When the import fails, the reloader
  parent can survive and hold `:8000`, so the next start dies with
  `[Errno 48] Address already in use`. Clear it with
  `pkill -f "uvicorn api.main"` (or `lsof -t -iTCP:8000 | xargs kill`).
- **Do not write `--reload` output inside the repository.** The watcher covers
  the whole checkout, so a log file in `data/logs/` retriggers reloads. Redirect
  to `/tmp` or narrow it with `--reload-dir backend/src --reload-dir apps/api`.

`scripts/development/start_all.sh` runs the API without `--reload` and logs to
`data/logs/fastapi.log`, which is why that path is safe there.

Admin CLI:

```bash
.venv/bin/python -m apps.api.cli create-admin
```

## Full local stack

```bash
./scripts/development/start_all.sh
```

Services: ZooKeeper/Kafka on `localhost:9092`, Fluent Bit, live pipeline, aggregator (60s loop), FastAPI on `:8000`, Next.js on `:3000`.

Each step verifies the process is actually alive — a dead service prints ❌ and the
script exits non-zero instead of claiming success.

## Tests and validation

```bash
.venv/bin/python -m compileall -q backend/src apps/api tests scripts
.venv/bin/pytest
.venv/bin/pytest --run-legacy-udr tests/unit/unknown_domains

cd apps/web
pnpm test
pnpm build
```

## Maintenance

```bash
# Dry run, then rotate a local admin password
.venv/bin/python scripts/maintenance/rotate_admin_password.py --username admin
.venv/bin/python scripts/maintenance/rotate_admin_password.py --username admin --execute

# Bootstrap the first SUPER_ADMIN
.venv/bin/python scripts/development/create_super_admin.py --username superadmin
.venv/bin/python scripts/development/create_super_admin.py --username superadmin --execute
```
