# Scripts

Operational and development entrypoints. Run from the repository root with the canonical `.venv`.

```text
scripts/
  audit/          API completeness, reconciliation, benchmark, and production checks
  data/           dataset generation and label repair
  development/    local pipelines, demos, admin bootstrap, full-stack launcher
  maintenance/    password rotation, test-user purge, data wipe
  migration/      one-off migration helpers
```

Common commands:

```bash
.venv/bin/python scripts/development/run_pipeline.py --help
.venv/bin/python scripts/development/run_live_pipeline.py --help
.venv/bin/python scripts/development/run_aggregation.py
./scripts/development/start_all.sh
```

Each Python entrypoint adds `backend/src` to `sys.path` itself so it can be run directly from a source checkout. Prefer running from the repository root.
