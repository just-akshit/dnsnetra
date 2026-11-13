# Backend packages

Python packages live under `backend/src/dnsnetra/`.

```text
dnsnetra/
  core/                configuration, paths, security, audit, logging
  domains/             business domains and repositories
  intelligence/        labeling, scoring, enrichment, reputation, trusted/malicious intel
  ingestion/           batch and live pipelines
  parsing/             BIND and DNS parsers
  feature_extraction/  feature extractors and enrichment
  aggregation/         PostgreSQL aggregation engine
  time_engine/         time range and bucket resolution
  persistence/         schema, migrations, repositories
```

Run code with `backend/src` on `PYTHONPATH` or through one of the entrypoints in `apps/api` / `scripts/`, which add it automatically. Packaging metadata and pytest configuration live in the root `pyproject.toml`.
