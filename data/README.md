# Data

This directory holds the datasets, local intelligence databases, sample logs, and runtime logs used by DNSNetra. Paths are centralized in `backend/src/dnsnetra/core/config/paths.py`; code must use those constants rather than constructing relative paths.

## Layout

```text
data/
  datasets/
    live_dataset.csv              normalized live query dataset
    live_features.csv             extracted feature output for the live pipeline
    feature_matrix.csv            batch feature matrix
    normalized_dns_dataset.csv    normalized batch dataset
    labelled_dns_dataset.csv      labelled batch dataset
    invalid_logs.csv              parser rejects
  intelligence/
    malicious_domains.db          URLhaus-derived malicious-domain SQLite database
    trusted_domains.db            Tranco-derived trusted-domain SQLite database
    malicious.lock                malicious database update lock
    archive/labeler-data/         archived copy of the legacy labeler data directory
  samples/
    logs/query.log                small BIND log fixture for local runs
    logs/query1.log               additional BIND log fixture
    logs/query.log.bak            preserved backup of the sample log
    invalid_logs.csv              sample parser rejects
    report.json                   sample reporting payload
  logs/
    dns_labeller.log              preserved labeller log
    nextjs.log                    preserved dashboard log
    pipeline.log                  preserved pipeline log
```

## Conventions

- **Datasets are inputs or generated outputs.** Do not edit them by hand unless the task is specifically a data repair; prefer regenerating them with `scripts/data/` or the ingestion pipeline.
- **Intelligence databases are runtime state.** The update processes replace them atomically. `*-wal` and `*-shm` files are SQLite sidecars and are ignored by git.
- **Sample data is a fixture.** Keep `data/samples/` small and deterministic so tests and local demos remain fast.
- **Runtime logs are not source.** New `data/logs/*.log` files are ignored. The three preserved historical logs are explicitly un-ignored in `.gitignore`.
- **Backups before destructive changes.** If a migration or repair rewrites a dataset or database, keep a copy outside git (or in `data/intelligence/archive/` when it is genuinely historical data).

## Environment overrides

- `DNSNETRA_ROOT` changes the detected repository root.
- `INTEL_DB_BASE_DIR` overrides the malicious-domain SQLite directory.
- `TRUSTED_DOMAINS_DB` overrides the trusted-domain database path.

Keep these variable names stable; deployment configuration depends on them.

## Git policy

Datasets and intelligence databases are tracked because they are part of the local product fixture. Runtime WAL/SHM files, new log files, and credentials are not. Never add secrets or provider API keys to this directory.
