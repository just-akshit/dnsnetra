# Monorepo migration record

## Scope

The repository was reorganized into an `apps/` + `backend/` + `infrastructure/` + `data/` + `docs/` monorepo without changing API routes, database schemas, aggregation behavior, environment variable names, or test coverage. Runtime code was moved and imports were rewritten mechanically.

Backup of the pre-change tree: `/private/var/folders/98/mngfqhbx1rd0nwgb97wt9_300000gn/T/dnsnetra-pre-restructure/`.

## Migration table

| Previous location | Current location |
| --- | --- |
| `api/main.py`, `api/routes/`, `api/schemas/`, `api/cli.py` | `apps/api/` |
| `api/{audit,auth,auth_config,captcha,csrf,login_throttle,rate_limiter,rbac,sessions,trusted_proxy,user_admin_policy}.py` | `backend/src/dnsnetra/core/security/` |
| `api/auth_config.py` | `backend/src/dnsnetra/core/config/auth.py` |
| `aggregator/` | `backend/src/dnsnetra/aggregation/` |
| `cases/` | `backend/src/dnsnetra/domains/cases/` |
| `client_profiling/` | `backend/src/dnsnetra/domains/clients/` |
| `domain_profiling/` | `backend/src/dnsnetra/domains/domain_profiles/` |
| `investigation/` | `backend/src/dnsnetra/domains/investigations/` |
| `reporting/` | `backend/src/dnsnetra/domains/reporting/` |
| `unknown_domain_repository/unknown_domain_repository/` | `backend/src/dnsnetra/domains/unknown_domains/` |
| `unknown_domain_repository/tests/` | `tests/unit/unknown_domains/` |
| `unknown_domain_repository/docs/` | `docs/reference/unknown_domains/` |
| `labeler/pipeline.py`, `labeler/label_dataset.py`, `labeler/heuristics.py`, `labeler/config.py`, `labeler/utils.py`, `labeler/threat_intelligence.py` | `backend/src/dnsnetra/intelligence/labeling/` |
| `labeler/logger.py` | `backend/src/dnsnetra/core/logging/labeller.py` |
| `labeler/intel/cache/` | `backend/src/dnsnetra/intelligence/enrichment/cache/` |
| `labeler/intel/correlation/` | `backend/src/dnsnetra/intelligence/scoring/` |
| `labeler/intel/daily_review/` | `backend/src/dnsnetra/intelligence/labeling/daily_review/` |
| `labeler/intel/providers/` | `backend/src/dnsnetra/intelligence/providers/` |
| `labeler/intel/reputation/` | `backend/src/dnsnetra/intelligence/reputation/` |
| `labeler/intel/malicious/` | `backend/src/dnsnetra/intelligence/malicious/` |
| `labeler/intel/{database,downloader,lock,manager,updater}.py` | `backend/src/dnsnetra/intelligence/trusted/` |
| `labeler/intel/{threat_intelligence,unknown_domain_processor}.py` | `backend/src/dnsnetra/intelligence/enrichment/` |
| `bind converter/`, `parsing logs/`, `parsing/` | `backend/src/dnsnetra/parsing/` |
| `feature extraction/` | `backend/src/dnsnetra/feature_extraction/` |
| `database/schema.sql` | `backend/src/dnsnetra/persistence/models/schema.sql` |
| `database/migrations/` | `backend/src/dnsnetra/persistence/migrations/` |
| `database/migrate.py` | `backend/src/dnsnetra/persistence/migrations/runner.py` |
| `domain_persistence.py` | `backend/src/dnsnetra/persistence/repositories/domain_persistence.py` |
| `time_engine/` | `backend/src/dnsnetra/time_engine/` |
| `frontend/` | `apps/web/` |
| `deploy/` | `infrastructure/deployment/` |
| `fluent-bit.conf`, `parsers.conf` | `infrastructure/fluent-bit/` |
| root `scripts/*.py`, `start_all.sh` | `scripts/{audit,data,development,maintenance}/` |
| root `tests/test_*.py`, `tests/auth_testkit.py` | `tests/{unit,integration,fixtures}/` |
| root `docs/*` | `docs/{architecture,reference,development}/` |
| root `CONTEXT.md`, `DESIGN.md`, `PRODUCT.md` | `docs/architecture/`, `docs/reference/product.md` |
| `dns/` | `legacy/dns-snapshot/` (frozen, not imported) |
| `data/malicious_domains.db`, `labeler/data/*` | `data/intelligence/`, `data/intelligence/archive/labeler-data/` |
| `live_dataset.csv`, `live_features.csv` | `data/datasets/` |
| `logs/*.log` | `data/logs/` |
| `parsing logs/logs/query*.log`, `parsing logs/invalid_logs.csv` | `data/samples/` |
| `pytest.ini` | `pyproject.toml` (`[tool.pytest.ini_options]`) |

## Import and configuration updates

- All Python imports now use `dnsnetra.*` and `apps.api.*`.
- Relative imports were repaired after file moves; `compileall` passes for `backend/src`, `apps/api`, `tests`, and `scripts`.
- `pyproject.toml` provides the package metadata, `pythonpath = ["backend/src"]`, and pytest configuration.
- `backend/src/dnsnetra/core/config/paths.py` is the single source for `REPO_ROOT`, `DATA_DIR`, `DATASETS_DIR`, `INTELLIGENCE_DIR`, `SAMPLES_DIR`, and `LOGS_DIR`. `DNSNETRA_ROOT` overrides the root.
- `backend/src/dnsnetra/core/config/env.py` centralizes `.env` and `api.env` loading.
- Malicious database lock now resolves to `data/intelligence/malicious.lock`.
- Hardcoded database-password fallbacks were removed from client profiling, domain profiling, and the historical dataset generator; they now read the configured environment values.
- `uvicorn` target is `apps.api.main:app`; admin CLI is `python -m apps.api.cli`.
- Fluent Bit uses `${DNSNETRA_ROOT}` for parser and sample-log paths.
- Systemd API unit sets `DNSNETRA_ROOT`, `PYTHONPATH`, and the new entrypoint; web unit runs from `apps/web`.
- Deployment docs and commands point at `infrastructure/deployment/`, `apps/web/`, and `python -m dnsnetra.persistence.migrations.runner`.
- Runtime and generated data paths were routed through the canonical constants.

## Files intentionally left at the repository root

`README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `pyproject.toml`, `requirements.txt`, `.env.example`, `api.env.example`, `.gitignore`, `.gitattributes`, `.mcp.json`, `.env` (ignored), `api.env` (ignored).

`.env` and `api.env` remain local secrets and are ignored.

## Validation results

Initial restructure run on 2026-11-13:

```text
$ .venv/bin/python -m compileall -q backend/src apps/api tests scripts
COMPILE_OK

$ import smoke test (189 dnsnetra.* and apps.* modules)
imported 189 modules; failures=0
```

Follow-up remediation run on 2026-11-13 (database restored, suites repaired):

```text
$ .venv/bin/pytest -q
676 passed, 113 skipped, 2 warnings in 134.43s

$ .venv/bin/pytest --run-legacy-udr tests/unit/unknown_domains -q
113 passed in 1.60s

$ .venv/bin/python scripts/audit/reconciliation_check.py
ALL RECONCILIATION CHECKS PASSED WITH 100% MATHEMATICAL EXACTNESS!

$ cd apps/web && pnpm test
Test Files 21 passed (21) | Tests 140 passed (140)

$ cd apps/web && npx tsc --noEmit
exit 0

$ cd apps/web && pnpm lint
0 errors, 3 warnings

$ cd apps/web && pnpm build
Compiled successfully; 20/20 static pages; TypeScript passed; exit 0

$ DNSNETRA_ROOT="$PWD" fluent-bit --dry-run -c infrastructure/fluent-bit/fluent-bit.conf
configuration test is successful

$ bash -n scripts/development/start_all.sh
$ bash -n infrastructure/deployment/gen-internal-cert.sh
$ bash -n infrastructure/deployment/ufw-dnsnetra.sh
all exit 0

$ git diff --check
exit 0
```

Data preservation check: 11 source data files compared against the pre-change backup by SHA-256; 0 missing, 0 different.

## Known results and remaining risks

1. **The dev database was restored to the canonical fixture.** It now holds exactly 30,181 rows (Benign 23,371 / Malicious 4,626 / Review Needed 448 / Unknown 1,736) across 49 domains and 12 clients, with rollups reconciled. A pre-reset backup was taken first:
   `/private/var/folders/98/mngfqhbx1rd0nwgb97wt9_300000gn/T/dnsnetra-db-backup/dnsnetra-20261113-163340.dump`.
   Regenerate at any time with `scripts/data/generate_historical_dataset.py`.
2. **The unknown-domain suite is reconciled and green.** It stays opt-in via `--run-legacy-udr` for speed, not because of failures.
3. **`pnpm lint` reports 0 errors and 3 warnings.** The warnings are `@next/next/no-location-assign-relative-destination` in `features/clients/client-columns.tsx`, `features/domains/domain-columns.tsx`, and `lib/data-table/api-client.ts`. They are full-page navigations (including the 401 redirect); changing them to `router.push` is a behavior decision, not a lint fix.
4. **`nginx -t` and `systemd-analyze verify` were not run** because nginx and systemd are not installed on the development host. Unit files and nginx files were reviewed; shell and Fluent Bit configs were executed.
5. **Working tree is uncommitted.** The move is a large rename/addition set. Stage and review before committing.

## Remediation log (2026-11-13)

Bugs found while clearing the reported failures, with the root cause that turned
out correct:

| Symptom | Root cause | Fix |
| --- | --- | --- |
| 13 integration tests failed on exact counts | Dev DB drifted to 64,000 rows with no `Unknown` verdict | Backed up, then regenerated the canonical 30,181-row fixture; rollups rebuilt |
| `test_dashboard_all_time_and_known_window` expected `timeseries is None` | Commit `a3daac7` intentionally made all-time dashboards render a bounded AUTO timeline; the test was never updated | Assert the bounded timeline instead of `None` (test + reconciliation script) |
| `test_18_clients_pagination` failed on the last page | Test asserted `has_more == (total > offset)`, which is only valid when the final page is full | Assert `has_more == total > offset + limit` |
| `UnknownDomainService` could not be constructed standalone | `__init__` called `get_logger()` with no config, though it already held one | Pass `config.logging` to `get_logger()` |
| `UnknownDomainRepository(None)` "raised" only by accident | No `None` guard; the error came from the logger | Added an explicit guard |
| 38 unknown-domain suite failures | Logger not initialised in tests; stale patch targets (`get_connection`, class-level `_pool`); removed APIs (`create_default_service`, `PipelineIntegration`, `batch_upsert`, `to_database_values`); env-polluted default assertions | Reconciled tests to the shipped contract; suite now 113 passed |
| 31 frontend lint errors | 25 `no-explicit-any` in test files; 6 `react-hooks/set-state-in-effect` on fetch-on-mount and theme/table hydration | Real types instead of `any`; derived loading keys, `useSyncExternalStore` for the system theme, lazy localStorage initialiser for column visibility |

## Next steps

1. Run `nginx -t` and `systemd-analyze verify` on the target host before deployment.
2. Decide whether to promote `tests/unit/unknown_domains` into the default suite, now that it is green and runs in under two seconds.
3. Revisit the three navigation warnings if client-side routing is preferred over full page loads.
4. Commit the restructure as a rename-focused commit, then a separate commit for path/import fixes if review prefers.
