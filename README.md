# DNSNetra

DNSNetra is an on-prem DNS threat-detection and investigation platform. It ingests BIND query telemetry, profiles clients and domains, enriches indicators with local and live threat intelligence, and gives analysts a single dossier for deciding whether an indicator is dangerous.

This repository is a monorepo: the FastAPI service, the Next.js dashboard, the Python domain packages, deployment assets, data, and tests live in one tree.

## Repository layout

```text
apps/
  api/                     FastAPI entrypoint, routes, request/response schemas, admin CLI
  web/                     Next.js 16 dashboard (App Router, Tailwind, Vitest)
backend/src/dnsnetra/
  core/                    config, auth, sessions, RBAC, rate limiting, audit, logging
  domains/                 cases, clients, domain profiles, investigations, reporting, unknown domains
  intelligence/            labeling, enrichment, reputation, scoring, trusted/malicious intel
  ingestion/               batch and live Kafka/BIND ingestion pipelines
  parsing/                 BIND and DNS log parsing
  feature_extraction/      lexical, DNS, infra, behavioural, and WHOIS features
  aggregation/             PostgreSQL telemetry aggregation engine
  time_engine/             canonical time-range resolution and bucket generation
  persistence/             schema, SQL migrations, persistence repositories
data/
  datasets/                generated and curated CSV datasets
  intelligence/            SQLite intelligence databases and archive data
  samples/                 sample BIND logs and fixtures
  logs/                    runtime logs (ignored except the preserved historical logs)
docs/                      architecture, deployment, development, reference, learning
infrastructure/            deployment, Fluent Bit, and host integration assets
legacy/dns-snapshot/       frozen pre-monorepo snapshot; never imported by runtime code
scripts/                   audit, data, development, maintenance utilities
tests/                     unit and integration suites
```

`CONTEXT.md`, `DESIGN.md`, and `PRODUCT.md` moved to `docs/architecture/` and `docs/reference/`; their content is preserved.

## Prerequisites

- Python 3.11+ (the checked-in `.venv` uses 3.13)
- PostgreSQL 14+
- Node.js 20+ and pnpm 11+
- Optional: Kafka, ZooKeeper, Fluent Bit, nginx, systemd for the full local stack or production deployment

## Setup

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
cp api.env.example api.env
```

Fill in `UDR_DB_PASSWORD` / `DB_PASSWORD`, `AUTH_SESSION_SECRET`, `AUTH_CAPTCHA_SECRET`, and any optional VirusTotal or AlienVault OTX keys. Never commit `.env`, `api.env`, or real provider keys.

The Python packages are not installed into site-packages by default. Run Python commands with `backend/src` on the path:

```bash
export PYTHONPATH="$PWD/backend/src:$PWD"
```

`pyproject.toml` provides packaging metadata and the pytest configuration (`pythonpath = ["backend/src"]`).

## Run locally

```bash
# Apply PostgreSQL migrations
.venv/bin/python -m dnsnetra.persistence.migrations.runner

# API (http://localhost:8000)
.venv/bin/uvicorn apps.api.main:app --reload

# Dashboard (http://localhost:3000)
cd apps/web
pnpm install
pnpm dev
```

To start the full local stack (Kafka, Fluent Bit, live pipeline, aggregator, API, web):

```bash
./scripts/development/start_all.sh
```

The script verifies each service is actually alive before printing ✅ and starts the
aggregator in a 60-second loop, so rollups stay current without a second terminal.

## Tests

```bash
# Backend
.venv/bin/pytest

# Dashboard
cd apps/web
pnpm test
pnpm build
```

The `tests/unit/unknown_domains` suite is green but opt-in so the default run stays fast:

```bash
.venv/bin/pytest --run-legacy-udr tests/unit/unknown_domains
```

## Data and configuration

All canonical filesystem locations are defined in `backend/src/dnsnetra/core/config/paths.py`:

- `REPO_ROOT`
- `DATA_DIR` → `data/`
- `DATASETS_DIR` → `data/datasets/`
- `INTELLIGENCE_DIR` → `data/intelligence/`
- `SAMPLES_DIR` → `data/samples/`
- `LOGS_DIR` → `data/logs/`

Set `DNSNETRA_ROOT` to override the detected repository root in a deployment. Existing environment variable names (`UDR_DB_*`, `DB_*`, `AUTH_*`, `VT_API_KEYS`, `OTX_API_KEYS`) are unchanged.

See `data/README.md` for dataset and runtime-artifact conventions.

## Deployment

Production instructions live in `docs/deployment/production.md`. Deployment assets are under `infrastructure/deployment/` (nginx, systemd, UFW, TLS helper) and `infrastructure/fluent-bit/`.

The systemd API unit runs `apps.api.main:app`; the web unit runs the Next.js server from `apps/web`.

## Documentation

Start at `docs/README.md`. Historical audit reports and implementation plans retain the paths that were valid when they were written; the current layout is documented here and in `AGENTS.md`.
