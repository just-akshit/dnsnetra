# Applications

- `api/` — FastAPI service. Entrypoint: `apps.api.main:app`.
- `web/` — Next.js dashboard. Entrypoint: `pnpm dev` or `pnpm start` from `apps/web`.

Run both from the repository root during local development:

```bash
PYTHONPATH=backend/src .venv/bin/uvicorn apps.api.main:app --reload
cd apps/web && pnpm dev
```

Deployment assets and service units are under `infrastructure/deployment/`.
