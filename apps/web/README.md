# DNSNetra Web

Next.js 16 dashboard for DNSNetra. The app talks to the FastAPI service under `apps/api/`.

## Development

```bash
pnpm install
pnpm dev
```

The dashboard runs at `http://localhost:3000`. Set `NEXT_PUBLIC_API_URL` in `.env.local` if the API is not at `http://localhost:8000`.

## Checks

```bash
pnpm test
pnpm build
pnpm lint
```

## Structure

- `app/` — App Router routes: auth, dashboard, clients, domains, queries, reports, cases, daily review, users.
- `components/` — shared UI, auth, data-table, intelligence, and time-range components.
- `features/` — table and detail definitions grouped by product area.
- `lib/` — API clients, formatters, permissions, URL state, and search helpers.
- `tests/` — Vitest suites.

The `@/*` alias resolves to this directory. Do not hardcode API or deployment hostnames; use `NEXT_PUBLIC_API_URL` at build time.
