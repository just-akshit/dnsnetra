# Backend tests

- `unit/` — fast unit tests; the only exception is the frozen `unit/unknown_domains/` suite.
- `integration/` — tests that exercise PostgreSQL, API seams, aggregators, and investigation/reporting flows.
- `fixtures/` — shared auth and database helpers.

Run the default suite from the repository root:

```bash
.venv/bin/pytest
```

The `tests/unit/unknown_domains/` suite is a preserved contract suite from the older
standalone `unknown_domain_repository` package. Its expectations no longer match the
current `dnsnetra.domains.unknown_domains` implementation and it is skipped by default.
Run it explicitly when working on that reconciliation:

```bash
.venv/bin/pytest --run-legacy-udr tests/unit/unknown_domains
```
