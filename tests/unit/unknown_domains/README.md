# Unknown-domain repository suite

This suite came from the standalone `unknown_domain_repository` package and now
runs against `dnsnetra.domains.unknown_domains`.

It is kept opt-in so the default backend run stays fast and free of
subsystem-specific setup:

```bash
.venv/bin/pytest --run-legacy-udr tests/unit/unknown_domains
```

Current result: **113 passed**.

## Reconciliation notes

The suite was previously failing against the current service contract. The
following were fixed to match the shipped implementation:

- `conftest.py` initialises the subsystem's global logger for every test.
  `UnknownDomainRepository` and `DatabaseManager` call `get_logger()` and fail
  fast unless a logger exists, mirroring the production factory path.
- Config default tests clear the relevant `UDR_*` environment variables, since
  the autouse fixture intentionally populates them.
- Serialization tests use `Config.to_dict()`, which is the API that actually
  exists (`DatabaseConfig` has no `to_dict`).
- Repository/database tests patch the real seams (`db_manager.transaction()`,
  `db_manager.get_connection()`) and set instance attributes instead of patching
  `_pool` / `_initialized` on the class.
- Service tests construct the service with a mocked database manager and assert
  the current API (`create_service`, `_process_domains_batch`, context manager).
- Model tests reflect the documented validation contract: bare reserved names
  (`localhost`, `local`) are rejected, while valid private/internal FQDNs are
  preserved (see `docs/architecture/context.md` §4).

Keep the suite green. Do not delete the files to silence failures; fix the
contract or update the tests deliberately.
