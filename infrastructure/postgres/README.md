# PostgreSQL

DNSNetra uses PostgreSQL as its authoritative store. Connection settings come from the existing environment variable names:

- `UDR_DB_HOST`, `UDR_DB_PORT`, `UDR_DB_DATABASE`, `UDR_DB_USERNAME`, `UDR_DB_PASSWORD`
- `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`

The canonical database is `dns_threat_detection`. Apply migrations from the repository root:

```bash
PYTHONPATH=backend/src .venv/bin/python -m dnsnetra.persistence.migrations.runner
```

Migrations are append-only files in `backend/src/dnsnetra/persistence/migrations/`, applied in filename order and recorded in `schema_migrations`. The `pg_trgm` extension is required for search indexes; create it once as a database owner or superuser if the application role cannot.
