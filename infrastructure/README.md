# Infrastructure

Deployment and host-integration assets for DNSNetra.

```text
infrastructure/
  deployment/
    api.env.example           production API environment template
    gen-internal-cert.sh      self-signed internal TLS helper
    nginx/                    reverse-proxy config for API + dashboard
    systemd/                  dnsnetra-api.service and dnsnetra-web.service
    ufw-dnsnetra.sh           host firewall policy
  fluent-bit/
    fluent-bit.conf           tails BIND logs and publishes to Kafka
    parsers.conf              BIND log parser
  kafka/                      Kafka operational notes
  monitoring/                 monitoring integration notes
  postgres/                   PostgreSQL operational notes
```

The production procedure is `docs/deployment/production.md`.

## Root resolution

`fluent-bit.conf` reads `${DNSNETRA_ROOT}` so the same file works in a source checkout and under `/opt/dnsnetra`:

```bash
DNSNETRA_ROOT=/opt/dnsnetra fluent-bit -c /opt/dnsnetra/infrastructure/fluent-bit/fluent-bit.conf
```

The systemd API unit sets `DNSNETRA_ROOT=/opt/dnsnetra` and
`PYTHONPATH=/opt/dnsnetra/backend/src:/opt/dnsnetra` explicitly.

## Service entrypoints

- API: `apps.api.main:app` on `127.0.0.1:8000`
- Web: Next.js from `apps/web` on `127.0.0.1:3000`
- Kafka topic: `dns-logs`
- Fluent Bit input: `${DNSNETRA_ROOT}/data/samples/logs/query.log`
