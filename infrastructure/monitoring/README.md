# Monitoring

No monitoring stack is checked into this directory. Operational monitoring uses the host's existing tooling around:

- `systemctl status dnsnetra-api dnsnetra-web nginx`
- `journalctl -u dnsnetra-api`
- `data/logs/` for pipeline and dashboard process logs
- The API health/status endpoints exposed by `apps/api/routes/status.py`

Keep dashboards and alert rules in the deployment environment's monitoring system rather than coupling them to this repository.
