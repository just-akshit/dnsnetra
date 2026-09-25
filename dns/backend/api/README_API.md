# DNS Threat Detection — Dashboard API

REST API serving pre-computed dashboard metrics from the DNS threat detection pipeline.

## Architecture

```
BIND Log → Pipeline (run_pipeline.py) → dashboard.db (SQLite)
                                              ↓
                                    FastAPI (api/main.py) → JSON Endpoints
```

The pipeline's final stage runs `DashboardAggregator.run_all()` which reads from:
- `parsing logs/labelled_dns_dataset.csv` (row-level DNS query data)
- `feature extraction/data/feature_matrix.csv` (per-domain feature vectors)
- PostgreSQL (`client_profiles`, `client_history`) — falls back to CSV if unavailable

…and writes pre-computed summaries into `dashboard.db`. The API reads **only** from `dashboard.db`.

---

## Quick Start

### 1. Run the Pipeline (generates `dashboard.db`)

```bash
python3 run_pipeline.py \
  --input "parsing logs/logs/query.log" \
  --dataset "parsing logs/normalized_dns_dataset.csv" \
  --output "feature extraction/data/feature_matrix.csv"
```

### 2. Start the API Server

```bash
uvicorn api.main:app --reload --port 8000
```

### 3. Open Swagger Docs

Navigate to [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## Endpoints

All endpoints are prefixed with `/api/v1`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/api/v1/summary` | Pipeline metrics snapshot |
| `GET` | `/api/v1/threats/timeseries` | Hourly query & threat timeseries |
| `GET` | `/api/v1/threats/categories` | Threat breakdown by category |
| `GET` | `/api/v1/threats/geo` | Geo distribution (empty if GeoIP disabled) |
| `GET` | `/api/v1/domains/top` | Top queried domains |
| `GET` | `/api/v1/domains/recent` | Recently flagged domains |
| `GET` | `/api/v1/clients/top` | Top client IPs |

---

## Example Responses

### `GET /health`
```json
{
  "status": "ok",
  "service": "dns-threat-dashboard-api"
}
```

### `GET /api/v1/summary`
```json
{
  "data": {
    "total_queries": 332,
    "total_threats": 198,
    "threats_blocked_pct": 59.64,
    "unique_clients": 42,
    "unique_domains": 280,
    "last_pipeline_run_at": "2026-08-06T13:30:00+00:00"
  }
}
```

### `GET /api/v1/threats/timeseries`
```json
{
  "data": [
    {
      "time_bucket": "2026-07-19 06:00",
      "total_queries": 145,
      "threat_queries": 87
    },
    {
      "time_bucket": "2026-07-19 07:00",
      "total_queries": 187,
      "threat_queries": 111
    }
  ]
}
```

### `GET /api/v1/threats/categories`
```json
{
  "data": [
    {
      "category": "Known Malicious Domain (URLhaus)",
      "count": 120,
      "pct": 36.14
    },
    {
      "category": "Trusted Tranco Domain",
      "count": 95,
      "pct": 28.61
    }
  ]
}
```

### `GET /api/v1/threats/geo`
```json
{
  "geoip_enabled": false,
  "data": []
}
```

> **Note:** GeoIP enrichment is currently disabled (`enable_geoip=False` in `run_pipeline.py`). Enable it to populate geo data.

### `GET /api/v1/domains/top`
```json
{
  "data": [
    {
      "domain": "example-malicious.com",
      "query_count": 15,
      "label": "Malicious",
      "threat_score": 100.0,
      "last_seen": "2026-07-19T07:45:12.000Z"
    }
  ]
}
```

### `GET /api/v1/domains/recent`
```json
{
  "data": [
    {
      "domain": "suspicious-domain.xyz",
      "label": "Malicious",
      "label_reason": "Known Malicious Domain (URLhaus)",
      "ti_source": "malicious",
      "confidence": 98.0,
      "flagged_at": "2026-07-19T07:45:12.000Z"
    }
  ]
}
```

### `GET /api/v1/clients/top`
```json
{
  "data": [
    {
      "client_ip": "192.168.9.157",
      "query_count": 25,
      "malicious_query_count": 12,
      "last_seen": "2026-07-19T07:45:12.000Z"
    }
  ]
}
```

---

## Configuration

The API reads `dashboard.db` from the project root by default. Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DASHBOARD_DB_PATH` | `./dashboard.db` | Path to the SQLite dashboard database |
| `DB_HOST` | `localhost` | PostgreSQL host (used by aggregator) |
| `DB_PORT` | `5432` | PostgreSQL port |
| `DB_NAME` | `dns_threat_detection` | PostgreSQL database name |
| `DB_USER` | `postgres` | PostgreSQL user |
| `DB_PASSWORD` | `postgres` | PostgreSQL password |

---

## CORS

CORS is currently set to allow all origins (`*`) for development. **Restrict this in production** by updating `api/main.py`.
