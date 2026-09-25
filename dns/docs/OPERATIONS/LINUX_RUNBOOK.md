# DNS Threat Detection System — Linux Operations Runbook

> **Target Platform:** Linux (Ubuntu 22.04/24.04 LTS / Debian 12 / RHEL 9)  
> **Environment:** Production / Staging / Office Demonstration  
> **Repository:** `just-akshit/dns-threat-detection-system`  
> **Architecture:** Modern hybrid streaming pipeline (BIND/DNS Logs → Fluent Bit → Kafka → Live Consumer/Labeler → PostgreSQL & SQLite Read Model → FastAPI → React Dashboard)

---

## 1. System Prerequisites

The following system packages, runtimes, and background daemons must be installed on the Linux host before starting the pipeline.

### A. Runtimes & Package Managers

| Software | Minimum Version | Installation Command (Ubuntu/Debian) | Installation Command (RHEL/Rocky) | Verification Command | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Python** | `3.11+` | `sudo apt update && sudo apt install -y python3.11 python3.11-venv python3.11-dev` | `sudo dnf install -y python3.11 python3.11-devel` | `python3.11 --version` | Backend API, pipeline consumers, enrichment, aggregator |
| **Node.js** | `v20+` (v22 LTS rec.) | `curl -fsSL https://deb.nodesource.com/setup_22.x \| sudo -E bash - && sudo apt install -y nodejs` | `curl -fsSL https://rpm.nodesource.com/setup_22.x \| sudo bash - && sudo dnf install -y nodejs` | `node --version` | Frontend React UI build and execution |
| **npm** | `10.x+` | Installed with Node.js | Installed with Node.js | `npm --version` | Frontend dependency management |
| **Git** | `2.34+` | `sudo apt install -y git` | `sudo dnf install -y git` | `git --version` | Repository version control |

### B. Core Infrastructure Daemons

| Service | Minimum Version | Installation Command (Ubuntu/Debian) | Verification Command | Default Port | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **PostgreSQL** | `14+` (16/18 rec.) | `sudo apt install -y postgresql postgresql-contrib` | `psql --version` | `5432` | Primary persistent telemetry store, domain & client profiles |
| **Apache Kafka** | `3.5+` (KRaft or ZK) | Download Apache Kafka binary (see Section 5) | `kafka-topics.sh --version` | `9092` | Real-time DNS log message bus |
| **Fluent Bit** | `3.0+` (v5.1+ rec.) | `curl https://packages.fluentbit.io/fluentbit.key \| gpg --dearmor \| sudo tee /usr/share/keyrings/fluentbit-keyring.gpg && sudo apt install -y fluent-bit` | `fluent-bit --version` | N/A (Agent) | High-throughput DNS log parser and Kafka shipper |

### C. Standard System Utilities

```bash
# Ubuntu / Debian
sudo apt update && sudo apt install -y \
  curl jq dnsutils lsof procps net-tools iproute2 tar unzip build-essential libpq-dev
```

---

## 2. Repository Setup

### Step 1: Clone and Enter Repository
```bash
git clone https://github.com/just-akshit/dns-threat-detection-system.git dns
cd dns
git checkout feat/incremental-aggregator
git status
```

### Step 2: Set Up Python Virtual Environment
```bash
python3.11 -m venv backend/.venv
source backend/.venv/bin/activate

# Upgrade packaging tools
pip install --upgrade pip setuptools wheel

# Install backend dependencies
pip install -r backend/requirements.txt
```

### Step 3: Install Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

---

## 3. Environment Configuration

The application reads configuration from two files inside `backend/`:
1. `backend/.env` — Database connection pools, log levels, batch sizes.
2. `backend/api.env` — Threat intelligence provider credentials and API keys.

### Template: `backend/.env`
Create `backend/.env` with your Linux environment settings:
```ini
# PostgreSQL Database Connection
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=dns_threat_detection
DB_USER=postgres
DB_PASSWORD=your_secure_db_password

# Unknown Domain Repository (UDR) Configuration
UDR_DB_HOST=127.0.0.1
UDR_DB_PORT=5432
UDR_DB_DATABASE=dns_threat_detection
UDR_DB_USERNAME=postgres
UDR_DB_PASSWORD=your_secure_db_password
UDR_DB_MIN_CONNECTIONS=2
UDR_DB_MAX_CONNECTIONS=10
UDR_DB_CONNECT_TIMEOUT=5.0
UDR_DB_COMMAND_TIMEOUT=30.0
UDR_DB_MAX_IDLE_TIME=300.0

# Logging & Batch Tuning
UDR_LOG_LEVEL=INFO
UDR_LOG_FORMAT=json
UDR_BATCH_SIZE=1000
UDR_BATCH_TIMEOUT=5.0
UDR_BATCH_MAX_MEMORY=104857600
UDR_ENVIRONMENT=production
UDR_DEBUG=false

# Kafka Broker Configuration
KAFKA_BOOTSTRAP_SERVERS=127.0.0.1:9092
KAFKA_DNS_TOPIC=dns-logs

# Dashboard Aggregator Settings
AGGREGATION_BATCH_SIZE=1000
AGGREGATION_NAME=dashboard
RECENT_FLAGGED_DOMAINS_LIMIT=20
AGGREGATION_STALE_THRESHOLD_MINUTES=15
```

### Template: `backend/api.env`
Create `backend/api.env` (never commit secrets to version control):
```ini
# Threat Intelligence External Provider Keys (Optional for live enrichment)
VT_API_KEY=your_virustotal_api_key
OTX_API_KEY=your_alienvault_otx_api_key
IPINFO_TOKEN=your_ipinfo_token

# Investigation SLA
INVESTIGATION_DEADLINE_SECONDS=5.0
```

---

## 4. PostgreSQL Database Setup

### Step 1: Start and Enable PostgreSQL
```bash
sudo systemctl enable postgresql
sudo systemctl start postgresql
sudo systemctl status postgresql
```

### Step 2: Create User and Database
```bash
sudo -u postgres psql -c "CREATE USER postgres WITH PASSWORD 'your_secure_db_password';"
sudo -u postgres psql -c "ALTER USER postgres WITH SUPERUSER;"
sudo -u postgres psql -c "CREATE DATABASE dns_threat_detection OWNER postgres;"
```

### Step 3: Initialize Database Schemas
The application schema initializers will automatically provision required tables (`client_profiles`, `client_history`, `domain_profiles`, `domain_query_history`, `unknown_domains`, `reputation_domains`, `schema_metadata`, `dashboard_users`).

To verify or initialize explicitly via Python:
```bash
./backend/.venv/bin/python -c "
from labeler.intel.reputation import initialize_database
from client_profiling.schema import initialize_schema
from domain_profiling.service import DomainProfilingService

initialize_database()
initialize_schema()
DomainProfilingService().initialize_database()
print('PostgreSQL Schemas Initialized Successfully')
"
```

### Step 4: Verify Database Connection
```bash
PGPASSWORD='your_secure_db_password' psql -h 127.0.0.1 -U postgres -d dns_threat_detection -c "
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name;
"
```

---

## 5. Apache Kafka Setup (KRaft Mode)

If running standalone Kafka on Linux:

### Step 1: Download & Extract Kafka
```bash
cd /opt
sudo curl -O https://archive.apache.org/dist/kafka/3.7.0/kafka_2.13-3.7.0.tgz
sudo tar -xzf kafka_2.13-3.7.0.tgz
sudo mv kafka_2.13-3.7.0 kafka
sudo chown -R $USER:$USER /opt/kafka
```

### Step 2: Format KRaft Storage & Start Broker
```bash
cd /opt/kafka
KAFKA_CLUSTER_ID="$(bin/kafka-storage.sh random-cluster-id)"
bin/kafka-storage.sh format -t "$KAFKA_CLUSTER_ID" -c config/kraft/server.properties

# Start Kafka broker in background
nohup bin/kafka-server-start.sh config/kraft/server.properties > /tmp/kafka.log 2>&1 &
```

### Step 3: Create Ingestion Topic
```bash
/opt/kafka/bin/kafka-topics.sh --create \
    --bootstrap-server 127.0.0.1:9092 \
    --replication-factor 1 \
    --partitions 1 \
    --topic dns-logs

# Verify topic existence
/opt/kafka/bin/kafka-topics.sh --list --bootstrap-server 127.0.0.1:9092
```

---

## 6. Fluent Bit Setup

Fluent Bit parses raw BIND/DNS logs into structured JSON and forwards them to Kafka.

### Step 1: Verify Configuration
```bash
fluent-bit -c backend/fluent-bit.conf --dry-run
```

### Step 2: Start Fluent Bit
Ensure the input log path matches your Linux DNS server log path (e.g. `/var/cache/bind/query.log` or `./backend/parsing logs/logs/query.log`):
```bash
# Foreground execution (for testing / demo)
fluent-bit -c backend/fluent-bit.conf

# Or background daemon
nohup fluent-bit -c backend/fluent-bit.conf > /tmp/fluent-bit.log 2>&1 &
```

---

## 7. Pipeline Execution

### Component Dependency & Startup Sequence

```
1. PostgreSQL (Port 5432)
2. Apache Kafka (Port 9092)
3. Live Pipeline Consumer (run_live_pipeline.py)
4. Fluent Bit Log Shipper (fluent-bit)
5. Incremental Aggregator (run_aggregation.py)
6. Backend API (FastAPI - Port 8000)
7. Frontend React Dashboard (Port 5173 / Nginx)
```

### Step 1: Start Live Streaming Pipeline Consumer
In Terminal 1 (or as a systemd service):
```bash
cd /path/to/dns
./backend/.venv/bin/python backend/run_live_pipeline.py \
    --dataset backend/live_dataset.csv \
    --output backend/live_features.csv \
    --kafka-bootstrap 127.0.0.1:9092 \
    --kafka-topic dns-logs
```

### Step 2: Run Incremental Aggregator
In Terminal 2 (can be run on a 1-minute cron or systemd timer):
```bash
cd /path/to/dns
./backend/.venv/bin/python backend/run_aggregation.py --incremental
```

*(Note: For offline demo with pre-labelled CSV, run: `./backend/.venv/bin/python backend/run_aggregation.py --source auto`)*

---

## 8. Backend API Server

### Step 1: Start FastAPI via Uvicorn
In Terminal 3:
```bash
cd /path/to/dns
./backend/.venv/bin/uvicorn api.main:app \
    --app-dir backend \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 4
```

### Step 2: Verify Health & Endpoints
```bash
# 1. Health check
curl -s http://127.0.0.1:8000/health

# 2. Time-Window Analytics (5m window)
curl -s "http://127.0.0.1:8000/api/v1/analytics/domains?window=5m" | jq .

# 3. Domain Investigation (Tranco match)
curl -s "http://127.0.0.1:8000/api/v1/investigation/domain/google.com" | jq .

# 4. Domain Investigation (Zero-signal unknown)
curl -s "http://127.0.0.1:8000/api/v1/investigation/domain/test-suspicious-domain-123.xyz" | jq .
```

---

## 9. Frontend Application

### Development Server
```bash
cd /path/to/dns/frontend
npm run dev -- --host 0.0.0.0 --port 5173
```

### Production Build & Static Serving (Recommended for Linux Server)
```bash
cd /path/to/dns/frontend
npm run build

# Preview build locally
npm run preview -- --host 0.0.0.0 --port 5173
```

---

## 10. Clean State Reset Procedure

To reset all runtime telemetry and database state between test runs:

> **SAFETY GUARANTEE:** `backend/wipe_data.py` resets only runtime observational data, clears `dashboard.db`, and purges Kafka topics. Threat intelligence reference databases (`malicious_domains.db`, `trusted_domains.db`, Tranco, GeoLite2) and auth schemas are strictly preserved and cryptographically verified.

### Execution Commands:

```bash
# 1. Preview changes (Read-only simulation)
./backend/.venv/bin/python backend/wipe_data.py --dry-run

# 2. Execute non-interactive clean reset
./backend/.venv/bin/python backend/wipe_data.py --yes

# 3. Optional: Execute with pre-wipe timestamped backup
./backend/.venv/bin/python backend/wipe_data.py --yes --backup
```

---

## 11. Monitoring & Process Management

### Active Ports & Connections
```bash
# Check listening ports (5432, 9092, 8000, 5173)
ss -tulpn | grep -E "5432|9092|8000|5173"
```

### Process Status
```bash
ps aux | grep -E "uvicorn|run_live_pipeline|fluent-bit|kafka|postgres" | grep -v grep
```

### PostgreSQL Row Counts Check
```bash
./backend/.venv/bin/python -c "
import psycopg, os
from dotenv import load_dotenv; load_dotenv('backend/.env')
with psycopg.connect(host=os.getenv('DB_HOST','localhost'), port=int(os.getenv('DB_PORT','5432')), dbname=os.getenv('DB_NAME','dns_threat_detection'), user=os.getenv('DB_USER','postgres'), password=os.getenv('DB_PASSWORD','')) as conn:
    with conn.cursor() as cur:
        for t in ['domain_query_history', 'domain_profiles', 'client_history', 'client_profiles', 'unknown_domains']:
            cur.execute(f'SELECT COUNT(*) FROM {t}')
            print(f'{t}: {cur.fetchone()[0]} rows')
"
```

---

## 12. Graceful Shutdown Procedure

To cleanly terminate all running services without data corruption:

```bash
# 1. Stop DNS traffic generator / log writer
# 2. Stop Fluent Bit
kill $(pgrep -f "fluent-bit -c") 2>/dev/null

# 3. Stop Live Pipeline Consumer (allow in-flight commits to drain)
kill -INT $(pgrep -f "run_live_pipeline.py") 2>/dev/null

# 4. Stop Backend API
kill -INT $(pgrep -f "uvicorn api.main:app") 2>/dev/null

# 5. Stop Frontend dev server
kill $(pgrep -f "vite") 2>/dev/null

# 6. Stop Kafka
/opt/kafka/bin/kafka-server-stop.sh 2>/dev/null

# 7. Stop PostgreSQL (if needed)
sudo systemctl stop postgresql
```

---

## 13. Operational Troubleshooting Matrix

| Symptom | Probable Cause | Diagnostic Command | Safe Corrective Action |
| :--- | :--- | :--- | :--- |
| **`ConnectionRefusedError: 61 ECONNREFUSED` on port 9092** | Kafka broker is not running. | `ss -tulpn \| grep 9092` | Start Kafka broker using KRaft or systemd. |
| **`ImportError: attempted relative import with no known parent package`** | Direct script execution of `labeler/label_dataset.py`. | Run with `-m` flag from `backend/`. | Execute as module: `cd backend && python -m labeler.label_dataset`. |
| **`column cp.malicious_queries does not exist` warning in aggregator** | Legacy CSV mode query references non-existent column in PostgreSQL `client_profiles`. | Observe aggregator log. | Use production incremental mode: `python backend/run_aggregation.py --incremental`. |
| **`ModuleNotFoundError: No module named 'live_log_reader'` in `run_pipeline.py`** | Legacy batch script references deprecated helper. | `find backend -name "live_log_reader*"` | Use production streaming pipeline `backend/run_live_pipeline.py`. |
| **Investigation API returns `status: NO_DATA` for external TI** | Missing API keys in `backend/api.env`. | Check `backend/api.env` file. | Populate `VT_API_KEY`, `OTX_API_KEY`, `IPINFO_TOKEN`. |
| **Time-window analytics returns empty timeline** | No queries ingested in chosen window. | Query `domain_query_history` timestamp range. | Ingest fresh DNS traffic or widen window parameter. |
