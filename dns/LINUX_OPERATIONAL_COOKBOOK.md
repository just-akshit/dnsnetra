# LINUX OPERATIONAL COOKBOOK: DNS THREAT DETECTION SYSTEM

> **Document Type:** Definitive Operations Runbook & System Operating Procedure  
> **Target OS:** Linux (Ubuntu 22.04 / 24.04 LTS, Debian 12)  
> **Architecture:** Hybrid Streaming Pipeline (BIND Log → Fluent Bit → Apache Kafka → Live Python Consumer → PostgreSQL 14+ → Incremental Aggregator → SQLite Read Model → FastAPI → React Dashboard)  
> **Source Repository:** `just-akshit/dns-threat-detection-system` (`feat/incremental-aggregator`)  
> **Operating Rule:** OPERATE THE EXISTING REPOSITORY. ZERO SOURCE CODE REFACTORING.

---

## TABLE OF CONTENTS

- [SECTION 00 — Important Safety & Operating Rules](#section-00--important-safety--operating-rules)
- [SECTION 01 — Office Machine Pre-Flight & Environment Discovery](#section-01--office-machine-pre-flight--environment-discovery)
- [SECTION 02 — Project Checkout & Revision Verification](#section-02--project-checkout--revision-verification)
- [SECTION 03 — Linux Dependencies (Ubuntu / Debian)](#section-03--linux-dependencies-ubuntu--debian)
- [SECTION 04 — Python Virtual Environment Setup](#section-04--python-virtual-environment-setup)
- [SECTION 05 — Node.js & Frontend Build Setup](#section-05--nodejs--frontend-build-setup)
- [SECTION 06 — Environment Configuration & Secrets Management](#section-06--environment-configuration--secrets-management)
- [SECTION 07 — PostgreSQL Database Setup & Verification](#section-07--postgresql-database-setup--verification)
- [SECTION 08 — ZooKeeper Service Operations](#section-08--zookeeper-service-operations)
- [SECTION 09 — Apache Kafka Broker & Topic Operations](#section-09--apache-kafka-broker--topic-operations)
- [SECTION 10 — Kafka Clean-State Inspection & Reset Procedure](#section-10--kafka-clean-state-inspection--reset-procedure)
- [SECTION 11 — Fluent Bit Log Shipper Configuration & Run](#section-11--fluent-bit-log-shipper-configuration--run)
- [SECTION 12 — DNS Query Log Source & Ingestion Data Flow](#section-12--dns-query-log-source--ingestion-data-flow)
- [SECTION 13 — Live Pipeline Streaming Consumer Execution](#section-13--live-pipeline-streaming-consumer-execution)
- [SECTION 14 — PostgreSQL Telemetry Ingestion Verification](#section-14--postgresql-telemetry-ingestion-verification)
- [SECTION 15 — Incremental Aggregator Operations](#section-15--incremental-aggregator-operations)
- [SECTION 16 — SQLite Read-Model Inspection (`dashboard.db`)](#section-16--sqlite-read-model-inspection-dashboarddb)
- [SECTION 17 — FastAPI Backend API Server](#section-17--fastapi-backend-api-server)
- [SECTION 18 — Frontend React Dashboard Application](#section-18--frontend-react-dashboard-application)
- [SECTION 19 — Complete End-to-End Execution Sequence (Multi-Terminal)](#section-19--complete-end-to-end-execution-sequence-multi-terminal)
- [SECTION 20 — End-to-End Lineage & Invariant Verification](#section-20--end-to-end-lineage--invariant-verification)
- [SECTION 21 — Comprehensive Troubleshooting Matrix](#section-21--comprehensive-troubleshooting-matrix)
- [SECTION 22 — Process, Port, and Resource Diagnostics](#section-22--process-port-and-resource-diagnostics)
- [SECTION 23 — Graceful System Shutdown Sequence](#section-23--graceful-system-shutdown-sequence)
- [SECTION 24 — Non-Destructive System Restart Procedure](#section-24--non-destructive-system-restart-procedure)
- [SECTION 25 — Clean-State Reset Procedure (`wipe_data.py`)](#section-25--clean-state-reset-procedure-wipe_datapy)
- [SECTION 26 — Protected Threat-Intelligence & Dataset Integrity](#section-26--protected-threat-intelligence--dataset-integrity)
- [SECTION 27 — Office Machine "From Zero" Quick Run](#section-27--office-machine-from-zero-quick-run)
- [SECTION 28 — Quick Command Reference Cheat Sheet](#section-28--quick-command-reference-cheat-sheet)
- [FINAL VALIDATION AUDIT TABLE](#final-validation-audit-table)
- [UNKNOWN / MACHINE-SPECIFIC VALUES](#unknown--machine-specific-values)
- [FINAL OFFICE EXECUTION ORDER](#final-office-execution-order)

---

## SECTION 00 — IMPORTANT SAFETY & OPERATING RULES

> [!CAUTION]
> **CRITICAL OPERATIONAL RULES:**
> 1. **Zero Code Modification:** Do not modify, refactor, patch, or reorganize Python code, TypeScript code, schemas, or configs during operations.
> 2. **Explicit Reset Mechanism:** The **ONLY** approved data reset mechanism is `backend/wipe_data.py`. Never run manual `DROP TABLE`, `TRUNCATE`, or `DELETE FROM` SQL commands against the database.
> 3. **Immutable Reference Intelligence:** The threat intelligence reference databases (`backend/data/malicious_domains.db`, `backend/labeler/intel/trusted_domains.db`, `backend/data/top-1m.csv`, and `GeoLite2-ASN.mmdb`) must **NEVER** be deleted, overwritten, or re-initialized during operational test runs.
> 4. **No Secret Leaks:** Never print unmasked `.env` or `api.env` file contents in terminal logs or presentations.

### Command Classification Legend
- `[SAFE / READ-ONLY]` — Diagnostic or inspection command. Makes no changes to disk or database state.
- `[MUTATING]` — Standard runtime operational command (starts a process, appends telemetry, updates aggregation watermark).
- `[DESTRUCTIVE]` — Resets runtime telemetry and wipes temporary test state. Must only be executed when preparing a clean run.

---

## SECTION 01 — OFFICE MACHINE PRE-FLIGHT & ENVIRONMENT DISCOVERY

### Purpose
Inspect the host Linux system architecture, available runtimes, system utilities, and active services before running any pipeline component.

### Step 1.1: System Architecture & Resources `[SAFE / READ-ONLY]`
```bash
# Kernel, distribution, user, and hostname
uname -a
cat /etc/os-release
whoami
hostname
pwd

# CPU, memory, and disk capacity
nproc
free -h
df -h .
```
- **Expected Output:** Linux 64-bit (x86_64 or aarch64), Ubuntu 22.04/24.04 or Debian 12, minimum 4 GB RAM available, minimum 10 GB free disk space.

### Step 1.2: Runtime & Toolchain Inspection `[SAFE / READ-ONLY]`
```bash
python3 --version
node --version
npm --version
git --version
curl --version
jq --version
psql --version
dig -v
ss --version
```
- **Expected Output:**
  - Python: `3.11.x` or `3.12.x`
  - Node.js: `v20.x` or `v22.x`
  - npm: `10.x+`
  - Git: `2.34+`
  - PostgreSQL client (`psql`): `14+`, `16+`, or `18+`

### Step 1.3: Service & Binary Path Discovery `[SAFE / READ-ONLY]`
Discover where core infrastructure packages are installed on this Linux host:
```bash
# Check PostgreSQL status
systemctl is-active postgresql 2>/dev/null || echo "PostgreSQL systemd service not running"

# Locate Kafka installation directory (search common Linux paths)
KAFKA_DIR=$(find /opt /usr/local /home/$USER ~ -maxdepth 3 -name "kafka-server-start.sh" -exec dirname {} \; 2>/dev/null | head -n 1 | sed 's#/bin##')
echo "Discovered KAFKA_HOME: ${KAFKA_DIR:-NOT_FOUND}"

# Locate Fluent Bit binary
which fluent-bit /opt/fluent-bit/bin/fluent-bit /usr/local/bin/fluent-bit 2>/dev/null | head -n 1
```

---

## SECTION 02 — PROJECT CHECKOUT & REVISION VERIFICATION

### Purpose
Ensure the repository is positioned at the validated branch (`feat/incremental-aggregator`) with a clean working tree.

### Step 2.1: Verify Repository Directory & Remote `[SAFE / READ-ONLY]`
```bash
cd /path/to/dns
git rev-parse --show-toplevel
git remote -v
```
- **Expected Output:** Top-level directory matches the repository root.

### Step 2.2: Branch & Commit Verification `[SAFE / READ-ONLY]`
```bash
git checkout feat/incremental-aggregator
git status --short
git log -n 1 --oneline
```
- **Expected Verification:** Commit `489226f` (or latest HEAD of `feat/incremental-aggregator`). No modified application files in `backend/` or `frontend/`.

---

## SECTION 03 — LINUX DEPENDENCIES (UBUNTU / DEBIAN)

### Purpose
Install the minimal system packages required by the Python C-extensions (psycopg2, geoip2), Fluent Bit, PostgreSQL client, and DNS lookup utilities.

### Step 3.1: Install System Packages `[MUTATING]`
```bash
sudo apt update
sudo apt install -y \
  python3.11 python3.11-venv python3.11-dev \
  nodejs npm \
  postgresql postgresql-contrib \
  curl jq dnsutils iproute2 net-tools procps \
  build-essential libpq-dev default-jre
```
- **Verification:** `dpkg -l | grep -E "python3.11|postgresql|dnsutils|nodejs"`
- **Expected Result:** All packages listed as `ii` (installed).

### Step 3.2: Install Fluent Bit (Official Repository) `[MUTATING]`
```bash
# If fluent-bit is not already installed:
curl https://packages.fluentbit.io/fluentbit.key | gpg --dearmor | sudo tee /usr/share/keyrings/fluentbit-keyring.gpg > /dev/null
echo "deb [signed-by=/usr/share/keyrings/fluentbit-keyring.gpg] https://packages.fluentbit.io/ubuntu/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/fluent-bit.list
sudo apt update
sudo apt install -y fluent-bit
```
- **Verification:** `fluent-bit --version`
- **Expected Result:** `Fluent Bit v3.x` or `v5.x` displayed.

---

## SECTION 04 — PYTHON VIRTUAL ENVIRONMENT SETUP

### Purpose
Set up an isolated Python virtual environment inside `backend/.venv` and install the pinned dependencies.

### Step 4.1: Create Virtual Environment `[MUTATING]`
```bash
cd /path/to/dns
python3.11 -m venv backend/.venv
source backend/.venv/bin/activate
```
- **Verification:** `which python` → outputs `/path/to/dns/backend/.venv/bin/python`

### Step 4.2: Install Python Dependencies `[MUTATING]`
```bash
pip install --upgrade pip setuptools wheel
pip install -r backend/requirements.txt
```

### Step 4.3: Verify Core Library Imports `[SAFE / READ-ONLY]`
```bash
./backend/.venv/bin/python -c "
import pandas, psycopg, psycopg2, fastapi, uvicorn, kafka, dnspython, tldextract, geoip2, dotenv
print('Python dependencies verified successfully')
"
```
- **Expected Result:** `Python dependencies verified successfully` (exits with code 0).

---

## SECTION 05 — NODE.JS & FRONTEND BUILD SETUP

### Purpose
Install frontend npm packages and verify TypeScript compilation and Vite production build.

### Step 5.1: Install NPM Dependencies `[MUTATING]`
```bash
cd /path/to/dns/frontend
npm install
```
- **Verification:** `ls -d node_modules`

### Step 5.2: Verify Build & Linter `[SAFE / READ-ONLY]`
```bash
cd /path/to/dns/frontend
npm run build
npm run lint
```
- **Expected Verification:** `npm run build` completes in < 1.5s with output written to `frontend/dist/`. `oxlint` returns 0 errors.

---

## SECTION 06 — ENVIRONMENT CONFIGURATION & SECRETS MANAGEMENT

### Purpose
Provision the two required environment configuration files: `backend/.env` (infrastructure settings) and `backend/api.env` (threat intelligence credentials).

### Step 6.1: Create `backend/.env` `[MUTATING]`
```bash
cat << 'EOF' > backend/.env
# ===========================================================================
# PostgreSQL Database Connection
# ===========================================================================
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=dns_threat_detection
DB_USER=postgres
DB_PASSWORD=postgres

# ===========================================================================
# Unknown Domain Repository (UDR) Connection Pool
# ===========================================================================
UDR_DB_HOST=127.0.0.1
UDR_DB_PORT=5432
UDR_DB_DATABASE=dns_threat_detection
UDR_DB_USERNAME=postgres
UDR_DB_PASSWORD=postgres
UDR_DB_MIN_CONNECTIONS=2
UDR_DB_MAX_CONNECTIONS=10
UDR_DB_CONNECT_TIMEOUT=5.0
UDR_DB_COMMAND_TIMEOUT=30.0
UDR_DB_MAX_IDLE_TIME=300.0
UDR_LOG_LEVEL=INFO
UDR_LOG_FORMAT=json
UDR_BATCH_SIZE=1000
UDR_BATCH_TIMEOUT=5.0
UDR_BATCH_MAX_MEMORY=104857600
UDR_ENVIRONMENT=production
UDR_DEBUG=false

# ===========================================================================
# Apache Kafka Settings
# ===========================================================================
KAFKA_BOOTSTRAP_SERVERS=127.0.0.1:9092
KAFKA_DNS_TOPIC=dns-logs

# ===========================================================================
# Dashboard Aggregation Configuration
# ===========================================================================
AGGREGATION_BATCH_SIZE=1000
AGGREGATION_NAME=dashboard
RECENT_FLAGGED_DOMAINS_LIMIT=20
AGGREGATION_STALE_THRESHOLD_MINUTES=15
EOF
```

### Step 6.2: Create `backend/api.env` `[MUTATING]`
```bash
cat << 'EOF' > backend/api.env
# Threat Intelligence External Provider Credentials (Optional for live lookups)
VT_API_KEY=
OTX_API_KEY=
IPINFO_TOKEN=

# Investigation SLA
INVESTIGATION_DEADLINE_SECONDS=5.0
EOF
```

### Step 6.3: Safe Environment Validation (Zero Secret Leak) `[SAFE / READ-ONLY]`
```bash
./backend/.venv/bin/python -c "
from dotenv import dotenv_values
from pathlib import Path
for f in ['backend/.env', 'backend/api.env']:
    p = Path(f)
    if p.exists():
        print(f'{f} verified ({len(dotenv_values(p))} keys configured)')
"
```
- **Expected Result:** Both files reported as verified with expected key counts without exposing values.

---

## SECTION 07 — POSTGRESQL DATABASE SETUP & VERIFICATION

### Purpose
Start PostgreSQL, ensure user/database exist, initialize all required schemas, and verify connection pooling.

### Step 7.1: Service Management `[MUTATING]`
```bash
sudo systemctl start postgresql
sudo systemctl enable postgresql
sudo systemctl status postgresql --no-pager
```
- **Verification:** `pg_isready -h 127.0.0.1 -p 5432` → `127.0.0.1:5432 - accepting connections`

### Step 7.2: Create Database & User `[MUTATING]`
```bash
sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='postgres'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER postgres WITH PASSWORD 'postgres' SUPERUSER;"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='dns_threat_detection'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE dns_threat_detection OWNER postgres;"
```

### Step 7.3: Schema Initialization `[MUTATING]`
Execute Python schema initializers to guarantee all tables exist:
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

### Step 7.4: Schema Table Verification `[SAFE / READ-ONLY]`
```bash
PGPASSWORD=postgres psql -h 127.0.0.1 -U postgres -d dns_threat_detection -c "
SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY table_name;
"
```
- **Expected Output:** Public tables include: `client_history`, `client_profiles`, `dashboard_users`, `domain_profiles`, `domain_query_history`, `reputation_domains`, `schema_metadata`, `unknown_domains`, `users`.

---

## SECTION 08 — ZOOKEEPER SERVICE OPERATIONS

> [!NOTE]
> The current system uses ZooKeeper (Port 2181) as the metadata coordinator for Apache Kafka.

### Step 8.1: Locate ZooKeeper Configuration `[SAFE / READ-ONLY]`
```bash
# Export KAFKA_HOME variable (adjust path based on discovery from Section 01)
export KAFKA_HOME=${KAFKA_HOME:-/opt/kafka}
ls -la $KAFKA_HOME/config/zookeeper.properties
```

### Step 8.2: Start ZooKeeper `[MUTATING]`
In dedicated Terminal (or as background daemon):
```bash
$KAFKA_HOME/bin/zookeeper-server-start.sh $KAFKA_HOME/config/zookeeper.properties
```
- **Background Startup Option:**
  ```bash
  nohup $KAFKA_HOME/bin/zookeeper-server-start.sh $KAFKA_HOME/config/zookeeper.properties > /tmp/zookeeper.log 2>&1 &
  ```

### Step 8.3: Verify ZooKeeper Port & Process `[SAFE / READ-ONLY]`
```bash
ss -ltnp | grep :2181
```
- **Expected Verification:** Port 2181 in `LISTEN` state by Java process.

---

## SECTION 09 — APACHE KAFKA BROKER & TOPIC OPERATIONS

### Step 9.1: Start Kafka Broker `[MUTATING]`
In dedicated Terminal (or as background daemon):
```bash
$KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties
```
- **Background Startup Option:**
  ```bash
  nohup $KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties > /tmp/kafka.log 2>&1 &
  ```

### Step 9.2: Verify Kafka Port & Broker Readiness `[SAFE / READ-ONLY]`
```bash
ss -ltnp | grep :9092
```
- **Expected Verification:** Port 9092 in `LISTEN` state.

### Step 9.3: Create / Verify Ingestion Topic (`dns-logs`) `[MUTATING]`
```bash
# Create topic if not existing
$KAFKA_HOME/bin/kafka-topics.sh \
    --bootstrap-server 127.0.0.1:9092 \
    --create --if-not-exists \
    --topic dns-logs \
    --partitions 1 \
    --replication-factor 1

# Describe topic
$KAFKA_HOME/bin/kafka-topics.sh \
    --bootstrap-server 127.0.0.1:9092 \
    --describe \
    --topic dns-logs
```
- **Expected Output:** `Topic: dns-logs PartitionCount: 1 ReplicationFactor: 1 ...`

---

## SECTION 10 — KAFKA CLEAN-STATE INSPECTION & RESET PROCEDURE

### Step 10.1: Read-Only Topic & Offset Inspection `[SAFE / READ-ONLY]`
```bash
./backend/.venv/bin/python -c "
from kafka import KafkaConsumer, TopicPartition
consumer = KafkaConsumer(bootstrap_servers='127.0.0.1:9092')
tp = TopicPartition('dns-logs', 0)
consumer.assign([tp])
consumer.seek_to_beginning(tp)
start_off = consumer.position(tp)
consumer.seek_to_end(tp)
end_off = consumer.position(tp)
print(f'Topic dns-logs: partition=0 start_offset={start_off} end_offset={end_off} total_messages={end_off - start_off}')
consumer.close()
"
```

### Step 10.2: Consumer Group Lag Inspection `[SAFE / READ-ONLY]`
```bash
$KAFKA_HOME/bin/kafka-consumer-groups.sh \
    --bootstrap-server 127.0.0.1:9092 \
    --group dns_threat_pipeline \
    --describe 2>/dev/null || echo "Consumer group not yet registered (starts upon live consumer launch)"
```

### Step 10.3: Clean Reset of Kafka Topic `[DESTRUCTIVE]`
> [!WARNING]
> This destroys buffered unconsumed messages in `dns-logs`. Use only during clean-state test resets.
```bash
./backend/.venv/bin/python -c "
from kafka.admin import KafkaAdminClient, NewTopic
import time
admin = KafkaAdminClient(bootstrap_servers='127.0.0.1:9092')
if 'dns-logs' in admin.list_topics():
    admin.delete_topics(['dns-logs'])
    time.sleep(1)
admin.create_topics([NewTopic(name='dns-logs', num_partitions=1, replication_factor=1)])
print('Kafka topic dns-logs deleted and recreated (0 messages)')
admin.close()
"
```

---

## SECTION 11 — FLUENT BIT LOG SHIPPER CONFIGURATION & RUN

### Purpose
Fluent Bit tails the BIND query log file, parses raw logs with `dns_bind_parser` regex, and emits JSON messages to Kafka topic `dns-logs`.

### Step 11.1: Configuration File Verification `[SAFE / READ-ONLY]`
Inspect [`backend/fluent-bit.conf`](file:///Users/akshit/Developer/dns/backend/fluent-bit.conf) and [`backend/parsers.conf`](file:///Users/akshit/Developer/dns/backend/parsers.conf).
```bash
# Validate Fluent Bit configuration syntax
fluent-bit -c backend/fluent-bit.conf --dry-run
```
- **Expected Output:** `configuration test is successful`

### Step 11.2: Start Fluent Bit Shipper `[MUTATING]`
In dedicated Terminal:
```bash
cd /path/to/dns
fluent-bit -c backend/fluent-bit.conf
```
- **Expected Startup Log:**
  ```
  [info] [engine] started (pid=...)
  [info] [input:tail:tail.0] inotify_fs_add(): ...
  [info] [output:kafka:kafka.0] brokers=localhost:9092 topics=dns-logs
  ```

---

## SECTION 12 — DNS QUERY LOG SOURCE & INGESTION DATA FLOW

### Ingestion Data Flow Architecture
```
[Sample / Live BIND Queries]
            │
            ▼ (appends raw lines)
backend/parsing logs/logs/query.log
            │
            ▼ (tails & parses with dns_bind_parser)
Fluent Bit Shipper
            │
            ▼ (structured JSON format)
Kafka Topic: dns-logs (Port 9092)
```

### Step 12.1: Verify Sample Dataset Source `[SAFE / READ-ONLY]`
```bash
wc -l "backend/parsing logs/logs/query1.log"
head -n 3 "backend/parsing logs/logs/query1.log"
```
- **Expected Verification:** `700 backend/parsing logs/logs/query1.log`. Lines contain standard BIND format:  
  `01-Aug-2026 13:18:35.000 client @0x1000 192.168.1.101#19048 (google.com): query: google.com IN TXT + (10.0.0.1)`

### Step 12.2: Feed Traffic to Ingestion File `[MUTATING]`
To inject test queries into the running Fluent Bit tailer:
```bash
cat "backend/parsing logs/logs/query1.log" >> "backend/parsing logs/logs/query.log"
```

---

## SECTION 13 — LIVE PIPELINE STREAMING CONSUMER EXECUTION

### Purpose
Consume structured messages from Kafka, execute threat classification, update client/domain profiles, queue unindexed domains, and extract features.

### Step 13.1: Start Live Consumer `[MUTATING]`
In dedicated Terminal:
```bash
cd /path/to/dns
./backend/.venv/bin/python backend/run_live_pipeline.py \
    --dataset backend/live_dataset.csv \
    --output backend/live_features.csv \
    --kafka-bootstrap 127.0.0.1:9092 \
    --kafka-topic dns-logs
```
- **Expected Startup Output:**
  ```
  Client + domain profiling pools initialized
  ThreatIntelligence initialised
  Pipeline: DNS Enabled
  Pipeline: WHOIS Enabled
  Pipeline: ASN Enabled
  Waiting for Kafka messages … Press Ctrl-C to stop.
  ```

---

## SECTION 14 — POSTGRESQL TELEMETRY INGESTION VERIFICATION

### Purpose
Verify that streaming records from the live pipeline are landing in PostgreSQL.

### Step 14.1: Row Count & Telemetry Inspection `[SAFE / READ-ONLY]`
```bash
./backend/.venv/bin/python -c "
import psycopg, os
from dotenv import load_dotenv; load_dotenv('backend/.env')

with psycopg.connect(host=os.getenv('DB_HOST','localhost'), port=int(os.getenv('DB_PORT','5432')), dbname=os.getenv('DB_NAME','dns_threat_detection'), user=os.getenv('DB_USER','postgres'), password=os.getenv('DB_PASSWORD','')) as conn:
    with conn.cursor() as cur:
        for t in ['domain_query_history', 'client_history', 'domain_profiles', 'client_profiles', 'unknown_domains', 'reputation_domains']:
            cur.execute(f'SELECT COUNT(*) FROM \"{t}\"')
            print(f'PG {t:<22}: {cur.fetchone()[0]} rows')
        
        print('\n--- Latest Ingested Telemetry Events ---')
        cur.execute('SELECT id, timestamp, client_ip, domain, query_type, final_label, ti_source FROM domain_query_history ORDER BY id DESC LIMIT 5;')
        for r in cur.fetchall():
            print(r)
"
```
- **Expected Verification:** `domain_query_history` count > 0 with current timestamps and valid labels (`Benign`, `Suspicious`, `Malicious`).

---

## SECTION 15 — INCREMENTAL AGGREGATOR OPERATIONS

### Purpose
Process newly arrived PostgreSQL telemetry events since the last watermark and update the SQLite read model (`dashboard.db`).

### Step 15.1: Check Watermark & Pending Events `[SAFE / READ-ONLY]`
```bash
cd /path/to/dns
./backend/.venv/bin/python backend/run_aggregation.py --status
```
- **Expected Output:** Displays `Current watermark ID`, `Last run status`, and `Pending events`.

### Step 15.2: Execute Incremental Batch Pass `[MUTATING]`
```bash
cd /path/to/dns
./backend/.venv/bin/python backend/run_aggregation.py --incremental
```
- **Expected Output:**
  ```
  ============================================================
  Incremental Aggregation Result
  ============================================================
    Run ID          : <UUID>
    Status          : success
    Batches         : 1
    Events seen     : <COUNT>
    Events processed: <COUNT>
    Events rejected : 0
    Duration        : ~100ms
  ============================================================
  ```

---

## SECTION 16 — SQLITE READ-MODEL INSPECTION (`dashboard.db`)

### Purpose
Verify that pre-computed dashboard metrics are available in the SQLite read model.

### Step 16.1: Table Row Counts Check `[SAFE / READ-ONLY]`
```bash
./backend/.venv/bin/python -c "
import sqlite3
with sqlite3.connect('backend/dashboard.db') as conn:
    cur = conn.cursor()
    cur.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;\")
    for (t,) in cur.fetchall():
        cur.execute(f'SELECT COUNT(*) FROM \"{t}\"')
        print(f'SQLite {t:<26}: {cur.fetchone()[0]} rows')
"
```
- **Expected Output:** `metrics_summary`, `top_domains`, `top_clients`, `aggregation_state`, and `domain_details` contain populated records.

---

## SECTION 17 — FASTAPI BACKEND API SERVER

### Purpose
Serve pre-computed metrics and live investigation endpoints to the frontend dashboard.

### Step 17.1: Start FastAPI Server `[MUTATING]`
In dedicated Terminal:
```bash
cd /path/to/dns
./backend/.venv/bin/uvicorn api.main:app \
    --app-dir backend \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 4
```

### Step 17.2: Verify API Health & Endpoints `[SAFE / READ-ONLY]`
```bash
# 1. Health check
curl -s http://127.0.0.1:8000/health | jq .

# 2. Dashboard bundle
curl -s http://127.0.0.1:8000/api/v1/dashboard | jq .data.summary

# 3. Time-Window Analytics (5m window)
curl -s "http://127.0.0.1:8000/api/v1/analytics/domains?window=5m" | jq .data.metrics
```
- **Expected Results:** HTTP 200 responses with valid JSON data structures.

---

## SECTION 18 — FRONTEND REACT DASHBOARD APPLICATION

### Purpose
Serve the interactive React analytics interface on Linux host port 5173.

### Step 18.1: Start Vite Dev Server `[MUTATING]`
In dedicated Terminal:
```bash
cd /path/to/dns/frontend
npm run dev -- --host 0.0.0.0 --port 5173
```
- **Expected Startup:**
  ```
  VITE v8.2.x ready in ~300 ms
  ➜ Local:   http://localhost:5173/
  ➜ Network: http://<LINUX_IP>:5173/
  ```

### Step 18.2: Verify Frontend HTTP Availability `[SAFE / READ-ONLY]`
```bash
curl -s -I http://127.0.0.1:5173/
```
- **Expected Verification:** `HTTP/1.1 200 OK`

---

## SECTION 19 — COMPLETE END-TO-END RUN SEQUENCE (MULTI-TERMINAL)

Execute this exact numbered sequence across 7 terminal sessions:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TERMINAL 1: Infrastructure (PostgreSQL & ZooKeeper)                   │
│   1. sudo systemctl start postgresql                                   │
│   2. $KAFKA_HOME/bin/zookeeper-server-start.sh $KAFKA_HOME/config/zookeeper.properties
├────────────────────────────────────────────────────────────────────────┤
│ TERMINAL 2: Apache Kafka Broker                                        │
│   1. $KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties
├────────────────────────────────────────────────────────────────────────┤
│ TERMINAL 3: Live Pipeline Consumer                                     │
│   1. cd /path/to/dns                                                   │
│   2. ./backend/.venv/bin/python backend/run_live_pipeline.py           │
│        --dataset backend/live_dataset.csv                              │
│        --output backend/live_features.csv                              │
│        --kafka-bootstrap 127.0.0.1:9092                                │
│        --kafka-topic dns-logs                                          │
├────────────────────────────────────────────────────────────────────────┤
│ TERMINAL 4: Fluent Bit Log Shipper                                     │
│   1. cd /path/to/dns                                                   │
│   2. fluent-bit -c backend/fluent-bit.conf                             │
├────────────────────────────────────────────────────────────────────────┤
│ TERMINAL 5: Traffic Feed / Injection                                   │
│   1. cd /path/to/dns                                                   │
│   2. cat "backend/parsing logs/logs/query1.log" >> "backend/parsing logs/logs/query.log"
├────────────────────────────────────────────────────────────────────────┤
│ TERMINAL 6: Incremental Aggregator & API Server                        │
│   1. cd /path/to/dns                                                   │
│   2. ./backend/.venv/bin/python backend/run_aggregation.py --incremental
│   3. ./backend/.venv/bin/uvicorn api.main:app --app-dir backend --host 0.0.0.0 --port 8000
├────────────────────────────────────────────────────────────────────────┤
│ TERMINAL 7: Frontend Application                                       │
│   1. cd /path/to/dns/frontend                                          │
│   2. npm run dev -- --host 0.0.0.0 --port 5173                         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## SECTION 20 — END-TO-END LINEAGE & INVARIANT VERIFICATION

Verify the end-to-end telemetry equality and lag invariants:

### Step 20.1: Check End-to-End Pipeline Lineage `[SAFE / READ-ONLY]`
```bash
./backend/.venv/bin/python -c "
import psycopg, sqlite3, os
from dotenv import load_dotenv
from kafka import KafkaConsumer, TopicPartition
load_dotenv('backend/.env')

# 1. Kafka Offsets
consumer = KafkaConsumer(bootstrap_servers='127.0.0.1:9092', group_id='dns_threat_pipeline')
tp = TopicPartition('dns-logs', 0)
comm_off = consumer.committed(tp) or 0
consumer.assign([tp])
consumer.seek_to_end(tp)
end_off = consumer.position(tp)
consumer.close()

# 2. PostgreSQL Telemetry
with psycopg.connect(host=os.getenv('DB_HOST','localhost'), port=int(os.getenv('DB_PORT','5432')), dbname=os.getenv('DB_NAME','dns_threat_detection'), user=os.getenv('DB_USER','postgres'), password=os.getenv('DB_PASSWORD','')) as conn:
    with conn.cursor() as cur:
        cur.execute('SELECT COUNT(*), COALESCE(MAX(id),0) FROM domain_query_history;')
        pg_cnt, pg_max_id = cur.fetchone()

# 3. SQLite Read Model
with sqlite3.connect('backend/dashboard.db') as conn:
    cur = conn.cursor()
    cur.execute('SELECT last_watermark_id FROM aggregation_state WHERE aggregation_name=\"dashboard\";')
    row = cur.fetchone()
    sqlite_watermark = row[0] if row else 0

print('=' * 60)
print('END-TO-END DATA LINEAGE & INVARIANT AUDIT')
print('=' * 60)
print(f'1. Kafka Published Messages (End Offset) : {end_off}')
print(f'2. Kafka Consumer Committed Offset       : {comm_off}')
print(f'3. Kafka Consumer Lag                    : {end_off - comm_off}')
print(f'4. PostgreSQL domain_query_history Count : {pg_cnt} (Max ID: {pg_max_id})')
print(f'5. Aggregator Watermark in SQLite        : {sqlite_watermark}')
print('=' * 60)
assert end_off - comm_off >= 0, 'Consumer lag must be non-negative'
assert sqlite_watermark <= pg_max_id, 'Aggregator watermark cannot exceed PostgreSQL max event ID'
print('ALL PIPELINE LINEAGE INVARIANTS SATISFIED')
"
```

---

## SECTION 21 — COMPREHENSIVE TROUBLESHOOTING MATRIX

| Problem | Diagnostic Command | Expected Result | Likely Root Cause | Safe Remediation |
| :--- | :--- | :--- | :--- | :--- |
| **PostgreSQL connection refused** | `pg_isready -h 127.0.0.1 -p 5432` | `accepting connections` | Service stopped or non-standard port. | `sudo systemctl start postgresql` |
| **Kafka ECONNREFUSED on 9092** | `ss -ltnp \| grep :9092` | Port 9092 listening | Kafka broker is not started. | Start ZooKeeper then start Kafka broker. |
| **ZooKeeper connection failed** | `ss -ltnp \| grep :2181` | Port 2181 listening | ZooKeeper daemon stopped. | Run `$KAFKA_HOME/bin/zookeeper-server-start.sh`. |
| **Fluent Bit drops records** | `fluent-bit -c backend/fluent-bit.conf --dry-run` | `test is successful` | Malformed regex in `parsers.conf`. | Verify BIND log format matches regex in `parsers.conf`. |
| **Consumer group high lag** | `$KAFKA_HOME/bin/kafka-consumer-groups.sh ...` | Lag approaches 0 | Heavy online TI lookups. | Allow consumer to drain or verify TI timeouts. |
| **PostgreSQL rows not increasing** | Check `domain_query_history` count | Count increases | `query.log` empty or Fluent Bit down. | Append queries to `query.log` and verify consumer. |
| **Aggregator watermark stagnant** | `./backend/.venv/bin/python backend/run_aggregation.py --status` | Watermark = Max PG ID | Aggregator not run after ingestion. | Run `python backend/run_aggregation.py --incremental`. |
| **FastAPI 500 on Investigation** | `curl -s http://127.0.0.1:8000/api/v1/investigation/domain/google.com` | HTTP 200 with JSON | External API timeout. | Verify `INVESTIGATION_DEADLINE_SECONDS=5.0` in `api.env`. |
| **Frontend cannot reach API** | `curl -s http://127.0.0.1:8000/health` | `{"status":"ok"}` | Uvicorn not listening on `0.0.0.0`. | Start Uvicorn with `--host 0.0.0.0`. |

---

## SECTION 22 — PROCESS, PORT, AND RESOURCE DIAGNOSTICS

```bash
# Check all required listening ports (5432, 2181, 9092, 8000, 5173)
ss -tulpn | grep -E "5432|2181|9092|8000|5173"

# Find running pipeline processes
ps aux | grep -E "uvicorn|run_live_pipeline|fluent-bit|kafka|zookeeper|postgres" | grep -v grep

# Check system memory and CPU utilization
free -h
top -b -n 1 | head -n 20
```

---

## SECTION 23 — GRACEFUL SYSTEM SHUTDOWN SEQUENCE

To stop all services cleanly without telemetry loss or database lock contention:

```bash
# 1. Stop Traffic Generation (Stop writing to query.log)
# 2. Stop Frontend dev server
kill $(pgrep -f "vite") 2>/dev/null || true

# 3. Stop FastAPI backend server
kill -INT $(pgrep -f "uvicorn api.main:app") 2>/dev/null || true

# 4. Stop Fluent Bit log shipper
kill $(pgrep -f "fluent-bit -c") 2>/dev/null || true

# 5. Stop Live Pipeline Consumer (allows in-flight commits to flush)
kill -INT $(pgrep -f "run_live_pipeline.py") 2>/dev/null || true

# 6. Stop Kafka Broker
$KAFKA_HOME/bin/kafka-server-stop.sh 2>/dev/null || true

# 7. Stop ZooKeeper
$KAFKA_HOME/bin/zookeeper-server-stop.sh 2>/dev/null || true

# 8. Stop PostgreSQL (if needed)
sudo systemctl stop postgresql 2>/dev/null || true
```

---

## SECTION 24 — NON-DESTRUCTIVE SYSTEM RESTART PROCEDURE

To restart the system while **preserving all existing telemetry, profiles, and aggregation state**:

```bash
# 1. Start Infrastructure
sudo systemctl start postgresql
$KAFKA_HOME/bin/zookeeper-server-start.sh $KAFKA_HOME/config/zookeeper.properties &
$KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties &

# 2. Start Streaming Pipeline & Ingestion
cd /path/to/dns
./backend/.venv/bin/python backend/run_live_pipeline.py \
    --dataset backend/live_dataset.csv --output backend/live_features.csv &
fluent-bit -c backend/fluent-bit.conf &

# 3. Catch Up Aggregation State
./backend/.venv/bin/python backend/run_aggregation.py --incremental

# 4. Start API & Frontend
./backend/.venv/bin/uvicorn api.main:app --app-dir backend --host 0.0.0.0 --port 8000 &
cd frontend && npm run dev -- --host 0.0.0.0 --port 5173 &
```

---

## SECTION 25 — CLEAN-STATE RESET PROCEDURE (`wipe_data.py`)

> [!CAUTION]
> Execute this procedure **ONLY** when intentionally performing a clean-state baseline test run.

### Step 25.1: Preview Reset Actions (Simulation) `[SAFE / READ-ONLY]`
```bash
./backend/.venv/bin/python backend/wipe_data.py --dry-run
```

### Step 25.2: Execute Reset `[DESTRUCTIVE]`
```bash
./backend/.venv/bin/python backend/wipe_data.py --yes
```

### Post-Reset Guarantees:
- `domain_query_history`, `client_history`, `domain_profiles`, `client_profiles`, `unknown_domains`, `reputation_domains` = **0 rows**.
- `dashboard.db` = **0 rows across all 20 read-model tables**.
- `dns-logs` topic = **0 messages**.
- Protected Auth & Reference Intelligence = **100% Intact**.

---

## SECTION 26 — PROTECTED THREAT-INTELLIGENCE & DATASET INTEGRITY

The following reference files must never be removed or modified:

| Protected File Path | Purpose | Integrity Check Command |
| :--- | :--- | :--- |
| [`backend/data/malicious_domains.db`](file:///Users/akshit/Developer/dns/backend/data/malicious_domains.db) | URLhaus Local SQLite Database (~1.9 MB) | `sha256sum backend/data/malicious_domains.db` |
| [`backend/labeler/intel/trusted_domains.db`](file:///Users/akshit/Developer/dns/backend/labeler/intel/trusted_domains.db) | Tranco Local SQLite Database (~82 MB) | `sha256sum backend/labeler/intel/trusted_domains.db` |
| [`backend/data/top-1m.csv`](file:///Users/akshit/Developer/dns/backend/data/top-1m.csv) | Tranco Top 1M CSV Reference | `wc -l backend/data/top-1m.csv` |
| `backend/feature extraction/enrichment/databases/GeoLite2-ASN.mmdb` | MaxMind Local ASN Database | `ls -lh "backend/feature extraction/enrichment/databases/GeoLite2-ASN.mmdb"` |

---

## SECTION 27 — OFFICE MACHINE "FROM ZERO" QUICK RUN

Copy-paste sequence for a fresh run on an office Linux host:

```bash
# 1. Enter repository & activate environment
cd /path/to/dns
source backend/.venv/bin/activate

# 2. Start Services
sudo systemctl start postgresql
nohup $KAFKA_HOME/bin/zookeeper-server-start.sh $KAFKA_HOME/config/zookeeper.properties > /tmp/zk.log 2>&1 &
sleep 2
nohup $KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties > /tmp/kafka.log 2>&1 &
sleep 3

# 3. Clean-State Reset
./backend/.venv/bin/python backend/wipe_data.py --yes

# 4. Start Live Consumer (Background)
nohup ./backend/.venv/bin/python backend/run_live_pipeline.py \
    --dataset backend/live_dataset.csv \
    --output backend/live_features.csv \
    --kafka-bootstrap 127.0.0.1:9092 \
    --kafka-topic dns-logs > /tmp/pipeline.log 2>&1 &

# 5. Start Fluent Bit Shipper (Background)
nohup fluent-bit -c backend/fluent-bit.conf > /tmp/fluent-bit.log 2>&1 &

# 6. Inject 700 Test DNS Queries
cat "backend/parsing logs/logs/query1.log" >> "backend/parsing logs/logs/query.log"
sleep 5

# 7. Run Incremental Aggregator
./backend/.venv/bin/python backend/run_aggregation.py --incremental

# 8. Start Backend API Server (Background)
nohup ./backend/.venv/bin/uvicorn api.main:app --app-dir backend --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &

# 9. Start Frontend Dashboard (Background)
cd frontend
nohup npm run dev -- --host 0.0.0.0 --port 5173 > /tmp/frontend.log 2>&1 &
cd ..

# 10. Verify Full System
curl -s http://127.0.0.1:8000/health
curl -s http://127.0.0.1:8000/api/v1/dashboard | jq .data.summary
```

---

## SECTION 28 — QUICK COMMAND REFERENCE CHEAT SHEET

| Operation | Linux Shell Command |
| :--- | :--- |
| **PostgreSQL Status** | `sudo systemctl status postgresql` |
| **PostgreSQL CLI** | `PGPASSWORD=postgres psql -h 127.0.0.1 -U postgres -d dns_threat_detection` |
| **ZooKeeper Start** | `$KAFKA_HOME/bin/zookeeper-server-start.sh $KAFKA_HOME/config/zookeeper.properties` |
| **Kafka Start** | `$KAFKA_HOME/bin/kafka-server-start.sh $KAFKA_HOME/config/server.properties` |
| **List Kafka Topics** | `$KAFKA_HOME/bin/kafka-topics.sh --bootstrap-server 127.0.0.1:9092 --list` |
| **Check Kafka Lag** | `$KAFKA_HOME/bin/kafka-consumer-groups.sh --bootstrap-server 127.0.0.1:9092 --group dns_threat_pipeline --describe` |
| **Test Fluent Bit Config** | `fluent-bit -c backend/fluent-bit.conf --dry-run` |
| **Start Live Consumer** | `./backend/.venv/bin/python backend/run_live_pipeline.py --dataset backend/live_dataset.csv --output backend/live_features.csv` |
| **Run Aggregator (Incremental)**| `./backend/.venv/bin/python backend/run_aggregation.py --incremental` |
| **Check Aggregator Watermark** | `./backend/.venv/bin/python backend/run_aggregation.py --status` |
| **Start Backend API** | `./backend/.venv/bin/uvicorn api.main:app --app-dir backend --host 0.0.0.0 --port 8000` |
| **Start Frontend** | `cd frontend && npm run dev -- --host 0.0.0.0 --port 5173` |
| **Run Pytest Test Suite** | `./backend/.venv/bin/pytest backend/tests/ -v` |
| **Reset Telemetry Data** | `./backend/.venv/bin/python backend/wipe_data.py --yes` |

---

## FINAL VALIDATION AUDIT TABLE

| Component | Actual Implementation | Cookbook Command | Verified From |
| :--- | :--- | :--- | :--- |
| **PostgreSQL** | Postgres 14+ on port 5432, db: `dns_threat_detection` | `systemctl start postgresql`, `psql -h 127.0.0.1` | [`backend/.env`](file:///Users/akshit/Developer/dns/backend/.env), [`backend/database/schema.sql`](file:///Users/akshit/Developer/dns/backend/database/schema.sql) |
| **ZooKeeper** | Port 2181 coordinator | `$KAFKA_HOME/bin/zookeeper-server-start.sh ...` | Process inspection (`PID 35853`), `zookeeper.properties` |
| **Kafka** | Port 9092 broker | `$KAFKA_HOME/bin/kafka-server-start.sh ...` | Process inspection (`server.properties`), port check |
| **Kafka Topic** | Topic `dns-logs` (1 partition) | `kafka-topics.sh --topic dns-logs` | [`backend/fluent-bit.conf`](file:///Users/akshit/Developer/dns/backend/fluent-bit.conf#L41), [`backend/run_live_pipeline.py`](file:///Users/akshit/Developer/dns/backend/run_live_pipeline.py) |
| **Consumer Group** | Group `dns_threat_pipeline` | `kafka-consumer-groups.sh --group dns_threat_pipeline` | [`backend/run_live_pipeline.py#L868`](file:///Users/akshit/Developer/dns/backend/run_live_pipeline.py#L868) |
| **Fluent Bit** | Tailer + `dns_bind_parser` regex | `fluent-bit -c backend/fluent-bit.conf` | [`backend/fluent-bit.conf`](file:///Users/akshit/Developer/dns/backend/fluent-bit.conf), [`backend/parsers.conf`](file:///Users/akshit/Developer/dns/backend/parsers.conf) |
| **DNS Source** | BIND log file | `cat query1.log >> query.log` | [`backend/fluent-bit.conf#L16`](file:///Users/akshit/Developer/dns/backend/fluent-bit.conf#L16), [`backend/parsing logs/logs/`](file:///Users/akshit/Developer/dns/backend/parsing%20logs/logs/) |
| **Python Pipeline** | Streaming consumer & feature extractor | `python backend/run_live_pipeline.py ...` | [`backend/run_live_pipeline.py`](file:///Users/akshit/Developer/dns/backend/run_live_pipeline.py) |
| **PostgreSQL Persistence**| `domain_query_history`, `client_profiles` | SQL count verification queries | [`backend/domain_persistence.py`](file:///Users/akshit/Developer/dns/backend/domain_persistence.py), `client_profiling` |
| **Incremental Aggregator**| Watermark-based batch sync | `python backend/run_aggregation.py --incremental` | [`backend/run_aggregation.py`](file:///Users/akshit/Developer/dns/backend/run_aggregation.py) |
| **SQLite Read Model** | `backend/dashboard.db` (20 tables) | Python SQLite inspection query | [`backend/dashboard_aggregation/config.py`](file:///Users/akshit/Developer/dns/backend/dashboard_aggregation/config.py) |
| **FastAPI** | Uvicorn on port 8000 | `uvicorn api.main:app --host 0.0.0.0 --port 8000` | [`backend/api/main.py`](file:///Users/akshit/Developer/dns/backend/api/main.py) |
| **Frontend** | React 19 + Vite 8.2 on port 5173 | `npm run dev -- --host 0.0.0.0 --port 5173` | [`frontend/package.json`](file:///Users/akshit/Developer/dns/frontend/package.json) |
| **Threat Intelligence** | URLhaus & Tranco DBs | `sha256sum backend/data/malicious_domains.db` | [`backend/data/`](file:///Users/akshit/Developer/dns/backend/data/), [`backend/labeler/intel/`](file:///Users/akshit/Developer/dns/backend/labeler/intel/) |
| **Reset Utility** | `backend/wipe_data.py` | `python backend/wipe_data.py --yes` | [`backend/wipe_data.py`](file:///Users/akshit/Developer/dns/backend/wipe_data.py) |

---

## UNKNOWN / MACHINE-SPECIFIC VALUES

The following parameters are specific to the destination Linux host and must be verified on-site:

1. **`KAFKA_HOME`:** The absolute path where Apache Kafka is installed on Linux (e.g. `/opt/kafka`, `/usr/local/kafka`, or `/home/user/kafka`). Set via `export KAFKA_HOME=/actual/path`.
2. **`PROJECT_PATH`:** The absolute path to the checked-out repository (e.g. `/home/user/dns` or `/opt/dns`).
3. **`DB_PASSWORD`:** The password assigned to PostgreSQL superuser `postgres`.
4. **`LINUX_HOST_IP`:** The network IP address of the Linux server (used to open the React dashboard from client browser machines via `http://<LINUX_HOST_IP>:5173`).
5. **`API Credentials (Optional)`:** API keys for VirusTotal, AlienVault OTX, and IPinfo if external live enrichment is required during office demonstration.

---

## FINAL OFFICE EXECUTION ORDER

1. **Log in** to the Linux machine and run pre-flight inspection (`SECTION 01`).
2. **Verify repository checkout** at branch `feat/incremental-aggregator` (`SECTION 02`).
3. **Verify/install Linux system dependencies** (`SECTION 03`).
4. **Activate Python virtual environment** in `backend/.venv` (`SECTION 04`).
5. **Verify/build frontend dependencies** in `frontend/` (`SECTION 05`).
6. **Populate `backend/.env` and `backend/api.env`** (`SECTION 06`).
7. **Start PostgreSQL service** and initialize schemas (`SECTION 07`).
8. **Start ZooKeeper coordinator** on port 2181 (`SECTION 08`).
9. **Start Apache Kafka broker** on port 9092 and verify topic `dns-logs` (`SECTION 09`).
10. **Perform clean-state reset** using `backend/wipe_data.py --yes` (`SECTION 25`).
11. **Start Live Streaming Consumer** (`backend/run_live_pipeline.py`) (`SECTION 13`).
12. **Start Fluent Bit Shipper** (`backend/fluent-bit.conf`) (`SECTION 11`).
13. **Inject DNS traffic** by appending to `query.log` (`SECTION 12`).
14. **Verify PostgreSQL ingestion** in `domain_query_history` (`SECTION 14`).
15. **Run Incremental Aggregator** (`run_aggregation.py --incremental`) (`SECTION 15`).
16. **Verify SQLite Read Model** in `backend/dashboard.db` (`SECTION 16`).
17. **Start FastAPI Backend Server** on port 8000 (`SECTION 17`).
18. **Start Frontend Dashboard** on port 5173 (`SECTION 18`).
19. **Perform End-to-End Verification** audit (`SECTION 20`).
