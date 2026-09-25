# macOS vs Linux Command Matrix

This document provides a comprehensive side-by-side comparison of every operational command across macOS (Darwin / Homebrew) and Linux (Ubuntu/Debian / systemd).

---

## 1. System Package Management & Dependencies

| Operation | macOS (Homebrew) | Linux (Ubuntu / Debian) | Linux (RHEL / Rocky / Alma) |
| :--- | :--- | :--- | :--- |
| **Update Package Index** | `brew update` | `sudo apt update` | `sudo dnf check-update` |
| **Install Python 3.11** | `brew install python@3.11` | `sudo apt install -y python3.11 python3.11-venv python3.11-dev` | `sudo dnf install -y python3.11 python3.11-devel` |
| **Install Node.js & npm** | `brew install node` | `sudo apt install -y nodejs npm` (or NodeSource) | `sudo dnf install -y nodejs npm` |
| **Install PostgreSQL** | `brew install postgresql@18` | `sudo apt install -y postgresql postgresql-contrib` | `sudo dnf install -y postgresql-server` |
| **Install Fluent Bit** | `brew install fluent-bit` | `sudo apt install -y fluent-bit` (via official repo) | `sudo dnf install -y fluent-bit` |
| **Install Network & DNS Tools** | `brew install bind curl jq` | `sudo apt install -y dnsutils curl jq iproute2 net-tools` | `sudo dnf install -y bind-utils curl jq iproute` |

---

## 2. Service Management (System Daemons)

| Daemon / Service | macOS (Homebrew Services) | Linux (systemd) |
| :--- | :--- | :--- |
| **Start PostgreSQL** | `brew services start postgresql@18` | `sudo systemctl start postgresql` |
| **Stop PostgreSQL** | `brew services stop postgresql@18` | `sudo systemctl stop postgresql` |
| **PostgreSQL Status** | `brew services info postgresql@18` | `sudo systemctl status postgresql` |
| **Enable PostgreSQL on Boot** | Automatic with `brew services start` | `sudo systemctl enable postgresql` |
| **Start Kafka (Standalone/KRaft)** | `nohup /opt/homebrew/bin/kafka-server-start ... &` | `sudo systemctl start kafka` (or `/opt/kafka/bin/kafka-server-start.sh`) |
| **Stop Kafka** | `kill -TERM $(pgrep -f "kafka.Kafka")` | `sudo systemctl stop kafka` (or `/opt/kafka/bin/kafka-server-stop.sh`) |
| **Start Fluent Bit Daemon** | `brew services start fluent-bit` | `sudo systemctl start fluent-bit` |
| **Stop Fluent Bit Daemon** | `brew services stop fluent-bit` | `sudo systemctl stop fluent-bit` |

---

## 3. Network, Port, and Process Inspection

| Task | macOS | Linux |
| :--- | :--- | :--- |
| **List Listening TCP Ports** | `lsof -iTCP -sTCP:LISTEN -n -P` | `ss -tulpn` *(or `netstat -tulpn`)* |
| **Check Port 5432 (Postgres)** | `lsof -i :5432` | `ss -tulpn \| grep :5432` |
| **Check Port 9092 (Kafka)** | `lsof -i :9092` | `ss -tulpn \| grep :9092` |
| **Check Port 8000 (FastAPI)** | `lsof -i :8000` | `ss -tulpn \| grep :8000` |
| **Check Port 5173 (Frontend)** | `lsof -i :5173` | `ss -tulpn \| grep :5173` |
| **Find Process by Substring** | `ps aux \| grep <pattern>` | `ps aux \| grep <pattern>` *(or `pgrep -af <pattern>`)* |
| **Process Tree** | `pstree` *(requires `brew install pstree`)* | `pstree -p` |
| **Memory & CPU Stats** | `top -l 1` *(or Activity Monitor)* | `htop` / `top -b -n 1` / `free -h` |

---

## 4. Python Environment & Pipeline Execution

| Step | macOS | Linux |
| :--- | :--- | :--- |
| **Create Virtual Environment** | `python3 -m venv backend/.venv` | `python3.11 -m venv backend/.venv` |
| **Activate Virtual Environment** | `source backend/.venv/bin/activate` | `source backend/.venv/bin/activate` |
| **Install Requirements** | `pip install -r backend/requirements.txt` | `pip install -r backend/requirements.txt` |
| **Run Data Reset Utility** | `./backend/.venv/bin/python backend/wipe_data.py --yes` | `./backend/.venv/bin/python backend/wipe_data.py --yes` |
| **Run Live Pipeline Consumer** | `./backend/.venv/bin/python backend/run_live_pipeline.py --dataset backend/live_dataset.csv --output backend/live_features.csv` | `./backend/.venv/bin/python backend/run_live_pipeline.py --dataset backend/live_dataset.csv --output backend/live_features.csv` |
| **Run Incremental Aggregator** | `./backend/.venv/bin/python backend/run_aggregation.py --incremental` | `./backend/.venv/bin/python backend/run_aggregation.py --incremental` |
| **Run Offline Labeller Module** | `cd backend && .venv/bin/python -m labeler.label_dataset` | `cd backend && .venv/bin/python -m labeler.label_dataset` |
| **Start FastAPI API Server** | `cd backend && .venv/bin/uvicorn api.main:app --reload --port 8000` | `cd backend && .venv/bin/uvicorn api.main:app --host 0.0.0.0 --port 8000 --workers 4` |

---

## 5. Fluent Bit Configuration & Execution

| Step | macOS | Linux |
| :--- | :--- | :--- |
| **Default Config Directory** | `/opt/homebrew/etc/fluent-bit/` | `/etc/fluent-bit/` |
| **Binary Location** | `/opt/homebrew/bin/fluent-bit` | `/opt/fluent-bit/bin/fluent-bit` *(or `/usr/bin/fluent-bit`)* |
| **Config Validation** | `fluent-bit -c backend/fluent-bit.conf --dry-run` | `fluent-bit -c backend/fluent-bit.conf --dry-run` |
| **Run with Project Config** | `fluent-bit -c backend/fluent-bit.conf` | `fluent-bit -c backend/fluent-bit.conf` |
| **Log Tail Target Path** | `/Users/akshit/.../parsing logs/logs/query.log` | `/var/cache/bind/query.log` *(or repo path)* |

---

## 6. Frontend Execution & Building

| Step | macOS | Linux |
| :--- | :--- | :--- |
| **Install Node Dependencies** | `cd frontend && npm install` | `cd frontend && npm install` |
| **Run Vite Dev Server** | `cd frontend && npm run dev` | `cd frontend && npm run dev -- --host 0.0.0.0` |
| **Build Production Bundle** | `cd frontend && npm run build` | `cd frontend && npm run build` |
| **Preview Production Bundle** | `cd frontend && npm run preview` | `cd frontend && npm run preview -- --host 0.0.0.0` |
| **Run Linter** | `cd frontend && npm run lint` | `cd frontend && npm run lint` |

---

## 7. Diagnostics & System Log Inspection

| Diagnostic | macOS | Linux |
| :--- | :--- | :--- |
| **PostgreSQL Error Logs** | `/Library/PostgreSQL/18/data/log/` *(or Homebrew logs)* | `/var/log/postgresql/postgresql-*.log` *(or `journalctl -u postgresql`)* |
| **System Service Logs** | `log show --predicate 'process == "postgres"'` | `journalctl -u <service-name> -f` |
| **DNS Resolution Test** | `dig @127.0.0.1 -p 53 example.com` | `dig @127.0.0.1 -p 53 example.com` |
| **HTTP API Endpoint Test** | `curl -s http://127.0.0.1:8000/health` | `curl -s http://127.0.0.1:8000/health` |
| **Time-Window Analytics Test** | `curl -s "http://127.0.0.1:8000/api/v1/analytics/domains?window=5m" \| jq .` | `curl -s "http://127.0.0.1:8000/api/v1/analytics/domains?window=5m" \| jq .` |
