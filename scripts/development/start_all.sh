#!/usr/bin/env bash
# DNSNetra — Start All Services
# Run from anywhere: scripts/development/start_all.sh
# Usage:            ./scripts/development/start_all.sh
set -e

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
KAFKA=~/kafka
LOGS="$PROJECT/data/logs"
mkdir -p "$LOGS"

FAILED=""

ok()   { echo "      ✅ $1"; }
fail() { echo "      ❌ $1"; FAILED="$FAILED $2"; }

# wait_for_port <port> [seconds]
wait_for_port() {
    local port=$1 ticks=$(( ${2:-10} * 2 ))
    for _ in $(seq 1 "$ticks"); do
        if lsof -i ":$port" 2>/dev/null | grep -q LISTEN; then
            return 0
        fi
        sleep 0.5
    done
    return 1
}

# check_proc <pid> <log path> <label>
check_proc() {
    if kill -0 "$1" 2>/dev/null; then
        ok "started (log: $2)"
    else
        fail "failed to start — see $2" "$3"
    fi
}

# running_pid <pidfile> — true when the recorded pid is still alive.
# Avoids `ps | grep` matching unrelated shells that merely mention the command.
running_pid() {
    [ -f "$1" ] || return 1
    local pid
    pid=$(cat "$1" 2>/dev/null)
    [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

echo "Starting DNSNetra services..."
echo ""

echo "[1/8] ZooKeeper..."
if lsof -i :2181 2>/dev/null | grep -q LISTEN; then
    echo "      already running"
else
    $KAFKA/bin/zookeeper-server-start.sh -daemon $KAFKA/config/zookeeper.properties
    if wait_for_port 2181 15; then
        ok "started"
    else
        fail "did not bind :2181 — see $KAFKA/logs" "zookeeper"
    fi
fi

echo "[2/8] Kafka..."
if lsof -i :9092 2>/dev/null | grep -q LISTEN; then
    echo "      already running"
else
    $KAFKA/bin/kafka-server-start.sh -daemon $KAFKA/config/server.properties
    if wait_for_port 9092 20; then
        ok "started"
    else
        fail "did not bind :9092 — see $KAFKA/logs" "kafka"
    fi
fi

echo "[3/8] Kafka topic dns-logs..."
$KAFKA/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --create --if-not-exists --topic dns-logs --partitions 1 --replication-factor 1 >/dev/null 2>&1 || true
if $KAFKA/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list 2>/dev/null | grep -qx "dns-logs"; then
    ok "ready"
else
    fail "topic dns-logs not found on :9092" "kafka-topic"
fi

echo "[4/8] Fluent Bit..."
if running_pid /tmp/fluent-bit.pid; then
    echo "      already running"
else
    cd "$PROJECT"
    DNSNETRA_ROOT="$PROJECT" fluent-bit -c "$PROJECT/infrastructure/fluent-bit/fluent-bit.conf" > "$LOGS/fluent-bit.log" 2>&1 &
    FB_PID=$!
    echo "$FB_PID" > /tmp/fluent-bit.pid
    sleep 2
    check_proc "$FB_PID" "$LOGS/fluent-bit.log" "fluent-bit"
fi

echo "[5/8] Live Pipeline (dnsnetra.ingestion.pipelines.live)..."
if running_pid /tmp/pipeline.pid; then
    echo "      already running"
else
    cd "$PROJECT"
    PYTHONPATH="$PROJECT/backend/src:$PROJECT" nohup "$PROJECT/.venv/bin/python" -m dnsnetra.ingestion.pipelines.live \
      --dataset "$PROJECT/data/datasets/live_dataset.csv" \
      --output  "$PROJECT/data/datasets/live_features.csv" \
      --kafka-topic dns-logs \
      --kafka-bootstrap localhost:9092 \
      > "$LOGS/pipeline.log" 2>&1 &
    PL_PID=$!
    echo "$PL_PID" > /tmp/pipeline.pid
    sleep 3
    check_proc "$PL_PID" "$LOGS/pipeline.log" "pipeline"
fi

echo "[6/8] FastAPI (port 8000)..."
if lsof -i :8000 2>/dev/null | grep -q LISTEN; then
    echo "      already running"
else
    cd "$PROJECT"
    PYTHONPATH="$PROJECT/backend/src:$PROJECT" nohup "$PROJECT/.venv/bin/uvicorn" apps.api.main:app --host 0.0.0.0 --port 8000 \
      > "$LOGS/fastapi.log" 2>&1 &
    API_PID=$!
    echo "$API_PID" > /tmp/fastapi.pid
    sleep 2
    if wait_for_port 8000 10; then
        ok "started (log: $LOGS/fastapi.log)"
    else
        fail "did not bind :8000 — see $LOGS/fastapi.log" "fastapi"
    fi
fi

echo "[7/8] Next.js (port 3000)..."
if lsof -i :3000 2>/dev/null | grep -q LISTEN; then
    echo "      already running"
else
    cd "$PROJECT/apps/web"
    nohup pnpm dev > "$LOGS/nextjs.log" 2>&1 &
    WEB_PID=$!
    echo "$WEB_PID" > /tmp/nextjs.pid
    sleep 3
    if wait_for_port 3000 20; then
        ok "started (log: $LOGS/nextjs.log)"
    else
        fail "did not bind :3000 — see $LOGS/nextjs.log" "nextjs"
    fi
fi

echo "[8/8] Aggregator (loop 60s)..."
if running_pid /tmp/aggregator.pid; then
    echo "      already running"
else
    cd "$PROJECT"
    PYTHONPATH="$PROJECT/backend/src:$PROJECT" nohup "$PROJECT/.venv/bin/python" \
      "$PROJECT/scripts/development/run_aggregation.py" --loop 60 \
      > "$LOGS/aggregator.log" 2>&1 &
    AGG_PID=$!
    echo "$AGG_PID" > /tmp/aggregator.pid
    sleep 3
    check_proc "$AGG_PID" "$LOGS/aggregator.log" "aggregator"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Dashboard  : http://localhost:3000  (credentials: managed by an administrator)"
echo "  API        : http://localhost:8000/health"
echo "  Kafka      : localhost:9092  topic=dns-logs"
echo "  Logs       : data/logs/{fluent-bit,pipeline,fastapi,nextjs,aggregator}.log"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -n "$FAILED" ]; then
    echo ""
    echo "⚠️  Failed to start:$FAILED"
    exit 1
fi
