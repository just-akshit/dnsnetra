#!/usr/bin/env bash
# DNSNetra — Start All Services
# Run from: /Users/akshit/Developer/dnsnetra
# Usage:    ./start_all.sh
set -e

PROJECT="$(cd "$(dirname "$0")" && pwd)"
KAFKA=~/kafka
mkdir -p "$PROJECT/logs"

echo "Starting DNSNetra services..."
echo ""

echo "[1/7] ZooKeeper..."
if lsof -i :2181 | grep -q LISTEN 2>/dev/null; then
    echo "      already running"
else
    $KAFKA/bin/zookeeper-server-start.sh -daemon $KAFKA/config/zookeeper.properties
    sleep 3
    echo "      ✅ started"
fi

echo "[2/7] Kafka..."
if lsof -i :9092 | grep -q LISTEN 2>/dev/null; then
    echo "      already running"
else
    $KAFKA/bin/kafka-server-start.sh -daemon $KAFKA/config/server.properties
    sleep 5
    echo "      ✅ started"
fi

echo "[3/7] Kafka topic dns-logs..."
$KAFKA/bin/kafka-topics.sh --bootstrap-server localhost:9092 \
  --create --if-not-exists --topic dns-logs --partitions 1 --replication-factor 1 2>/dev/null || true
echo "      ✅ ready"

echo "[4/7] Fluent Bit..."
if ps aux | grep -q '[f]luent-bit'; then
    echo "      already running"
else
    cd "$PROJECT"
    fluent-bit -c fluent-bit.conf > logs/fluent-bit.log 2>&1 &
    echo $! > /tmp/fluent-bit.pid
    sleep 2
    echo "      ✅ started (log: logs/fluent-bit.log)"
fi

echo "[5/7] Live Pipeline (run_live_pipeline.py)..."
if ps aux | grep -q '[r]un_live_pipeline'; then
    echo "      already running"
else
    cd "$PROJECT"
    nohup python3 run_live_pipeline.py \
      --dataset live_dataset.csv \
      --output  live_features.csv \
      --kafka-topic dns-logs \
      --kafka-bootstrap localhost:9092 \
      > logs/pipeline.log 2>&1 &
    echo $! > /tmp/pipeline.pid
    sleep 2
    echo "      ✅ started (log: logs/pipeline.log)"
fi

echo "[6/7] FastAPI (port 8000)..."
if lsof -i :8000 | grep -q LISTEN 2>/dev/null; then
    echo "      already running"
else
    cd "$PROJECT"
    nohup uvicorn api.main:app --host 0.0.0.0 --port 8000 \
      > logs/fastapi.log 2>&1 &
    echo $! > /tmp/fastapi.pid
    sleep 2
    echo "      ✅ started (log: logs/fastapi.log)"
fi

echo "[7/7] Next.js (port 3000)..."
if lsof -i :3000 | grep -q LISTEN 2>/dev/null; then
    echo "      already running"
else
    cd "$PROJECT/frontend"
    nohup npm run dev > "$PROJECT/logs/nextjs.log" 2>&1 &
    echo $! > /tmp/nextjs.pid
    sleep 3
    echo "      ✅ started (log: logs/nextjs.log)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Dashboard  : http://localhost:3000  (admin / admin)"
echo "  API        : http://localhost:8000/health"
echo "  Kafka      : localhost:9092  topic=dns-logs"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
