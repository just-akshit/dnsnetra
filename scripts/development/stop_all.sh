#!/usr/bin/env bash
# DNSNetra — Stop All Services
# Usage: ./scripts/development/stop_all.sh
set -u

PROJECT="$(cd "$(dirname "$0")/../.." && pwd)"
KAFKA=~/kafka

echo "Stopping DNSNetra services..."

# 1. Processes recorded by start_all.sh
for name in aggregator pipeline fastapi nextjs fluent-bit; do
    pidfile="/tmp/$name.pid"
    [ -f "$pidfile" ] || continue
    pid=$(cat "$pidfile" 2>/dev/null)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null && echo "  stopped $name (pid $pid)"
    fi
    rm -f "$pidfile"
done

# 2. Anything left behind (dev-server children, stale starts)
pkill -f "uvicorn apps.api.main" 2>/dev/null && echo "  stopped uvicorn"
pkill -f "dnsnetra.ingestion.pipelines.live" 2>/dev/null && echo "  stopped pipeline"
pkill -f "scripts/development/run_aggregation.py" 2>/dev/null && echo "  stopped aggregator"
pkill -f "fluent-bit -c" 2>/dev/null && echo "  stopped fluent-bit"
pkill -f "next dev" 2>/dev/null && echo "  stopped next dev"
pkill -f "pnpm dev" 2>/dev/null

# 3. Kafka + ZooKeeper (graceful stop scripts)
if [ -x "$KAFKA/bin/kafka-server-stop.sh" ]; then
    "$KAFKA/bin/kafka-server-stop.sh" >/dev/null 2>&1 && echo "  stopped kafka"
fi
if [ -x "$KAFKA/bin/zookeeper-server-stop.sh" ]; then
    "$KAFKA/bin/zookeeper-server-stop.sh" >/dev/null 2>&1 && echo "  stopped zookeeper"
fi

# 4. Free the ports of anything that ignored the polite request
sleep 2
for port in 8000 3000; do
    if lsof -i ":$port" 2>/dev/null | grep -q LISTEN; then
        lsof -ti "tcp:$port" | xargs kill -9 2>/dev/null
        echo "  force-killed process on :$port"
    fi
done

sleep 1
remaining=""
for port in 2181 9092 8000 3000; do
    if lsof -i ":$port" 2>/dev/null | grep -q LISTEN; then
        remaining="$remaining $port"
    fi
done

if [ -n "$remaining" ]; then
    echo "⚠️  still listening:$remaining"
    exit 1
fi

echo "✅ all services stopped (PostgreSQL left running)"
