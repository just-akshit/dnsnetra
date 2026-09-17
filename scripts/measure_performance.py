"""
scripts/measure_performance.py
==============================
Measures cold, warm, and repeated latency across representative DNSNetra endpoints.
"""

from __future__ import annotations

import os
import statistics
import sys
import time
import warnings
from pathlib import Path

# Suppress external starlette testclient warning
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi.testclient import TestClient

from api.auth import create_access_token
from api.main import app

client = TestClient(app)
token = create_access_token(data={"sub": "admin@security.local", "role": "admin"})
headers = {"Authorization": f"Bearer {token}"}


def measure_endpoint(method: str, path: str, n_repeats: int = 5) -> dict:
    latencies = []
    for i in range(n_repeats):
        t0 = time.perf_counter()
        if method == "GET":
            res = client.get(path, headers=headers)
        elif method == "POST":
            res = client.post(path, headers=headers)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert res.status_code == 200, f"Failed on {path}: {res.status_code}"
        latencies.append(elapsed_ms)

    cold = latencies[0]
    warm = latencies[1] if len(latencies) > 1 else cold
    repeated_mean = statistics.mean(latencies[1:]) if len(latencies) > 1 else cold
    repeated_median = statistics.median(latencies[1:]) if len(latencies) > 1 else cold

    return {
        "cold_ms": round(cold, 2),
        "warm_ms": round(warm, 2),
        "mean_warm_ms": round(repeated_mean, 2),
        "median_warm_ms": round(repeated_median, 2),
    }


def main():
    endpoints = [
        ("GET", "/health"),
        ("GET", "/api/v1/auth/me"),
        ("GET", "/api/v1/dashboard?window=24h"),
        ("GET", "/api/v1/reports/summary"),
        ("GET", "/api/v1/reports/timeseries?window=24h"),
        ("GET", "/api/v1/reports/clients?limit=10"),
        ("GET", "/api/v1/reports/domains?limit=10"),
        ("GET", "/api/v1/reports/queries?limit=10"),
        ("GET", "/api/v1/reports/entity?entity=apple.com"),
        ("GET", "/api/v1/reports/export/csv?limit=50"),
        ("GET", "/api/v1/domains/apple.com"),
        ("GET", "/api/v1/clients/192.168.1.100"),
        ("GET", "/api/v1/investigation/domains/apple.com"),
        ("GET", "/api/v1/investigation/clients/192.168.1.100"),
        ("GET", "/api/v1/status"),
        ("GET", "/api/v1/analytics/domains?window=1h"),
        ("GET", "/api/v1/daily-review?limit=10"),
    ]

    print(f"{'Endpoint':<45} | {'Cold (ms)':<10} | {'Warm (ms)':<10} | {'Mean Warm (ms)':<15}")
    print("-" * 88)
    for method, path in endpoints:
        m = measure_endpoint(method, path)
        print(f"{path:<45} | {m['cold_ms']:<10} | {m['warm_ms']:<10} | {m['mean_warm_ms']:<15}")


if __name__ == "__main__":
    main()
