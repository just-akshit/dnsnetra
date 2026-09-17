"""
scripts/verify_http_live.py
===========================
Live HTTP verification script for DNSNetra Phase 2D.
Executes requests against the full FastAPI application connected to live PostgreSQL.
"""

from __future__ import annotations

import json
import sys
import time
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def verify():
    print("=" * 70)
    print("DNSNetra Phase 2D Live HTTP Verification")
    print("=" * 70)

    results = []

    def check(name, status_code, ok, details=""):
        status_str = "PASS" if ok else "FAIL"
        print(f"[{status_str}] {name} (HTTP {status_code}) {details}")
        results.append((name, ok))

    # 1. Health
    res = client.get("/health")
    check("GET /health", res.status_code, res.status_code == 200 and res.json().get("status") == "healthy")

    # 2. Auth Token (OAuth2 form)
    t0 = time.perf_counter()
    res = client.post("/api/v1/auth/token", data={"username": "admin@security.local", "password": "admin"})
    auth_latency = (time.perf_counter() - t0) * 1000
    token_ok = res.status_code == 200 and "access_token" in res.json()
    check("POST /api/v1/auth/token", res.status_code, token_ok, f"({auth_latency:.1f}ms)")
    token = res.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}

    # 3. Auth JSON Login
    res = client.post("/api/v1/auth/login", json={"email": "admin@security.local", "password": "admin"})
    check("POST /api/v1/auth/login", res.status_code, res.status_code == 200 and "access_token" in res.json())

    # 4. Auth Me
    res = client.get("/api/v1/auth/me", headers=headers)
    me_ok = res.status_code == 200 and res.json().get("email") == "admin@security.local"
    check("GET /api/v1/auth/me", res.status_code, me_ok, f"user={res.json().get('email')}")

    # 5. Dashboard Bundle
    t0 = time.perf_counter()
    res = client.get("/api/v1/dashboard?window=24h", headers=headers)
    dash_latency = (time.perf_counter() - t0) * 1000
    data = res.json()
    dash_ok = (
        res.status_code == 200
        and "summary" in data
        and "timeseries" in data
        and "top_clients" in data
        and "top_domains" in data
        and "total_queries" in data["summary"]
    )
    check("GET /api/v1/dashboard", res.status_code, dash_ok, f"({dash_latency:.1f}ms, queries={data.get('summary', {}).get('total_queries')})")

    # 6. Reports Summary
    t0 = time.perf_counter()
    res = client.get("/api/v1/reports/summary", headers=headers)
    rep_latency = (time.perf_counter() - t0) * 1000
    r_sum = res.json()
    sum_ok = res.status_code == 200 and r_sum.get("total_queries") == 30181
    check("GET /api/v1/reports/summary", res.status_code, sum_ok, f"({rep_latency:.1f}ms, total=30181, ben={r_sum.get('verdict_breakdown', {}).get('benign')})")

    # 7. Reports root alias
    res = client.get("/api/v1/reports", headers=headers)
    check("GET /api/v1/reports (alias)", res.status_code, res.status_code == 200 and res.json() == r_sum)

    # 8. Reports Timeseries
    res = client.get("/api/v1/reports/timeseries?window=24h", headers=headers)
    ts_data = res.json()
    ts_ok = res.status_code == 200 and "buckets" in ts_data and len(ts_data["buckets"]) > 0
    check("GET /api/v1/reports/timeseries", res.status_code, ts_ok, f"(buckets={len(ts_data.get('buckets', []))}, source={ts_data.get('bucket_source')})")

    # 9. Reports Clients
    res = client.get("/api/v1/reports/clients?limit=10", headers=headers)
    c_data = res.json()
    clients_ok = res.status_code == 200 and len(c_data.get("items", [])) == 10 and c_data.get("total") == 12
    check("GET /api/v1/reports/clients", res.status_code, clients_ok, f"(total={c_data.get('total')}, limit={c_data.get('limit')})")

    # 10. Reports Domains
    res = client.get("/api/v1/reports/domains?limit=10", headers=headers)
    d_data = res.json()
    domains_ok = res.status_code == 200 and len(d_data.get("items", [])) == 10 and d_data.get("total") == 49
    check("GET /api/v1/reports/domains", res.status_code, domains_ok, f"(total={d_data.get('total')}, limit={d_data.get('limit')})")

    # 11. Reports Queries
    res = client.get("/api/v1/reports/queries?limit=10", headers=headers)
    q_data = res.json()
    queries_ok = res.status_code == 200 and len(q_data.get("items", [])) == 10
    check("GET /api/v1/reports/queries", res.status_code, queries_ok, f"(total={q_data.get('total')}, items=10)")

    # 12. Domains List
    res = client.get("/api/v1/domains?limit=5", headers=headers)
    check("GET /api/v1/domains", res.status_code, res.status_code == 200 and len(res.json().get("items", [])) == 5)

    # 13. Domain Detail
    res = client.get("/api/v1/domains/apple.com", headers=headers)
    d_det = res.json()
    check("GET /api/v1/domains/apple.com", res.status_code, res.status_code == 200 and d_det.get("domain") == "apple.com")

    # 14. Clients List
    res = client.get("/api/v1/clients?limit=5", headers=headers)
    check("GET /api/v1/clients", res.status_code, res.status_code == 200 and len(res.json().get("items", [])) == 5)

    # 15. Client Detail
    res = client.get("/api/v1/clients/192.168.1.100", headers=headers)
    c_det = res.json()
    check("GET /api/v1/clients/192.168.1.100", res.status_code, res.status_code == 200 and c_det.get("client_ip") == "192.168.1.100")

    # 16. Investigation Domain (plural & singular)
    t0 = time.perf_counter()
    res_p = client.get("/api/v1/investigation/domains/apple.com", headers=headers)
    res_s = client.get("/api/v1/investigation/domain/apple.com", headers=headers)
    inv_lat = (time.perf_counter() - t0) * 1000
    check("GET /api/v1/investigation/domains/apple.com", res_p.status_code, res_p.status_code == 200 and res_p.json() == res_s.json(), f"({inv_lat:.1f}ms)")

    # 17. Investigation Client (plural & singular)
    res_p = client.get("/api/v1/investigation/clients/192.168.1.100", headers=headers)
    res_s = client.get("/api/v1/investigation/client/192.168.1.100", headers=headers)
    check("GET /api/v1/investigation/clients/192.168.1.100", res_p.status_code, res_p.status_code == 200 and res_p.json() == res_s.json())

    # 18. Status
    res = client.get("/api/v1/status", headers=headers)
    st = res.json()
    check("GET /api/v1/status", res.status_code, res.status_code == 200 and st.get("status") == "healthy" and st.get("database", {}).get("connected") is True)

    # 19. Analytics Domains
    res = client.get("/api/v1/analytics/domains?window=1h", headers=headers)
    an = res.json()
    check("GET /api/v1/analytics/domains", res.status_code, res.status_code == 200 and "metrics" in an and "timeline" in an)

    # 20. Daily Review List & Stats
    res_dr = client.get("/api/v1/daily-review", headers=headers)
    res_stats = client.get("/api/v1/daily-review/stats", headers=headers)
    check("GET /api/v1/daily-review", res_dr.status_code, res_dr.status_code == 200)
    check("GET /api/v1/daily-review/stats", res_stats.status_code, res_stats.status_code == 200)

    # 21. Compatibility endpoints
    res_mal = client.get("/api/v1/reports/malicious-domains", headers=headers)
    check("GET /api/v1/reports/malicious-domains", res_mal.status_code, res_mal.status_code == 200 and res_mal.json().get("total") == 9)
    res_flag = client.get("/api/v1/reports/flagged", headers=headers)
    check("GET /api/v1/reports/flagged", res_flag.status_code, res_flag.status_code == 200)
    res_ent = client.get("/api/v1/reports/entity", headers=headers)
    check("GET /api/v1/reports/entity (deferred)", res_ent.status_code, res_ent.status_code == 501)
    res_csv = client.get("/api/v1/reports/export/csv", headers=headers)
    check("GET /api/v1/reports/export/csv (deferred)", res_csv.status_code, res_csv.status_code == 501)

    print("-" * 70)
    failed = [name for name, ok in results if not ok]
    if failed:
        print(f"FAILED {len(failed)} endpoints: {failed}")
        sys.exit(1)
    else:
        print(f"ALL {len(results)} ENDPOINTS PASSED LIVE VERIFICATION SUCCESSFULLY!")
        print("-" * 70)


if __name__ == "__main__":
    verify()
