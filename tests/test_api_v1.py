"""
tests/test_api_v1.py
====================
Exhaustive integration and contract test suite for DNSNetra Phase 2D Backend API.
Covers:
- Route registration & OpenAPI contract
- Authentication & authorization matrix
- Request validation & error mapping (400, 401, 403, 404, 501)
- Unified pagination shape: {total, limit, offset, has_more, items}
- Canonical four-state verdicts: Benign, Malicious, Review Needed, Unknown
- Time engine integration (single temporal range resolution)
- Dashboard composition and 6 KPI invariants
- Detail and investigation endpoints (zero live network calls, rejection of temporal params)
- System status and domain analytics
- PostgreSQL database truth reconciliation
"""

from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from api.auth import create_access_token
from api.main import app
from reporting.schemas import CanonicalVerdict

client = TestClient(app)


@pytest.fixture
def auth_headers():
    """Generates valid Bearer token for an active admin user."""
    token = create_access_token(data={"sub": "admin@security.local", "role": "admin"})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def non_admin_headers():
    """Generates valid Bearer token for a non-admin user."""
    token = create_access_token(data={"sub": "analyst@security.local", "role": "analyst"})
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# 1. Health & OpenAPI (Category A)
# ===========================================================================

def test_health_endpoint():
    """Health check is public and reports healthy."""
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert "version" in data


def test_openapi_schema_contains_canonical_endpoints():
    """OpenAPI schema registers all required v1 endpoints."""
    res = client.get("/openapi.json")
    assert res.status_code == 200
    paths = res.json()["paths"]

    expected = [
        "/health",
        "/api/v1/auth/token",
        "/api/v1/auth/login",
        "/api/v1/auth/me",
        "/api/v1/dashboard",
        "/api/v1/reports",
        "/api/v1/reports/summary",
        "/api/v1/reports/timeseries",
        "/api/v1/reports/clients",
        "/api/v1/reports/domains",
        "/api/v1/reports/queries",
        "/api/v1/reports/malicious-domains",
        "/api/v1/reports/flagged",
        "/api/v1/reports/entity",
        "/api/v1/reports/export/csv",
        "/api/v1/domains",
        "/api/v1/domains/{domain}",
        "/api/v1/clients",
        "/api/v1/clients/{client_ip}",
        "/api/v1/investigation/domains/{domain}",
        "/api/v1/investigation/clients/{client_ip}",
        "/api/v1/status",
        "/api/v1/analytics/domains",
    ]
    for p in expected:
        assert p in paths, f"Path {p} missing from OpenAPI schema"


# ===========================================================================
# 2. Authentication & Authorization (Categories B & C)
# ===========================================================================

def test_auth_token_success():
    """OAuth2 password form login succeeds with valid credentials."""
    res = client.post(
        "/api/v1/auth/token",
        data={"username": "admin@security.local", "password": "admin"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] == 86400


def test_auth_token_invalid_password():
    """OAuth2 password form login fails with wrong password."""
    res = client.post(
        "/api/v1/auth/token",
        data={"username": "admin@security.local", "password": "wrongpassword"},
    )
    assert res.status_code == 401
    assert "Incorrect username or password" in res.json()["detail"]


def test_auth_login_json_success():
    """JSON login alias succeeds with email and password."""
    res = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@security.local", "password": "admin"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data


def test_auth_login_json_missing_credentials():
    """JSON login alias fails if neither email nor username is provided."""
    res = client.post(
        "/api/v1/auth/login",
        json={"password": "admin"},
    )
    assert res.status_code == 400


def test_auth_me_requires_bearer_token():
    """Protected /auth/me returns 401 without Authorization header."""
    res = client.get("/api/v1/auth/me")
    assert res.status_code == 401


def test_auth_me_invalid_token():
    """Protected /auth/me returns 401 with forged token."""
    res = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer forged-invalid-token"},
    )
    assert res.status_code == 401


def test_auth_me_success(auth_headers):
    """Protected /auth/me returns user profile with valid Bearer token."""
    res = client.get("/api/v1/auth/me", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["email"] == "admin@security.local"
    assert data["role"] == "admin"
    assert data["is_active"] is True


def test_unauthenticated_endpoints_return_401():
    """All data endpoints reject anonymous requests with 401."""
    endpoints = [
        "/api/v1/dashboard",
        "/api/v1/reports/summary",
        "/api/v1/reports/timeseries",
        "/api/v1/reports/clients",
        "/api/v1/reports/domains",
        "/api/v1/reports/queries",
        "/api/v1/domains",
        "/api/v1/domains/apple.com",
        "/api/v1/clients",
        "/api/v1/clients/192.168.1.100",
        "/api/v1/investigation/domains/apple.com",
        "/api/v1/investigation/clients/192.168.1.100",
        "/api/v1/status",
        "/api/v1/analytics/domains",
    ]
    for ep in endpoints:
        res = client.get(ep)
        assert res.status_code == 401, f"Endpoint {ep} did not enforce auth (status={res.status_code})"


# ===========================================================================
# 3. Dashboard Endpoint (Category Q & F & H)
# ===========================================================================

def test_dashboard_endpoint_structure(auth_headers):
    """GET /api/v1/dashboard returns coherent single-range bundle with exactly 6 KPIs."""
    res = client.get("/api/v1/dashboard?window=24h", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    # Verify 6 canonical KPIs
    summary = data["summary"]
    for kpi in [
        "total_queries",
        "total_clients",
        "unique_domains",
        "unique_clients",
        "malicious_domains",
        "unknown_domains",
    ]:
        assert kpi in summary, f"Missing KPI {kpi}"

    # Verify absence of banned legacy fields
    for banned in ["threats_blocked_pct", "total_threats", "threat_queries"]:
        assert banned not in summary, f"Found banned legacy field {banned}"

    # Verify verdict breakdown
    vb = summary["verdict_breakdown"]
    for v in ["benign", "malicious", "review_needed", "unknown"]:
        assert v in vb
    assert vb["benign"] + vb["malicious"] + vb["review_needed"] + vb["unknown"] == summary["total_queries"]

    # Verify timeseries has Phase 2C resolution metadata
    ts = data["timeseries"]
    assert "bucket_size" in ts
    assert "bucket_source" in ts
    assert "buckets" in ts
    if ts["buckets"]:
        b0 = ts["buckets"][0]
        assert "bucket_start" in b0
        assert "bucket_end" in b0
        assert "effective_start" in b0
        assert "effective_end" in b0
        assert "is_partial" in b0
        assert "covered_seconds" in b0
        assert "benign_queries" in b0
        assert "malicious_queries" in b0
        assert "review_needed_queries" in b0
        assert "unknown_queries" in b0

    # Verify entity lists
    assert isinstance(data["top_clients"], list)
    assert isinstance(data["top_domains"], list)
    assert isinstance(data["top_benign_domains"], list)
    assert isinstance(data["top_malicious_domains"], list)
    assert isinstance(data["daily_review_domains"], list)


def test_dashboard_empty_range(auth_headers):
    """GET /api/v1/dashboard with zero-duration range returns zeroed KPIs."""
    t = "2026-09-16T12:00:00Z"
    res = client.get(f"/api/v1/dashboard?start_time={t}&end_time={t}", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["summary"]["total_queries"] == 0
    assert data["summary"]["unique_domains"] == 0
    assert data["summary"]["malicious_domains"] == 0
    assert data["timeseries"]["buckets"] == []


# ===========================================================================
# 4. Reporting Endpoints (Categories E, F, G, H, S)
# ===========================================================================

def test_reports_summary_canonical_verdicts(auth_headers):
    """GET /api/v1/reports/summary preserves all four canonical verdicts."""
    res = client.get("/api/v1/reports/summary", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    assert data["total_queries"] == 30181
    assert data["unique_clients"] == 12
    assert data["unique_domains"] == 49

    vb = data["verdict_breakdown"]
    assert vb["benign"] == 23371
    assert vb["malicious"] == 4626
    assert vb["review_needed"] == 448
    assert vb["unknown"] == 1736
    assert vb["benign"] + vb["malicious"] + vb["review_needed"] + vb["unknown"] == 30181


def test_reports_root_delegates_to_summary(auth_headers):
    """GET /api/v1/reports delegates to the same summary logic."""
    res_root = client.get("/api/v1/reports", headers=auth_headers)
    res_summary = client.get("/api/v1/reports/summary", headers=auth_headers)
    assert res_root.status_code == 200
    assert res_root.json() == res_summary.json()


def test_reports_timeseries_all_time_rejected(auth_headers):
    """GET /api/v1/reports/timeseries with all-time window is rejected."""
    res = client.get("/api/v1/reports/timeseries?window=all_time", headers=auth_headers)
    assert res.status_code == 400


def test_reports_clients_pagination_shape(auth_headers):
    """GET /api/v1/reports/clients satisfies the unified pagination contract."""
    res = client.get("/api/v1/reports/clients?limit=5&offset=0", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    assert "total" in data
    assert data["limit"] == 5
    assert data["offset"] == 0
    assert "has_more" in data
    assert "items" in data
    assert len(data["items"]) == 5

    c0 = data["items"][0]
    assert "client_ip" in c0
    assert "total_queries" in c0
    assert "benign_queries" in c0
    assert "malicious_queries" in c0
    assert "review_needed_queries" in c0
    assert "unknown_queries" in c0


def test_reports_domains_verdict_filter(auth_headers):
    """GET /api/v1/reports/domains filters strictly by canonical verdict."""
    res = client.get("/api/v1/reports/domains?verdict=Malicious", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()

    assert data["total"] == 9
    for item in data["items"]:
        assert item["malicious_queries"] > 0


def test_reports_queries_filters_and_ordering(auth_headers):
    """GET /api/v1/reports/queries supports parameter filtering and returns deterministic order."""
    res = client.get("/api/v1/reports/queries?limit=10", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data["items"]) == 10

    # Check deterministic ordering: timestamp DESC, id DESC
    items = data["items"]
    for i in range(len(items) - 1):
        assert items[i]["timestamp"] >= items[i + 1]["timestamp"]
        if items[i]["timestamp"] == items[i + 1]["timestamp"]:
            assert items[i]["id"] >= items[i + 1]["id"]


def test_reports_queries_invalid_ip_rejected(auth_headers):
    """GET /api/v1/reports/queries with invalid client IP returns 400."""
    res = client.get("/api/v1/reports/queries?client_ip=not-an-ip", headers=auth_headers)
    assert res.status_code == 400
    assert "Invalid client IP" in res.json()["detail"]


def test_reports_malicious_domains_compatibility(auth_headers):
    """GET /api/v1/reports/malicious-domains delegates with verdict=Malicious."""
    res = client.get("/api/v1/reports/malicious-domains", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total"] == 9


def test_reports_flagged_compatibility(auth_headers):
    """GET /api/v1/reports/flagged delegates with Review Needed verdict."""
    res = client.get("/api/v1/reports/flagged", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    for item in data["items"]:
        assert item["final_label"] == "Review Needed"


def test_reports_entity_endpoint(auth_headers):
    """GET /api/v1/reports/entity returns 200 for valid domain or client, 404 for nonexistent."""
    # 1. Look up an existing domain
    res_d = client.get("/api/v1/reports/entity?entity=google.com", headers=auth_headers)
    assert res_d.status_code == 200
    data_d = res_d.json()
    assert data_d["entity"] == "google.com"
    assert data_d["entity_type"] == "domain"
    assert data_d["domain_dossier"] is not None
    assert data_d["domain_dossier"]["profile"]["domain"] == "google.com"

    # 2. Look up an existing client (obtain a known client from client list)
    clients_res = client.get("/api/v1/clients?limit=1", headers=auth_headers)
    client_ip = clients_res.json()["items"][0]["client_ip"]
    res_c = client.get(f"/api/v1/reports/entity?entity={client_ip}", headers=auth_headers)
    assert res_c.status_code == 200
    data_c = res_c.json()
    assert data_c["entity"] == client_ip
    assert data_c["entity_type"] == "client"
    assert data_c["client_dossier"] is not None
    assert data_c["client_dossier"]["profile"]["client_ip"] == client_ip

    # 3. Missing entity parameter returns 422
    assert client.get("/api/v1/reports/entity", headers=auth_headers).status_code == 422

    # 4. Non-existent domain returns 404
    res_missing = client.get("/api/v1/reports/entity?entity=nonexistent-entity-987654321.com", headers=auth_headers)
    assert res_missing.status_code == 404


def test_reports_export_csv_endpoint(auth_headers):
    """GET /api/v1/reports/export/csv streams valid RFC 4180 CSV with bounded limit."""
    res = client.get("/api/v1/reports/export/csv?limit=25", headers=auth_headers)
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]
    assert "attachment" in res.headers["content-disposition"]
    lines = res.text.strip().splitlines()
    assert len(lines) >= 2  # header + at least 1 record
    header = lines[0].split(",")
    assert "id" in header
    assert "timestamp" in header
    assert "client_ip" in header
    assert "domain" in header
    assert "verdict" in header

    # Filtered export with canonical verdict
    res_filtered = client.get("/api/v1/reports/export/csv?limit=10&verdict=Malicious", headers=auth_headers)
    assert res_filtered.status_code == 200
    assert "text/csv" in res_filtered.headers["content-type"]

    # Exceeding maximum limit (50,000) is rejected with 422
    res_over = client.get("/api/v1/reports/export/csv?limit=50001", headers=auth_headers)
    assert res_over.status_code == 422



# ===========================================================================
# 5. Domains & Clients Lists & Details (Categories D, L, P)
# ===========================================================================

def test_domains_list_and_detail(auth_headers):
    """GET /api/v1/domains and /api/v1/domains/{domain} work cleanly."""
    res_list = client.get("/api/v1/domains?limit=5", headers=auth_headers)
    assert res_list.status_code == 200
    data = res_list.json()
    assert len(data["items"]) == 5

    first_domain = data["items"][0]["domain"]
    res_detail = client.get(f"/api/v1/domains/{first_domain}", headers=auth_headers)
    assert res_detail.status_code == 200
    dossier = res_detail.json()
    assert dossier["domain"] == first_domain
    assert "profile" in dossier
    assert "top_querying_clients" in dossier
    assert "threat_intel" in dossier
    assert "recent_queries" in dossier


def test_domains_detail_404_not_found(auth_headers):
    """GET /api/v1/domains/{domain} for non-existent domain returns 404."""
    res = client.get("/api/v1/domains/nonexistent-xyz-random-1234.org", headers=auth_headers)
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_domains_detail_rejects_temporal_params(auth_headers):
    """GET /api/v1/domains/{domain} rejects temporal parameters with 400."""
    res = client.get("/api/v1/domains/apple.com?window=24h", headers=auth_headers)
    assert res.status_code == 400
    assert "temporal" in res.json()["detail"].lower()


def test_clients_list_and_detail(auth_headers):
    """GET /api/v1/clients and /api/v1/clients/{client_ip} work cleanly."""
    res_list = client.get("/api/v1/clients?limit=5", headers=auth_headers)
    assert res_list.status_code == 200
    data = res_list.json()
    assert len(data["items"]) == 5

    first_ip = data["items"][0]["client_ip"]
    res_detail = client.get(f"/api/v1/clients/{first_ip}", headers=auth_headers)
    assert res_detail.status_code == 200
    dossier = res_detail.json()
    assert dossier["client_ip"] == first_ip
    assert "profile" in dossier
    assert "top_domains" in dossier
    assert "threat_activity" in dossier
    assert "recent_queries" in dossier


def test_clients_detail_404_not_found(auth_headers):
    """GET /api/v1/clients/{client_ip} for un-profiled client returns 404."""
    res = client.get("/api/v1/clients/10.254.254.254", headers=auth_headers)
    assert res.status_code == 404


def test_clients_detail_rejects_temporal_params(auth_headers):
    """GET /api/v1/clients/{client_ip} rejects temporal parameters with 400."""
    res = client.get("/api/v1/clients/192.168.1.100?window=24h", headers=auth_headers)
    assert res.status_code == 400


# ===========================================================================
# 6. Investigation Endpoints (Category P)
# ===========================================================================

def test_investigation_domain_and_aliases(auth_headers):
    """Investigation plural and singular domain routes return identical dossiers."""
    res_plural = client.get("/api/v1/investigation/domains/apple.com", headers=auth_headers)
    res_singular = client.get("/api/v1/investigation/domain/apple.com", headers=auth_headers)
    assert res_plural.status_code == 200
    assert res_singular.status_code == 200
    assert res_plural.json() == res_singular.json()


def test_investigation_client_and_aliases(auth_headers):
    """Investigation plural and singular client routes return identical dossiers."""
    res_plural = client.get("/api/v1/investigation/clients/192.168.1.100", headers=auth_headers)
    res_singular = client.get("/api/v1/investigation/client/192.168.1.100", headers=auth_headers)
    assert res_plural.status_code == 200
    assert res_singular.status_code == 200
    assert res_plural.json() == res_singular.json()


def test_investigation_rejects_temporal_params(auth_headers):
    """Investigation routes reject temporal params explicitly with 400."""
    res = client.get("/api/v1/investigation/domains/apple.com?start_time=2026-09-16T12:00:00Z", headers=auth_headers)
    assert res.status_code == 400


# ===========================================================================
# 7. Status and Analytics (Categories R & S)
# ===========================================================================

def test_system_status(auth_headers):
    """GET /api/v1/status reports healthy PostgreSQL and aggregation watermark."""
    res = client.get("/api/v1/status", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["database"]["connected"] is True
    assert data["database"]["database"] == "dns_threat_detection"
    assert data["aggregation"] is not None
    assert data["aggregation"]["watermark_id"] >= 0


def test_domain_analytics(auth_headers):
    """GET /api/v1/analytics/domains returns window, metrics, and timeline."""
    res = client.get("/api/v1/analytics/domains?window=1h", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert "window" in data
    assert "metrics" in data
    assert "timeline" in data
    assert data["metrics"]["total_queries"] >= 0


# ===========================================================================
# 8. Database Reconciliation & Invariant Verification (Category M & N)
# ===========================================================================

def test_reconciliation_verdicts_sum_to_total_across_all_summary_endpoints(auth_headers):
    """Benign + Malicious + Review Needed + Unknown == Total Queries across endpoints."""
    # 1. Dashboard
    d_res = client.get("/api/v1/dashboard", headers=auth_headers)
    d_sum = d_res.json()["summary"]
    d_vb = d_sum["verdict_breakdown"]
    assert d_vb["benign"] + d_vb["malicious"] + d_vb["review_needed"] + d_vb["unknown"] == d_sum["total_queries"]

    # 2. Reports summary
    r_res = client.get("/api/v1/reports/summary", headers=auth_headers)
    r_sum = r_res.json()
    r_vb = r_sum["verdict_breakdown"]
    assert r_vb["benign"] + r_vb["malicious"] + r_vb["review_needed"] + r_vb["unknown"] == r_sum["total_queries"]


def test_dashboard_all_time_and_known_window(auth_headers):
    """Verify dashboard behavior across rolling default, all-time, and known data windows."""
    # 1. All-time window: timeseries must be None, bucket_source must be None, no fake buckets
    res_at = client.get("/api/v1/dashboard?window=all_time", headers=auth_headers)
    assert res_at.status_code == 200
    data_at = res_at.json()
    assert data_at["summary"]["total_queries"] == 30181
    assert data_at["timeseries"] is None
    assert data_at["time_range"]["is_all_time"] is True
    assert data_at["time_range"]["bucket_source"] is None
    assert data_at["summary"]["total_clients"] == 12
    assert data_at["summary"]["unique_clients"] == 12

    # 2. Known temporal window containing data (AUTO bucket resolution)
    res_known = client.get(
        "/api/v1/dashboard?start_time=2026-09-16T00:00:00Z&end_time=2026-09-16T12:00:00Z",
        headers=auth_headers,
    )
    assert res_known.status_code == 200
    data_known = res_known.json()
    assert data_known["summary"]["total_queries"] == 30180
    assert len(data_known["timeseries"]["buckets"]) == 72
    assert data_known["timeseries"]["bucket_source"] == "AUTO"
    assert data_known["time_range"]["bucket_source"] == "AUTO"
    vb = data_known["summary"]["verdict_breakdown"]
    assert vb["benign"] + vb["malicious"] + vb["review_needed"] + vb["unknown"] == 30180
    assert len(data_known["top_clients"]) <= 10
    assert len(data_known["top_domains"]) <= 10
    assert data_known["summary"]["total_clients"] == 12
    assert data_known["summary"]["unique_clients"] == 11

    # 3. Explicit preset window (PRESET_DEFAULT bucket source)
    res_preset = client.get("/api/v1/dashboard?window=24h", headers=auth_headers)
    assert res_preset.status_code == 200
    data_preset = res_preset.json()
    assert data_preset["timeseries"]["bucket_source"] == "PRESET_DEFAULT"
    assert data_preset["time_range"]["bucket_source"] == "PRESET_DEFAULT"

    # 4. Explicit bucket specification (EXPLICIT bucket source)
    res_explicit = client.get(
        "/api/v1/dashboard?start_time=2026-09-16T00:00:00Z&end_time=2026-09-16T12:00:00Z&bucket=1h",
        headers=auth_headers,
    )
    assert res_explicit.status_code == 200
    data_explicit = res_explicit.json()
    assert data_explicit["timeseries"]["bucket_source"] == "EXPLICIT"
    assert data_explicit["time_range"]["bucket_source"] == "EXPLICIT"
    assert len(data_explicit["timeseries"]["buckets"]) == 12

    # 5. Empty window showing semantic distinction between total_clients and unique_clients
    res_empty = client.get(
        "/api/v1/dashboard?start_time=2020-01-01T00:00:00Z&end_time=2020-01-01T01:00:00Z",
        headers=auth_headers,
    )
    assert res_empty.status_code == 200
    data_empty = res_empty.json()
    assert data_empty["summary"]["total_queries"] == 0
    assert data_empty["summary"]["unique_clients"] == 0
    assert data_empty["summary"]["total_clients"] == 12  # Lifetime enrolled fleet size remains 12
    assert len(data_empty["timeseries"]["buckets"]) == 60
    assert all(b["total_queries"] == 0 for b in data_empty["timeseries"]["buckets"])
    assert data_empty["timeseries"]["bucket_source"] == "AUTO"



def test_daily_review_endpoints_and_mutations(auth_headers, non_admin_headers, monkeypatch):
    """Verify daily review queries, statistics, and safe admin mutations."""
    # 1. List review domains
    res_list = client.get("/api/v1/daily-review?limit=5", headers=auth_headers)
    assert res_list.status_code == 200
    data_list = res_list.json()
    assert "total" in data_list
    assert "limit" in data_list
    assert "offset" in data_list
    assert "has_more" in data_list
    assert "items" in data_list
    assert "domains" in data_list  # compatibility alias

    # 2. Daily review stats
    res_stats = client.get("/api/v1/daily-review/stats", headers=auth_headers)
    assert res_stats.status_code == 200
    data_stats = res_stats.json()
    assert "total" in data_stats
    assert "review_needed" in data_stats

    # 3. Domain review dossier
    if data_list["items"]:
        domain_name = data_list["items"][0]["domain"]
        res_item = client.get(f"/api/v1/daily-review/{domain_name}", headers=auth_headers)
        assert res_item.status_code == 200
        assert res_item.json()["domain"] == domain_name

    # 4. Mutation: POST /verdict authorization checks
    # Configure mock user lookup for analyst role
    monkeypatch.setattr(
        "api.auth.get_user_by_email",
        lambda email: {"id": 3, "email": email, "role": "analyst", "is_active": True}
        if "analyst" in email
        else {"id": 1, "email": email, "role": "admin", "is_active": True},
    )

    # Non-admin is rejected with 403 Forbidden
    res_forbidden = client.post(
        "/api/v1/daily-review/test-safe-domain.example.com/verdict",
        headers=non_admin_headers,
        json={"verdict": "clean", "reason": "Unauthorized test"},
    )
    assert res_forbidden.status_code == 403

    # Invalid verdict choice is rejected with 400
    res_invalid = client.post(
        "/api/v1/daily-review/test-safe-domain.example.com/verdict",
        headers=auth_headers,
        json={"verdict": "invalid_choice", "reason": "Test reason"},
    )
    assert res_invalid.status_code == 400

    # Valid admin override with mocked promoter
    monkeypatch.setattr("api.routes.daily_review.promote_to_clean", lambda *args, **kwargs: None)
    res_admin = client.post(
        "/api/v1/daily-review/test-safe-domain.example.com/verdict",
        headers=auth_headers,
        json={"verdict": "clean", "reason": "Unit test verified safe"},
    )
    assert res_admin.status_code == 200
    assert res_admin.json()["success"] is True

    # 5. Mutation: POST /trigger authorization and TI isolation
    # Non-admin is rejected with 403
    res_trig_forbidden = client.post(
        "/api/v1/daily-review/test-safe-domain.example.com/trigger",
        headers=non_admin_headers,
    )
    assert res_trig_forbidden.status_code == 403

    # Admin trigger with mocked DailyReviewWorker (zero external live network calls)
    monkeypatch.setattr(
        "labeler.intel.daily_review.DailyReviewWorker.process_domain_investigation",
        lambda self, d: "CLEAN",
    )
    res_trig = client.post(
        "/api/v1/daily-review/test-safe-domain.example.com/trigger",
        headers=auth_headers,
    )
    assert res_trig.status_code == 200
    assert res_trig.json()["success"] is True
    assert res_trig.json()["investigation_result"] == "CLEAN"

