"""
Unit & Integration Tests for PostgreSQL-Backed Dashboard API
===========================================================
Validates:
- GET /api/v1/dashboard (bundle)
- GET /api/v1/summary (KPIs)
- GET /api/v1/threats/timeseries (hourly volume)
- GET /api/v1/threats/categories (threat breakdown)
- GET /api/v1/threats/geo (geo structure)
- GET /api/v1/domains (paginated, search, label filter)
- GET /api/v1/domains/top (top 20 domains)
- GET /api/v1/domains/recent (recent flagged detections)
- GET /api/v1/domains/{domain} (domain profile & DNS breakdown)
- GET /api/v1/clients (paginated, search)
- GET /api/v1/clients/top (top 20 clients)
- GET /api/v1/clients/{client_ip} (client profile & top destinations)
- GET /api/v1/status (honest PostgreSQL status)
"""

from __future__ import annotations

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient
from api.main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


class TestDashboardPostgresAPI:
    def test_dashboard_bundle(self, client):
        res = client.get("/api/v1/dashboard")
        assert res.status_code == 200
        body = res.json()
        assert body["status"] == "success"
        data = body["data"]

        # Summary
        summary = data["summary"]
        assert summary is not None
        assert summary["total_queries"] > 0
        assert summary["unique_clients"] > 0
        assert summary["unique_domains"] > 0
        assert "threats_blocked_pct" in summary

        # Arrays
        assert isinstance(data["timeseries"], list)
        assert len(data["timeseries"]) > 0
        assert isinstance(data["categories"], list)
        assert isinstance(data["top_domains"], list)
        assert len(data["top_domains"]) > 0
        assert isinstance(data["top_clients"], list)
        assert len(data["top_clients"]) > 0
        assert isinstance(data["recent_flagged"], list)

        # Honest status
        assert data["aggregation"]["name"] == "postgresql"

    def test_summary_kpis(self, client):
        res = client.get("/api/v1/summary")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["total_queries"] >= 1000
        assert data["unique_clients"] >= 1
        assert data["unique_domains"] >= 1

    def test_threats_timeseries(self, client):
        res = client.get("/api/v1/threats/timeseries")
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) > 0
        first = data[0]
        assert "time_bucket" in first
        assert "total_queries" in first
        assert "threat_queries" in first

    def test_threats_categories(self, client):
        res = client.get("/api/v1/threats/categories")
        assert res.status_code == 200
        data = res.json()["data"]
        assert isinstance(data, list)
        for cat in data:
            assert "category" in cat
            assert "count" in cat
            assert "pct" in cat

    def test_threats_geo(self, client):
        res = client.get("/api/v1/threats/geo")
        assert res.status_code == 200
        body = res.json()
        assert body["geoip_enabled"] is False
        assert isinstance(body["data"], list)

    def test_domains_pagination(self, client):
        res = client.get("/api/v1/domains?page=1&page_size=10")
        assert res.status_code == 200
        body = res.json()
        assert len(body["data"]) <= 10
        assert body["meta"]["page"] == 1
        assert body["meta"]["page_size"] == 10
        assert body["meta"]["total"] > 0
        assert body["meta"]["pages"] >= 1

        first = body["data"][0]
        assert "domain" in first
        assert "total_queries" in first
        assert "unique_clients" in first
        assert "label" in first

    def test_domains_search(self, client):
        res = client.get("/api/v1/domains?search=google")
        assert res.status_code == 200
        data = res.json()["data"]
        for d in data:
            assert "google" in d["domain"].lower()

    def test_domains_top(self, client):
        res = client.get("/api/v1/domains/top")
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) <= 20
        # Verify sorted descending
        counts = [d["query_count"] for d in data]
        assert counts == sorted(counts, reverse=True)

    def test_domains_recent_flagged(self, client):
        res = client.get("/api/v1/domains/recent")
        assert res.status_code == 200
        data = res.json()["data"]
        assert isinstance(data, list)
        if data:
            first = data[0]
            assert "domain" in first
            assert "flagged_at" in first
            assert first["label"].lower() == "malicious"

    def test_domain_detail_success(self, client):
        res = client.get("/api/v1/domains/google.com")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["domain"] == "google.com"
        assert data["source"] == "postgresql"
        assert "stats" in data
        assert data["stats"]["total_queries"] > 0
        assert "dns" in data
        assert "A" in data["dns"]["query_type_breakdown"]

    def test_domain_detail_not_found(self, client):
        res = client.get("/api/v1/domains/thisdomaindoesnotexist12345.xyz")
        assert res.status_code == 404

    def test_clients_pagination(self, client):
        res = client.get("/api/v1/clients?page=1&page_size=10")
        assert res.status_code == 200
        body = res.json()
        assert len(body["data"]) <= 10
        assert body["meta"]["page"] == 1
        assert body["meta"]["total"] > 0

        first = body["data"][0]
        assert "client_ip" in first
        assert "total_queries" in first
        assert "unique_domains" in first

    def test_clients_top(self, client):
        res = client.get("/api/v1/clients/top")
        assert res.status_code == 200
        data = res.json()["data"]
        assert len(data) <= 20
        counts = [c["query_count"] for c in data]
        assert counts == sorted(counts, reverse=True)

    def test_client_detail_success(self, client):
        res = client.get("/api/v1/clients/10.0.0.5")
        assert res.status_code == 200
        data = res.json()["data"]
        assert data["client_ip"] == "10.0.0.5"
        assert data["source"] == "postgresql"
        assert data["stats"]["total_queries"] > 0
        assert isinstance(data["top_domains"], list)

    def test_client_detail_not_found(self, client):
        res = client.get("/api/v1/clients/192.0.2.254")
        assert res.status_code == 404

    def test_status_honest_postgresql(self, client):
        res = client.get("/api/v1/status")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["database"] == "postgresql"
        assert data["total_queries"] > 0
        assert data["unique_domains"] > 0
        assert data["unique_clients"] > 0
        assert "last_event_ts" in data
