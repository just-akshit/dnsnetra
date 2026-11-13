"""DNS page endpoint: one row per queried domain."""

from fastapi.testclient import TestClient

from apps.api.main import app

client = TestClient(app)


def test_dns_domains_returns_one_row_per_domain(admin_headers):
    res = client.get("/api/v1/dns/domains", headers=admin_headers, params={"limit": 5})
    assert res.status_code == 200
    body = res.json()
    assert body["total"] > 0
    assert len(body["items"]) <= 5
    item = body["items"][0]
    assert {
        "domain",
        "registered_domain",
        "query_type",
        "client_ip",
        "first_seen",
        "last_seen",
        "total_queries",
    } <= set(item)
    assert body["items"] == sorted(
        body["items"], key=lambda row: row["last_seen"], reverse=True
    )


def test_dns_domains_search_matches_domain_or_registered(admin_headers):
    res = client.get(
        "/api/v1/dns/domains",
        headers=admin_headers,
        params={"search": "apple", "limit": 50},
    )
    assert res.status_code == 200
    for item in res.json()["items"]:
        haystack = f"{item['domain']} {item['registered_domain']}".lower()
        assert "apple" in haystack


def test_dns_domains_is_readable_by_support(support_headers):
    res = client.get("/api/v1/dns/domains", headers=support_headers, params={"limit": 1})
    assert res.status_code == 200
