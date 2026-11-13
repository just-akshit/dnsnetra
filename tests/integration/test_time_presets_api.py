"""Short presets and all-time correctness across the API."""

from fastapi.testclient import TestClient

from apps.api.main import app

client = TestClient(app)


def test_short_presets_are_accepted_and_bucketed(admin_headers):
    for window, expected_bucket in (
        ("30s", "5s"),
        ("1m", "10s"),
        ("5m", "30s"),
        ("10m", "1m"),
        ("15m", "1m"),
    ):
        res = client.get(
            "/api/v1/dashboard", headers=admin_headers, params={"window": window}
        )
        assert res.status_code == 200, f"{window}: {res.text}"
        body = res.json()
        assert body["timeseries"]["bucket_size"] == expected_bucket, window
        assert 0 < len(body["timeseries"]["buckets"]) <= 100, window


def test_all_time_returns_real_data(admin_headers):
    for path in ("/api/v1/domains", "/api/v1/clients", "/api/v1/reports/queries"):
        res = client.get(
            path, headers=admin_headers, params={"window": "all_time", "limit": 1}
        )
        assert res.status_code == 200, f"{path}: {res.text}"
        assert res.json()["total"] > 0, path


def test_dashboard_all_time_has_a_bounded_timeline(admin_headers):
    res = client.get(
        "/api/v1/dashboard", headers=admin_headers, params={"window": "all_time"}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["summary"]["total_queries"] > 0
    assert len(body["timeseries"]["buckets"]) > 0
    assert len(body["timeseries"]["buckets"]) <= 100
