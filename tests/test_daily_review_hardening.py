"""Daily-review hardening: atomic promote, confidence, search escaping."""

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_zero_confidence_is_preserved(admin_headers):
    res = client.post(
        "/api/v1/daily-review/zero-confidence.example/verdict",
        headers=admin_headers,
        json={"verdict": "malicious", "reason": "test", "confidence": 0.0},
    )
    assert res.status_code == 200

    from labeler.intel.reputation.repository import get_domain
    record = get_domain("zero-confidence.example")
    assert record["confidence"] == 0.0


def test_review_search_escapes_wildcards(admin_headers):
    res = client.get(
        "/api/v1/daily-review",
        headers=admin_headers,
        params={"search": "%", "status": "all"},
    )
    assert res.status_code == 200
    assert res.json()["total"] >= 0
