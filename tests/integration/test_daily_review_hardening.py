"""Daily-review hardening: atomic promote, confidence, search escaping."""

import uuid

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from dnsnetra.intelligence.labeling.daily_review import repository as daily_review_repository
from dnsnetra.intelligence.labeling.daily_review.repository import (
    promote_to_malicious,
    upsert_review_needed,
)
from dnsnetra.intelligence.reputation.connection import get_connection
from dnsnetra.intelligence.reputation.repository import get_domain, store_malicious_domain

client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup_domains():
    """Track per-test domains and delete every row they created afterwards."""
    domains: list[str] = []
    yield domains
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                for domain in domains:
                    cur.execute("DELETE FROM daily_review_domains WHERE domain = %s", (domain,))
                    cur.execute("DELETE FROM reviewed_clean_domains WHERE domain = %s", (domain,))
                    cur.execute("DELETE FROM reputation_domains WHERE domain = %s", (domain,))
            conn.commit()
    except Exception:
        pass


def test_zero_confidence_is_preserved(admin_headers, cleanup_domains):
    domain = f"zero-confidence-{uuid.uuid4().hex}.example"
    cleanup_domains.append(domain)

    res = client.post(
        f"/api/v1/daily-review/{domain}/verdict",
        headers=admin_headers,
        json={"verdict": "malicious", "reason": "test", "confidence": 0.0},
    )
    assert res.status_code == 200

    record = get_domain(domain)
    assert record["confidence"] == 0.0


def test_promotion_rolls_back_when_review_update_fails(monkeypatch, cleanup_domains):
    domain = f"atomic-{uuid.uuid4().hex}.example"
    cleanup_domains.append(domain)

    def failing_store(domain, metadata=None, conn=None, **kwargs):
        # Run the real insert on the caller's connection, then fail before the
        # daily_review_domains update so the whole transaction must roll back.
        store_malicious_domain(domain, metadata=metadata, conn=conn, **kwargs)
        raise RuntimeError("boom")

    monkeypatch.setattr(
        daily_review_repository, "store_malicious_domain", failing_store
    )

    with pytest.raises(RuntimeError, match="boom"):
        promote_to_malicious(domain, metadata={"source": "test"})

    assert get_domain(domain) is None


def test_review_search_escapes_wildcards(admin_headers, cleanup_domains):
    domain = f"search-{uuid.uuid4().hex}.example"
    cleanup_domains.append(domain)
    upsert_review_needed(domain, reason="hardening-test")

    full = client.get(
        "/api/v1/daily-review",
        headers=admin_headers,
        params={"status": "all", "limit": 1},
    )
    assert full.status_code == 200
    assert full.json()["total"] >= 1

    res = client.get(
        "/api/v1/daily-review",
        headers=admin_headers,
        params={"search": "%", "status": "all"},
    )
    assert res.status_code == 200
    assert res.json()["total"] == 0
    assert res.json()["total"] != full.json()["total"]
