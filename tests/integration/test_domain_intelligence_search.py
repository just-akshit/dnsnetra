"""HTTP integration tests for the search endpoints behind the domain-intelligence bar.

The bar has no dedicated endpoint: it aggregates ``/api/v1/domains``,
``/api/v1/clients`` and ``/api/v1/queries`` with a ``search`` term, then lands
on the investigation dossier. These tests pin that contract at the HTTP seam.

Assertions are behavioral (case-insensitivity, substring matching, blank-term
handling, pagination) rather than exact fixture counts, so they survive dataset
changes.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app
from dnsnetra.core.security.rate_limiter import reset_rate_limits
from dnsnetra.domains.investigations.live.models import IndicatorVerdict, LiveIntelReport

client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_rate_limits_each_test():
    reset_rate_limits()
    yield
    reset_rate_limits()


def _items(path: str, headers: dict[str, str], **params: object) -> dict:
    res = client.get(path, headers=headers, params=params)
    assert res.status_code == 200, res.text
    return res.json()


def _known_domain(headers: dict[str, str]) -> str:
    payload = _items("/api/v1/domains", headers, limit=1)
    if not payload["items"]:
        pytest.skip("No domain-profile fixture data in this database.")
    return payload["items"][0]["domain"]


def _known_client(headers: dict[str, str]) -> str:
    payload = _items("/api/v1/clients", headers, limit=1)
    if not payload["items"]:
        pytest.skip("No client-profile fixture data in this database.")
    return payload["items"][0]["client_ip"]


def _known_query(headers: dict[str, str]) -> dict:
    payload = _items("/api/v1/reports/queries", headers, limit=1)
    if not payload["items"]:
        pytest.skip("No query-history fixture data in this database.")
    return payload["items"][0]


# ---------------------------------------------------------------------------
# Domains search
# ---------------------------------------------------------------------------

def test_domain_search_returns_the_searched_domain(admin_headers):
    domain = _known_domain(admin_headers)

    payload = _items("/api/v1/domains", admin_headers, search=domain)

    assert payload["total"] >= 1
    assert domain in {item["domain"] for item in payload["items"]}


def test_domain_search_is_case_insensitive(admin_headers):
    domain = _known_domain(admin_headers)

    lower = _items("/api/v1/domains", admin_headers, search=domain.lower())
    upper = _items("/api/v1/domains", admin_headers, search=domain.upper())

    assert upper["total"] == lower["total"]


def test_domain_search_only_returns_matching_rows(admin_headers):
    term = _known_domain(admin_headers)[:4]

    payload = _items("/api/v1/domains", admin_headers, search=term, limit=10)

    assert payload["items"]
    for item in payload["items"]:
        assert term.lower() in item["domain"].lower()


def test_domain_search_without_match_is_empty(admin_headers):
    payload = _items(
        "/api/v1/domains", admin_headers, search="zzz-no-such-domain-zzz"
    )

    assert payload["total"] == 0
    assert payload["items"] == []
    assert payload["has_more"] is False


def test_domain_search_respects_limit(admin_headers):
    payload = _items("/api/v1/domains", admin_headers, search="a", limit=2)

    assert len(payload["items"]) <= 2
    assert payload["limit"] == 2


def test_blank_domain_search_is_ignored(admin_headers):
    unfiltered = _items("/api/v1/domains", admin_headers, limit=5)
    blank = _items("/api/v1/domains", admin_headers, search="   ", limit=5)

    assert blank["total"] == unfiltered["total"]


# ---------------------------------------------------------------------------
# Clients search
# ---------------------------------------------------------------------------

def test_client_search_returns_the_searched_ip(admin_headers):
    client_ip = _known_client(admin_headers)

    payload = _items("/api/v1/clients", admin_headers, search=client_ip)

    assert payload["total"] >= 1
    assert client_ip in {item["client_ip"] for item in payload["items"]}


def test_client_search_only_returns_matching_rows(admin_headers):
    client_ip = _known_client(admin_headers)
    term = client_ip.split(".")[0]

    payload = _items("/api/v1/clients", admin_headers, search=term, limit=10)

    assert payload["items"]
    for item in payload["items"]:
        assert term in item["client_ip"]


def test_client_search_without_match_is_empty(admin_headers):
    payload = _items("/api/v1/clients", admin_headers, search="zzz-not-an-ip")

    assert payload["total"] == 0
    assert payload["items"] == []


def test_blank_client_search_is_ignored(admin_headers):
    unfiltered = _items("/api/v1/clients", admin_headers, limit=5)
    blank = _items("/api/v1/clients", admin_headers, search="   ", limit=5)

    assert blank["total"] == unfiltered["total"]


# ---------------------------------------------------------------------------
# Queries search
# ---------------------------------------------------------------------------

def test_query_search_returns_matching_domain_or_client(admin_headers):
    query = _known_query(admin_headers)
    term = query["domain"]

    payload = _items("/api/v1/reports/queries", admin_headers, search=term, limit=10)

    assert payload["total"] >= 1
    assert any(item["domain"] == term for item in payload["items"])
    for item in payload["items"]:
        assert term.lower() in (item["domain"] + "|" + item["client_ip"]).lower()


def test_query_search_matches_client_ip(admin_headers):
    query = _known_query(admin_headers)
    client_ip = query["client_ip"]

    payload = _items("/api/v1/reports/queries", admin_headers, search=client_ip, limit=10)

    assert payload["total"] >= 1
    for item in payload["items"]:
        assert client_ip in (item["domain"] + "|" + item["client_ip"])


def test_query_search_is_case_insensitive(admin_headers):
    term = _known_query(admin_headers)["domain"]

    lower = _items("/api/v1/reports/queries", admin_headers, search=term.lower())
    upper = _items("/api/v1/reports/queries", admin_headers, search=term.upper())

    assert upper["total"] == lower["total"]


def test_query_search_without_match_is_empty(admin_headers):
    payload = _items(
        "/api/v1/reports/queries", admin_headers, search="zzz-no-such-query-zzz"
    )

    assert payload["total"] == 0
    assert payload["items"] == []


# ---------------------------------------------------------------------------
# Abuse hardening
# ---------------------------------------------------------------------------

def test_like_wildcards_are_treated_literally(admin_headers):
    """A bare `%` must not turn into a full-table scan."""
    for path in ("/api/v1/domains", "/api/v1/clients", "/api/v1/reports/queries"):
        payload = _items(path, admin_headers, search="%")
        assert payload["total"] == 0


def test_overlong_search_term_does_not_error(admin_headers):
    payload = _items("/api/v1/domains", admin_headers, search="a" * 500)

    assert payload["total"] == 0


def test_investigation_refresh_flag_bypasses_live_cache(monkeypatch, admin_headers):
    from apps.api.routes import investigation as investigation_routes

    seen: list[bool] = []

    class FakeLiveIntel:
        def lookup_domain(self, value, refresh=False):
            seen.append(refresh)
            return None

        def lookup_ip(self, value, refresh=False):
            seen.append(refresh)
            return None

    monkeypatch.setattr(investigation_routes, "LiveIntelService", FakeLiveIntel)

    res = client.get(
        "/api/v1/investigation/domains/refresh-check.example",
        headers=admin_headers,
        params={"refresh": "true"},
    )

    assert res.status_code == 200
    assert seen == [True]


def test_typing_a_long_domain_does_not_trip_the_search_limiter(admin_headers):
    """One keystroke fans out to three endpoints; that must not eat the budget.

    A 25-character domain typed at the bar's debounce rate used to exhaust a
    single shared 60/min bucket and surface "partial results" during normal use.
    """
    for length in range(2, 27):
        for path in ("/api/v1/domains", "/api/v1/clients", "/api/v1/reports/queries"):
            res = client.get(path, headers=admin_headers, params={"search": "a" * length})
            assert res.status_code == 200, f"{path} limited at keystroke {length}: {res.text}"


def test_search_then_open_unseen_domain_reaches_a_dossier(monkeypatch, admin_headers):
    """Happy path through the bar, without a browser: search misses, dossier still opens."""
    term = "unseen-e2e.example"

    assert _items("/api/v1/domains", admin_headers, search=term)["total"] == 0

    from apps.api.routes import investigation as investigation_routes

    class FakeLiveIntel:
        def lookup_domain(self, value, refresh=False):
            return LiveIntelReport(
                indicator=value,
                kind="domain",
                verdict=IndicatorVerdict(state="unknown", reasons=["no data"]),
                checked_at="2026-11-08T00:00:00Z",
            )

        def lookup_ip(self, value, refresh=False):
            return None

    monkeypatch.setattr(investigation_routes, "LiveIntelService", FakeLiveIntel)

    res = client.get(f"/api/v1/investigation/domains/{term}", headers=admin_headers)

    assert res.status_code == 200
    body = res.json()
    assert body["observed_in_network"] is False
    assert body["live_intel"]["verdict"]["state"] == "unknown"


def test_search_is_rate_limited(monkeypatch, admin_headers):
    from dnsnetra.core.security import rate_limiter

    monkeypatch.setattr(rate_limiter, "SEARCH_MAX_REQUESTS", 2)
    rate_limiter.reset_rate_limits()

    for _ in range(2):
        assert client.get(
            "/api/v1/domains", headers=admin_headers, params={"search": "a"}
        ).status_code == 200

    limited = client.get(
        "/api/v1/domains", headers=admin_headers, params={"search": "a"}
    )

    assert limited.status_code == 429
    assert limited.headers.get("Retry-After")
