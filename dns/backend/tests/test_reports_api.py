"""
Test Suite: Reports API (PostgreSQL Only)
=========================================
Validates the read-only analytical reporting layer over PostgreSQL:
1. Report overview summary & continuous zero-filled timeseries.
2. Preset windows (5m, 1h, 24h, 7d, 30d, 1y).
3. Custom ranges and custom-over-preset precedence.
4. Zero-data intervals returning HTTP 200 with zero metrics (no 500).
5. Canonical half-open interval boundaries [start_time, end_time):
   - timestamp == start_time is INCLUDED.
   - timestamp == end_time is EXCLUDED.
6. Paginated DNS query records (/reports/queries).
7. Paginated top domains with latest_verdict (/reports/domains).
8. Paginated malicious domains having >= 1 malicious event (/reports/malicious-domains).
9. Paginated client activity (/reports/clients).
10. Paginated flagged queries (/reports/flagged).
11. Consistent streaming CSV export (/reports/export/csv).
12. Safety, parameter validation, and SQL injection resilience.
"""

from __future__ import annotations

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from api.main import app
from domain_profiling.connection import get_db_connection

client = TestClient(app)


# ===========================================================================
# 1. Report Overview & Time Window Tests
# ===========================================================================

class TestReportOverview:
    def test_report_overview_default_24h(self):
        resp = client.get("/api/v1/reports")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        data = body["data"]
        assert "time_range" in data
        assert data["time_range"]["preset"] == "24h"
        assert "summary" in data
        summary = data["summary"]
        assert "total_queries" in summary
        assert "malicious_queries" in summary
        assert "unique_domains" in summary
        assert "unique_clients" in summary
        assert "threat_percentage" in summary
        assert isinstance(data["timeseries"], list)

    @pytest.mark.parametrize("preset", ["1m", "5m", "15m", "30m", "1h", "6h", "12h", "24h", "7d", "30d", "6mo", "1y"])
    def test_report_overview_presets(self, preset):
        resp = client.get(f"/api/v1/reports?window={preset}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["time_range"]["preset"] == preset
        assert len(data["timeseries"]) > 0

    def test_report_overview_custom_range(self):
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/reports?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["time_range"]["start"] == start
        assert data["time_range"]["end"] == end
        assert data["summary"]["total_queries"] > 0

    def test_report_overview_custom_and_preset_conflict_rejected_with_400(self):
        # Mutual exclusivity: passing both window and custom start_time/end_time MUST return HTTP 400
        start = "2026-08-28T00:00:00Z"
        end = "2026-08-29T00:00:00Z"
        resp = client.get(f"/api/v1/reports?window=1m&start_time={start}&end_time={end}")
        assert resp.status_code == 400
        assert "Cannot specify both 'window' preset and custom" in resp.json()["detail"]

    def test_report_overview_zero_data_handling(self):
        # Far historical interval with no recorded queries
        start = "2015-01-01T00:00:00Z"
        end = "2015-01-01T01:00:00Z"
        resp = client.get(f"/api/v1/reports?start_time={start}&end_time={end}")
        assert resp.status_code == 200
        data = resp.json()["data"]
        summary = data["summary"]
        assert summary["total_queries"] == 0
        assert summary["malicious_queries"] == 0
        assert summary["unique_domains"] == 0
        assert summary["unique_clients"] == 0
        assert summary["threat_percentage"] == 0.0
        # Timeseries still returns continuous zero-filled buckets
        assert len(data["timeseries"]) > 0
        assert all(b["total_queries"] == 0 for b in data["timeseries"])
        assert all(b["malicious_queries"] == 0 for b in data["timeseries"])


# ===========================================================================
# 2. Canonical Half-Open Interval Boundary Tests [start, end)
# ===========================================================================

class TestHalfOpenIntervalBoundaries:
    """Proves that timestamp == start is INCLUDED and timestamp == end is EXCLUDED."""

    def test_half_open_boundary_precision(self):
        # Find an existing event timestamp in domain_query_history
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT timestamp FROM domain_query_history ORDER BY timestamp ASC LIMIT 1;")
                row = cur.fetchone()
                assert row is not None, "Precondition: domain_query_history has test data"
                event_ts: datetime = row[0]

        # Convert to proper UTC ISO strings
        from analytics.time_window import format_iso8601_utc
        start_iso = format_iso8601_utc(event_ts)
        later_iso = format_iso8601_utc(event_ts + timedelta(seconds=60))
        earlier_iso = format_iso8601_utc(event_ts - timedelta(seconds=60))

        # 1. Window [event_ts, later_ts) -> event_ts == start -> MUST BE INCLUDED
        resp_incl = client.get(f"/api/v1/reports/queries?start_time={start_iso}&end_time={later_iso}")
        assert resp_incl.status_code == 200
        incl_data = resp_incl.json()
        assert incl_data["meta"]["total"] >= 1

        # 2. Window [earlier_ts, event_ts) -> event_ts == end -> MUST BE EXCLUDED
        resp_excl = client.get(f"/api/v1/reports/queries?start_time={earlier_iso}&end_time={start_iso}")
        assert resp_excl.status_code == 200
        excl_data = resp_excl.json()
        event_utc = event_ts.astimezone(timezone.utc)
        for item in excl_data["data"]:
            item_dt = datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
            assert item_dt < event_utc


# ===========================================================================
# 3. Paginated Data Table Endpoints
# ===========================================================================

class TestReportDataTables:
    @pytest.fixture(autouse=True)
    def setup_range(self):
        self.start = "2026-08-28T00:00:00Z"
        self.end = "2026-08-29T00:00:00Z"

    def test_queries_table(self):
        resp = client.get(f"/api/v1/reports/queries?start_time={self.start}&end_time={self.end}&page=1&page_size=10")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "success"
        meta = body["meta"]
        assert meta["page"] == 1
        assert meta["page_size"] == 10
        assert meta["total"] > 0
        assert meta["pages"] >= 1
        items = body["data"]
        assert len(items) <= 10
        # Check ordering newest first
        if len(items) > 1:
            for i in range(1, len(items)):
                assert items[i - 1]["timestamp"] >= items[i]["timestamp"]

    def test_queries_table_filter_by_label(self):
        resp = client.get(f"/api/v1/reports/queries?start_time={self.start}&end_time={self.end}&label=Malicious")
        assert resp.status_code == 200
        items = resp.json()["data"]
        for item in items:
            assert item["final_label"].lower() == "malicious"

    def test_domains_table_latest_verdict(self):
        resp = client.get(f"/api/v1/reports/domains?start_time={self.start}&end_time={self.end}&page=1&page_size=20")
        assert resp.status_code == 200
        body = resp.json()
        items = body["data"]
        assert len(items) > 0
        for item in items:
            assert "domain" in item
            assert "query_count" in item
            assert "unique_clients" in item
            assert "malicious_queries" in item
            assert "latest_verdict" in item
            assert "first_seen" in item
            assert "last_seen" in item
            assert item["query_count"] >= item["malicious_queries"]

    def test_malicious_domains_table(self):
        resp = client.get(f"/api/v1/reports/malicious-domains?start_time={self.start}&end_time={self.end}")
        assert resp.status_code == 200
        items = resp.json()["data"]
        # All items must have at least 1 malicious query in the interval
        for item in items:
            assert item["malicious_queries"] >= 1
            assert "latest_verdict" in item
            assert "ti_source" in item

    def test_clients_table(self):
        resp = client.get(f"/api/v1/reports/clients?start_time={self.start}&end_time={self.end}&page=1&page_size=10")
        assert resp.status_code == 200
        body = resp.json()
        items = body["data"]
        assert len(items) > 0
        for item in items:
            assert "client_ip" in item
            assert "query_count" in item
            assert "unique_domains" in item
            assert "malicious_queries" in item
            assert item["query_count"] >= 1

    def test_flagged_queries_table(self):
        resp = client.get(f"/api/v1/reports/flagged?start_time={self.start}&end_time={self.end}&page=1&page_size=15")
        assert resp.status_code == 200
        body = resp.json()
        items = body["data"]
        assert len(items) > 0
        for item in items:
            assert item["final_label"].lower() == "malicious"
            assert "ti_source" in item
            assert "client_ip" in item


# ===========================================================================
# 4. CSV Export Tests (Consistent Data Reproduction)
# ===========================================================================

class TestReportCsvExport:
    @pytest.fixture(autouse=True)
    def setup_range(self):
        self.start = "2026-08-28T00:00:00Z"
        self.end = "2026-08-29T00:00:00Z"

    @pytest.mark.parametrize("table_name", ["queries", "domains", "malicious-domains", "clients", "flagged"])
    def test_csv_export_format_and_headers(self, table_name):
        resp = client.get(f"/api/v1/reports/export/csv?table={table_name}&start_time={self.start}&end_time={self.end}")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")
        assert "attachment" in resp.headers["content-disposition"]
        assert f"report_{table_name}_" in resp.headers["content-disposition"]

        text = resp.text
        lines = [line for line in text.split("\r\n") if line.strip()]
        assert len(lines) >= 1, "CSV must have header row"
        header = lines[0].split(",")
        if table_name == "queries":
            assert "domain" in header
            assert "client_ip" in header
            assert "final_label" in header
        elif table_name == "domains":
            assert "domain" in header
            assert "query_count" in header
            assert "latest_verdict" in header
        elif table_name == "malicious-domains":
            assert "domain" in header
            assert "malicious_queries" in header
            assert "ti_source" in header
        elif table_name == "clients":
            assert "client_ip" in header
            assert "unique_domains" in header

    def test_csv_export_count_matches_endpoint_count(self):
        # Verify that CSV row count matches endpoint total count exactly
        json_resp = client.get(f"/api/v1/reports/malicious-domains?start_time={self.start}&end_time={self.end}")
        assert json_resp.status_code == 200
        json_total = json_resp.json()["meta"]["total"]

        csv_resp = client.get(f"/api/v1/reports/export/csv?table=malicious-domains&start_time={self.start}&end_time={self.end}&limit=5000")
        assert csv_resp.status_code == 200
        csv_lines = [l for l in csv_resp.text.split("\r\n") if l.strip()]
        data_rows_count = len(csv_lines) - 1  # exclude header
        assert data_rows_count == json_total

    def test_csv_invalid_table_raises_400(self):
        resp = client.get(f"/api/v1/reports/export/csv?table=invalid_table")
        assert resp.status_code == 400
        assert "Invalid table" in resp.json()["detail"]


# ===========================================================================
# 5. Validation and Injection Resilience
# ===========================================================================

class TestValidationAndSecurity:
    def test_invalid_window_raises_400(self):
        resp = client.get("/api/v1/reports?window=invalid_preset")
        assert resp.status_code == 400

    def test_invalid_pagination_page_raises_422(self):
        resp = client.get("/api/v1/reports/queries?page=0")
        assert resp.status_code == 422

    def test_invalid_pagination_pagesize_raises_422(self):
        resp = client.get("/api/v1/reports/queries?page_size=1000")
        assert resp.status_code == 422

    def test_sql_injection_resilience_in_search(self):
        # Dangerous string in search query
        payload = "' OR 1=1; DROP TABLE dummy; --"
        resp = client.get(f"/api/v1/reports/queries?search={payload}")
        assert resp.status_code == 200
        # No SQL injection occurs; returns 0 rows safely
        assert resp.json()["meta"]["total"] == 0

    def test_partial_custom_range_rejected_with_400(self):
        # start_time without end_time
        resp1 = client.get("/api/v1/reports?start_time=2026-08-28T00:00:00Z")
        assert resp1.status_code == 400
        assert "Both 'start' and 'end' must be provided" in resp1.json()["detail"]

        # end_time without start_time
        resp2 = client.get("/api/v1/reports?end_time=2026-08-29T00:00:00Z")
        assert resp2.status_code == 400
        assert "Both 'start' and 'end' must be provided" in resp2.json()["detail"]

    def test_future_range_returns_200_empty(self):
        resp = client.get("/api/v1/reports?start_time=2099-01-01T00:00:00Z&end_time=2099-01-02T00:00:00Z")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["summary"]["total_queries"] == 0
        assert data["summary"]["malicious_queries"] == 0

        # Data table empty response
        resp_q = client.get("/api/v1/reports/queries?start_time=2099-01-01T00:00:00Z&end_time=2099-01-02T00:00:00Z")
        assert resp_q.status_code == 200
        assert resp_q.json()["data"] == []
        assert resp_q.json()["meta"]["total"] == 0


# ===========================================================================
# 6. Canonical Presets (6h verification & 5h rejection)
# ===========================================================================

class TestCanonicalPresets:
    def test_6h_preset_works_across_all_endpoints(self):
        # 1. Summary
        resp = client.get("/api/v1/reports?window=6h")
        assert resp.status_code == 200
        assert resp.json()["data"]["time_range"]["preset"] == "6h"
        assert resp.json()["data"]["time_range"]["bucket_seconds"] == 900  # 15 min buckets

        # 2. Queries
        resp = client.get("/api/v1/reports/queries?window=6h")
        assert resp.status_code == 200
        assert resp.json()["meta"]["time_range"]["preset"] == "6h"

        # 3. Domains
        resp = client.get("/api/v1/reports/domains?window=6h")
        assert resp.status_code == 200
        assert resp.json()["meta"]["time_range"]["preset"] == "6h"

        # 4. Malicious Domains
        resp = client.get("/api/v1/reports/malicious-domains?window=6h")
        assert resp.status_code == 200
        assert resp.json()["meta"]["time_range"]["preset"] == "6h"

        # 5. Clients
        resp = client.get("/api/v1/reports/clients?window=6h")
        assert resp.status_code == 200
        assert resp.json()["meta"]["time_range"]["preset"] == "6h"

        # 6. Flagged
        resp = client.get("/api/v1/reports/flagged?window=6h")
        assert resp.status_code == 200
        assert resp.json()["meta"]["time_range"]["preset"] == "6h"

        # 7. CSV
        resp = client.get("/api/v1/reports/export/csv?table=queries&window=6h&limit=10")
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/csv")

    def test_5h_preset_is_rejected_everywhere(self):
        resp = client.get("/api/v1/reports?window=5h")
        assert resp.status_code == 400
        assert "Invalid window preset '5h'" in resp.json()["detail"]

        resp_q = client.get("/api/v1/reports/queries?window=5h")
        assert resp_q.status_code == 400
        assert "Invalid window preset '5h'" in resp_q.json()["detail"]


# ===========================================================================
# 7. Cross-Endpoint Consistency Tests
# ===========================================================================

class TestCrossEndpointConsistency:
    @pytest.fixture(autouse=True)
    def setup_range(self):
        self.start = "2026-08-28T00:00:00Z"
        self.end = "2026-08-29T00:00:00Z"

    def test_summary_and_tables_consistency(self):
        # 1. Summary
        summary_resp = client.get(f"/api/v1/reports?start_time={self.start}&end_time={self.end}")
        assert summary_resp.status_code == 200
        summary = summary_resp.json()["data"]["summary"]

        # 2. Queries count must equal summary.total_queries
        queries_resp = client.get(f"/api/v1/reports/queries?start_time={self.start}&end_time={self.end}&page_size=1")
        assert queries_resp.status_code == 200
        queries_total = queries_resp.json()["meta"]["total"]
        assert summary["total_queries"] == queries_total

        # 3. Flagged count must equal summary.malicious_queries
        flagged_resp = client.get(f"/api/v1/reports/flagged?start_time={self.start}&end_time={self.end}&page_size=1")
        assert flagged_resp.status_code == 200
        flagged_total = flagged_resp.json()["meta"]["total"]
        assert summary["malicious_queries"] == flagged_total

        # 4. Domains count must equal summary.unique_domains
        domains_resp = client.get(f"/api/v1/reports/domains?start_time={self.start}&end_time={self.end}&page_size=1")
        assert domains_resp.status_code == 200
        domains_total = domains_resp.json()["meta"]["total"]
        assert summary["unique_domains"] == domains_total

        # 5. Clients count must equal summary.unique_clients
        clients_resp = client.get(f"/api/v1/reports/clients?start_time={self.start}&end_time={self.end}&page_size=1")
        assert clients_resp.status_code == 200
        clients_total = clients_resp.json()["meta"]["total"]
        assert summary["unique_clients"] == clients_total

    def test_malicious_domains_consistency(self):
        # Malicious domains must only contain domains with >= 1 malicious queries
        resp = client.get(f"/api/v1/reports/malicious-domains?start_time={self.start}&end_time={self.end}&page_size=500")
        assert resp.status_code == 200
        items = resp.json()["data"]
        for d in items:
            assert d["malicious_queries"] >= 1
            assert d["query_count"] >= d["malicious_queries"]

    def test_csv_matches_json_endpoint_counts_and_filters(self):
        # Query with search filter
        search_term = "example"
        json_resp = client.get(f"/api/v1/reports/queries?start_time={self.start}&end_time={self.end}&search={search_term}&page_size=1")
        assert json_resp.status_code == 200
        json_total = json_resp.json()["meta"]["total"]

        csv_resp = client.get(f"/api/v1/reports/export/csv?table=queries&start_time={self.start}&end_time={self.end}&search={search_term}&limit=5000")
        assert csv_resp.status_code == 200
        csv_lines = [l for l in csv_resp.text.split("\r\n") if l.strip()]
        assert len(csv_lines) - 1 == json_total


# ===========================================================================
# 8. Entity-Centric Reports Tests (Client IP & Domain Reports)
# ===========================================================================

class TestEntityReports:
    def test_client_report_192_168_1_104_7d(self):
        resp = client.get("/api/v1/reports/entity?entity=192.168.1.104&window=7d")
        assert resp.status_code == 200
        data = resp.json()["data"]
        summary = data["summary"]

        assert summary["entity"] == "192.168.1.104"
        assert summary["entity_type"] == "client"
        assert summary["total_queries"] >= 120
        assert summary["unique_domains"] >= 40
        assert "most_queried_domains" in data
        assert "malicious_domains" in data
        assert "clean_domains" in data
        assert "query_history" in data
        assert len(data["most_queried_domains"]) > 0

    def test_domain_report_stackoverflow_7d(self):
        resp = client.get("/api/v1/reports/entity?entity=stackoverflow.com&window=7d")
        assert resp.status_code == 200
        data = resp.json()["data"]
        summary = data["summary"]

        assert summary["entity"] == "stackoverflow.com"
        assert summary["entity_type"] == "domain"
        assert summary["total_queries"] >= 48
        assert summary["unique_clients"] >= 10
        assert "clients_querying" in data
        assert "query_history" in data
        assert len(data["clients_querying"]) > 0

    def test_entity_auto_detection(self):
        # IP automatically detects as client
        resp_ip = client.get("/api/v1/reports/entity?entity=10.0.0.5&window=7d")
        assert resp_ip.status_code == 200
        assert resp_ip.json()["data"]["summary"]["entity_type"] == "client"

        # Hostname automatically detects as domain
        resp_dom = client.get("/api/v1/reports/entity?entity=cloudflare.com&window=7d")
        assert resp_dom.status_code == 200
        assert resp_dom.json()["data"]["summary"]["entity_type"] == "domain"

    def test_entity_time_window_scaling(self):
        # 1m should return 0 or fewer than 7d
        resp_1m = client.get("/api/v1/reports/entity?entity=192.168.1.104&window=1m")
        assert resp_1m.status_code == 200
        total_1m = resp_1m.json()["data"]["summary"]["total_queries"]

        resp_7d = client.get("/api/v1/reports/entity?entity=192.168.1.104&window=7d")
        assert resp_7d.status_code == 200
        total_7d = resp_7d.json()["data"]["summary"]["total_queries"]

        assert total_7d >= total_1m

    def test_entity_empty_nonexistent(self):
        # A valid IP with no activity should return 200 with 0 queries
        resp = client.get("/api/v1/reports/entity?entity=10.254.254.254&window=7d")
        assert resp.status_code == 200
        data = resp.json()["data"]
        assert data["summary"]["total_queries"] == 0
        assert data["summary"]["unique_domains"] == 0
        assert data["most_queried_domains"] == []
        assert data["query_history"] == []

    def test_entity_invalid_identifier_rejected_with_400(self):
        # Invalid IP (out of bounds octet)
        resp1 = client.get("/api/v1/reports/entity?entity=999.999.999.999&window=7d")
        assert resp1.status_code == 400
        assert "Invalid entity identifier" in resp1.json()["detail"]

        # Malformed domain name
        resp2 = client.get("/api/v1/reports/entity?entity=invalid_domain_no_dot&window=7d")
        assert resp2.status_code == 400
        assert "Invalid entity identifier" in resp2.json()["detail"]

    def test_entity_empty_parameter_rejected_with_400(self):
        resp = client.get("/api/v1/reports/entity?entity=%20%20&window=7d")
        assert resp.status_code == 400

    def test_entity_csv_streaming_export(self):
        # Client queried domains CSV
        resp_c = client.get("/api/v1/reports/export/csv?table=client-domains&entity=192.168.1.104&window=7d")
        assert resp_c.status_code == 200
        assert "text/csv" in resp_c.headers["content-type"]
        assert "domain,query_count" in resp_c.text

        # Client unknown domains CSV
        resp_u = client.get("/api/v1/reports/export/csv?table=client-unknown&entity=192.168.1.104&window=7d")
        assert resp_u.status_code == 200
        assert "text/csv" in resp_u.headers["content-type"]
        assert "domain,query_count" in resp_u.text

        # Domain clients CSV
        resp_d = client.get("/api/v1/reports/export/csv?table=domain-clients&entity=stackoverflow.com&window=7d")
        assert resp_d.status_code == 200
        assert "text/csv" in resp_d.headers["content-type"]
        assert "client_ip,query_count" in resp_d.text


# ===========================================================================
# 11. Classification Immutability Tests
# ===========================================================================

class TestClassificationImmutability:
    """
    Validates the architectural invariant:
    'The pipeline decides the verdict. PostgreSQL persists the verdict.
     Reports only reports the verdict.'
    Reports must NEVER recalculate or alter persisted verdicts.
    """

    @pytest.fixture(autouse=True)
    def setup_immutability_fixtures(self):
        """Inserts test records with all four verdicts for an isolated test entity."""
        self.test_ip = "192.168.200.99"
        self.test_domain = "immutability-test-domain.org"
        self.test_start = "2026-08-30T00:00:00Z"
        self.test_end = "2026-08-30T01:00:00Z"

        # Insert 4 queries: 1 Benign, 1 Malicious, 1 Review Needed, 1 Unknown
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM domain_query_history WHERE client_ip = %s;", (self.test_ip,))
                cur.execute("""
                    INSERT INTO domain_query_history
                        (timestamp, client_ip, domain, query_type, final_label, ti_source, response_code)
                    VALUES
                        ('2026-08-30T00:05:00Z', %(ip)s, %(dom)s, 'A', 'Benign', 'whitelist', 'NOERROR'),
                        ('2026-08-30T00:10:00Z', %(ip)s, %(dom)s, 'A', 'Malicious', 'alienvault', 'NOERROR'),
                        ('2026-08-30T00:15:00Z', %(ip)s, %(dom)s, 'A', 'Review Needed', 'heuristic', 'NOERROR'),
                        ('2026-08-30T00:20:00Z', %(ip)s, %(dom)s, 'A', 'Unknown', '', 'SERVFAIL');
                """, {"ip": self.test_ip, "dom": self.test_domain})
                conn.commit()

        yield

        # Cleanup
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM domain_query_history WHERE client_ip = %s;", (self.test_ip,))
                conn.commit()

    def test_client_entity_report_preserves_persisted_verdicts(self):
        """Confirms that the client report returns the exact counts for each verdict without recalculation."""
        resp = client.get(
            f"/api/v1/reports/entity?entity={self.test_ip}&entity_type=client&start_time={self.test_start}&end_time={self.test_end}"
        )
        assert resp.status_code == 200
        summary = resp.json()["data"]["summary"]
        assert summary["total_queries"] == 4
        assert summary["benign_queries"] == 1
        assert summary["malicious_queries"] == 1
        assert summary["review_needed_queries"] == 1
        assert summary["unknown_queries"] == 1

    def test_domain_entity_report_preserves_persisted_verdicts(self):
        """Confirms that the domain report returns the exact counts for each verdict without recalculation."""
        resp = client.get(
            f"/api/v1/reports/entity?entity={self.test_domain}&entity_type=domain&start_time={self.test_start}&end_time={self.test_end}"
        )
        assert resp.status_code == 200
        summary = resp.json()["data"]["summary"]
        assert summary["total_queries"] == 4
        assert summary["benign_queries"] == 1
        assert summary["malicious_queries"] == 1
        assert summary["review_needed_queries"] == 1
        assert summary["unknown_queries"] == 1


