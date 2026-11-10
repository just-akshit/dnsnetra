"""CSV safety and filter parity."""

from reporting.exporters import sanitize_csv_cell
from reporting.repository import ReportingRepository, like_pattern


def test_formula_cells_are_neutralized():
    assert sanitize_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert sanitize_csv_cell("+1") == "'+1"
    assert sanitize_csv_cell("-1") == "'-1"
    assert sanitize_csv_cell("@SUM") == "'@SUM"
    assert sanitize_csv_cell("example.com") == "example.com"
    assert sanitize_csv_cell(42) == 42


def test_like_pattern_escapes_metacharacters():
    assert like_pattern("%_x") == "%\\%\\_x%"


class _FakeCursor:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params=None):
        self.log.append((" ".join(sql.split()), params))

    def fetchmany(self, size):
        return []


class _FakeConn:
    def __init__(self):
        self.log = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self, *args, **kwargs):
        return _FakeCursor(self.log)


def test_export_uses_ilike_for_domain_and_search():
    conn = _FakeConn()
    repo = ReportingRepository(connection_factory=lambda: conn)
    list(repo.stream_queries_csv(domain="example", search="foo", limit=10))

    sql = conn.log[-1][0]
    params = conn.log[-1][1]
    assert "domain ILIKE" in sql
    assert "client_ip ILIKE" in sql
    assert "%example%" in params
    assert params.count("%foo%") == 2
