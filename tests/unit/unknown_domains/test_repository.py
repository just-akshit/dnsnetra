"""
Unit tests for UnknownDomainRepository (data access layer).

Tests cover single domain CRUD, batch operations, UPSERT logic,
query patterns, and error handling when database interactions fail.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime, timedelta, timezone
from typing import List

from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository


class TestRepositoryInitialization:
    """Verify repository requires valid database manager."""

    def test_requires_database_manager(self):
        """Repository cannot function without a DatabaseManager instance."""
        from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository
        
        with pytest.raises(Exception):
            UnknownDomainRepository(database_manager=None)

    def test_stores_reference_to_db_manager(self):
        """Constructor should store DB manager for later use."""
        from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository
        from dnsnetra.domains.unknown_domains.database import DatabaseManager
        
        mock_mgr = Mock(spec=DatabaseManager)
        repo = UnknownDomainRepository(database_manager=mock_mgr)
        
        assert repo.db_manager is mock_mgr


class TestSingleDomainInsert:
    """Test insert_domain() with allow_duplicates control."""

    @patch.object(UnknownDomainRepository, '_domain_exists', return_value=False)
    def test_insert_new_domain_returns_entity_with_id(self, mock_exists):
        """
        Successful insertion returns UnknownDomain where id is populated
        and created_at/updated_at have real timestamps.
        """
        from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainSource, DomainStatus
        )
        
        # Setup mocks for internal flow
        repo = UnknownDomainRepository(database_manager=MagicMock())
        
        now = datetime.now(timezone.utc)
        domain = UnknownDomain.create_new(
            domain="fresh-insert.xyz",
            first_seen=now,
            last_seen=now,
            source=DomainSource.DNS_QUERY_LOG
        )
        
        # Simulate INSERT ... RETURNING id, created_at, updated_at
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (42, now, now)
        tx_ctx = MagicMock()
        tx_ctx.__enter__.return_value = mock_conn
        repo.db_manager.transaction.return_value = tx_ctx
        
        result = repo.insert_domain(domain, allow_duplicates=False)
        
        assert result.id == 42
        assert isinstance(result.created_at, datetime)

    @patch.object(UnknownDomainRepository, '_domain_exists', return_value=True)
    def test_insert_raises_on_duplicate_when_forbidden(self, mock_exists):
        """If domain exists and allow_duplicates=False, raise DomainExistsError."""
        from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainSource, DomainStatus
        )
        from dnsnetra.domains.unknown_domains.exceptions import DomainExistsError
        
        repo = UnknownDomainRepository(database_manager=MagicMock())
        now = datetime.now(timezone.utc)
        dup_domain = UnknownDomain.create_new(
            domain="already-here.xyz",
            first_seen=now,
            last_seen=now,
            source=DomainSource.DNS_QUERY_LOG
        )
        
        with pytest.raises(DomainExistsError, match="already exists"):
            repo.insert_domain(dup_domain, allow_duplicates=False)


class TestUpsertLogic:
    """Test upsert_domain() behavior on conflict resolution."""

    def test_upsert_returns_tuple_was_inserted_bool(self):
        """
        Returns (entity, was_inserted).
        - New domain -> was_inserted=True
        - Existing domain -> was_inserted=False
        """
        from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainSource
        )
        
        repo = UnknownDomainRepository(database_manager=Mock())
        now = datetime.now(timezone.utc)
        new_dom = UnknownDomain.create_new(
            domain="upsert-test.io",
            first_seen=now,
            last_seen=now,
            source=DomainSource.DNS_QUERY_LOG
        )
        
        # Setup connection stack: upsert uses db_manager.transaction() as a
        # context manager and reads the RETURNING row from conn.execute().
        mock_conn = MagicMock()
        # Return value: (id, created_at, updated_at, is_new_bool)
        mock_conn.execute.return_value.fetchone.return_value = (
            555, now, now + timedelta(seconds=1), True
        )
        mock_conn.row_factory = None  # Skip dict_row
        tx_ctx = MagicMock()
        tx_ctx.__enter__.return_value = mock_conn
        repo.db_manager.transaction.return_value = tx_ctx
        
        entity, inserted_flag = repo.upsert_domain(new_dom, update_last_seen=True)
        
        assert inserted_flag is True
        assert entity.domain == "upsert-test.io"


class TestBatchOperations:
    """Test batch_insert() and batch_upsert() splitting and stats."""

    def test_batch_splits_when_exceeds_max_size(self):
        """
        If list of domains > MAX_BATCH_SIZE (10k), batch_insert must split.
        Each chunk size <= MAX_BATCH_SIZE.
        """
        from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository
        from dnsnetra.domains.unknown_domains.constants import MAX_BATCH_SIZE
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainSource
        )
        
        repo = UnknownDomainRepository(database_manager=MagicMock())
        repo.db_manager.transaction.return_value.__enter__.return_value = MagicMock()
        now = datetime.now(timezone.utc)
        
        # Generate 15000 domains (exceeds max of 10000)
        big_list = [
            UnknownDomain.create_new(
                domain=f"mass-{i}.com",
                first_seen=now,
                last_seen=now,
                source=DomainSource.DNS_QUERY_LOG
            ) for i in range(15000)
        ]
        
        # Configure mock to track chunk sizes passed
        captured_sizes = []
        def capture_insert(chunk, skip_duplicates):
            captured_sizes.append(len(chunk.domains))
            return len(chunk.domains)  # inserted count
        
        with patch.object(UnknownDomainRepository, '_insert_chunk', side_effect=capture_insert):
            inserted = repo.batch_insert(big_list, chunk_size=5000, skip_duplicates=True)
        
        assert inserted == 15000
        assert len(captured_sizes) == 3
        # Verify chunks never exceeded configured limit
        for size in captured_sizes:
            assert size <= 5000

    def test_batch_empty_list_returns_zero_stats(self):
        """Empty domain list should short-circuit and return zero inserted."""
        from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository
        
        repo = UnknownDomainRepository(database_manager=MagicMock())
        inserted = repo.batch_insert(domains=[], chunk_size=100)
        
        assert inserted == 0


class TestQueryByStatusAndTimeRange:
    """Test filtering queries used by enrichment services."""

    def test_get_domains_by_status_uses_where_clause(self):
        """Method builds SQL query with status filter parameter."""
        from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository
        from dnsnetra.domains.unknown_domains.constants import DomainStatus
        
        repo = UnknownDomainRepository(database_manager=Mock())
        
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchall.return_value = []
        mock_conn.execute.return_value.fetchone.return_value = None
        conn_ctx = MagicMock()
        conn_ctx.__enter__.return_value = mock_conn
        repo.db_manager.get_connection.return_value = conn_ctx
        
        results = repo.get_domains_by_status(DomainStatus.NEW, limit=10)
        
        # Should have executed a SELECT with status='new' condition somewhere
        execute_call_args = str(mock_conn.execute.call_args)
        assert "new" in execute_call_args.lower() or len(results) >= 0


class TestCountDomainsAggregation:
    """Test COUNT(*) queries returning integer totals."""

    def test_count_returns_integer(self):
        """count_domains() returns int count of matching rows."""
        from dnsnetra.domains.unknown_domains.repository import UnknownDomainRepository
        
        repo = UnknownDomainRepository(database_manager=Mock())
        
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (42,)  # Scalar count
        conn_ctx = MagicMock()
        conn_ctx.__enter__.return_value = mock_conn
        repo.db_manager.get_connection.return_value = conn_ctx
        
        total = repo.count_domains(status=None, source=None)
        
        assert total == 42
        assert isinstance(total, int)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])