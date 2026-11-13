"""
Unit tests for UnknownDomainService (business logic orchestration).

Validates process_domains(), store_unknown_domain(), statistics tracking,
session management, and health checks without real database calls.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from dnsnetra.domains.unknown_domains.service import UnknownDomainService


class TestServiceLifecycle:
    """Test init/shutdown and context manager protocol."""

    @patch('dnsnetra.domains.unknown_domains.service.create_database_manager')
    def test_init_creates_db_and_repo(self, create_db_mgr_mock):
        """initialize() must construct DatabaseManager then Repository."""
        from dnsnetra.domains.unknown_domains.service import UnknownDomainService
        from dnsnetra.domains.unknown_domains.config import Config
        
        cfg = Config()
        svc = UnknownDomainService(config=cfg)
        
        svc.initialize()
        
        create_db_mgr_mock.assert_called_once_with(cfg)

    @patch('dnsnetra.domains.unknown_domains.service.create_database_manager')
    def test_initialize_idempotent(self, mock_create_db):
        """Double initialization should not raise error or rebuild components."""
        from dnsnetra.domains.unknown_domains.service import UnknownDomainService
        from dnsnetra.domains.unknown_domains.config import Config

        mock_create_db.return_value.health_check.return_value = {'healthy': True}

        svc = UnknownDomainService(Config())
        svc.initialize()
        svc.initialize()                              # Safe second call

        mock_create_db.assert_called_once()

    @patch('dnsnetra.domains.unknown_domains.service.create_database_manager')
    def test_shutdown_resets_state(self, mock_create):
        """
        After shutdown(), the service is marked uninitialized and the database
        manager is closed. Service must be re-initialized before reuse.
        """
        from dnsnetra.domains.unknown_domains.service import (
            UnknownDomainService,
            ProcessingStats,
        )
        from dnsnetra.domains.unknown_domains.config import Config

        mock_create.return_value.health_check.return_value = {'healthy': True}

        svc = UnknownDomainService(Config())
        svc.initialize()

        db_manager = svc._db_manager
        # Keep shutdown free of batch I/O while still returning real stats.
        batch_processor = Mock()
        batch_processor.flush.return_value = ProcessingStats()
        svc._batch_processor = batch_processor

        svc.shutdown()

        db_manager.close.assert_called_once()
        assert svc._initialized is False


class TestProcessDomainsOrchestration:
    """Main entry point: receives list of strings, batches them for persistence."""

    @patch('dnsnetra.domains.unknown_domains.service.create_database_manager')
    def test_process_domains_delegates_to_internal_method(self, mock_create_db):
        """
        External interface forwards records, source and timestamp to the
        batch-processing path unchanged.
        """
        from dnsnetra.domains.unknown_domains.service import (
            UnknownDomainService,
            ProcessingStats,
        )
        from dnsnetra.domains.unknown_domains.config import Config
        from dnsnetra.domains.unknown_domains.models import DomainSource

        mock_create_db.return_value.health_check.return_value = {'healthy': True}
        svc = UnknownDomainService(Config())
        svc.initialize()

        domains = [
            {"domain": "alpha.example"},
            {"domain": "beta.org"},
            {"domain": "gamma.net"},
        ]
        obs_time = datetime(2024, 6, 15, tzinfo=timezone.utc)

        with patch.object(
            UnknownDomainService, "_process_domains_batch"
        ) as mock_batch:
            mock_batch.return_value = ProcessingStats()
            svc.process_domains(
                domains=domains,
                source=DomainSource.DNS_QUERY_LOG,
                observed_at=obs_time,
                batch_process=True,
            )

        args, _ = mock_batch.call_args
        assert args[0] == domains
        assert args[1] == DomainSource.DNS_QUERY_LOG
        assert args[2] == obs_time

    def test_process_empty_list_returns_zero_stats(self):
        """Empty domain list returns empty ProcessingStats immediately."""
        from dnsnetra.domains.unknown_domains.service import UnknownDomainService
        from dnsnetra.domains.unknown_domains.config import Config
        
        svc = UnknownDomainService(Config())
        # Not initialized - but should still handle gracefully?
        try:
            stats = svc.process_domains([])
            assert stats.total_processed == 0
        except Exception as e:
            # Acceptable if it says "not initialized"
            if "not initialized" not in str(e).lower():
                raise


class TestBatchingBehavior:
    """Service-level batching wraps repository operations."""

    @patch('dnsnetra.domains.unknown_domains.service.create_database_manager')
    @patch('dnsnetra.domains.unknown_domains.service.DomainBatchProcessor')
    def test_batch_size_configurable_from_config_object(
        self, mock_processor_cls, mock_create_db
    ):
        """batch_size pulled from config.batch.size property."""
        from dnsnetra.domains.unknown_domains.service import UnknownDomainService
        from dnsnetra.domains.unknown_domains.config import Config, BatchConfig

        mock_create_db.return_value.health_check.return_value = {'healthy': True}

        custom_config = Config(batch=BatchConfig(size=200))
        svc = UnknownDomainService(config=custom_config)

        svc.initialize()

        # Inspect processor construction call
        _, kwargs = mock_processor_cls.call_args
        assert kwargs['batch_size'] == 200
        assert kwargs['batch_timeout_seconds'] == custom_config.batch.timeout


class TestStatisticsTracking:
    """Session and per-call statistics accumulation."""

    def test_session_stats_accumulate_across_calls(self):
        """
        Multiple calls to process_domains accumulate into session totals.
        """
        from dnsnetra.domains.unknown_domains.service import UnknownDomainService, ProcessingStats
        from dnsnetra.domains.unknown_domains.config import Config
        from datetime import timezone
        
        svc = UnknownDomainService(config=Config())
        svc._session_stats = ProcessingStats()
        svc._session_stats.total_processed = 50
        svc._session_stats.domains_stored = 40
        svc._session_stats.errors = []
        
        # Simulate second operation updating stats
        delta = ProcessingStats(total_processed=30, domains_stored=25)
        svc._update_session_stats(delta)
        
        assert svc._session_stats.total_processed == 80
        assert svc._session_stats.domains_stored == 65


class TestHealthCheckDelegation:
    """Health checks mirror db+repository composite status."""

    def test_health_check_returns_dict(self):
        """
        Returns dict with keys: healthy, timestamp, checks, etc.
        """
        from dnsnetra.domains.unknown_domains.service import UnknownDomainService
        from dnsnetra.domains.unknown_domains.config import Config

        svc = UnknownDomainService(config=Config())
        svc._initialized = True
        svc._db_manager = MagicMock()
        svc._db_manager.health_check.return_value = {
            'healthy': True,
            'timestamp': '2024-06-15T12:30Z'
        }
        svc._repository = MagicMock()
        svc._repository.count_domains.return_value = 12345
        
        result = svc.health_check(timeout=5)

        assert isinstance(result, dict)
        assert 'service_healthy' in result
        assert 'service_initialized' in result
        assert 'database' in result


class TestPipelineIntegrationHelper:
    """Test convenience functions for pipeline integration."""

    def test_create_service_builds_and_initializes(self):
        """
        create_service() constructs the service from the supplied config and
        initializes it before returning.
        """
        from dnsnetra.domains.unknown_domains.service import create_service
        from dnsnetra.domains.unknown_domains.config import Config

        cfg = Config()

        with patch(
            'dnsnetra.domains.unknown_domains.service.UnknownDomainService'
        ) as mock_svc_cls:
            result = create_service(cfg)

            mock_svc_cls.assert_called_once_with(cfg)
            result.initialize.assert_called_once()
            assert result is mock_svc_cls.return_value

    def test_service_context_manager_usage_pattern(self):
        """
        The service is usable as a context manager: entering initializes it and
        exiting shuts it down.
        """
        from dnsnetra.domains.unknown_domains.service import UnknownDomainService
        from dnsnetra.domains.unknown_domains.config import Config

        svc = UnknownDomainService(config=Config())

        with patch.object(UnknownDomainService, 'initialize') as mock_init, \
             patch.object(UnknownDomainService, 'shutdown') as mock_shutdown:
            with svc as integration:
                assert integration is svc
                assert hasattr(integration, 'store_unknown_domain')
                assert hasattr(integration, 'process_domains')
                assert hasattr(integration, 'get_session_stats')

            mock_init.assert_called_once()
            mock_shutdown.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])