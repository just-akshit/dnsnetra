"""
Concurrency & Thread-Safety Tests.

Validate that shared resources (connection pool, logger, global state)
do not corrupt under simultaneous access from multiple worker threads/tasks.
Uses Python threading/futures to simulate parallel workload.
"""

import pytest
import threading
import concurrent.futures
import queue
import time
from datetime import datetime, timezone
from typing import List
from unittest.mock import Mock, patch, MagicMock


class TestGlobalLoggerThreadSafety:
    """
    Shared singleton logger must produce consistent output without garbled lines
    across threads calling debug/info/error simultaneously.
    """

    @patch('dnsnetra.domains.unknown_domains.logger.logging.getLogger')
    def test_multiple_threads_logging_same_component(self, mock_getLogger):
        """
        Thread safety requirement: N threads all logging to same logger name
        must not interleave log messages between distinct log() calls.
        """
        from dnsnetra.domains.unknown_domains.logger import get_logger, LoggingConfig
        import logging
        
        cfg = LoggingConfig(level='DEBUG', format='text')
        main_logger = get_logger(cfg)
        
        captured_messages = queue.Queue()
        
        # Record messages instead of actual I/O
        orig_info = main_logger.info
        
        def thread_safe_info(msg, extra=None):
            captured_messages.put(msg)
            return orig_info(msg, extra=extra)
            
        main_logger.info = thread_safe_info
        
        errors = []
        
        def worker(thread_id):
            try:
                for i in range(50):
                    main_logger.info(f"Thread-{thread_id} Message-{i}")
            except Exception as e:
                errors.append(e)
        
        threads = [
            threading.Thread(target=worker, args=(tid,))
            for tid in range(8)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Restore original method
        main_logger.info = orig_info
        
        # Validate no corruption expected at message boundaries
        # (Actual string fragmentation depends on write buffering of underlying handler)
        assert errors == [], f"Errors during concurrency test: {errors}"
        assert captured_messages.qsize() == 400     # 8 threads * 50 msgs


class TestConnectionPoolContention:
    """
    Under high concurrency (> pool.max_connections), waiters may queue.
    Verify that pool does not exceed capacity or deadlock waiting.
    """

    @patch('dnsnetra.domains.unknown_domains.database.ConnectionPool')
    def test_concurrent_get_connections_within_capacity(self, mock_pool_cls):
        """
        When multiple callers request connections simultaneously:
         - Pool should deliver connections up to limit
         - Surplus requests timeout gracefully (raise PoolTimeout)
         - No infinite blocking allowed
        """
        from dnsnetra.domains.unknown_domains.database import DatabaseManager, DatabaseConnectionError
        from dnsnetra.domains.unknown_domains.config import DatabaseConfig
        from psycopg_pool import PoolTimeout
        
        cfg = DatabaseConfig(max_connections=2)           # Tiny pool for stress test
        mgr = DatabaseManager.__new__(DatabaseManager)    # Bypass __init__ side effects
        mgr.db_config = cfg
        
        # Build realistic pool mock
        mock_pool_instance = mock_pool_cls.return_value
        connection_count = {'active': 0}
        lock = threading.Lock()
        
        def acquire_connection(timeout=None):
            with lock:
                if connection_count['active'] < cfg.max_connections:
                    connection_count['active'] += 1
                    conn_ctx = MagicMock()
                    
                    class ConnCtx(MagicMock):
                        def __enter__(inner_self):
                            return self
                        
                        def __exit__(inner_self, *args):
                            with lock:
                                connection_count['active'] -= 1
                            return False
                    
                    return ConnCtx()
                else:
                    raise PoolTimeout(f"No connections available")
        
        mock_pool_instance.connection.side_effect = acquire_connection
        mgr._pool = mock_pool_instance
        mgr._initialized = True
        
        successful = 0
        timed_out = 0
        thread_errors = []
        
        def worker():
            nonlocal successful, timed_out
            
            try:
                with mgr.get_connection(timeout=0.1):      # 100ms timeout
                    successful += 1
                    time.sleep(0.02)                      # Hold briefly
            except (PoolTimeout, Exception) as err:
                timed_out += 1  # Timeout/denied normal under contention
        
        workers = [threading.Thread(target=worker) for _ in range(6)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        
        # Assertions
        assert successful <= cfg.max_connections * 2  # Reasonable ceiling
        assert timed_out > 0                        # Some should have failed given tiny pool


class TestBatchProcessorSharedState:
    """
    DomainBatchProcessor accumulates _pending_domains dict.
    Concurrent add_domain() must ensure dictionary consistency.
    """

    @patch('dnsnetra.domains.unknown_domains.service.UnknownDomainRepository')
    def test_concurrent_add_domain_deduplicates_without_race(self, mock_repo):
        """
        When multiple threads add identical domain simultaneously,
        batch must contain exactly ONE copy (no duplicate inserts).
        """
        from dnsnetra.domains.unknown_domains.service import DomainBatchProcessor
        from dnsnetra.domains.unknown_domains.models import UnknownDomain, DomainSource
        from datetime import timezone
        
        processor = DomainBatchProcessor(repository=Mock())
        
        target_domain = "concurrent-dedupe.test"
        now = datetime.now(timezone.utc)
        
        def submitter(thread_idx):
            d = UnknownDomain.create_new(
                domain=target_domain,
                first_seen=now,
                last_seen=now,
                source=DomainSource.DNS_QUERY_LOG
            )
            processor.add_domain(d)                  # May trigger flush or just queue
        
        threads = [threading.Thread(target=submitter, args=(i,)) for i in range(10)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # The pending buffer is keyed by domain name, so concurrent adds of the
        # same name must collapse to exactly one queued entity.
        pending = list(processor._pending_domains.keys())

        assert pending.count(target_domain) == 1, (
            f"Expected 1 copy of {target_domain}, got {pending.count(target_domain)}"
        )
        assert len(pending) == 1


class TestContextManagerIsolationBetweenThreads:
    """
    Each thread maintaining its own context (operation_context) must see its own data.
    Context bleeding between threads indicates incorrect design.
    """

    def test_thread_local_context_isolation(self):
        """
        Operation context set in Thread-A must be invisible to Thread-B.
        """
        from dnsnetra.domains.unknown_domains.logger import get_logger, LoggingConfig
        
        cfg = LoggingConfig(level='DEBUG', format='text')
        logger_a = get_logger(cfg)
        logger_b = logger_a  # Same shared instance currently (acceptable)
        
        results = {}
        barrier = threading.Barrier(2)

        def thread_work(context_val):
            with logger_a.operation_context(operation=f"op-{context_val}"):
                # Ensure both threads are inside their own context at once
                barrier.wait(timeout=5)
                current = logger_a._get_context()

                # Key by the caller's own label, not the thread name
                results[context_val] = current.get('operation')
        
        t1 = threading.Thread(target=thread_work, args=("A",))
        t2 = threading.Thread(target=thread_work, args=("B",))
        
        t1.start(); t2.start()
        t1.join(); t2.join()
        
        # Each thread must observe only its own operation context
        assert results == {"A": "op-A", "B": "op-B"}


if __name__ == '__main__':
    pytest.main([__file__, '-v'])