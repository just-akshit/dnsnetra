"""
Database schema initialization

Provides functions to create and verify database schema.
"""

import logging
from .db import get_pool

logger = logging.getLogger(__name__)

# SQL to create client_profiles table
CREATE_CLIENT_PROFILES = """
CREATE TABLE IF NOT EXISTS client_profiles (
    client_ip INET PRIMARY KEY,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    total_queries BIGINT NOT NULL DEFAULT 0,
    unique_domains INTEGER NOT NULL DEFAULT 0,
    benign_queries BIGINT NOT NULL DEFAULT 0,
    malicious_queries BIGINT NOT NULL DEFAULT 0,
    review_needed_queries BIGINT NOT NULL DEFAULT 0,
    unknown_queries BIGINT NOT NULL DEFAULT 0,
    last_domain VARCHAR(255),
    last_query_type VARCHAR(20),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

# SQL to create client_history table
CREATE_CLIENT_HISTORY = """
CREATE TABLE IF NOT EXISTS client_history (
    id BIGSERIAL PRIMARY KEY,
    client_ip INET NOT NULL,
    domain VARCHAR(255) NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    visit_count INTEGER NOT NULL DEFAULT 1,
    benign_visits INTEGER NOT NULL DEFAULT 0,
    malicious_visits INTEGER NOT NULL DEFAULT 0,
    review_needed_visits INTEGER NOT NULL DEFAULT 0,
    unknown_visits INTEGER NOT NULL DEFAULT 0,
    
    CONSTRAINT fk_client
        FOREIGN KEY(client_ip)
        REFERENCES client_profiles(client_ip)
        ON DELETE CASCADE,
    
    CONSTRAINT unique_client_domain
        UNIQUE(client_ip, domain)
);
"""

# SQL to create indexes
CREATE_INDEXES = [
    """
    CREATE INDEX IF NOT EXISTS idx_client_profiles_last_seen 
        ON client_profiles(last_seen DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_client_profiles_total_queries 
        ON client_profiles(total_queries DESC);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_client_history_client_ip 
        ON client_history(client_ip);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_client_history_last_seen 
        ON client_history(last_seen);
    """,
    """
    CREATE INDEX IF NOT EXISTS idx_client_history_domain 
        ON client_history(domain);
    """,
]


def initialize_schema():
    """
    Initialize database schema.
    
    Creates all necessary tables and indexes if they don't exist.
    This is idempotent and safe to run multiple times.
    
    Raises:
        Exception: If schema creation fails
    """
    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                # Create tables
                logger.info("Creating client_profiles table...")
                cur.execute(CREATE_CLIENT_PROFILES)
                
                logger.info("Creating client_history table...")
                cur.execute(CREATE_CLIENT_HISTORY)
                
                # Create indexes
                logger.info("Creating indexes...")
                for idx_sql in CREATE_INDEXES:
                    cur.execute(idx_sql)
                
                conn.commit()
                logger.info("Database schema initialized successfully")
                
    except Exception as e:
        logger.error(f"Failed to initialize schema: {e}")
        raise


def verify_schema():
    """
    Verify that required tables exist.
    
    Returns:
        bool: True if schema is valid, False otherwise
    """
    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                # Check if both tables exist
                cur.execute("""
                    SELECT COUNT(*)
                    FROM information_schema.tables
                    WHERE table_name IN ('client_profiles', 'client_history')
                """)
                
                count = cur.fetchone()[0]
                
                if count == 2:
                    logger.info("Schema verification passed")
                    return True
                else:
                    logger.error(f"Schema verification failed: found {count}/2 tables")
                    return False
                    
    except Exception as e:
        logger.error(f"Schema verification error: {e}")
        return False