from datetime import datetime
import logging
from . import config
from . import database

__all__ = ["is_trusted"]

logger = logging.getLogger(__name__)


def is_trusted(domain: str) -> bool:
    """
    Public API: Checks if a domain is present in PostgreSQL trusted_db.
    """
    if not domain:
        return False

    normalized_domain = database.normalize_domain(domain)
    if not normalized_domain:
        return False

    try:
        return database.is_domain_trusted(normalized_domain)
    except Exception as exc:
        logger.error("Trusted domain check error for '%s': %s", domain, exc)
        return False