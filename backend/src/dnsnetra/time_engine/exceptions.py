"""
time_engine/exceptions.py
=========================
Domain exceptions for the DNSNetra Centralized Temporal Engine.
"""

from __future__ import annotations


class TimeEngineError(Exception):
    """Base exception for all temporal engine errors."""
    pass


class TimeEngineValidationError(TimeEngineError):
    """
    Raised when temporal input is malformed, missing, unparseable, naive,
    or violates canonical grammar / parameter constraints.
    """
    pass


class InvalidTimeRangeError(TimeEngineError):
    """
    Raised when temporal range is inverted (start > end), entirely in the future,
    or exceeds maximum permissible bucket limits.
    """
    pass
