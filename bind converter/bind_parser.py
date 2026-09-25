"""
bind_parser.py
==============
Compatibility parser adapter bridging BIND log lines to DNSRecord / ParsedBINDLine.
Uses the authoritative legacy_bind_parser engine.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from parser.models import DNSRecord
from legacy_bind_parser import parse_bind_line, BindParseResult

logger = logging.getLogger(__name__)


class ParsedBINDLine(DNSRecord):
    """Subclass of DNSRecord providing parser compatibility flags."""
    is_valid: bool = True
    error_message: Optional[str] = None


class BINDLogParser:
    """Parser adapter for BIND named logs."""

    def __init__(self) -> None:
        pass

    def parse_line(
        self,
        raw_line: str,
        source_file: str = "file",
        line_number: int = 0,
    ) -> ParsedBINDLine:
        """Parse a single raw BIND 9 named log line."""
        result: BindParseResult = parse_bind_line(
            raw_line=raw_line,
            source_file=source_file,
            line_number=line_number,
        )

        if not result.success or not result.record:
            invalid_record = ParsedBINDLine()
            invalid_record.is_valid = False
            invalid_record.error_message = result.error or "Failed to parse BIND line"
            invalid_record.raw_log = raw_line
            invalid_record.source_file = source_file
            invalid_record.line_number = line_number
            return invalid_record

        # Wrap existing valid DNSRecord into ParsedBINDLine
        rec = result.record
        parsed = ParsedBINDLine(
            timestamp=getattr(rec, "timestamp", None),
            client_ip=getattr(rec, "client_ip", None),
            domain=getattr(rec, "domain", None),
            query_type=getattr(rec, "query_type", "A"),
            response_code=getattr(rec, "response_code", "NOERROR"),
            resolved_ip=getattr(rec, "resolved_ip", None),
            ttl=getattr(rec, "ttl", None),
            raw_log=getattr(rec, "raw_log", raw_line),
            source_file=getattr(rec, "source_file", source_file),
            line_number=line_number,
            hostname=getattr(rec, "hostname", None),
            server_name=getattr(rec, "server_name", None),
            client_port=getattr(rec, "client_port", None),
            resolver_ip=getattr(rec, "resolver_ip", None),
            transport_protocol=getattr(rec, "transport_protocol", "UDP"),
            query_class=getattr(rec, "query_class", "IN"),
            subdomain=getattr(rec, "subdomain", None),
            registered_domain=getattr(rec, "registered_domain", None),
            tld=getattr(rec, "tld", None),
            is_ipv4=getattr(rec, "is_ipv4", True),
            is_ipv6=getattr(rec, "is_ipv6", False),
            log_category=getattr(rec, "log_category", "queries"),
            severity=getattr(rec, "severity", "info"),
        )
        parsed.is_valid = True
        parsed.error_message = None
        return parsed
