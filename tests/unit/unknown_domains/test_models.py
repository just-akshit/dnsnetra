"""
Unit tests for Domain Models (UnknownDomain, DomainBatch).

Tests cover domain validation rules, field constraints, serialization/deserialization,
mutability (frozen), and metadata handling.
"""

import json
import pytest
from datetime import datetime, timedelta, timezone
from typing import List, Optional


class TestDomainValidationRules:
    """Verify domain name sanitization per RFC standards."""

    def test_lowercase_normalization(self):
        """Domain case folding to lowercase must always happen."""
        from dnsnetra.domains.unknown_domains.models import validate_domain_name
        
        result = validate_domain_name("MiXeD.CaSe.ExAmPlE.OrG")
        assert result == "mixed.case.example.org"
        assert any(c.isupper() for c in result) == False

    def test_reject_empty_strings(self):
        """Empty or whitespace-only strings are invalid."""
        from dnsnetra.domains.unknown_domains.models import validate_domain_name
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        with pytest.raises(DomainValidationError):
            validate_domain_name("")
        with pytest.raises(DomainValidationError):
            validate_domain_name("   ")

    def test_rfc_max_length_253_chars(self):
        """Reject domains exceeding 253 octets total."""
        from dnsnetra.domains.unknown_domains.models import validate_domain_name
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        long_domain = ("a" * 250) + ".com"
        with pytest.raises(DomainValidationError, match="maximum length"):
            validate_domain_name(long_domain)

    def test_label_length_limited_to_63(self):
        """Individual labels between dots cannot exceed 63 chars."""
        from dnsnetra.domains.unknown_domains.models import validate_domain_name
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        bad_label = ("b" * 64) + ".example.com"
        # The 64-character label fails the RFC label pattern, which surfaces the
        # generic structure error rather than a label-specific one.
        with pytest.raises(DomainValidationError):
            validate_domain_name(bad_label)

    def test_consecutive_dots_forbidden(self):
        """'..' sequences make domain invalid."""
        from dnsnetra.domains.unknown_domains.models import validate_domain_name
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        with pytest.raises(DomainValidationError):
            validate_domain_name("broken..domain.com")

    def test_leading_or_trailing_dots_invalid(self):
        from dnsnetra.domains.unknown_domains.models import validate_domain_name
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        with pytest.raises(DomainValidationError):
            validate_domain_name(".leading.dot")
        with pytest.raises(DomainValidationError):
            validate_domain_name("trailing.dot.")

    def test_ip_addresses_not_allowed_as_domains(self):
        """
        While IPs may be queried, they are not classified as 'domains' in this repo.
        Validation function may reject them depending on implementation.
        For now, we allow basic numeric components but reserve right to block.
        """
        from dnsnetra.domains.unknown_domains.models import validate_domain_name
        # Should accept valid-looking domains even if all numeric labels?
        # Let's see what our implementation does.
        pass  # Implementation-defined currently

    def test_reserved_names_rejected_internal_names_allowed(self):
        """
        Only bare reserved names are blocked; valid private/internal FQDNs survive.

        `docs/architecture/context.md` §4 freezes domain validation as accepting
        valid private/internal domains (the canonical dataset contains internal
        TLDs such as `.int`). Only the bare reserved set is rejected.
        """
        from dnsnetra.domains.unknown_domains.models import validate_domain_name
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError

        for reserved in ["localhost", "local"]:
            with pytest.raises(DomainValidationError):
                validate_domain_name(reserved)

        for internal in ["myhost.local", "telemetry-metrics.int", "log-collector.net"]:
            assert validate_domain_name(internal) == internal


class TestUnknownDomainEntityCreation:
    """Test immutable data class construction and post-init validation."""

    def test_creation_with_minimum_params(self):
        """Create entity using required fields only; defaults fill rest."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainSource, DomainStatus
        )
        
        now = datetime.now(timezone.utc)
        
        d = UnknownDomain.create_new(
            domain="fresh-domain.xyz",
            first_seen=now,
            last_seen=now,
            source=DomainSource.DNS_QUERY_LOG
        )
        
        assert d.domain == "fresh-domain.xyz"
        assert d.status == DomainStatus.NEW
        assert d.source == DomainSource.DNS_QUERY_LOG
        assert d.metadata is None
        assert d.id is None             # New entity has no ID yet

    def test_frozen_prevents_post_creation_mutation(self):
        """
        @dataclass(frozen=True) means attempts to set attributes after __init__
        must raise FrozenInstanceError.
        """
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainSource
        )
        
        now = datetime.now(timezone.utc)
        d = UnknownDomain(domain="test.xyz", first_seen=now, last_seen=now,
                         source=DomainSource.DNS_QUERY_LOG)
        
        with pytest.raises(Exception):   # FrozenInstanceError subclass
            d.domain = "changed.xyz"

    def test_timezones_must_be_aware(self):
        """Naive datetimes rejected by validator to prevent UTC ambiguity bugs."""
        from dnsnetra.domains.unknown_domains.models import UnknownDomain, DomainSource
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        naive_now = datetime.now()  # No tzinfo!
        
        with pytest.raises(DomainValidationError, match="timezone"):
            UnknownDomain(domain="tz-test.xyz",
                          first_seen=naive_now,
                          last_seen=naive_now,
                          source=DomainSource.DNS_QUERY_LOG)

    def test_last_seen_cannot_precede_first_seen(self):
        """Business rule: you cannot observe a domain before it appears."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import UnknownDomain, DomainSource
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        later = datetime.now(timezone.utc)
        earlier = later - timedelta(hours=24)
        
        # Swapped order causes error
        with pytest.raises(DomainValidationError, match="before"):
            UnknownDomain(domain="time-error.xyz",
                          first_seen=later,
                          last_seen=earlier,
                          source=DomainSource.DNS_QUERY_LOG)


class TestMetadataHandling:
    """Test flexible JSONB metadata storage constraints."""

    def test_accepts_valid_dictionary(self):
        """Plain dicts accepted for enrichment payloads."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import UnknownDomain, DomainSource
        
        meta = {
            "virustotal": {"malicious": True, "score": 90},
            "last_scanned": "2024-06-15T12:30Z"
        }
        
        now = datetime.now(timezone.utc)
        d = UnknownDomain(
            domain="meta-test.xyz",
            first_seen=now,
            last_seen=now,
            source=DomainSource.DNS_QUERY_LOG,
            metadata=meta
        )
        
        assert d.metadata["virustotal"]["malicious"] == True

    def test_none_metadata_ok(self):
        """Metadata defaulting to None is perfectly acceptable."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import UnknownDomain, DomainSource
        
        now = datetime.now(timezone.utc)
        d = UnknownDomain(domain="no-meta.xyz", first_seen=now, last_seen=now,
                         source=DomainSource.DNS_QUERY_LOG, metadata=None)
        assert d.metadata is None

    def test_reject_non_serializable_types_inside_metadata(self):
        """Arbitrary Python objects (sets, classes) inside metadata dict blocked."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import UnknownDomain, DomainSource
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        now = datetime.now(timezone.utc)
        
        with pytest.raises(DomainValidationError, match="JSON serializable"):
            UnknownDomain(domain="bad-meta.xyz",
                          first_seen=now,
                          last_seen=now,
                          source=DomainSource.DNS_QUERY_LOG,
                          metadata={'key': {1, 2, 3}})  # Set unserializable!


class TestSerializationRoundTrips:
    """Test to_database_values(), to_dict(), from_database_row() conversion."""

    def test_to_dict_contains_all_public_fields(self):
        """Dictionary representation mirrors constructor parameters."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import UnknownDomain, DomainSource
        
        now = datetime.now(timezone.utc)
        d = UnknownDomain(id=55, domain="serial.xyz",
                         first_seen=now, last_seen=now,
                         created_at=now, updated_at=now,
                         source=DomainSource.MANUAL_IMPORT,
                         metadata=None)
        
        output = d.to_dict()
        
        assert output['id'] == 55
        assert output['domain'] == "serial.xyz"
        assert 'first_seen' in output
        assert 'status' in output
        assert 'created_at' in output           # Auditable fields included

    def test_from_database_row_takes_list_tuple(self):
        """Reconstruct entity from positional row returned by SQL query."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import UnknownDomain
        
        now = datetime.now(timezone.utc)
        
        # Simulate psycopg fetchone() tuple result
        row = (
            99,                           # id
            "row-based.example.com",      # domain
            now,                           # first_seen  
            now + timedelta(hours=1),     # last_seen
            "dns_query_log",              # source enum raw
            "new",                        # status enum raw
            None,                         # metadata json or None
            now,                           # created_at
            now + timedelta(minutes=5),   # updated_at
            2                              # schema_version
        )
        
        obj = UnknownDomain.from_database_row(row)
        
        assert obj.id == 99
        assert obj.domain == "row-based.example.com"
        assert obj.status.value == "new"


class TestBatchContainer:
    """Test DomainBatch grouping and splitting utilities."""

    def test_batch_requires_at_least_one_element(self):
        from dnsnetra.domains.unknown_domains.models import DomainBatch, UnknownDomain, DomainSource
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        with pytest.raises(DomainValidationError, match="empty"):
            DomainBatch(domains=[])

    def test_batch_rejects_duplicate_domain_names(self):
        """
        Batches intended for database upsert must contain unique domains;
        duplicates violate unique constraint logic.
        """
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainBatch, DomainSource
        )
        from dnsnetra.domains.unknown_domains.exceptions import DomainValidationError
        
        now = datetime.now(timezone.utc)
        dupes = [
            UnknownDomain(domain="dupe.xyz", first_seen=now, last_seen=now,
                         source=DomainSource.DNS_QUERY_LOG),
            UnknownDomain(domain="dupE.xYz", first_seen=now, last_seen=now,
                         source=DomainSource.DNS_QUERY_LOG),
        ]
        
        # Normalized both become same -> duplicate
        with pytest.raises(DomainValidationError, match="duplicate"):
            DomainBatch(domains=dupes)

    def test_split_into_smaller_chunks(self):
        """Large batches divided evenly into chunks of size limit."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainBatch, DomainSource, validate_domain_name
        )
        
        now = datetime.now(timezone.utc)
        domains = [
            UnknownDomain(
                domain=f"chunk-{i}.com",
                first_seen=now,
                last_seen=now,
                source=DomainSource.DNS_QUERY_LOG
            ) for i in range(25)              # 25 items
        ]
        
        big = DomainBatch(domains=domains)
        splits = list(big.split(chunk_size=10))
        
        assert len(splits) == 3                 # 10 + 10 + 5
        assert splits[0].size == 10
        assert splits[2].size == 5               # Remainder chunk

    def test_batch_property_helpers(self):
        """Convenience attributes expose size and domain lists quickly."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainBatch, DomainSource
        )
        
        now = datetime.now(timezone.utc)
        dlist = [UnknownDomain(domain=f"hlp-{i}.org", first_seen=now,
                               last_seen=now, source=DomainSource.DNS_QUERY_LOG) 
                for i in range(5)]
        b = DomainBatch(dlist)
        
        assert b.size == 5
        assert len(b.domain_names) == 5
        assert "hlp-3.org" in b.domain_names


# Mutation helper methods tested next

class TestWithUpdatedStatus:
    """Test fluent API returns new objects preserving immutability."""

    def test_update_status_creates_new_instance(self):
        """with_updated_status must NOT modify self, return brand new object."""
        from datetime import timezone
        from dnsnetra.domains.unknown_domains.models import (
            UnknownDomain, DomainStatus, DomainSource
        )
        
        now = datetime.now(timezone.utc)
        orig = UnknownDomain(domain="mutable-check.xyz",
                             first_seen=now, last_seen=now,
                             source=DomainSource.DNS_QUERY_LOG,
                             status=DomainStatus.NEW)
        orig_id = id(orig)
        
        enriched = orig.with_updated_status(status=DomainStatus.ENRICHING if hasattr(DomainStatus, 'ENRICHING') else DomainStatus.NEW)
        
        # Must be different instance
        assert id(enriched) != orig_id
        # Original unchanged
        assert orig.status == DomainStatus.NEW


if __name__ == '__main__':
    pytest.main([__file__, '-v'])