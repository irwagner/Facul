"""
Unit tests for ``toolkit.governance.scope.ScopeValidator`` (Task 2.3).

These tests verify:
- Exact domain match (case-insensitive)
- Subdomain suffix match (case-insensitive)
- IP address in CIDR range
- Out-of-scope targets return False / raise ScopeError
- assert_in_scope logs an AuditEvent before raising ScopeError
- In-scope targets do not raise
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from toolkit.exceptions import ScopeError
from toolkit.governance.scope import ScopeValidator
from toolkit.models import AuditEvent


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_logger() -> MagicMock:
    """Return a mock that records calls to .log()."""
    logger = MagicMock()
    logger.logged_events: list[AuditEvent] = []

    def _log(event: AuditEvent) -> None:
        logger.logged_events.append(event)

    logger.log.side_effect = _log
    return logger


# ---------------------------------------------------------------------------
# in_scope — domain matching
# ---------------------------------------------------------------------------

class TestInScopeDomain:
    def test_exact_match(self):
        sv = ScopeValidator(["example.com"], [])
        assert sv.in_scope("example.com") is True

    def test_exact_match_case_insensitive(self):
        sv = ScopeValidator(["Example.COM"], [])
        assert sv.in_scope("example.com") is True

    def test_target_case_insensitive(self):
        sv = ScopeValidator(["example.com"], [])
        assert sv.in_scope("EXAMPLE.COM") is True

    def test_subdomain_match(self):
        sv = ScopeValidator(["example.com"], [])
        assert sv.in_scope("sub.example.com") is True

    def test_deep_subdomain_match(self):
        sv = ScopeValidator(["example.com"], [])
        assert sv.in_scope("a.b.c.example.com") is True

    def test_subdomain_case_insensitive(self):
        sv = ScopeValidator(["example.com"], [])
        assert sv.in_scope("Sub.EXAMPLE.com") is True

    def test_partial_domain_not_matched(self):
        # "notexample.com" should NOT match authorized "example.com"
        sv = ScopeValidator(["example.com"], [])
        assert sv.in_scope("notexample.com") is False

    def test_different_tld_not_matched(self):
        sv = ScopeValidator(["example.com"], [])
        assert sv.in_scope("example.org") is False

    def test_empty_authorized_domains(self):
        sv = ScopeValidator([], [])
        assert sv.in_scope("example.com") is False

    def test_multiple_authorized_domains(self):
        sv = ScopeValidator(["alpha.io", "beta.io"], [])
        assert sv.in_scope("alpha.io") is True
        assert sv.in_scope("sub.beta.io") is True
        assert sv.in_scope("gamma.io") is False


# ---------------------------------------------------------------------------
# in_scope — IP / CIDR matching
# ---------------------------------------------------------------------------

class TestInScopeCIDR:
    def test_ip_in_cidr(self):
        sv = ScopeValidator([], ["192.168.1.0/24"])
        assert sv.in_scope("192.168.1.100") is True

    def test_ip_network_address_in_cidr(self):
        sv = ScopeValidator([], ["10.0.0.0/8"])
        assert sv.in_scope("10.255.255.255") is True

    def test_ip_outside_cidr(self):
        sv = ScopeValidator([], ["192.168.1.0/24"])
        assert sv.in_scope("192.168.2.1") is False

    def test_ip_multiple_cidrs(self):
        sv = ScopeValidator([], ["10.0.0.0/8", "172.16.0.0/12"])
        assert sv.in_scope("10.1.2.3") is True
        assert sv.in_scope("172.20.0.1") is True
        assert sv.in_scope("192.168.1.1") is False

    def test_ipv6_in_cidr(self):
        sv = ScopeValidator([], ["2001:db8::/32"])
        assert sv.in_scope("2001:db8::1") is True

    def test_ipv6_outside_cidr(self):
        sv = ScopeValidator([], ["2001:db8::/32"])
        assert sv.in_scope("2001:dc9::1") is False

    def test_ip_not_matched_by_domain_rules(self):
        # An IP that also looks like it could be a subdomain shouldn't match
        sv = ScopeValidator(["1.0/8"], [])  # invalid CIDR as domain — still no IP match
        assert sv.in_scope("10.0.0.1") is False

    def test_malformed_cidr_ignored(self):
        # ScopeValidator must not raise on malformed CIDR during construction
        sv = ScopeValidator([], ["not-a-cidr", "192.168.1.0/24"])
        assert sv.in_scope("192.168.1.50") is True

    def test_domain_not_matched_as_ip(self):
        sv = ScopeValidator([], ["10.0.0.0/8"])
        assert sv.in_scope("example.com") is False


# ---------------------------------------------------------------------------
# assert_in_scope
# ---------------------------------------------------------------------------

class TestAssertInScope:
    def test_in_scope_does_not_raise(self):
        sv = ScopeValidator(["example.com"], [])
        logger = make_logger()
        # Must not raise
        sv.assert_in_scope("example.com", "test_module", logger)
        logger.log.assert_not_called()

    def test_out_of_scope_raises_scope_error(self):
        sv = ScopeValidator(["example.com"], [])
        logger = make_logger()
        with pytest.raises(ScopeError) as exc_info:
            sv.assert_in_scope("evil.com", "scanner", logger)
        assert "evil.com" in str(exc_info.value)

    def test_scope_error_has_target_attribute(self):
        sv = ScopeValidator(["example.com"], [])
        logger = make_logger()
        with pytest.raises(ScopeError) as exc_info:
            sv.assert_in_scope("evil.com", "scanner", logger)
        assert exc_info.value.target == "evil.com"

    def test_scope_error_has_authorized_scope_attribute(self):
        sv = ScopeValidator(["example.com"], ["10.0.0.0/8"])
        logger = make_logger()
        with pytest.raises(ScopeError) as exc_info:
            sv.assert_in_scope("evil.com", "scanner", logger)
        assert "example.com" in exc_info.value.authorized_scope
        assert "10.0.0.0/8" in exc_info.value.authorized_scope

    def test_out_of_scope_logs_audit_event(self):
        sv = ScopeValidator(["example.com"], [])
        logger = make_logger()
        with pytest.raises(ScopeError):
            sv.assert_in_scope("evil.com", "scanner", logger)
        logger.log.assert_called_once()

    def test_logged_event_has_correct_event_type(self):
        sv = ScopeValidator(["example.com"], [])
        logger = make_logger()
        with pytest.raises(ScopeError):
            sv.assert_in_scope("evil.com", "scanner", logger)
        event: AuditEvent = logger.logged_events[0]
        assert event.event_type == "scope_block"

    def test_logged_event_has_correct_target(self):
        sv = ScopeValidator(["example.com"], [])
        logger = make_logger()
        with pytest.raises(ScopeError):
            sv.assert_in_scope("evil.com", "scanner", logger)
        event: AuditEvent = logger.logged_events[0]
        assert event.target == "evil.com"

    def test_logged_event_has_correct_module(self):
        sv = ScopeValidator(["example.com"], [])
        logger = make_logger()
        with pytest.raises(ScopeError):
            sv.assert_in_scope("evil.com", "my_module", logger)
        event: AuditEvent = logger.logged_events[0]
        assert event.module == "my_module"

    def test_logged_event_has_timestamp(self):
        sv = ScopeValidator(["example.com"], [])
        logger = make_logger()
        with pytest.raises(ScopeError):
            sv.assert_in_scope("evil.com", "scanner", logger)
        event: AuditEvent = logger.logged_events[0]
        # Timestamp should be a non-empty ISO 8601 string
        assert isinstance(event.timestamp, str)
        assert len(event.timestamp) > 0
        # Basic ISO 8601 check: contains 'T' separator
        assert "T" in event.timestamp

    def test_logged_event_detail_contains_scope(self):
        sv = ScopeValidator(["example.com"], ["10.0.0.0/8"])
        logger = make_logger()
        with pytest.raises(ScopeError):
            sv.assert_in_scope("evil.com", "scanner", logger)
        event: AuditEvent = logger.logged_events[0]
        assert "authorized_domains" in event.detail
        assert "authorized_cidrs" in event.detail
        assert "example.com" in event.detail["authorized_domains"]
        assert "10.0.0.0/8" in event.detail["authorized_cidrs"]

    def test_log_called_before_raise(self):
        """The event must be logged even when the exception propagates."""
        sv = ScopeValidator([], [])
        logger = make_logger()
        call_order: list[str] = []

        def _log(event: AuditEvent) -> None:
            call_order.append("log")

        logger.log.side_effect = _log

        with pytest.raises(ScopeError):
            sv.assert_in_scope("1.2.3.4", "probe", logger)

        assert call_order == ["log"]

    def test_subdomain_in_scope_does_not_raise(self):
        sv = ScopeValidator(["example.com"], [])
        logger = make_logger()
        sv.assert_in_scope("api.example.com", "enumerator", logger)
        logger.log.assert_not_called()

    def test_ip_in_cidr_does_not_raise(self):
        sv = ScopeValidator([], ["192.168.0.0/16"])
        logger = make_logger()
        sv.assert_in_scope("192.168.1.42", "scanner", logger)
        logger.log.assert_not_called()
