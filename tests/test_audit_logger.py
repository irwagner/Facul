"""
Tests for AuditLogger (task 3.3).

Covers:
- Unit tests: basic log/get_events, masking of sensitive keys, append-to-file,
  IO error silencing, get_events returns a copy.
- Property-based tests: masking invariant across arbitrary detail dicts.

Requirements: 1.5, 2.6, 9.6
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from toolkit.governance.audit_logger import AuditLogger, _MASK, _SENSITIVE_KEY_FRAGMENTS
from toolkit.models import AuditEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_EVENT_TYPES = ["scope_block", "exclusion", "biz_request", "error", "info"]


def _make_event(
    detail: dict | None = None,
    event_type: str = "info",
    target: str | None = "example.com",
    module: str | None = "test",
) -> AuditEvent:
    """Build an AuditEvent with an ISO 8601 timestamp."""
    return AuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type=event_type,  # type: ignore[arg-type]
        target=target,
        module=module,
        detail=detail or {},
    )


# ---------------------------------------------------------------------------
# Unit tests — basic behaviour
# ---------------------------------------------------------------------------


class TestAuditLoggerBasic:
    def test_initial_events_is_empty(self):
        logger = AuditLogger()
        assert logger.get_events() == []

    def test_log_single_event(self):
        logger = AuditLogger()
        event = _make_event(detail={"url": "https://example.com"})
        logger.log(event)
        events = logger.get_events()
        assert len(events) == 1
        assert events[0] is event

    def test_log_multiple_events_preserves_order(self):
        logger = AuditLogger()
        events = [_make_event(detail={"i": str(i)}) for i in range(5)]
        for e in events:
            logger.log(e)
        stored = logger.get_events()
        assert stored == events

    def test_get_events_returns_copy(self):
        """Mutating the returned list must not affect the internal log."""
        logger = AuditLogger()
        logger.log(_make_event())
        copy1 = logger.get_events()
        copy1.clear()
        assert len(logger.get_events()) == 1

    def test_log_without_file_path_does_not_raise(self):
        logger = AuditLogger(log_file_path=None)
        logger.log(_make_event(detail={"status": "ok"}))  # no exception

    def test_event_types_all_accepted(self):
        logger = AuditLogger()
        for et in _EVENT_TYPES:
            logger.log(_make_event(event_type=et))
        assert len(logger.get_events()) == len(_EVENT_TYPES)


# ---------------------------------------------------------------------------
# Unit tests — sensitive key masking
# ---------------------------------------------------------------------------


class TestSensitiveMasking:
    def test_password_key_is_masked(self):
        logger = AuditLogger()
        event = _make_event(detail={"password": "s3cr3t"})
        logger.log(event)
        assert event.detail["password"] == _MASK

    def test_token_key_is_masked(self):
        logger = AuditLogger()
        event = _make_event(detail={"token": "eyJhbGciOiJIUzI1NiJ9"})
        logger.log(event)
        assert event.detail["token"] == _MASK

    def test_secret_key_is_masked(self):
        logger = AuditLogger()
        event = _make_event(detail={"secret": "mysecret"})
        logger.log(event)
        assert event.detail["secret"] == _MASK

    def test_key_fragment_in_compound_name_is_masked(self):
        logger = AuditLogger()
        event = _make_event(detail={"apiKey": "ABCDEF1234567890"})
        logger.log(event)
        assert event.detail["apiKey"] == _MASK

    def test_authorization_key_is_masked(self):
        logger = AuditLogger()
        event = _make_event(detail={"authorization": "Bearer abc123"})
        logger.log(event)
        assert event.detail["authorization"] == _MASK

    def test_payload_key_is_masked(self):
        logger = AuditLogger()
        event = _make_event(detail={"payload": '{"amount": -1}'})
        logger.log(event)
        assert event.detail["payload"] == _MASK

    def test_case_insensitive_masking(self):
        logger = AuditLogger()
        event = _make_event(detail={"PASSWORD": "abc", "Token": "xyz"})
        logger.log(event)
        assert event.detail["PASSWORD"] == _MASK
        assert event.detail["Token"] == _MASK

    def test_non_sensitive_key_not_masked(self):
        logger = AuditLogger()
        event = _make_event(detail={"url": "https://example.com", "status": 200})
        logger.log(event)
        assert event.detail["url"] == "https://example.com"
        assert event.detail["status"] == 200

    def test_non_string_sensitive_value_not_masked(self):
        """Only string values are masked; other types are kept intact."""
        logger = AuditLogger()
        event = _make_event(detail={"token": 12345})  # int, not str
        logger.log(event)
        assert event.detail["token"] == 12345

    def test_mixed_detail_partial_masking(self):
        logger = AuditLogger()
        event = _make_event(
            detail={"url": "https://example.com", "password": "pass", "status": "ok"}
        )
        logger.log(event)
        assert event.detail["url"] == "https://example.com"
        assert event.detail["password"] == _MASK
        assert event.detail["status"] == "ok"


# ---------------------------------------------------------------------------
# Unit tests — file-based append logging
# ---------------------------------------------------------------------------


class TestFileLogging:
    def test_log_writes_jsonl_to_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as tmp:
            path = tmp.name

        try:
            logger = AuditLogger(log_file_path=path)
            event = _make_event(detail={"url": "https://example.com"})
            logger.log(event)

            with open(path, encoding="utf-8") as fh:
                lines = fh.readlines()

            assert len(lines) == 1
            parsed = json.loads(lines[0])
            assert parsed["event_type"] == "info"
            assert parsed["target"] == "example.com"
        finally:
            os.unlink(path)

    def test_log_appends_multiple_events_to_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as tmp:
            path = tmp.name

        try:
            logger = AuditLogger(log_file_path=path)
            for i in range(3):
                logger.log(_make_event(detail={"i": str(i)}))

            with open(path, encoding="utf-8") as fh:
                lines = [l for l in fh.readlines() if l.strip()]

            assert len(lines) == 3
        finally:
            os.unlink(path)

    def test_file_contains_masked_values(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as tmp:
            path = tmp.name

        try:
            logger = AuditLogger(log_file_path=path)
            logger.log(_make_event(detail={"token": "secret-value-123"}))

            with open(path, encoding="utf-8") as fh:
                content = fh.read()

            assert "secret-value-123" not in content
            assert _MASK in content
        finally:
            os.unlink(path)

    def test_io_error_is_silenced(self):
        """A bad file path must not raise; the event is still stored in memory."""
        # Use an invalid path (directory that doesn't exist)
        bad_path = "/nonexistent_dir/audit.jsonl"
        logger = AuditLogger(log_file_path=bad_path)
        event = _make_event(detail={"url": "https://example.com"})
        # Must not raise
        logger.log(event)
        # Event is still in memory
        assert len(logger.get_events()) == 1

    def test_json_line_has_iso8601_timestamp(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False
        ) as tmp:
            path = tmp.name

        try:
            logger = AuditLogger(log_file_path=path)
            ts = datetime.now(timezone.utc).isoformat()
            event = AuditEvent(
                timestamp=ts,
                event_type="info",
                target=None,
                module=None,
                detail={},
            )
            logger.log(event)

            with open(path, encoding="utf-8") as fh:
                parsed = json.loads(fh.readline())

            # Timestamp must be preserved exactly
            assert parsed["timestamp"] == ts
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Property-based tests — masking invariant
# ---------------------------------------------------------------------------

# Strategy: dict with arbitrary string keys and mixed-type values
_value_strategy = st.one_of(
    st.text(min_size=0, max_size=50),
    st.integers(),
    st.booleans(),
    st.none(),
)

_detail_strategy = st.dictionaries(
    keys=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
        min_size=1,
        max_size=30,
    ),
    values=_value_strategy,
    min_size=0,
    max_size=10,
)


@given(detail=_detail_strategy)
@settings(max_examples=100)
def test_property_sensitive_keys_always_masked(detail: dict):
    """
    # Feature: web-security-audit-toolkit, Property 3.3-a:
    For any detail dict, every string value associated with a key containing
    a sensitive fragment is replaced with MASK after logging.

    **Validates: Requirements 1.5, 9.6**
    """
    logger = AuditLogger()
    event = AuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="info",
        target=None,
        module=None,
        detail=dict(detail),  # copy so original is unaffected
    )
    logger.log(event)
    stored_detail = logger.get_events()[0].detail

    for key, value in detail.items():
        key_lower = key.lower()
        is_sensitive = any(frag in key_lower for frag in _SENSITIVE_KEY_FRAGMENTS)
        if is_sensitive and isinstance(value, str):
            assert stored_detail[key] == _MASK, (
                f"Expected key '{key}' with value '{value}' to be masked, "
                f"got '{stored_detail[key]}'"
            )
        else:
            assert stored_detail[key] == value, (
                f"Expected key '{key}' to be unchanged, "
                f"got '{stored_detail[key]}' instead of '{value}'"
            )


@given(detail=_detail_strategy)
@settings(max_examples=100)
def test_property_non_sensitive_keys_never_masked(detail: dict):
    """
    # Feature: web-security-audit-toolkit, Property 3.3-b:
    For any detail dict, string values associated with non-sensitive keys
    are never replaced by the mask value.

    **Validates: Requirements 1.5, 9.6**
    """
    logger = AuditLogger()
    event = AuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="info",
        target=None,
        module=None,
        detail=dict(detail),
    )
    logger.log(event)
    stored_detail = logger.get_events()[0].detail

    for key, value in detail.items():
        key_lower = key.lower()
        is_sensitive = any(frag in key_lower for frag in _SENSITIVE_KEY_FRAGMENTS)
        if not is_sensitive:
            assert stored_detail[key] == value, (
                f"Non-sensitive key '{key}' should not be masked"
            )


@given(
    details=st.lists(_detail_strategy, min_size=1, max_size=20),
)
@settings(max_examples=100)
def test_property_get_events_count_matches_log_calls(details: list[dict]):
    """
    # Feature: web-security-audit-toolkit, Property 3.3-c:
    The number of events returned by get_events always equals the number of
    log() calls made, regardless of detail content.

    **Validates: Requirements 1.5**
    """
    logger = AuditLogger()
    for detail in details:
        logger.log(
            AuditEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="info",
                target=None,
                module=None,
                detail=dict(detail),
            )
        )
    assert len(logger.get_events()) == len(details)
