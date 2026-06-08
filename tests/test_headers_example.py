"""
Example tests for the HTTP security headers check (Req. 7.1).

All HTTP requests are fully mocked via ``unittest.mock``; no network access.

Test coverage
-------------
* Successful GET → status "ok", all response headers returned as dict
* Request timeout → status "check_failed", empty headers, error_message set
* Connection error → status "check_failed", empty headers, error_message set
* URL is preserved in the result
* Error is logged as AuditEvent when an AuditLogger is provided
* No audit event is logged when no logger is provided
* Headers dict is a plain dict (not a requests CaseInsensitiveDict)
* Request uses a 10-second timeout (Req. 7.1)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests as req_lib

from toolkit.execution.checks.headers import HeadersResult, check_security_headers
from toolkit.governance.audit_logger import AuditLogger


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

TARGET_URL = "https://example.com"


def _make_response(
    status_code: int = 200,
    headers: dict[str, str] | None = None,
) -> MagicMock:
    """Build a minimal requests.Response mock."""
    resp = MagicMock()
    resp.status_code = status_code
    headers_dict = headers or {}
    # dict(resp.headers) must work — use a real dict
    resp.headers = dict(headers_dict)
    return resp


# ---------------------------------------------------------------------------
# 1. Successful request
# ---------------------------------------------------------------------------

class TestSuccessfulRequest:
    """On a successful GET the function returns status='ok' with all headers."""

    def test_status_is_ok_on_success(self):
        resp = _make_response(200, headers={"Content-Type": "text/html"})
        with patch("toolkit.execution.checks.headers.requests.get", return_value=resp):
            result = check_security_headers(TARGET_URL)
        assert result.status == "ok"

    def test_headers_returned_as_dict(self):
        headers = {
            "Content-Type": "text/html",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000",
        }
        resp = _make_response(200, headers=headers)
        with patch("toolkit.execution.checks.headers.requests.get", return_value=resp):
            result = check_security_headers(TARGET_URL)
        assert isinstance(result.headers, dict)
        for key, value in headers.items():
            assert result.headers[key] == value

    def test_error_message_is_none_on_success(self):
        resp = _make_response(200, headers={"Server": "nginx"})
        with patch("toolkit.execution.checks.headers.requests.get", return_value=resp):
            result = check_security_headers(TARGET_URL)
        assert result.error_message is None

    def test_url_preserved_in_result(self):
        resp = _make_response(200, headers={})
        with patch("toolkit.execution.checks.headers.requests.get", return_value=resp):
            result = check_security_headers(TARGET_URL)
        assert result.url == TARGET_URL

    def test_all_headers_captured_not_just_security_headers(self):
        """All response headers are returned, not only security-related ones."""
        headers = {
            "Content-Type": "text/html",
            "Server": "nginx/1.20.0",
            "X-Request-Id": "abc-123",
            "Content-Security-Policy": "default-src 'self'",
        }
        resp = _make_response(200, headers=headers)
        with patch("toolkit.execution.checks.headers.requests.get", return_value=resp):
            result = check_security_headers(TARGET_URL)
        assert len(result.headers) == len(headers)
        assert set(result.headers.keys()) == set(headers.keys())


# ---------------------------------------------------------------------------
# 2. Request timeout (Req. 7.1)
# ---------------------------------------------------------------------------

class TestRequestTimeout:
    """On a timeout the function returns status='check_failed'."""

    def test_status_is_check_failed_on_timeout(self):
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_security_headers(TARGET_URL)
        assert result.status == "check_failed"

    def test_headers_empty_on_timeout(self):
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_security_headers(TARGET_URL)
        assert result.headers == {}

    def test_error_message_set_on_timeout(self):
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_security_headers(TARGET_URL)
        assert result.error_message is not None
        assert len(result.error_message) > 0

    def test_url_preserved_on_timeout(self):
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_security_headers(TARGET_URL)
        assert result.url == TARGET_URL


# ---------------------------------------------------------------------------
# 3. Connection error
# ---------------------------------------------------------------------------

class TestConnectionError:
    """On a connection error the function returns status='check_failed'."""

    def test_status_is_check_failed_on_connection_error(self):
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("connection refused"),
        ):
            result = check_security_headers(TARGET_URL)
        assert result.status == "check_failed"

    def test_headers_empty_on_connection_error(self):
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("connection refused"),
        ):
            result = check_security_headers(TARGET_URL)
        assert result.headers == {}

    def test_error_message_set_on_connection_error(self):
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("connection refused"),
        ):
            result = check_security_headers(TARGET_URL)
        assert result.error_message is not None
        assert len(result.error_message) > 0


# ---------------------------------------------------------------------------
# 4. Generic RequestException
# ---------------------------------------------------------------------------

class TestGenericRequestException:
    """Any requests.RequestException results in check_failed."""

    def test_status_is_check_failed_on_request_exception(self):
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.RequestException("generic error"),
        ):
            result = check_security_headers(TARGET_URL)
        assert result.status == "check_failed"

    def test_error_message_contains_description(self):
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.RequestException("generic error"),
        ):
            result = check_security_headers(TARGET_URL)
        assert result.error_message is not None
        assert len(result.error_message) > 0


# ---------------------------------------------------------------------------
# 5. Audit logging
# ---------------------------------------------------------------------------

class TestAuditLogging:
    """Errors are logged as AuditEvents when an AuditLogger is provided."""

    def test_error_logged_when_logger_provided_on_timeout(self):
        audit_logger = AuditLogger()
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            check_security_headers(TARGET_URL, logger=audit_logger)
        events = audit_logger.get_events()
        assert len(events) == 1
        assert events[0].event_type == "error"
        assert events[0].module == "security_headers"
        assert events[0].target == TARGET_URL

    def test_error_logged_when_logger_provided_on_connection_error(self):
        audit_logger = AuditLogger()
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("refused"),
        ):
            check_security_headers(TARGET_URL, logger=audit_logger)
        events = audit_logger.get_events()
        assert len(events) == 1
        assert events[0].event_type == "error"

    def test_no_event_logged_on_success(self):
        audit_logger = AuditLogger()
        resp = _make_response(200, headers={"Server": "nginx"})
        with patch("toolkit.execution.checks.headers.requests.get", return_value=resp):
            check_security_headers(TARGET_URL, logger=audit_logger)
        assert audit_logger.get_events() == []

    def test_no_exception_raised_when_no_logger_provided_on_error(self):
        """The function should not crash when logger=None and a request fails."""
        with patch(
            "toolkit.execution.checks.headers.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            # Must not raise
            result = check_security_headers(TARGET_URL, logger=None)
        assert result.status == "check_failed"


# ---------------------------------------------------------------------------
# 6. HeadersResult dataclass defaults
# ---------------------------------------------------------------------------

class TestHeadersResultDefaults:
    """HeadersResult has sensible defaults."""

    def test_headers_default_is_empty_dict(self):
        r = HeadersResult(url="https://x.com", status="check_failed")
        assert r.headers == {}

    def test_error_message_default_is_none(self):
        r = HeadersResult(url="https://x.com", status="ok")
        assert r.error_message is None


# ---------------------------------------------------------------------------
# 7. Request timeout value (Req. 7.1)
# ---------------------------------------------------------------------------

class TestRequestTimeoutValue:
    """The request is issued with exactly a 10-second timeout (Req. 7.1)."""

    def test_request_uses_10_second_timeout(self):
        resp = _make_response(200, headers={"Content-Type": "text/html"})
        with patch(
            "toolkit.execution.checks.headers.requests.get", return_value=resp
        ) as mock_get:
            check_security_headers(TARGET_URL)
        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        assert kwargs.get("timeout") == 10, (
            f"Expected timeout=10, got timeout={kwargs.get('timeout')}"
        )
