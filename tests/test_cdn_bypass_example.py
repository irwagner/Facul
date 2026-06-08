"""
Example tests for the CDN CloudFront bypass check (Req. 6.2).

All HTTP requests are fully mocked via ``unittest.mock``; no network access.

Test coverage
-------------
* Connection refused  → candidate marked as unreachable, check continues to next
* Timeout             → candidate marked as unreachable, check continues to next
* Successful direct IP request with Host header → response recorded as reachable
* Mixed reachable / unreachable candidates handled correctly
* CdnBypassResult helper properties (reachable_candidates, unreachable_candidates)
* Result structure: ip, status, body_size, reachable keys present in each entry
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
import requests as req_lib
import requests.exceptions

from toolkit.execution.checks.cdn_bypass import (
    CdnBypassResult,
    check_cdn_bypass,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

DOMAIN = "example.com"


def _make_response(
    status_code: int = 200,
    body: bytes = b"<html></html>",
) -> MagicMock:
    """Build a minimal requests.Response mock."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.content = body
    return resp


# ---------------------------------------------------------------------------
# 1. Connection refused → candidate marked unreachable, check continues
# ---------------------------------------------------------------------------

class TestConnectionRefused:
    """A ConnectionError causes the candidate to be marked unreachable (Req. 6.2)."""

    def test_connection_refused_marks_candidate_unreachable(self):
        """Single candidate that refuses the connection → reachable=False."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("Connection refused"),
        ):
            result = check_cdn_bypass(DOMAIN, ["1.2.3.4"])

        assert len(result.candidates_tested) == 1
        candidate = result.candidates_tested[0]
        assert candidate["reachable"] is False

    def test_connection_refused_status_is_none(self):
        """On connection refused, the status code is None."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("Connection refused"),
        ):
            result = check_cdn_bypass(DOMAIN, ["1.2.3.4"])

        assert result.candidates_tested[0]["status"] is None

    def test_connection_refused_body_size_is_none(self):
        """On connection refused, the body_size is None."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("Connection refused"),
        ):
            result = check_cdn_bypass(DOMAIN, ["1.2.3.4"])

        assert result.candidates_tested[0]["body_size"] is None

    def test_connection_refused_ip_recorded(self):
        """The refused IP is still recorded in candidates_tested."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("Connection refused"),
        ):
            result = check_cdn_bypass(DOMAIN, ["1.2.3.4"])

        assert result.candidates_tested[0]["ip"] == "1.2.3.4"

    def test_connection_refused_continues_to_next_candidate(self):
        """After a refused candidate, the check continues and probes the next IP."""
        good_resp = _make_response(200, body=b"hello")

        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=[
                req_lib.exceptions.ConnectionError("refused"),
                good_resp,
            ],
        ):
            result = check_cdn_bypass(DOMAIN, ["1.2.3.4", "5.6.7.8"])

        assert len(result.candidates_tested) == 2
        assert result.candidates_tested[0]["reachable"] is False
        assert result.candidates_tested[1]["reachable"] is True

    def test_connection_refused_does_not_abort_all_candidates(self):
        """Refused connections do not short-circuit the full candidate list."""
        good_resp = _make_response(200, body=b"OK")

        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=[
                req_lib.exceptions.ConnectionError("refused"),
                req_lib.exceptions.ConnectionError("refused"),
                good_resp,
            ],
        ):
            result = check_cdn_bypass(DOMAIN, ["10.0.0.1", "10.0.0.2", "10.0.0.3"])

        assert len(result.candidates_tested) == 3
        reachable = [c for c in result.candidates_tested if c["reachable"]]
        assert len(reachable) == 1
        assert reachable[0]["ip"] == "10.0.0.3"


# ---------------------------------------------------------------------------
# 2. Timeout → candidate marked unreachable, check continues
# ---------------------------------------------------------------------------

class TestTimeout:
    """A Timeout causes the candidate to be marked unreachable (Req. 6.2)."""

    def test_timeout_marks_candidate_unreachable(self):
        """Single candidate that times out → reachable=False."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_cdn_bypass(DOMAIN, ["1.2.3.4"])

        assert len(result.candidates_tested) == 1
        assert result.candidates_tested[0]["reachable"] is False

    def test_timeout_status_is_none(self):
        """On timeout, the status code is None."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_cdn_bypass(DOMAIN, ["1.2.3.4"])

        assert result.candidates_tested[0]["status"] is None

    def test_timeout_body_size_is_none(self):
        """On timeout, the body_size is None."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_cdn_bypass(DOMAIN, ["1.2.3.4"])

        assert result.candidates_tested[0]["body_size"] is None

    def test_timeout_ip_recorded(self):
        """The timed-out IP is still recorded in candidates_tested."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_cdn_bypass(DOMAIN, ["192.168.1.1"])

        assert result.candidates_tested[0]["ip"] == "192.168.1.1"

    def test_timeout_continues_to_next_candidate(self):
        """After a timeout, the check probes the remaining candidates."""
        good_resp = _make_response(200, body=b"content")

        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=[
                req_lib.exceptions.Timeout("timed out"),
                good_resp,
            ],
        ):
            result = check_cdn_bypass(DOMAIN, ["1.2.3.4", "5.6.7.8"])

        assert len(result.candidates_tested) == 2
        assert result.candidates_tested[0]["reachable"] is False
        assert result.candidates_tested[1]["reachable"] is True

    def test_all_candidates_timeout_yields_all_unreachable(self):
        """When every candidate times out, all are marked unreachable."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            result = check_cdn_bypass(DOMAIN, ["1.1.1.1", "2.2.2.2"])

        assert len(result.candidates_tested) == 2
        assert all(not c["reachable"] for c in result.candidates_tested)


# ---------------------------------------------------------------------------
# 3. Successful direct IP request with Host header → response recorded
# ---------------------------------------------------------------------------

class TestSuccessfulDirectRequest:
    """Successful probes record status code, body size, and reachable=True."""

    def test_successful_probe_marked_reachable(self):
        """A 200 response → reachable=True."""
        resp = _make_response(200, body=b"<html><body>Hello</body></html>")

        with patch("toolkit.execution.checks.cdn_bypass.requests.get", return_value=resp):
            result = check_cdn_bypass(DOMAIN, ["93.184.216.34"])

        assert len(result.candidates_tested) == 1
        assert result.candidates_tested[0]["reachable"] is True

    def test_successful_probe_records_status_code(self):
        """The HTTP status code is recorded in the candidate entry."""
        resp = _make_response(200, body=b"body")

        with patch("toolkit.execution.checks.cdn_bypass.requests.get", return_value=resp):
            result = check_cdn_bypass(DOMAIN, ["93.184.216.34"])

        assert result.candidates_tested[0]["status"] == 200

    def test_successful_probe_records_body_size(self):
        """The body size in bytes is recorded in the candidate entry."""
        body = b"<html><body>response content</body></html>"
        resp = _make_response(200, body=body)

        with patch("toolkit.execution.checks.cdn_bypass.requests.get", return_value=resp):
            result = check_cdn_bypass(DOMAIN, ["93.184.216.34"])

        assert result.candidates_tested[0]["body_size"] == len(body)

    def test_successful_probe_records_ip(self):
        """The probed IP is stored in the candidate entry."""
        resp = _make_response(200, body=b"ok")

        with patch("toolkit.execution.checks.cdn_bypass.requests.get", return_value=resp):
            result = check_cdn_bypass(DOMAIN, ["93.184.216.34"])

        assert result.candidates_tested[0]["ip"] == "93.184.216.34"

    def test_successful_probe_uses_host_header(self):
        """The GET request is sent with the correct Host header."""
        resp = _make_response(200, body=b"ok")
        mock_get = MagicMock(return_value=resp)

        with patch("toolkit.execution.checks.cdn_bypass.requests.get", mock_get):
            check_cdn_bypass(DOMAIN, ["93.184.216.34"])

        call_kwargs = mock_get.call_args
        headers_sent = call_kwargs.kwargs.get("headers") or call_kwargs.args[1] if len(call_kwargs.args) > 1 else {}
        # headers are passed as keyword argument
        sent_headers = mock_get.call_args.kwargs.get("headers", {})
        assert sent_headers.get("Host") == DOMAIN

    def test_successful_probe_url_uses_ip(self):
        """The GET request URL uses the candidate IP address."""
        resp = _make_response(200, body=b"ok")
        mock_get = MagicMock(return_value=resp)

        with patch("toolkit.execution.checks.cdn_bypass.requests.get", mock_get):
            check_cdn_bypass(DOMAIN, ["93.184.216.34"])

        called_url = mock_get.call_args.args[0]
        assert "93.184.216.34" in called_url

    def test_non_200_status_still_marks_reachable(self):
        """A non-200 HTTP response still means the candidate is reachable."""
        resp = _make_response(403, body=b"Forbidden")

        with patch("toolkit.execution.checks.cdn_bypass.requests.get", return_value=resp):
            result = check_cdn_bypass(DOMAIN, ["93.184.216.34"])

        assert result.candidates_tested[0]["reachable"] is True
        assert result.candidates_tested[0]["status"] == 403

    def test_zero_byte_body_recorded_correctly(self):
        """An empty response body is recorded with body_size=0."""
        resp = _make_response(204, body=b"")

        with patch("toolkit.execution.checks.cdn_bypass.requests.get", return_value=resp):
            result = check_cdn_bypass(DOMAIN, ["93.184.216.34"])

        assert result.candidates_tested[0]["body_size"] == 0
        assert result.candidates_tested[0]["reachable"] is True


# ---------------------------------------------------------------------------
# 4. Mixed reachable / unreachable candidates
# ---------------------------------------------------------------------------

class TestMixedCandidates:
    """Mixed scenarios with some reachable and some unreachable candidates."""

    def test_two_reachable_one_unreachable(self):
        """2 reachable + 1 unreachable → counts reflected in helper properties."""
        resp_a = _make_response(200, body=b"page A")
        resp_b = _make_response(200, body=b"page B")

        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=[
                resp_a,
                req_lib.exceptions.ConnectionError("refused"),
                resp_b,
            ],
        ):
            result = check_cdn_bypass(
                DOMAIN, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            )

        assert len(result.candidates_tested) == 3
        assert len(result.reachable_candidates) == 2
        assert len(result.unreachable_candidates) == 1

    def test_one_reachable_two_unreachable(self):
        """1 reachable + 2 unreachable → counts reflected in helper properties."""
        resp = _make_response(200, body=b"ok")

        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=[
                req_lib.exceptions.Timeout("timed out"),
                resp,
                req_lib.exceptions.ConnectionError("refused"),
            ],
        ):
            result = check_cdn_bypass(
                DOMAIN, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            )

        assert len(result.reachable_candidates) == 1
        assert len(result.unreachable_candidates) == 2

    def test_mixed_candidates_domain_preserved(self):
        """The domain is preserved in the result regardless of outcome."""
        resp = _make_response(200, body=b"ok")

        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=[
                req_lib.exceptions.Timeout("timed out"),
                resp,
            ],
        ):
            result = check_cdn_bypass(DOMAIN, ["10.0.0.1", "10.0.0.2"])

        assert result.domain == DOMAIN

    def test_order_preserved_in_candidates_tested(self):
        """Candidates are evaluated in order and appear in that order in results."""
        resp_first = _make_response(200, body=b"first")
        resp_third = _make_response(200, body=b"third")

        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=[
                resp_first,
                req_lib.exceptions.ConnectionError("refused"),
                resp_third,
            ],
        ):
            result = check_cdn_bypass(
                DOMAIN, ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            )

        assert result.candidates_tested[0]["ip"] == "10.0.0.1"
        assert result.candidates_tested[1]["ip"] == "10.0.0.2"
        assert result.candidates_tested[2]["ip"] == "10.0.0.3"

    def test_reachable_candidate_has_correct_body_size(self):
        """Reachable candidates have accurate body_size values."""
        body_a = b"short"
        body_b = b"a much longer response body here"
        resp_a = _make_response(200, body=body_a)
        resp_b = _make_response(200, body=body_b)

        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=[resp_a, resp_b],
        ):
            result = check_cdn_bypass(DOMAIN, ["10.0.0.1", "10.0.0.2"])

        assert result.candidates_tested[0]["body_size"] == len(body_a)
        assert result.candidates_tested[1]["body_size"] == len(body_b)

    def test_empty_candidate_list_returns_empty_results(self):
        """No candidates → no entries in candidates_tested."""
        result = check_cdn_bypass(DOMAIN, [])

        assert result.candidates_tested == []
        assert result.domain == DOMAIN

    def test_all_candidates_reachable(self):
        """When all candidates are reachable, unreachable_candidates is empty."""
        resp_1 = _make_response(200, body=b"ok1")
        resp_2 = _make_response(200, body=b"ok2")
        resp_3 = _make_response(200, body=b"ok3")

        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=[resp_1, resp_2, resp_3],
        ):
            result = check_cdn_bypass(DOMAIN, ["1.1.1.1", "2.2.2.2", "3.3.3.3"])

        assert len(result.reachable_candidates) == 3
        assert len(result.unreachable_candidates) == 0

    def test_all_candidates_unreachable(self):
        """When all candidates fail, reachable_candidates is empty."""
        with patch(
            "toolkit.execution.checks.cdn_bypass.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("refused"),
        ):
            result = check_cdn_bypass(DOMAIN, ["1.1.1.1", "2.2.2.2"])

        assert len(result.reachable_candidates) == 0
        assert len(result.unreachable_candidates) == 2


# ---------------------------------------------------------------------------
# 5. CdnBypassResult dataclass
# ---------------------------------------------------------------------------

class TestCdnBypassResult:
    """CdnBypassResult helper properties work correctly."""

    def test_reachable_candidates_filters_correctly(self):
        """reachable_candidates returns only entries where reachable=True."""
        r = CdnBypassResult(
            domain="example.com",
            candidates_tested=[
                {"ip": "1.1.1.1", "status": 200, "body_size": 100, "reachable": True},
                {"ip": "2.2.2.2", "status": None, "body_size": None, "reachable": False},
                {"ip": "3.3.3.3", "status": 403, "body_size": 50, "reachable": True},
            ],
        )
        reachable = r.reachable_candidates
        assert len(reachable) == 2
        assert all(c["reachable"] for c in reachable)

    def test_unreachable_candidates_filters_correctly(self):
        """unreachable_candidates returns only entries where reachable=False."""
        r = CdnBypassResult(
            domain="example.com",
            candidates_tested=[
                {"ip": "1.1.1.1", "status": 200, "body_size": 100, "reachable": True},
                {"ip": "2.2.2.2", "status": None, "body_size": None, "reachable": False},
            ],
        )
        unreachable = r.unreachable_candidates
        assert len(unreachable) == 1
        assert unreachable[0]["ip"] == "2.2.2.2"

    def test_empty_candidates_tested_gives_empty_properties(self):
        """With no candidates, both helper properties return empty lists."""
        r = CdnBypassResult(domain="example.com")
        assert r.reachable_candidates == []
        assert r.unreachable_candidates == []

    def test_domain_stored_correctly(self):
        """The domain field is stored on the result object."""
        r = CdnBypassResult(domain="test.example.com")
        assert r.domain == "test.example.com"
