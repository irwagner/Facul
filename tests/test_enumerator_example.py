"""
Example tests for Enumerator.probe_parameters and RateLimiter configuration limits.

Covers:
- Req. 3.5: Enumerator varies one parameter at a time and records observable
  JSON field names from response bodies.
- Req. 3.6: Configurable delay between requests under HTTP 429, with
  minimum 1 s and maximum 60 s (default 5 s).
"""

from __future__ import annotations

import json
import unittest.mock as mock

import pytest

from toolkit.discovery.enumerator import Enumerator
from toolkit.governance.rate_limiter import RateLimiter
from toolkit.models import Endpoint


# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------


def _make_endpoint(path: str = "https://example.com/api/users") -> Endpoint:
    """Return a minimal Endpoint suitable for probe_parameters."""
    return Endpoint(path=path, status_code=200, body_size=100, kind="page")


class _FakeResponse:
    """Minimal fake HTTP response returned by the fake session."""

    def __init__(
        self,
        status_code: int = 200,
        body: dict | None = None,
        text: str = "",
    ) -> None:
        self.status_code = status_code
        self._body = body
        self.text = text if body is None else json.dumps(body)

    def json(self) -> dict:  # pragma: no cover – not called by probe_parameters
        return self._body or {}


class _FakeSession:
    """
    Fake HTTP session that records every (url, params) call and returns a
    configurable sequence of responses.

    If ``responses`` is a single ``_FakeResponse``, every call returns it.
    If it is a list, responses are consumed in order (last one is repeated
    when the list is exhausted).
    """

    def __init__(
        self,
        responses: _FakeResponse | list[_FakeResponse] | None = None,
    ) -> None:
        if responses is None:
            responses = _FakeResponse()
        self._responses: list[_FakeResponse] = (
            responses if isinstance(responses, list) else [responses]
        )
        self.calls: list[dict] = []  # each entry: {"url": ..., "params": ..., "kwargs": ...}

    def get(self, url: str, **kwargs) -> _FakeResponse:
        params = kwargs.get("params", {})
        self.calls.append({"url": url, "params": params, "kwargs": kwargs})
        idx = min(len(self.calls) - 1, len(self._responses) - 1)
        return self._responses[idx]


# ---------------------------------------------------------------------------
# probe_parameters — Req. 3.5
# ---------------------------------------------------------------------------


class TestProbeParametersNoSession:
    """When session is None, probe_parameters must return an empty list."""

    def test_returns_empty_list_without_session(self):
        enumerator = Enumerator()
        result = enumerator.probe_parameters(_make_endpoint(), session=None)
        assert result == []


class TestProbeParametersOneAtATime:
    """
    Req. 3.5: The Enumerator SHALL attempt to identify accepted parameters by
    varying **one parameter at a time**.

    Each probe call must send exactly one query parameter per HTTP request.
    """

    def test_each_request_sends_exactly_one_param(self):
        """Every HTTP call produced by probe_parameters carries a single param."""
        session = _FakeSession(_FakeResponse(status_code=200, body={"id": 1, "name": "x"}))
        enumerator = Enumerator()
        enumerator.probe_parameters(_make_endpoint(), session=session)

        for call in session.calls:
            params = call["params"]
            assert isinstance(params, dict), "params must be a dict"
            assert len(params) == 1, (
                f"Expected exactly 1 parameter per request, got {len(params)}: {params!r}"
            )

    def test_each_probe_param_key_is_different(self):
        """Each request in the probe loop uses a distinct parameter name."""
        session = _FakeSession(_FakeResponse(status_code=200, body={}))
        enumerator = Enumerator()
        enumerator.probe_parameters(_make_endpoint(), session=session)

        param_keys = [list(call["params"].keys())[0] for call in session.calls]
        # All keys that were sent must be unique — no duplicated probes
        assert len(param_keys) == len(set(param_keys)), (
            f"Duplicate probe parameter keys detected: {param_keys!r}"
        )

    def test_multiple_calls_do_not_combine_params(self):
        """
        Verify that on the second call the enumerator does not accumulate
        parameters from previous iterations (each call is independent).
        """
        session = _FakeSession(_FakeResponse(status_code=200, body={"result": []}))
        enumerator = Enumerator()
        enumerator.probe_parameters(_make_endpoint(), session=session)

        for i, call in enumerate(session.calls):
            params = call["params"]
            assert len(params) == 1, (
                f"Call #{i} sent {len(params)} params; expected exactly 1. "
                f"params={params!r}"
            )


class TestProbeParametersFieldRecording:
    """
    Req. 3.5: The Enumerator SHALL record the observable output field names
    from the response JSON.
    """

    def test_records_json_field_names_from_200_response(self):
        """Fields from a JSON 200 response body are returned."""
        body = {"userId": 42, "email": "a@b.com", "balance": 100.0}
        session = _FakeSession(_FakeResponse(status_code=200, body=body))
        enumerator = Enumerator()

        result = enumerator.probe_parameters(_make_endpoint(), session=session)

        for field in body.keys():
            assert field in result, (
                f"Expected field {field!r} in probe result, got {result!r}"
            )

    def test_no_fields_recorded_for_non_200_response(self):
        """A non-200 response must not contribute field names to the result."""
        body = {"error": "not found"}
        session = _FakeSession(_FakeResponse(status_code=404, body=body))
        enumerator = Enumerator()

        result = enumerator.probe_parameters(_make_endpoint(), session=session)

        assert result == [], (
            f"Expected empty result for non-200 response, got {result!r}"
        )

    def test_non_json_200_response_not_recorded(self):
        """A 200 response with non-JSON body must not produce field names."""
        session = _FakeSession(
            _FakeResponse(status_code=200, text="<html><body>OK</body></html>")
        )
        enumerator = Enumerator()

        result = enumerator.probe_parameters(_make_endpoint(), session=session)

        assert result == [], (
            f"Expected empty result for non-JSON response, got {result!r}"
        )

    def test_fields_deduplicated_across_probes(self):
        """
        When multiple probe responses return overlapping JSON keys, the
        result list must not contain duplicates.
        """
        # All probes return the same body with overlapping keys
        common_body = {"id": 1, "name": "alice"}
        responses = [_FakeResponse(status_code=200, body=common_body)] * 10
        session = _FakeSession(responses)
        enumerator = Enumerator()

        result = enumerator.probe_parameters(_make_endpoint(), session=session)

        assert len(result) == len(set(result)), (
            f"Duplicate field names in result: {result!r}"
        )

    def test_records_fields_from_different_probe_responses(self):
        """
        Different probe requests may reveal different response fields.
        All unique field names across all successful probes must be recorded.
        """
        responses = [
            _FakeResponse(status_code=200, body={"id": 1}),
            _FakeResponse(status_code=200, body={"name": "alice"}),
            _FakeResponse(status_code=200, body={"balance": 100}),
            _FakeResponse(status_code=404, body={"error": "bad"}),
            _FakeResponse(status_code=200, body={"status": "active"}),
            _FakeResponse(status_code=200, body={}),
        ]
        session = _FakeSession(responses)
        enumerator = Enumerator()

        result = enumerator.probe_parameters(_make_endpoint(), session=session)

        for expected_field in ["id", "name", "balance", "status"]:
            assert expected_field in result, (
                f"Field {expected_field!r} missing from probe result {result!r}"
            )

        assert "error" not in result, (
            "Fields from non-200 responses must not appear in the result"
        )

    def test_empty_json_object_response_contributes_no_fields(self):
        """An empty JSON object {} must not add any field names."""
        session = _FakeSession(_FakeResponse(status_code=200, body={}))
        enumerator = Enumerator()

        result = enumerator.probe_parameters(_make_endpoint(), session=session)

        assert result == [], f"Expected empty result for empty JSON body, got {result!r}"

    def test_json_array_response_not_recorded(self):
        """A JSON array response (not a dict) must not contribute field names."""
        session = _FakeSession(_FakeResponse(status_code=200, text="[1, 2, 3]"))
        enumerator = Enumerator()

        result = enumerator.probe_parameters(_make_endpoint(), session=session)

        assert result == [], (
            f"Expected empty result for JSON array response, got {result!r}"
        )

    def test_network_error_on_one_probe_does_not_abort(self):
        """
        A network exception on one probe must not abort the remaining probes.
        Other probes that succeed must still contribute field names.
        """
        call_count = [0]
        probe_params_used = []

        def fake_get(url, **kwargs):
            call_count[0] += 1
            params = kwargs.get("params", {})
            probe_params_used.append(list(params.keys()))
            if call_count[0] == 1:
                raise ConnectionError("simulated network failure")
            return _FakeResponse(status_code=200, body={"found_field": "value"})

        fake_session = type("FakeSession", (), {"get": staticmethod(fake_get)})()
        enumerator = Enumerator()

        result = enumerator.probe_parameters(_make_endpoint(), session=fake_session)

        # At minimum, some probes after the failing one must have produced results
        assert "found_field" in result, (
            f"Expected 'found_field' in result after network error on first probe, "
            f"got {result!r}"
        )


# ---------------------------------------------------------------------------
# RateLimiter configuration limits — Req. 3.6, 3.7
# ---------------------------------------------------------------------------


class TestRateLimiterConfigLimits:
    """
    Req. 3.7: max_rps is clamped to [1, 10] req/s.
    Req. 3.6: backoff delay is clamped to [1, 60] s (default 5 s).
    """

    # ------------------------------------------------------------------
    # max_rps boundary values (Req. 3.7)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("rps, expected", [
        (1, 1.0),    # lower bound (in range)
        (10, 10.0),  # upper bound (in range)
        (5, 5.0),    # mid-range value
    ])
    def test_rps_within_range_is_accepted(self, rps: int, expected: float):
        """Values in [1, 10] must be accepted without clamping."""
        rl = RateLimiter(max_rps=rps)
        assert rl._max_tokens == expected
        assert rl._refill_rate == expected

    @pytest.mark.parametrize("rps, expected_clamped", [
        (0, 1.0),     # zero → clamped to minimum
        (-1, 1.0),    # negative → clamped to minimum
        (-100, 1.0),  # large negative → clamped to minimum
        (11, 10.0),   # one above maximum → clamped to maximum
        (100, 10.0),  # far above maximum → clamped to maximum
        (1000, 10.0), # very large → clamped to maximum
    ])
    def test_rps_outside_range_is_clamped(self, rps: int, expected_clamped: float):
        """Values outside [1, 10] must be clamped to the nearest boundary."""
        rl = RateLimiter(max_rps=rps)
        assert rl._max_tokens == expected_clamped, (
            f"max_rps={rps}: expected _max_tokens={expected_clamped}, "
            f"got {rl._max_tokens}"
        )
        assert rl._refill_rate == expected_clamped, (
            f"max_rps={rps}: expected _refill_rate={expected_clamped}, "
            f"got {rl._refill_rate}"
        )

    def test_default_rps_is_10(self):
        """Default max_rps must be 10 req/s (Req. 3.7 default)."""
        rl = RateLimiter()
        assert rl._max_tokens == 10.0
        assert rl._refill_rate == 10.0

    def test_token_bucket_starts_full(self):
        """The token bucket must start with all tokens available."""
        for rps in (1, 5, 10):
            rl = RateLimiter(max_rps=rps)
            assert rl._tokens == float(rps), (
                f"Expected _tokens={float(rps)} on init with max_rps={rps}, "
                f"got {rl._tokens}"
            )

    # ------------------------------------------------------------------
    # apply_backoff delay boundary values (Req. 3.6)
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("delay, expected_sleep", [
        (1.0, 1.0),   # lower bound (in range)
        (60.0, 60.0), # upper bound (in range)
        (5.0, 5.0),   # default value
        (30.0, 30.0), # mid-range
        (10.0, 10.0), # another mid-range
    ])
    def test_delay_within_range_is_accepted(self, delay: float, expected_sleep: float):
        """Delay values in [1, 60] must be applied without modification."""
        rl = RateLimiter()
        with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
            rl.apply_backoff(delay_s=delay)
        mock_sleep.assert_called_once_with(expected_sleep)

    @pytest.mark.parametrize("delay, expected_sleep", [
        (0.0, 1.0),    # zero → clamped to minimum
        (-5.0, 1.0),   # negative → clamped to minimum
        (0.5, 1.0),    # below minimum → clamped to 1
        (0.999, 1.0),  # just below minimum → clamped to 1
        (60.001, 60.0),# just above maximum → clamped to 60
        (61.0, 60.0),  # above maximum → clamped to 60
        (120.0, 60.0), # double maximum → clamped to 60
        (3600.0, 60.0),# large value → clamped to 60
    ])
    def test_delay_outside_range_is_clamped(self, delay: float, expected_sleep: float):
        """Delay values outside [1, 60] must be clamped to the nearest boundary."""
        rl = RateLimiter()
        with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
            rl.apply_backoff(delay_s=delay)
        mock_sleep.assert_called_once_with(expected_sleep)

    def test_default_delay_is_5_seconds(self):
        """apply_backoff() with no argument must use 5 s as the default (Req. 3.6)."""
        rl = RateLimiter()
        with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
            rl.apply_backoff()
        mock_sleep.assert_called_once_with(5.0)

    def test_apply_backoff_calls_sleep_exactly_once(self):
        """apply_backoff must invoke time.sleep exactly once per call."""
        rl = RateLimiter()
        with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
            rl.apply_backoff(delay_s=10.0)
        assert mock_sleep.call_count == 1

    def test_apply_backoff_does_not_modify_token_bucket(self):
        """apply_backoff must not consume tokens from the rate limiter bucket."""
        rl = RateLimiter(max_rps=5)
        initial_tokens = rl._tokens

        with mock.patch("toolkit.governance.rate_limiter.time.sleep"):
            rl.apply_backoff(delay_s=2.0)

        # Tokens should not have changed (backoff is independent of the bucket)
        assert rl._tokens == initial_tokens, (
            f"apply_backoff must not consume tokens; "
            f"expected {initial_tokens}, got {rl._tokens}"
        )

    # ------------------------------------------------------------------
    # Interaction between rate limit and backoff (Req. 3.6, 3.7)
    # ------------------------------------------------------------------

    def test_rate_limiter_with_minimum_rps_and_minimum_backoff(self):
        """
        A RateLimiter at minimum rate (1 req/s) with minimum backoff (1 s)
        must be constructable and callable without error.
        """
        rl = RateLimiter(max_rps=1)
        assert rl._max_tokens == 1.0

        with mock.patch("toolkit.governance.rate_limiter.time.sleep"):
            rl.apply_backoff(delay_s=1.0)

    def test_rate_limiter_with_maximum_rps_and_maximum_backoff(self):
        """
        A RateLimiter at maximum rate (10 req/s) with maximum backoff (60 s)
        must be constructable and callable without error.
        """
        rl = RateLimiter(max_rps=10)
        assert rl._max_tokens == 10.0

        with mock.patch("toolkit.governance.rate_limiter.time.sleep"):
            rl.apply_backoff(delay_s=60.0)
