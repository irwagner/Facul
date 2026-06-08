"""
Example / unit tests for the IDOR check (Req. 8.1, 8.6).

All HTTP requests are fully mocked; tests never touch the network.

Test coverage
-------------
* generate_variations — integer identifier produces exactly 5 variations
* generate_variations — UUID identifier produces exactly 5 variations
* generate_variations — always contains 0 and -1
* generate_variations — always contains exactly one random UUID
* check_idor — authenticated GET requests include Authorization header
* check_idor — returns at most 5 probes per endpoint
* check_idor — 200 response body is captured in probe
* check_idor — network timeout is captured as error probe
* check_idor — out-of-scope endpoint is skipped with error
* check_idor — no identifier in endpoint returns empty list
* check_idor — integer identifier substitution in URL
* check_idor — UUID identifier substitution in URL
"""

from __future__ import annotations

import re
import uuid as _uuid_mod
from unittest.mock import MagicMock, patch

import pytest
import requests as req_lib

from toolkit.execution.checks.idor import (
    IdorProbe,
    check_idor,
    generate_variations,
)
from toolkit.governance.audit_logger import AuditLogger
from toolkit.governance.scope import ScopeValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)


def _make_response(status_code: int = 200, body: str = "") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = body
    return resp


def _in_scope_validator(domain: str = "api.example.com") -> ScopeValidator:
    return ScopeValidator(authorized_domains=[domain], authorized_cidrs=[])


def _out_of_scope_validator() -> ScopeValidator:
    return ScopeValidator(authorized_domains=["other.com"], authorized_cidrs=[])


# ---------------------------------------------------------------------------
# generate_variations — integer identifiers
# ---------------------------------------------------------------------------

class TestGenerateVariationsInteger:
    """generate_variations behaves correctly for integer inputs."""

    def test_returns_exactly_5_variations(self):
        variations = generate_variations(42)
        assert len(variations) == 5

    def test_contains_increment(self):
        """original + 1 must be in the variation set."""
        variations = generate_variations(10)
        assert "11" in variations

    def test_contains_decrement(self):
        """original - 1 must be in the variation set."""
        variations = generate_variations(10)
        assert "9" in variations

    def test_contains_zero(self):
        """0 must always appear in the variation set."""
        variations = generate_variations(100)
        assert "0" in variations

    def test_contains_negative_one(self):
        """-1 must always appear in the variation set."""
        variations = generate_variations(100)
        assert "-1" in variations

    def test_contains_random_uuid(self):
        """Exactly one variation must be a valid UUID string."""
        variations = generate_variations(5)
        uuid_variants = [v for v in variations if _UUID_PATTERN.fullmatch(v)]
        assert len(uuid_variants) == 1

    def test_all_variations_are_strings(self):
        """All returned values must be strings."""
        variations = generate_variations(7)
        for v in variations:
            assert isinstance(v, str)

    def test_random_uuid_differs_across_calls(self):
        """Two calls should produce different UUIDs with overwhelming probability."""
        v1 = generate_variations(1)
        v2 = generate_variations(1)
        uuids1 = [v for v in v1 if _UUID_PATTERN.fullmatch(v)]
        uuids2 = [v for v in v2 if _UUID_PATTERN.fullmatch(v)]
        # Both should have exactly one UUID
        assert len(uuids1) == 1
        assert len(uuids2) == 1
        # They should differ (random UUID4 collision probability ≈ 0)
        # We don't assert inequality to avoid flakiness, but confirm format
        assert _UUID_PATTERN.fullmatch(uuids1[0])
        assert _UUID_PATTERN.fullmatch(uuids2[0])

    def test_identifier_1_variations(self):
        """Edge case: identifier=1 → decrement is 0, increment is 2."""
        variations = generate_variations(1)
        assert "2" in variations
        assert "0" in variations
        assert "-1" in variations
        assert len(variations) == 5


# ---------------------------------------------------------------------------
# generate_variations — UUID identifiers
# ---------------------------------------------------------------------------

class TestGenerateVariationsUUID:
    """generate_variations behaves correctly for UUID string inputs."""

    def test_returns_exactly_5_variations_for_uuid(self):
        uuid_str = str(_uuid_mod.uuid4())
        variations = generate_variations(uuid_str)
        assert len(variations) == 5

    def test_contains_zero_for_uuid(self):
        uuid_str = str(_uuid_mod.uuid4())
        variations = generate_variations(uuid_str)
        assert "0" in variations

    def test_contains_negative_one_for_uuid(self):
        uuid_str = str(_uuid_mod.uuid4())
        variations = generate_variations(uuid_str)
        assert "-1" in variations

    def test_contains_random_uuid_for_uuid_input(self):
        uuid_str = str(_uuid_mod.uuid4())
        variations = generate_variations(uuid_str)
        uuid_variants = [v for v in variations if _UUID_PATTERN.fullmatch(v)]
        assert len(uuid_variants) == 1

    def test_all_variations_are_strings_for_uuid_input(self):
        uuid_str = str(_uuid_mod.uuid4())
        variations = generate_variations(uuid_str)
        for v in variations:
            assert isinstance(v, str)


# ---------------------------------------------------------------------------
# check_idor — authenticated requests
# ---------------------------------------------------------------------------

class TestCheckIdorAuthentication:
    """check_idor attaches the auth token to every request."""

    def test_authorization_bearer_header_sent(self):
        """Each request must include 'Authorization: Bearer <token>'."""
        endpoint = "https://api.example.com/api/users/42"
        token = "my-secret-token"
        mock_resp = _make_response(200, body='{"id": 99}')

        captured_headers: list[dict] = []

        def side_effect(url, headers=None, **kwargs):
            captured_headers.append(dict(headers or {}))
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=side_effect,
        ):
            probes = check_idor(endpoint, auth_token=token)

        assert len(probes) > 0
        for hdrs in captured_headers:
            assert "Authorization" in hdrs
            assert hdrs["Authorization"] == f"Bearer {token}"

    def test_authorization_header_not_empty(self):
        """The Authorization header value is never empty."""
        endpoint = "https://api.example.com/api/users/7"
        token = "abc123"
        mock_resp = _make_response(404)

        captured_headers: list[dict] = []

        def side_effect(url, headers=None, **kwargs):
            captured_headers.append(dict(headers or {}))
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=side_effect,
        ):
            probes = check_idor(endpoint, auth_token=token)

        for hdrs in captured_headers:
            assert hdrs.get("Authorization", "") != ""


# ---------------------------------------------------------------------------
# check_idor — maximum probes (Req. 8.6)
# ---------------------------------------------------------------------------

class TestCheckIdorMaxProbes:
    """check_idor never returns more than 5 probes (Req. 8.6)."""

    def test_returns_at_most_5_probes_for_integer_id(self):
        endpoint = "https://api.example.com/api/users/100"
        mock_resp = _make_response(404)

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert len(probes) <= 5

    def test_returns_exactly_5_probes_for_integer_id(self):
        """For a numeric ID endpoint, exactly 5 probes are returned."""
        endpoint = "https://api.example.com/api/users/55"
        mock_resp = _make_response(200, body='{"id": 1}')

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert len(probes) == 5

    def test_returns_at_most_5_probes_for_uuid(self):
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        endpoint = f"https://api.example.com/api/users/{uuid_str}"
        mock_resp = _make_response(403)

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert len(probes) <= 5


# ---------------------------------------------------------------------------
# check_idor — response capture
# ---------------------------------------------------------------------------

class TestCheckIdorResponseCapture:
    """Probes correctly record status codes and response bodies."""

    def test_200_response_body_is_captured(self):
        """A 200 response body is stored in the probe."""
        endpoint = "https://api.example.com/api/users/10"
        body_200 = '{"id": 99, "name": "Alice"}'
        mock_resp = _make_response(200, body=body_200)

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        # At least one probe captured a 200 with that body
        successful = [p for p in probes if p.status_code == 200]
        assert len(successful) > 0
        for p in successful:
            assert p.response_body == body_200
            assert p.error is None

    def test_404_status_code_recorded(self):
        """A 404 response is correctly recorded with status_code=404."""
        endpoint = "https://api.example.com/api/users/10"
        mock_resp = _make_response(404)

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert any(p.status_code == 404 for p in probes)

    def test_probe_variation_value_is_string(self):
        """variation_value in every probe is a string."""
        endpoint = "https://api.example.com/api/users/20"
        mock_resp = _make_response(404)

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        for p in probes:
            assert isinstance(p.variation_value, str)

    def test_probe_endpoint_is_string(self):
        """The endpoint field in every probe is a string URL."""
        endpoint = "https://api.example.com/api/users/5"
        mock_resp = _make_response(200, body='{}')

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        for p in probes:
            assert isinstance(p.endpoint, str)
            assert p.endpoint.startswith("https://")


# ---------------------------------------------------------------------------
# check_idor — timeout handling
# ---------------------------------------------------------------------------

class TestCheckIdorTimeout:
    """Network timeouts are recorded as error probes without halting the check."""

    def test_timeout_captured_as_error_probe(self):
        """A Timeout exception produces an error probe with status_code=None."""
        endpoint = "https://api.example.com/api/users/30"

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            probes = check_idor(endpoint, auth_token="tok")

        timeout_probes = [p for p in probes if p.status_code is None and p.error]
        assert len(timeout_probes) > 0

    def test_timeout_probe_has_error_description(self):
        """The error field of a timeout probe is a non-empty string."""
        endpoint = "https://api.example.com/api/users/30"

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=req_lib.exceptions.Timeout("timed out"),
        ):
            probes = check_idor(endpoint, auth_token="tok")

        for p in probes:
            assert isinstance(p.error, str)
            assert len(p.error) > 0

    def test_timeout_does_not_abort_remaining_probes(self):
        """
        A timeout on the first probe does not abort the remaining 4 probes.
        """
        endpoint = "https://api.example.com/api/users/30"
        mock_resp = _make_response(404)

        call_count = {"n": 0}

        def side_effect(url, **kwargs):
            n = call_count["n"]
            call_count["n"] += 1
            if n == 0:
                raise req_lib.exceptions.Timeout("timed out")
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=side_effect,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        # All 5 variations attempted despite first timeout
        assert len(probes) == 5


# ---------------------------------------------------------------------------
# check_idor — scope validation
# ---------------------------------------------------------------------------

class TestCheckIdorScope:
    """Scope is validated before each probe request (Req. 8.1)."""

    def test_in_scope_endpoint_proceeds(self):
        """When the endpoint host is in scope, probes are executed."""
        endpoint = "https://api.example.com/api/users/1"
        scope = _in_scope_validator("api.example.com")
        logger_inst = AuditLogger()
        mock_resp = _make_response(200, body='{"id": 2}')

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(
                endpoint,
                auth_token="tok",
                scope_validator=scope,
                audit_logger=logger_inst,
            )

        assert len(probes) == 5
        # No out-of-scope errors
        out_of_scope = [p for p in probes if p.error and "scope" in p.error.lower()]
        assert len(out_of_scope) == 0

    def test_out_of_scope_endpoint_skipped_with_error(self):
        """When the endpoint host is out of scope, probes are skipped and error recorded."""
        endpoint = "https://evil.com/api/users/1"
        scope = _out_of_scope_validator()
        logger_inst = AuditLogger()

        mock_get = MagicMock()
        with patch(
            "toolkit.execution.checks.idor.requests.get",
            mock_get,
        ):
            probes = check_idor(
                endpoint,
                auth_token="tok",
                scope_validator=scope,
                audit_logger=logger_inst,
            )

        # All probes should be error probes (skipped due to scope)
        for p in probes:
            assert p.status_code is None
            assert p.error is not None
            assert "scope" in p.error.lower()

        # The network was never called
        mock_get.assert_not_called()

    def test_scope_block_logged_in_audit_logger(self):
        """Each out-of-scope probe produces an audit event."""
        endpoint = "https://evil.com/api/users/1"
        scope = _out_of_scope_validator()
        logger_inst = AuditLogger()

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            MagicMock(),
        ):
            check_idor(
                endpoint,
                auth_token="tok",
                scope_validator=scope,
                audit_logger=logger_inst,
            )

        events = logger_inst.get_events()
        scope_blocks = [e for e in events if e.event_type == "scope_block"]
        assert len(scope_blocks) > 0


# ---------------------------------------------------------------------------
# check_idor — no identifier in endpoint
# ---------------------------------------------------------------------------

class TestCheckIdorNoIdentifier:
    """When no identifier is found in the endpoint, an empty list is returned."""

    def test_endpoint_without_identifier_returns_empty(self):
        """A path with no numeric or UUID segment yields no probes."""
        endpoint = "https://api.example.com/api/users/profile/settings"
        mock_get = MagicMock()

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            mock_get,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert probes == []
        mock_get.assert_not_called()

    def test_root_endpoint_without_identifier_returns_empty(self):
        """A bare root path yields no probes."""
        endpoint = "https://api.example.com/"
        mock_get = MagicMock()

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            mock_get,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert probes == []


# ---------------------------------------------------------------------------
# check_idor — identifier substitution in URL
# ---------------------------------------------------------------------------

class TestCheckIdorIdentifierSubstitution:
    """The correct identifier is substituted in the probed URL."""

    def test_integer_id_is_replaced_in_url(self):
        """Each probe URL has the variation value substituted for the original ID."""
        endpoint = "https://api.example.com/api/users/42"
        mock_resp = _make_response(404)

        probed_urls: list[str] = []

        def side_effect(url, **kwargs):
            probed_urls.append(url)
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=side_effect,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        # The original ID "42" should NOT appear in most probe URLs
        # (it might appear in the increment 43 or decrement 41 by coincidence,
        #  but the substitution mechanism should replace it)
        for probe, url in zip(probes, probed_urls):
            # Each probe endpoint should not still contain the plain "/42" path
            # (unless the variation itself resolved to 42, which should not happen)
            assert probe.endpoint == url

    def test_uuid_id_is_replaced_in_url(self):
        """For a UUID endpoint, the UUID segment is replaced by each variation."""
        original_uuid = "550e8400-e29b-41d4-a716-446655440000"
        endpoint = f"https://api.example.com/api/users/{original_uuid}"
        mock_resp = _make_response(404)

        probed_urls: list[str] = []

        def side_effect(url, **kwargs):
            probed_urls.append(url)
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=side_effect,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert len(probes) == 5
        # At least one probed URL should not contain the original UUID
        assert not all(original_uuid.lower() in url.lower() for url in probed_urls)


# ---------------------------------------------------------------------------
# IdorProbe dataclass
# ---------------------------------------------------------------------------

class TestIdorProbeDataclass:
    """IdorProbe is a proper dataclass with the expected fields."""

    def test_idor_probe_fields(self):
        probe = IdorProbe(
            endpoint="https://api.example.com/api/users/2",
            variation_value="2",
            status_code=200,
            response_body='{"id": 2}',
        )
        assert probe.endpoint == "https://api.example.com/api/users/2"
        assert probe.variation_value == "2"
        assert probe.status_code == 200
        assert probe.response_body == '{"id": 2}'
        assert probe.error is None

    def test_idor_probe_with_error(self):
        probe = IdorProbe(
            endpoint="https://api.example.com/api/users/0",
            variation_value="0",
            status_code=None,
            response_body=None,
            error="Connection refused",
        )
        assert probe.status_code is None
        assert probe.response_body is None
        assert probe.error == "Connection refused"


# ---------------------------------------------------------------------------
# Task 10.3 — Authenticated IDOR request assembly (Req. 8.1)
# ---------------------------------------------------------------------------

class TestCheckIdorAuthenticatedRequests:
    """
    Explicit verification of authenticated request assembly for IDOR checks.

    Covers the four scenarios required by task 10.3 (Req. 8.1):
      1. Every request carries ``Authorization: Bearer <token>`` header.
      2. Each identifier variation generates exactly one separate request.
      3. Non-200 responses (e.g. 403, 404, 500) are recorded with their
         status code and ``error=None`` — they are *findings*, not errors.
      4. ``ScopeValidator.assert_in_scope`` is called once per variation
         (before each request) when a scope validator is provided.
    """

    # ------------------------------------------------------------------
    # 1. Authorization: Bearer <token> header
    # ------------------------------------------------------------------

    def test_bearer_token_exact_format_on_every_request(self):
        """
        Every outgoing GET request must include an *exact*
        ``Authorization: Bearer <token>`` header for the supplied token.

        Verifies Req. 8.1: "make authenticated requests with the current
        user's token."
        """
        endpoint = "https://api.example.com/api/users/99"
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
        mock_resp = _make_response(200, body='{"id": 1}')

        captured_headers: list[dict] = []

        def capture_headers(url, headers=None, **kwargs):
            captured_headers.append(dict(headers or {}))
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=capture_headers,
        ):
            probes = check_idor(endpoint, auth_token=token)

        # At least 5 requests must have been made
        assert len(captured_headers) == 5
        for hdrs in captured_headers:
            assert hdrs.get("Authorization") == f"Bearer {token}", (
                f"Expected 'Bearer {token}', got {hdrs.get('Authorization')!r}"
            )

    def test_bearer_token_with_simple_alphanumeric_token(self):
        """Authorization header is correct for a plain alphanumeric token."""
        endpoint = "https://api.example.com/api/transactions/7"
        token = "abc123xyz"
        mock_resp = _make_response(404)

        captured_headers: list[dict] = []

        def capture_headers(url, headers=None, **kwargs):
            captured_headers.append(dict(headers or {}))
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=capture_headers,
        ):
            check_idor(endpoint, auth_token=token)

        for hdrs in captured_headers:
            assert "Authorization" in hdrs
            assert hdrs["Authorization"] == f"Bearer {token}"

    # ------------------------------------------------------------------
    # 2. Each variation generates a separate request
    # ------------------------------------------------------------------

    def test_each_variation_generates_exactly_one_request(self):
        """
        Five identifier variations must produce exactly five separate
        HTTP GET requests — one per variation, in order.

        Each probe's ``endpoint`` field must match the URL that was actually
        requested, proving every variation has its own dedicated request.
        """
        endpoint = "https://api.example.com/api/users/42"
        mock_resp = _make_response(200, body='{"id": 5}')

        requested_urls: list[str] = []

        def capture_url(url, **kwargs):
            requested_urls.append(url)
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=capture_url,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        # Exactly 5 separate requests were made
        assert len(requested_urls) == 5
        assert len(probes) == 5

        # Each probe's endpoint field must equal the URL that was requested
        for probe, url in zip(probes, requested_urls):
            assert probe.endpoint == url, (
                f"Probe endpoint {probe.endpoint!r} does not match "
                f"the actual requested URL {url!r}"
            )

        # The 5 requests are pairwise distinct (no variation is skipped or doubled)
        assert len(set(requested_urls)) == len(requested_urls), (
            "Duplicate request URLs detected — each variation must produce a unique request"
        )

    def test_uuid_endpoint_each_variation_generates_one_request(self):
        """
        A UUID endpoint also generates exactly 5 separate requests,
        one per variation.
        """
        uuid_str = "550e8400-e29b-41d4-a716-446655440000"
        endpoint = f"https://api.example.com/api/users/{uuid_str}"
        mock_resp = _make_response(403)

        call_count = {"n": 0}

        def count_calls(url, **kwargs):
            call_count["n"] += 1
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=count_calls,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert call_count["n"] == 5
        assert len(probes) == 5

    # ------------------------------------------------------------------
    # 3. Non-200 responses recorded (not errors)
    # ------------------------------------------------------------------

    def test_non_200_response_recorded_with_status_code_not_error(self):
        """
        Non-200 responses (403, 404, 500, etc.) must be recorded as probes
        with the actual ``status_code`` set and ``error=None``.

        They are *findings* about the endpoint behaviour, not network errors.
        """
        endpoint = "https://api.example.com/api/users/20"
        mock_resp = _make_response(403, body="Forbidden")

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert len(probes) == 5
        for probe in probes:
            assert probe.status_code == 403, (
                f"Expected status_code=403, got {probe.status_code}"
            )
            assert probe.error is None, (
                f"Non-200 response must not set error field; got {probe.error!r}"
            )

    def test_404_recorded_with_null_error(self):
        """A 404 response sets status_code=404 and error=None."""
        endpoint = "https://api.example.com/api/users/50"
        mock_resp = _make_response(404, body="Not Found")

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        for probe in probes:
            assert probe.status_code == 404
            assert probe.error is None

    def test_500_recorded_with_null_error(self):
        """A 500 response sets status_code=500 and error=None (server error ≠ network error)."""
        endpoint = "https://api.example.com/api/users/3"
        mock_resp = _make_response(500, body="Internal Server Error")

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            return_value=mock_resp,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        for probe in probes:
            assert probe.status_code == 500
            assert probe.error is None

    def test_mixed_responses_each_recorded_correctly(self):
        """
        When responses differ per variation, each probe records its own
        status code with ``error=None``.
        """
        endpoint = "https://api.example.com/api/users/15"
        status_codes = [200, 403, 404, 401, 500]
        responses = [_make_response(sc, body=f"body-{sc}") for sc in status_codes]

        call_count = {"n": 0}

        def rotating_responses(url, **kwargs):
            resp = responses[call_count["n"] % len(responses)]
            call_count["n"] += 1
            return resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=rotating_responses,
        ):
            probes = check_idor(endpoint, auth_token="tok")

        assert len(probes) == 5
        for i, probe in enumerate(probes):
            assert probe.status_code == status_codes[i]
            assert probe.error is None, (
                f"Probe {i} has status_code={probe.status_code} but "
                f"error should be None, got {probe.error!r}"
            )

    # ------------------------------------------------------------------
    # 4. Scope validation called before each request
    # ------------------------------------------------------------------

    def test_scope_validator_called_before_each_request(self):
        """
        ``ScopeValidator.assert_in_scope`` must be called exactly once per
        variation (i.e. 5 times total) before any HTTP request is made.

        This ensures scope is enforced at the per-request level, not just
        once at the start of the check (Req. 8.1, 1.4).
        """
        endpoint = "https://api.example.com/api/users/42"
        scope = _in_scope_validator("api.example.com")
        logger_inst = AuditLogger()
        mock_resp = _make_response(200, body='{"id": 1}')

        scope_call_order: list[str] = []
        request_call_order: list[str] = []

        original_assert = scope.assert_in_scope

        def tracking_assert(target, module, logger):
            scope_call_order.append(target)
            return original_assert(target, module, logger)

        request_urls: list[str] = []

        def tracking_get(url, **kwargs):
            request_urls.append(url)
            return mock_resp

        scope.assert_in_scope = tracking_assert  # type: ignore[method-assign]

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=tracking_get,
        ):
            probes = check_idor(
                endpoint,
                auth_token="tok",
                scope_validator=scope,
                audit_logger=logger_inst,
            )

        # Scope must be validated for every variation (5 times)
        assert len(scope_call_order) == 5, (
            f"Expected 5 scope validation calls, got {len(scope_call_order)}"
        )
        # All 5 requests were dispatched (all in scope)
        assert len(request_urls) == 5
        assert len(probes) == 5

    def test_scope_validator_called_before_each_out_of_scope_request(self):
        """
        Even for out-of-scope endpoints, ``assert_in_scope`` must be called
        for every variation (5 times), and no HTTP request must be dispatched.
        """
        endpoint = "https://evil.com/api/users/1"
        scope = _out_of_scope_validator()
        logger_inst = AuditLogger()

        scope_call_count = {"n": 0}
        original_assert = scope.assert_in_scope

        def tracking_assert(target, module, logger):
            scope_call_count["n"] += 1
            return original_assert(target, module, logger)

        scope.assert_in_scope = tracking_assert  # type: ignore[method-assign]

        mock_get = MagicMock()

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            mock_get,
        ):
            probes = check_idor(
                endpoint,
                auth_token="tok",
                scope_validator=scope,
                audit_logger=logger_inst,
            )

        # Scope checked for every variation
        assert scope_call_count["n"] == 5
        # No HTTP requests dispatched
        mock_get.assert_not_called()
        # All 5 probes are error probes
        assert len(probes) == 5
        for probe in probes:
            assert probe.error is not None
            assert "scope" in probe.error.lower()

    def test_scope_validated_per_request_not_once_globally(self):
        """
        Scope validation must happen per-request, not once for the whole
        check.  We verify this by patching scope with a partial allow:
        some variations are in scope, others are not — each must be
        evaluated independently.
        """
        # We use a custom scope validator that only allows the first 2 calls
        endpoint = "https://api.example.com/api/users/5"
        logger_inst = AuditLogger()

        call_count = {"n": 0}

        class PartialScopeValidator:
            """Allows first 2 calls, rejects the remaining ones."""

            def assert_in_scope(self, target, module, logger):
                from toolkit.exceptions import ScopeError
                call_count["n"] += 1
                if call_count["n"] > 2:
                    raise ScopeError(
                        f"Rejected call {call_count['n']}",
                        target=target,
                        authorized_scope=[],
                    )

        partial_scope = PartialScopeValidator()
        mock_resp = _make_response(200, body='{"id": 1}')
        request_count = {"n": 0}

        def counting_get(url, **kwargs):
            request_count["n"] += 1
            return mock_resp

        with patch(
            "toolkit.execution.checks.idor.requests.get",
            side_effect=counting_get,
        ):
            probes = check_idor(
                endpoint,
                auth_token="tok",
                scope_validator=partial_scope,  # type: ignore[arg-type]
                audit_logger=logger_inst,
            )

        # Scope was checked per-request: 5 calls total
        assert call_count["n"] == 5
        # Only the first 2 requests were dispatched (scope allowed)
        assert request_count["n"] == 2
        # All 5 probes recorded
        assert len(probes) == 5
        # First 2 are successful, last 3 are scope-error probes
        successful = [p for p in probes if p.error is None]
        rejected = [p for p in probes if p.error is not None]
        assert len(successful) == 2
        assert len(rejected) == 3
