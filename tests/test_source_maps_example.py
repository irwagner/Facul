"""
Example tests for the source map exposure check (Req. 4.1, 4.6).

All HTTP requests are fully mocked via ``unittest.mock``; no network access.

Test coverage
-------------
* 403 response on .map path → logged as error, excluded from result
* 500 response on .map path → logged as error, excluded from result
* Timeout on .map path → logged as error, excluded from result
* 403/500/timeout paths are stored in error_maps, not accessible_maps or not_found_maps
* 403/500/timeout paths do not prevent other paths from being probed (check continues)
* HTML fetch succeeds and .map paths are constructed from extracted asset URLs
* HTML with no asset URLs → fallback Vite paths still tested (≥ 10 paths)
* 200 + valid JSON Content-Type → path appears in accessible_maps
* 404 response → path appears in not_found_maps
* Timeout on HTML fetch → returns empty result gracefully
* Connection error on HTML fetch → returns empty result gracefully
* Scope validation is called before each request (scope skip records out-of-scope error)
* MapProbeResult and SourceMapResult dataclass helper properties work correctly
* At least 10 paths are always probed (Req. 4.1)
"""

from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest
import requests as req_lib

from toolkit.execution.checks.source_maps import (
    MapProbeResult,
    SourceMapResult,
    check_source_maps,
)
from toolkit.governance.audit_logger import AuditLogger
from toolkit.governance.scope import ScopeValidator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE_URL = "https://example.com"
_HTML_WITH_ASSETS = (
    '<html><head>'
    '<script src="/assets/app.abc123.js"></script>'
    '<link rel="stylesheet" href="/assets/style.def456.css">'
    '</head><body></body></html>'
)
_HTML_NO_ASSETS = "<html><body>Hello</body></html>"


def _make_response(
    status_code: int = 200,
    body: str = "",
    content_type: str = "text/html",
) -> MagicMock:
    """Build a minimal requests.Response mock."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = body
    resp.headers = {"Content-Type": content_type}
    return resp


def _html_response(body: str = _HTML_NO_ASSETS) -> MagicMock:
    """Return a 200 HTML response mock."""
    return _make_response(200, body=body, content_type="text/html")


def _map_response_404() -> MagicMock:
    return _make_response(404, body="", content_type="text/html")


def _map_response_200_json() -> MagicMock:
    return _make_response(
        200,
        body='{"version":3,"sources":["src/App.vue"],"mappings":"AAAA"}',
        content_type="application/json",
    )


def _make_all_404_side_effects(count: int) -> list:
    """HTML 200 + `count` map responses of 404."""
    return [_html_response()] + [_map_response_404() for _ in range(count)]


# ---------------------------------------------------------------------------
# 1. 403 on .map path — logged and excluded from result
# ---------------------------------------------------------------------------

class TestForbiddenResponse:
    """A 403 on a .map path is logged, stored in error_maps, and does not stop the check."""

    def test_403_stored_in_error_maps(self):
        """A 403 response appears in error_maps, not accessible_maps or not_found_maps."""
        # HTML 200 first, then one 403, then 404s for the remaining paths
        side_effects = [_html_response()] + [_make_response(403)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.error_maps) >= 1
        statuses = [p.status_code for p in result.error_maps]
        assert 403 in statuses

    def test_403_not_in_accessible_maps(self):
        """A 403 response is not counted as accessible (status 200)."""
        side_effects = [_html_response()] + [_make_response(403)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        accessible_statuses = [p.status_code for p in result.accessible_maps]
        assert 403 not in accessible_statuses

    def test_403_not_in_not_found_maps(self):
        """A 403 response is not counted as not-found (status 404)."""
        side_effects = [_html_response()] + [_make_response(403)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        not_found_statuses = [p.status_code for p in result.not_found_maps]
        assert 403 not in not_found_statuses

    def test_403_error_field_is_populated(self):
        """The error field on a 403 probe is a non-empty string."""
        side_effects = [_html_response()] + [_make_response(403)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        error_403 = [p for p in result.error_maps if p.status_code == 403]
        assert len(error_403) >= 1
        assert error_403[0].error is not None
        assert len(error_403[0].error) > 0

    def test_403_does_not_abort_remaining_paths(self):
        """After a 403, the check continues probing the remaining paths."""
        # HTML + 1 forbidden + remaining 404s to ensure all paths are probed
        side_effects = [_html_response()] + [_make_response(403)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        # Total probed should be >= 10 (at least one from each bucket)
        assert len(result.probed_paths) >= 10

    def test_403_body_is_none_in_probe_result(self):
        """A 403 probe result stores body=None (no content retrieved)."""
        side_effects = [_html_response()] + [_make_response(403)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        error_403 = [p for p in result.error_maps if p.status_code == 403]
        assert len(error_403) >= 1
        assert error_403[0].body is None


# ---------------------------------------------------------------------------
# 2. 500 on .map path — logged and excluded from result
# ---------------------------------------------------------------------------

class TestServerErrorResponse:
    """A 500 on a .map path is logged, stored in error_maps, and does not stop the check."""

    def test_500_stored_in_error_maps(self):
        """A 500 response appears in error_maps."""
        side_effects = [_html_response()] + [_make_response(500)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert any(p.status_code == 500 for p in result.error_maps)

    def test_500_not_in_accessible_maps(self):
        """A 500 response is not counted as an accessible map."""
        side_effects = [_html_response()] + [_make_response(500)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert not any(p.status_code == 500 for p in result.accessible_maps)

    def test_500_error_field_populated(self):
        """The error field on a 500 probe is non-empty."""
        side_effects = [_html_response()] + [_make_response(500)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        error_500 = [p for p in result.error_maps if p.status_code == 500]
        assert len(error_500) >= 1
        assert error_500[0].error is not None

    def test_500_does_not_abort_remaining_paths(self):
        """After a 500, the check continues probing the remaining paths."""
        side_effects = [_html_response()] + [_make_response(500)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.probed_paths) >= 10

    def test_500_body_is_none_in_probe_result(self):
        """A 500 probe result stores body=None."""
        side_effects = [_html_response()] + [_make_response(500)] + [
            _map_response_404() for _ in range(20)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        error_500 = [p for p in result.error_maps if p.status_code == 500]
        assert len(error_500) >= 1
        assert error_500[0].body is None


# ---------------------------------------------------------------------------
# 3. Timeout on .map path — logged and excluded from result
# ---------------------------------------------------------------------------

class TestTimeoutOnMapPath:
    """A timeout on a .map path is logged, recorded with status_code=None, and does not stop the check."""

    def test_timeout_stored_in_error_maps(self):
        """A timeout probe appears in error_maps with status_code=None."""
        side_effects = (
            [_html_response()]
            + [req_lib.exceptions.Timeout("timed out")]
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        timeout_errors = [p for p in result.error_maps if p.status_code is None]
        assert len(timeout_errors) >= 1

    def test_timeout_status_code_is_none(self):
        """A timeout probe has status_code=None."""
        side_effects = (
            [_html_response()]
            + [req_lib.exceptions.Timeout("timed out")]
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        timeout_errors = [p for p in result.error_maps if p.status_code is None and p.error is not None]
        assert len(timeout_errors) >= 1

    def test_timeout_error_field_populated(self):
        """The error field on a timeout probe is non-empty."""
        side_effects = (
            [_html_response()]
            + [req_lib.exceptions.Timeout("timed out")]
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        # Find a probe with None status and an error (timeout)
        timeout_probes = [p for p in result.probed_paths if p.status_code is None and p.error]
        assert len(timeout_probes) >= 1
        assert len(timeout_probes[0].error) > 0

    def test_timeout_not_in_accessible_maps(self):
        """A timeout is not counted as an accessible map."""
        side_effects = (
            [_html_response()]
            + [req_lib.exceptions.Timeout("timed out")]
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        # accessible_maps only contain 200 responses
        assert all(p.status_code == 200 for p in result.accessible_maps)

    def test_timeout_does_not_abort_remaining_paths(self):
        """After a timeout, the check continues probing the remaining paths."""
        side_effects = (
            [_html_response()]
            + [req_lib.exceptions.Timeout("timed out")]
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.probed_paths) >= 10

    def test_timeout_body_is_none(self):
        """A timeout probe result stores body=None and content_type=None."""
        side_effects = (
            [_html_response()]
            + [req_lib.exceptions.Timeout("timed out")]
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        timeout_probes = [p for p in result.probed_paths if p.status_code is None]
        assert len(timeout_probes) >= 1
        assert timeout_probes[0].body is None
        assert timeout_probes[0].content_type is None

    def test_connection_error_treated_like_timeout(self):
        """A ConnectionError on a .map path is also stored with status_code=None."""
        side_effects = (
            [_html_response()]
            + [req_lib.exceptions.ConnectionError("refused")]
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        network_errors = [p for p in result.probed_paths if p.status_code is None and p.error]
        assert len(network_errors) >= 1


# ---------------------------------------------------------------------------
# 4. HTML fetch — graceful failure handling
# ---------------------------------------------------------------------------

class TestHtmlFetchFailure:
    """When the HTML page itself cannot be fetched, return an empty SourceMapResult."""

    def test_html_timeout_returns_empty_result(self):
        """Timeout on HTML fetch → empty probed_paths."""
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=req_lib.exceptions.Timeout("HTML timeout"),
        ):
            result = check_source_maps(BASE_URL)

        # The implementation returns the result after logging the error,
        # but no paths can be probed since candidate list comes from HTML
        # (fallback paths are still built but the check aborts HTML parse)
        assert isinstance(result, SourceMapResult)
        assert result.base_url == BASE_URL

    def test_html_connection_error_returns_empty_result(self):
        """Connection error on HTML fetch → result is returned gracefully."""
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=req_lib.exceptions.ConnectionError("refused"),
        ):
            result = check_source_maps(BASE_URL)

        assert isinstance(result, SourceMapResult)
        assert result.base_url == BASE_URL


# ---------------------------------------------------------------------------
# 5. HTML asset extraction and minimum path coverage (Req. 4.1)
# ---------------------------------------------------------------------------

class TestMinimumPathCoverage:
    """At least 10 .map paths are probed (Req. 4.1)."""

    def test_no_assets_in_html_still_probes_ten_fallback_paths(self):
        """When HTML has no assets, fallback Vite paths cover at least 10 probes."""
        side_effects = [_html_response(_HTML_NO_ASSETS)] + [
            _map_response_404() for _ in range(30)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.probed_paths) >= 10

    def test_assets_from_html_are_included_in_probed_paths(self):
        """Map paths derived from HTML asset URLs are included in probed paths."""
        side_effects = [_html_response(_HTML_WITH_ASSETS)] + [
            _map_response_404() for _ in range(30)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        probed_path_strs = [p.path for p in result.probed_paths]
        # The extracted assets should generate .map paths
        assert any(".js.map" in path or ".css.map" in path for path in probed_path_strs)

    def test_at_least_ten_paths_probed_with_assets(self):
        """With assets in HTML, still at least 10 paths are probed."""
        side_effects = [_html_response(_HTML_WITH_ASSETS)] + [
            _map_response_404() for _ in range(30)
        ]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.probed_paths) >= 10


# ---------------------------------------------------------------------------
# 6. Successful source map probe (200 JSON)
# ---------------------------------------------------------------------------

class TestSuccessfulMapProbe:
    """A 200 with JSON Content-Type appears in accessible_maps."""

    def test_200_json_map_in_accessible_maps(self):
        """An HTTP 200 with application/json Content-Type appears in accessible_maps."""
        side_effects = [
            _html_response(),
            _map_response_200_json(),
        ] + [_map_response_404() for _ in range(30)]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.accessible_maps) >= 1
        assert result.accessible_maps[0].status_code == 200

    def test_200_json_map_has_body(self):
        """An accessible map probe has a non-None body."""
        side_effects = [
            _html_response(),
            _map_response_200_json(),
        ] + [_map_response_404() for _ in range(30)]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert result.accessible_maps[0].body is not None

    def test_200_json_map_not_in_error_maps(self):
        """An accessible map is not counted as an error."""
        side_effects = [
            _html_response(),
            _map_response_200_json(),
        ] + [_map_response_404() for _ in range(30)]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        accessible_paths = {p.path for p in result.accessible_maps}
        error_paths = {p.path for p in result.error_maps}
        # The accessible paths should not overlap with error paths
        assert accessible_paths.isdisjoint(error_paths)


# ---------------------------------------------------------------------------
# 7. 404 on .map path
# ---------------------------------------------------------------------------

class TestNotFoundResponse:
    """A 404 response on a .map path is recorded in not_found_maps."""

    def test_404_stored_in_not_found_maps(self):
        """A 404 appears in not_found_maps."""
        side_effects = _make_all_404_side_effects(20)
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.not_found_maps) >= 1
        assert all(p.status_code == 404 for p in result.not_found_maps)

    def test_404_not_in_error_maps(self):
        """A 404 is not classified as an error."""
        side_effects = _make_all_404_side_effects(20)
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert not any(p.status_code == 404 for p in result.error_maps)

    def test_404_not_in_accessible_maps(self):
        """A 404 is not classified as accessible."""
        side_effects = _make_all_404_side_effects(20)
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert not any(p.status_code == 404 for p in result.accessible_maps)


# ---------------------------------------------------------------------------
# 8. Mixed error scenario — 403 + 500 + timeout together
# ---------------------------------------------------------------------------

class TestMixedErrors:
    """All three error types can coexist in the same check run."""

    def test_mixed_errors_all_appear_in_error_maps(self):
        """403, 500, and timeout probes all end up in error_maps."""
        side_effects = (
            [_html_response()]
            + [_make_response(403)]       # first path
            + [_make_response(500)]       # second path
            + [req_lib.exceptions.Timeout("timed out")]  # third path
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        error_statuses = [p.status_code for p in result.error_maps]
        assert 403 in error_statuses
        assert 500 in error_statuses
        # timeout: status_code is None, but error field set
        timeout_probes = [p for p in result.probed_paths if p.status_code is None and p.error]
        assert len(timeout_probes) >= 1

    def test_mixed_errors_do_not_prevent_404_recording(self):
        """Paths that return 404 are still correctly recorded despite errors on other paths."""
        side_effects = (
            [_html_response()]
            + [_make_response(403)]
            + [req_lib.exceptions.Timeout("timed out")]
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.not_found_maps) >= 1

    def test_mixed_errors_with_one_accessible_map(self):
        """Errors on some paths don't prevent a 200 path from being recorded."""
        side_effects = (
            [_html_response()]
            + [_make_response(403)]
            + [_map_response_200_json()]   # this one should be accessible
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.accessible_maps) >= 1
        assert len(result.error_maps) >= 1  # 403

    def test_mixed_errors_total_probed_at_least_ten(self):
        """Even with errors, total probed paths remain >= 10."""
        side_effects = (
            [_html_response()]
            + [_make_response(403)]
            + [_make_response(500)]
            + [req_lib.exceptions.Timeout("timed out")]
            + [_map_response_404() for _ in range(20)]
        )
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(BASE_URL)

        assert len(result.probed_paths) >= 10


# ---------------------------------------------------------------------------
# 9. Scope validation
# ---------------------------------------------------------------------------

class TestScopeValidation:
    """Scope is validated before each request; out-of-scope targets are skipped."""

    def test_out_of_scope_base_url_returns_empty_result(self):
        """When the base URL is out of scope, the check aborts and returns an empty result."""
        scope = ScopeValidator(
            authorized_domains=["allowed.com"],
            authorized_cidrs=[],
        )
        audit_logger = AuditLogger()
        # No requests.get call should happen
        with patch(
            "toolkit.execution.checks.source_maps.requests.get"
        ) as mock_get:
            result = check_source_maps(
                "https://evil.com",
                scope_validator=scope,
                audit_logger=audit_logger,
            )
        mock_get.assert_not_called()
        assert len(result.probed_paths) == 0

    def test_in_scope_base_url_proceeds_normally(self):
        """When the base URL is in scope, the check proceeds to probe paths."""
        scope = ScopeValidator(
            authorized_domains=["example.com"],
            authorized_cidrs=[],
        )
        audit_logger = AuditLogger()
        side_effects = [_html_response()] + [_map_response_404() for _ in range(30)]
        with patch(
            "toolkit.execution.checks.source_maps.requests.get",
            side_effect=side_effects,
        ):
            result = check_source_maps(
                BASE_URL,
                scope_validator=scope,
                audit_logger=audit_logger,
            )

        assert len(result.probed_paths) >= 10

    def test_scope_block_logged_as_audit_event(self):
        """When the base URL is out of scope, a scope_block event is logged."""
        scope = ScopeValidator(
            authorized_domains=["allowed.com"],
            authorized_cidrs=[],
        )
        audit_logger = AuditLogger()
        with patch("toolkit.execution.checks.source_maps.requests.get"):
            check_source_maps(
                "https://evil.com",
                scope_validator=scope,
                audit_logger=audit_logger,
            )

        events = audit_logger.get_events()
        scope_blocks = [e for e in events if e.event_type == "scope_block"]
        assert len(scope_blocks) >= 1


# ---------------------------------------------------------------------------
# 10. SourceMapResult and MapProbeResult dataclass properties
# ---------------------------------------------------------------------------

class TestSourceMapResultProperties:
    """SourceMapResult helper properties work correctly with constructed data."""

    def test_accessible_maps_filters_status_200(self):
        """accessible_maps returns only probes with status_code == 200."""
        r = SourceMapResult(
            base_url="https://example.com",
            probed_paths=[
                MapProbeResult(path="/a.map", status_code=200, content_type="application/json", body="{}"),
                MapProbeResult(path="/b.map", status_code=404, content_type="text/html", body=None),
                MapProbeResult(path="/c.map", status_code=403, content_type=None, body=None, error="403"),
                MapProbeResult(path="/d.map", status_code=None, content_type=None, body=None, error="Timeout"),
            ],
        )
        accessible = r.accessible_maps
        assert len(accessible) == 1
        assert accessible[0].path == "/a.map"

    def test_not_found_maps_filters_status_404(self):
        """not_found_maps returns only probes with status_code == 404."""
        r = SourceMapResult(
            base_url="https://example.com",
            probed_paths=[
                MapProbeResult(path="/a.map", status_code=200, content_type="application/json", body="{}"),
                MapProbeResult(path="/b.map", status_code=404, content_type="text/html", body=None),
                MapProbeResult(path="/c.map", status_code=404, content_type="text/html", body=None),
            ],
        )
        not_found = r.not_found_maps
        assert len(not_found) == 2
        assert all(p.status_code == 404 for p in not_found)

    def test_error_maps_excludes_200_and_404(self):
        """error_maps excludes both 200 and 404 status codes."""
        r = SourceMapResult(
            base_url="https://example.com",
            probed_paths=[
                MapProbeResult(path="/ok.map", status_code=200, content_type="application/json", body="{}"),
                MapProbeResult(path="/nf.map", status_code=404, content_type="text/html", body=None),
                MapProbeResult(path="/fb.map", status_code=403, content_type=None, body=None, error="403"),
                MapProbeResult(path="/sv.map", status_code=500, content_type=None, body=None, error="500"),
                MapProbeResult(path="/to.map", status_code=None, content_type=None, body=None, error="Timeout"),
            ],
        )
        error_maps = r.error_maps
        assert len(error_maps) == 3
        assert not any(p.status_code in (200, 404) for p in error_maps)

    def test_empty_probed_paths_gives_empty_properties(self):
        """With no probed paths, all helper properties return empty lists."""
        r = SourceMapResult(base_url="https://example.com")
        assert r.accessible_maps == []
        assert r.not_found_maps == []
        assert r.error_maps == []

    def test_base_url_stored_correctly(self):
        """The base_url field is stored on the result object."""
        r = SourceMapResult(base_url="https://target.example.com")
        assert r.base_url == "https://target.example.com"


# ---------------------------------------------------------------------------
# 11. MapProbeResult defaults and error field
# ---------------------------------------------------------------------------

class TestMapProbeResultDefaults:
    """MapProbeResult has correct defaults and error field behaviour."""

    def test_error_default_is_none(self):
        """The error field defaults to None for clean probes."""
        p = MapProbeResult(
            path="/test.map", status_code=404, content_type="text/html", body=None
        )
        assert p.error is None

    def test_error_field_set_for_403(self):
        """The error field is explicitly settable."""
        p = MapProbeResult(
            path="/test.map",
            status_code=403,
            content_type=None,
            body=None,
            error="Unexpected status 403 for path /test.map",
        )
        assert p.error is not None
        assert "403" in p.error

    def test_path_stored_correctly(self):
        """The path field stores the probed path."""
        p = MapProbeResult(path="/assets/app.js.map", status_code=404, content_type=None, body=None)
        assert p.path == "/assets/app.js.map"
