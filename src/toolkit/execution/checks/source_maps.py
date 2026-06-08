"""
Source map exposure check (Req. 4.1, 4.6).

``check_source_maps`` fetches the target's HTML page, extracts asset URLs,
constructs ``.map`` paths from them (augmented with a set of well-known Vite
output paths), tests at least 10 paths, and returns a ``SourceMapResult``.

Scope is validated before every network request via ``ScopeValidator``.

HTTP responses that are neither 200 nor 404 (e.g. 403, 500) or that time out
are logged and *excluded* from the result — they don't count as "not
vulnerable" and don't count as "confirmed" (Req. 4.6).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests

from toolkit.governance.audit_logger import AuditLogger
from toolkit.governance.scope import ScopeValidator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known Vite source map paths used when the HTML has fewer than 10 assets
# ---------------------------------------------------------------------------

_VITE_FALLBACK_PATHS: list[str] = [
    "/assets/index.js.map",
    "/assets/index.css.map",
    "/assets/vendor.js.map",
    "/assets/main.js.map",
    "/assets/app.js.map",
    "/assets/chunk-vendors.js.map",
    "/assets/index-legacy.js.map",
    "/assets/polyfills-legacy.js.map",
    "/assets/index-modern.js.map",
    "/assets/index-hash.js.map",
    "/assets/style.css.map",
    "/assets/main.css.map",
]

# Minimum number of paths the check must exercise (Req. 4.1)
_MIN_PATHS = 10


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class MapProbeResult:
    """Result of probing a single ``.map`` path."""

    path: str
    status_code: int | None   # None when a network error occurred
    content_type: str | None
    body: str | None          # raw response body (None on error)
    error: str | None = None  # description when status is not 200/404


@dataclass
class SourceMapResult:
    """Aggregated result returned by ``check_source_maps`` (Req. 4.1)."""

    base_url: str
    probed_paths: list[MapProbeResult] = field(default_factory=list)

    # Convenience properties derived from probed_paths
    @property
    def accessible_maps(self) -> list[MapProbeResult]:
        """Paths that returned HTTP 200."""
        return [p for p in self.probed_paths if p.status_code == 200]

    @property
    def not_found_maps(self) -> list[MapProbeResult]:
        """Paths that returned HTTP 404."""
        return [p for p in self.probed_paths if p.status_code == 404]

    @property
    def error_maps(self) -> list[MapProbeResult]:
        """
        Paths excluded from the result due to non-200/non-404 status codes or
        network errors (Req. 4.6).
        """
        return [
            p
            for p in self.probed_paths
            if p.status_code not in (200, 404)
        ]


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def check_source_maps(
    base_url: str,
    scope_validator: ScopeValidator | None = None,
    audit_logger: AuditLogger | None = None,
    timeout: float = 10.0,
) -> SourceMapResult:
    """
    Check whether Vite source maps are publicly exposed at *base_url*.

    Algorithm
    ---------
    1. Fetch the HTML at *base_url*.
    2. Extract ``src``/``href`` asset URLs from the HTML.
    3. Construct ``.map`` candidate paths from extracted assets plus the
       hard-coded Vite fallback list.
    4. Deduplicate and keep at least ``_MIN_PATHS`` paths.
    5. For each candidate, validate scope then probe with a GET request.
    6. Return a ``SourceMapResult`` with all probe results.

    Non-200/non-404 responses and network errors are logged and stored in the
    result with their ``error`` field populated, but they are *not* treated as
    confirmed findings or as "not vulnerable" (Req. 4.6).

    Parameters
    ----------
    base_url:
        The root URL of the target application (e.g. ``https://example.com``).
    scope_validator:
        Optional ``ScopeValidator``.  When provided, ``assert_in_scope`` is
        called before every request.  If the target is out of scope the path
        is skipped and an error probe result is recorded.
    audit_logger:
        Optional ``AuditLogger`` passed to ``assert_in_scope``.  Only
        required when *scope_validator* is provided.
    timeout:
        Per-request timeout in seconds (default 10).

    Returns
    -------
    SourceMapResult
    """
    result = SourceMapResult(base_url=base_url)
    parsed = urlparse(base_url)
    host = parsed.netloc or parsed.path  # handle bare hostnames

    # ------------------------------------------------------------------
    # Step 1 & 2 — fetch HTML and extract asset URLs
    # ------------------------------------------------------------------
    extracted_map_paths: list[str] = []
    try:
        _validate_scope(host, scope_validator, audit_logger)
        html_resp = requests.get(base_url, timeout=timeout, verify=False)  # noqa: S501
        if html_resp.status_code == 200:
            extracted_map_paths = _extract_map_paths(html_resp.text, base_url)
    except _ScopeSkip:
        logger.warning("Base URL %s is out of scope; aborting check.", base_url)
        return result
    except requests.exceptions.Timeout:
        logger.error("Timeout fetching HTML from %s", base_url)
    except requests.exceptions.RequestException as exc:
        logger.error("Error fetching HTML from %s: %s", base_url, exc)

    # ------------------------------------------------------------------
    # Step 3 & 4 — build candidate list (≥ MIN_PATHS)
    # ------------------------------------------------------------------
    candidate_paths = _build_candidates(base_url, extracted_map_paths)

    # ------------------------------------------------------------------
    # Step 5 — probe each candidate
    # ------------------------------------------------------------------
    for path in candidate_paths:
        probe_url = urljoin(base_url, path) if not path.startswith("http") else path
        probe_host = urlparse(probe_url).netloc

        try:
            _validate_scope(probe_host, scope_validator, audit_logger)
        except _ScopeSkip:
            logger.warning("Path %s is out of scope; skipping.", path)
            result.probed_paths.append(
                MapProbeResult(
                    path=path,
                    status_code=None,
                    content_type=None,
                    body=None,
                    error="Out of scope",
                )
            )
            continue

        probe_result = _probe_path(probe_url, path, timeout)
        result.probed_paths.append(probe_result)

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class _ScopeSkip(Exception):
    """Internal signal to skip a request due to scope violation."""


def _validate_scope(
    host: str,
    scope_validator: ScopeValidator | None,
    audit_logger: AuditLogger | None,
) -> None:
    """
    Call ``scope_validator.assert_in_scope`` if a validator is present.

    Raises ``_ScopeSkip`` if the target is out of scope so that the caller
    can handle it gracefully without propagating ``ScopeError``.
    """
    if scope_validator is None:
        return
    from toolkit.exceptions import ScopeError  # local import to avoid circular

    _logger = audit_logger if audit_logger is not None else AuditLogger()
    try:
        scope_validator.assert_in_scope(host, module="source_maps", logger=_logger)
    except ScopeError:
        raise _ScopeSkip()


def _extract_map_paths(html: str, base_url: str) -> list[str]:
    """
    Extract ``.js`` and ``.css`` asset URLs from HTML and return their
    corresponding ``.map`` path equivalents.
    """
    map_paths: list[str] = []
    # Match src="..." and href="..." attributes pointing at JS/CSS assets
    asset_pattern = re.compile(
        r'(?:src|href)\s*=\s*["\']([^"\']+\.(?:js|css)(?:\?[^"\']*)?)["\']',
        re.IGNORECASE,
    )
    for match in asset_pattern.finditer(html):
        asset_url = match.group(1)
        # Strip query strings before appending .map
        asset_path = asset_url.split("?")[0]
        map_path = asset_path + ".map"
        # Convert absolute URLs to paths relative to the host
        if map_path.startswith("http"):
            parsed = urlparse(map_path)
            map_path = parsed.path
        map_paths.append(map_path)
    return list(dict.fromkeys(map_paths))  # deduplicate preserving order


def _build_candidates(base_url: str, extracted: list[str]) -> list[str]:
    """
    Merge extracted paths with the fallback list so we always test at least
    ``_MIN_PATHS`` unique candidates.
    """
    seen: dict[str, None] = {}
    for p in extracted:
        seen[p] = None
    for p in _VITE_FALLBACK_PATHS:
        seen[p] = None

    candidates = list(seen.keys())
    # Ensure minimum coverage
    if len(candidates) < _MIN_PATHS:
        candidates = list(seen.keys())  # already includes fallback — should be ≥ 12
    return candidates


def _probe_path(url: str, path: str, timeout: float) -> MapProbeResult:
    """
    Perform a single GET probe against *url*.

    Returns a ``MapProbeResult``.  Non-200/non-404 responses and network
    errors are logged and stored with the ``error`` field populated (Req. 4.6).
    """
    try:
        resp = requests.get(url, timeout=timeout, verify=False)  # noqa: S501
        status = resp.status_code
        content_type = resp.headers.get("Content-Type")
        body = resp.text if status == 200 else None

        if status not in (200, 404):
            error_msg = f"Unexpected status {status} for path {path}"
            logger.error(error_msg)
            return MapProbeResult(
                path=path,
                status_code=status,
                content_type=content_type,
                body=None,
                error=error_msg,
            )

        return MapProbeResult(
            path=path,
            status_code=status,
            content_type=content_type,
            body=body,
            error=None,
        )

    except requests.exceptions.Timeout:
        error_msg = f"Timeout probing {path}"
        logger.error(error_msg)
        return MapProbeResult(
            path=path,
            status_code=None,
            content_type=None,
            body=None,
            error=error_msg,
        )
    except requests.exceptions.RequestException as exc:
        error_msg = f"Network error probing {path}: {exc}"
        logger.error(error_msg)
        return MapProbeResult(
            path=path,
            status_code=None,
            content_type=None,
            body=None,
            error=error_msg,
        )
