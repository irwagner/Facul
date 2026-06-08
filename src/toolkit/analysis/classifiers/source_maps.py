"""
Source map exposure classifier (Req. 4.2, 4.3, 4.5, 4.6).

``analyze_source_maps`` interprets a ``SourceMapResult`` produced by
``check_source_maps`` and returns a list of standardised ``Finding`` objects.

Decision logic
--------------
* **Confirmed (high severity)** — iff at least one probed path has:
    - HTTP status 200, AND
    - Content-Type header containing ``application/json``, AND
    - Response body that is valid JSON.
  When confirmed, up to 5 entries from the ``sources`` field of the first
  matching map file are extracted and truncated to 200 characters as evidence
  (Req. 4.3).

* **Not vulnerable (medium confidence)** — when all non-error paths return
  HTTP 404 or non-JSON content (no path satisfies the three conditions above).
  The result is recorded with medium confidence indicating standard Vite paths
  were covered (Req. 4.5).

* **Error paths excluded** — paths with status 403, 500, or a connection
  timeout (status_code is None and error is not None) are excluded from the
  analysis and do not count toward either confirmation or "not vulnerable"
  (Req. 4.6).
"""

from __future__ import annotations

import json
import logging

from toolkit.models import Finding
from toolkit.execution.checks.source_maps import MapProbeResult, SourceMapResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FINDING_ID = "SRCMAP-001"
_MAX_SOURCES_ENTRIES = 5
_MAX_EVIDENCE_CHARS = 200


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def analyze_source_maps(result: SourceMapResult) -> list[Finding]:
    """Classify a ``SourceMapResult`` into a list of standardised ``Finding`` objects.

    Parameters
    ----------
    result:
        The ``SourceMapResult`` returned by ``check_source_maps``.

    Returns
    -------
    list[Finding]
        A list containing exactly one ``Finding``:
        - ``confirmed`` / ``high`` severity when at least one map is exposed.
        - ``not_vulnerable`` / ``medium`` confidence when no exposure is found.
    """
    # ------------------------------------------------------------------
    # Separate error paths (excluded from analysis per Req. 4.6)
    # ------------------------------------------------------------------
    non_error_paths = _non_error_paths(result)

    # ------------------------------------------------------------------
    # Check for confirmed exposure
    # ------------------------------------------------------------------
    for probe in non_error_paths:
        if _is_confirmed_map(probe):
            evidence = _build_evidence(probe)
            return [_confirmed_finding(probe.path, evidence)]

    # ------------------------------------------------------------------
    # No exposure found → not vulnerable
    # ------------------------------------------------------------------
    return [_not_vulnerable_finding(result.base_url)]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _non_error_paths(result: SourceMapResult) -> list[MapProbeResult]:
    """Return probed paths excluding error paths (non-200/non-404 or timeout)."""
    return [
        p for p in result.probed_paths
        if p.status_code in (200, 404)
    ]


def _is_confirmed_map(probe: MapProbeResult) -> bool:
    """Return True iff the probe meets all three confirmation criteria."""
    if probe.status_code != 200:
        return False
    if probe.content_type is None:
        return False
    if "application/json" not in probe.content_type:
        return False
    if probe.body is None:
        return False
    try:
        json.loads(probe.body)
    except (json.JSONDecodeError, ValueError):
        return False
    return True


def _build_evidence(probe: MapProbeResult) -> str:
    """Extract up to 5 ``sources`` entries from the map body and build evidence string.

    The resulting evidence string is truncated to ``_MAX_EVIDENCE_CHARS``
    characters (Req. 4.3).
    """
    try:
        data = json.loads(probe.body)  # type: ignore[arg-type]
    except (json.JSONDecodeError, ValueError, TypeError):
        evidence = f"Source map exposed at {probe.path}"
        return evidence[:_MAX_EVIDENCE_CHARS]

    sources: list[str] = []
    if isinstance(data, dict) and "sources" in data:
        raw_sources = data["sources"]
        if isinstance(raw_sources, list):
            sources = [str(s) for s in raw_sources[:_MAX_SOURCES_ENTRIES]]

    if sources:
        evidence = f"sources: {sources}"
    else:
        evidence = f"Source map exposed at {probe.path} (no 'sources' field found)"

    return evidence[:_MAX_EVIDENCE_CHARS]


def _confirmed_finding(path: str, evidence: str) -> Finding:
    """Build a confirmed high-severity Finding for an exposed source map."""
    return Finding(
        id=_FINDING_ID,
        title="Exposed Vite Source Map",
        summary=(
            "A Vite source map file is publicly accessible. "
            "It maps minified production code back to original source files, "
            "exposing application internals to attackers."
        ),
        severity="high",
        confidence="high",
        status="confirmed",
        affected_endpoint=path,
        evidence=evidence,
        impact=(
            "Attackers can reconstruct the original source code, revealing "
            "business logic, internal file paths, component structure, and "
            "potentially hardcoded secrets or API endpoints."
        ),
        remediation=(
            "Block access to .map files in Nginx by adding the following "
            "location block:\n\n"
            "location ~* \\.map$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}\n\n"
            "Alternatively, disable source map generation in vite.config.js:\n"
            "build: { sourcemap: false }"
        ),
        next_steps=[
            "Immediately block .map file access via Nginx configuration.",
            "Rebuild and redeploy without source maps enabled.",
            "Audit other static file types for unintended exposure.",
            "Review CI/CD pipeline to prevent source maps in future releases.",
        ],
        references=[
            "CWE-540: Inclusion of Sensitive Information in Source Code",
            "https://owasp.org/www-project-web-security-testing-guide/",
        ],
    )


def _not_vulnerable_finding(base_url: str) -> Finding:
    """Build a not-vulnerable Finding with medium confidence."""
    return Finding(
        id=_FINDING_ID,
        title="No Exposed Vite Source Maps Found",
        summary=(
            "No publicly accessible Vite source map files were found at "
            "standard Vite output paths. The check covered at least 10 "
            "candidate .map paths."
        ),
        severity="low",
        confidence="medium",
        status="not_vulnerable",
        affected_endpoint=base_url,
        evidence=(
            "All tested .map paths returned HTTP 404 or non-JSON responses. "
            "Paths with server errors (403, 500) or timeouts were excluded "
            "from this result."
        ),
        impact="No source code exposure risk identified via standard Vite paths.",
        remediation=(
            "No action required. To maintain this posture, ensure Nginx is "
            "configured to deny .map files:\n\n"
            "location ~* \\.map$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}\n\n"
            "And keep source maps disabled in production builds:\n"
            "build: { sourcemap: false }"
        ),
        next_steps=[
            "Continue monitoring for new asset paths that may expose .map files.",
            "Run this check again after any deployment that updates frontend assets.",
        ],
        references=[
            "CWE-540: Inclusion of Sensitive Information in Source Code",
        ],
    )
