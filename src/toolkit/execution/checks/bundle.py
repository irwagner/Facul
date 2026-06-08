"""
JavaScript bundle download check (Req. 5.1).

``analyze_js_bundle`` fetches the target's HTML page, extracts ``.js`` asset
URLs, downloads each bundle file, and returns a list of ``BundleFile`` objects
with the raw content (or error information) for each file.

On any failure — non-200 HTTP status or connection error — the failure is
logged (URL + status / error message), that file is skipped, and processing
continues with the remaining files (Req. 5.1).

Two dataclasses are provided:

* ``BundleFile`` — the minimal interface required by the spec (url, content,
  error), returned by the public ``analyze_js_bundle`` function.
* ``BundleHit`` — a richer internal representation that also carries the raw
  HTTP status code; used by ``fetch_bundle_hits`` and internal helpers.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests

_module_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class BundleFile:
    """
    Result of attempting to download a single ``.js`` bundle file (Req. 5.1).

    Attributes
    ----------
    url:
        The absolute URL that was fetched (or attempted).
    content:
        Raw JavaScript text on success; ``None`` on failure.
    error:
        Human-readable description of the failure (URL + status); ``None``
        on success.
    """

    url: str
    content: str | None  # raw JS content; None on failure
    error: str | None    # set on failure (includes URL + status); None on success


@dataclass
class BundleHit:
    """
    Extended result of attempting to download a single ``.js`` bundle file.

    Carries the raw HTTP status code in addition to the fields in
    ``BundleFile``, which is useful for callers that need to inspect failure
    details (e.g. ``fetch_bundle_hits``).

    For successful downloads:
        - ``url``         : the absolute URL that was fetched
        - ``content``     : raw JavaScript text
        - ``status_code`` : 200
        - ``error_message``: None

    For failures (non-200 response or connection error):
        - ``url``          : the absolute URL that was attempted
        - ``content``      : None
        - ``status_code``  : HTTP status code if a response was received, else None
        - ``error_message``: human-readable description of the failure
    """

    url: str
    content: str | None          # raw JS content; None on failure
    status_code: int | None      # HTTP status code; None on connection error
    error_message: str | None    # set on failure; None on success

    @property
    def is_success(self) -> bool:
        """True when the download succeeded (content is available)."""
        return self.content is not None and self.error_message is None


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def analyze_js_bundle(
    base_url: str,
    session=None,   # requests.Session | None — optional, for interface consistency
    logger=None,    # AuditLogger | None — optional, logs failures as AuditEvents
    timeout: float = 10.0,
) -> list[BundleFile]:
    """
    Download ``.js`` bundle files from *base_url* and return a list of
    ``BundleFile`` objects containing the raw content per file (Req. 5.1).

    Algorithm
    ---------
    1. Fetch the HTML at *base_url*.
    2. Extract ``src`` attribute values of ``<script>`` tags pointing at
       ``.js`` files (relative or absolute).
    3. For each extracted URL, attempt an HTTP GET.
    4. On success (HTTP 200): store the raw response text.
    5. On failure (non-200 or connection error): log URL + status/error,
       skip the file, and continue with remaining files (Req. 5.1).
    6. Return a list of ``BundleFile`` objects — one per ``.js`` asset found.

    Parameters
    ----------
    base_url:
        Root URL of the target application (e.g. ``"https://example.com"``).
    session:
        Optional ``requests.Session`` instance.  When provided, HTTP requests
        are made through the session; otherwise a fresh session-less request
        is used.  Accepted for interface consistency with other check modules.
    logger:
        Optional ``AuditLogger`` instance.  When provided, failures are also
        recorded as ``AuditEvent`` entries in addition to the module-level
        logger.
    timeout:
        Per-request timeout in seconds (default 10).

    Returns
    -------
    list[BundleFile]
        One ``BundleFile`` per ``.js`` asset URL found in the HTML.
        Successful entries have ``content`` populated and ``error=None``.
        Failed entries have ``content=None`` and ``error`` set to a
        human-readable description including the URL and HTTP status.
    """
    hits = _fetch_bundle_hits(base_url, session=session, timeout=timeout)

    # Optionally log failures to the AuditLogger
    if logger is not None:
        _log_failures_to_audit(hits, logger, base_url)

    # Convert BundleHit objects to BundleFile objects
    return [
        BundleFile(
            url=hit.url,
            content=hit.content,
            error=hit.error_message,
        )
        for hit in hits
    ]


def fetch_bundle_hits(
    base_url: str,
    session=None,
    timeout: float = 10.0,
) -> list[BundleHit]:
    """
    Like ``analyze_js_bundle`` but returns the full list of ``BundleHit``
    objects (successes *and* failures).

    Useful for callers that need to inspect which URLs failed and why,
    including the raw HTTP status code.

    Parameters
    ----------
    base_url:
        Root URL of the target application.
    session:
        Optional ``requests.Session`` instance.
    timeout:
        Per-request timeout in seconds (default 10).
    """
    return _fetch_bundle_hits(base_url, session=session, timeout=timeout)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fetch_bundle_hits(base_url: str, session=None, timeout: float = 10.0) -> list[BundleHit]:
    """Core download logic; returns BundleHit for every JS asset found."""
    js_urls = _extract_js_urls(base_url, session=session, timeout=timeout)
    hits: list[BundleHit] = []

    for url in js_urls:
        hit = _download_js(url, session=session, timeout=timeout)
        hits.append(hit)

    return hits


def _extract_js_urls(base_url: str, session=None, timeout: float = 10.0) -> list[str]:
    """
    Fetch the HTML at *base_url* and return a deduplicated list of absolute
    ``.js`` asset URLs referenced via ``<script src="...">`` tags.

    Returns an empty list if the HTML cannot be fetched.
    """
    _get = session.get if session is not None else requests.get
    try:
        resp = _get(base_url, timeout=timeout, verify=False)  # noqa: S501
        if resp.status_code != 200:
            _module_logger.warning(
                "Failed to fetch HTML from %s — HTTP %s",
                base_url,
                resp.status_code,
            )
            return []
        return _parse_js_urls(resp.text, base_url)
    except requests.exceptions.Timeout:
        _module_logger.error("Timeout fetching HTML from %s", base_url)
        return []
    except requests.exceptions.RequestException as exc:
        _module_logger.error("Error fetching HTML from %s: %s", base_url, exc)
        return []


def _parse_js_urls(html: str, base_url: str) -> list[str]:
    """
    Parse *html* and return deduplicated absolute URLs for ``.js`` assets.

    Handles both absolute (``https://…``) and relative (``/assets/…``) src
    values.  Query strings are preserved so the exact file is fetched.
    """
    # Match src="..." in <script> tags pointing at .js files
    pattern = re.compile(
        r'<script[^>]+\bsrc\s*=\s*["\']([^"\']+\.js(?:[?#][^"\']*)?)["\']',
        re.IGNORECASE,
    )
    seen: dict[str, None] = {}
    for match in pattern.finditer(html):
        raw = match.group(1)
        # Resolve relative URLs against base_url
        absolute = urljoin(base_url, raw)
        seen[absolute] = None
    return list(seen.keys())


def _download_js(url: str, session=None, timeout: float = 10.0) -> BundleHit:
    """
    Attempt to download a single ``.js`` file.

    Returns a ``BundleHit`` with content on success, or with error_message
    (and no content) on failure.  Failures are logged via the module logger.
    """
    _get = session.get if session is not None else requests.get
    try:
        resp = _get(url, timeout=timeout, verify=False)  # noqa: S501
        if resp.status_code == 200:
            return BundleHit(
                url=url,
                content=resp.text,
                status_code=200,
                error_message=None,
            )
        # Non-200 response — log and return failure hit
        error_msg = f"HTTP {resp.status_code}"
        _module_logger.warning("Failed to download JS bundle %s — %s", url, error_msg)
        return BundleHit(
            url=url,
            content=None,
            status_code=resp.status_code,
            error_message=error_msg,
        )
    except requests.exceptions.Timeout:
        error_msg = f"Timeout downloading {url}"
        _module_logger.warning(error_msg)
        return BundleHit(
            url=url,
            content=None,
            status_code=None,
            error_message=error_msg,
        )
    except requests.exceptions.RequestException as exc:
        error_msg = f"Connection error downloading {url}: {exc}"
        _module_logger.warning(error_msg)
        return BundleHit(
            url=url,
            content=None,
            status_code=None,
            error_message=error_msg,
        )


def _log_failures_to_audit(
    hits: list[BundleHit],
    audit_logger,
    base_url: str,
) -> None:
    """Record each failed download as an AuditEvent (info type)."""
    from toolkit.models import AuditEvent  # local import to avoid circular
    import datetime

    for hit in hits:
        if not hit.is_success:
            event = AuditEvent(
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                event_type="error",
                target=hit.url,
                module="bundle",
                detail={
                    "base_url": base_url,
                    "status_code": hit.status_code,
                    "error": hit.error_message,
                },
            )
            audit_logger.log(event)
