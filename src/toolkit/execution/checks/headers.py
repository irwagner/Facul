"""
HTTP security headers check (Req. 7.1).

``check_security_headers`` makes a GET request to the target URL with a
10-second timeout and extracts all response headers.  On any request failure
(network error, timeout, etc.) it returns a ``HeadersResult`` with
``status="check_failed"`` and the error message populated.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

import requests

from toolkit.governance.audit_logger import AuditLogger

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class HeadersResult:
    """Result returned by ``check_security_headers`` (Req. 7.1).

    Attributes
    ----------
    url:
        The URL that was requested.
    status:
        ``"ok"`` when the request succeeded and headers were extracted;
        ``"check_failed"`` when the request could not be completed.
    headers:
        Dict of all response headers (header name → header value).
        Empty dict when ``status="check_failed"``.
    error_message:
        Human-readable description of the failure when
        ``status="check_failed"``; ``None`` on success.
    """

    url: str
    status: str  # "ok" | "check_failed"
    headers: dict = field(default_factory=dict)
    error_message: str | None = None


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------


def check_security_headers(
    url: str,
    logger: AuditLogger | None = None,
) -> HeadersResult:
    """
    Fetch *url* via HTTP GET and return all response headers.

    The request is issued with a 10-second timeout (Req. 7.1).  Any
    ``requests`` exception (connection error, timeout, invalid URL …) is
    caught, logged, and reflected in the returned ``HeadersResult`` as
    ``status="check_failed"``.

    Parameters
    ----------
    url:
        The target URL (e.g. ``https://example.com``).
    logger:
        Optional ``AuditLogger``.  When provided, errors are also recorded
        as audit events with ``event_type="error"`` and
        ``module="security_headers"``.

    Returns
    -------
    HeadersResult
        On success: ``status="ok"`` with all response headers in ``headers``.
        On failure: ``status="check_failed"`` with ``error_message`` set.
    """
    try:
        response = requests.get(url, timeout=10, verify=False)  # noqa: S501
        headers_dict = dict(response.headers)
        _logger.info("Security headers check succeeded for %s", url)
        return HeadersResult(
            url=url,
            status="ok",
            headers=headers_dict,
            error_message=None,
        )

    except requests.exceptions.Timeout as exc:
        error_msg = f"Request to {url} timed out: {exc}"
        _logger.error(error_msg)
        _record_error(logger, url, error_msg)
        return HeadersResult(
            url=url,
            status="check_failed",
            headers={},
            error_message=error_msg,
        )

    except requests.exceptions.RequestException as exc:
        error_msg = f"Request to {url} failed: {exc}"
        _logger.error(error_msg)
        _record_error(logger, url, error_msg)
        return HeadersResult(
            url=url,
            status="check_failed",
            headers={},
            error_message=error_msg,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _record_error(
    logger: AuditLogger | None,
    url: str,
    message: str,
) -> None:
    """Record an error event in the audit log when a logger is provided."""
    if logger is None:
        return
    from datetime import datetime, timezone

    from toolkit.models import AuditEvent

    event = AuditEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        event_type="error",
        target=url,
        module="security_headers",
        detail={"message": message},
    )
    logger.log(event)
