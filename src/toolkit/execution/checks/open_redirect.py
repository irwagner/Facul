"""
Open-redirect detector (passive payload generation, gated dispatch).

Generates a small, deterministic set of payloads for parameters that are
typically used by web applications to control post-action redirection
(``next``, ``url``, ``return``, ``redirect``, ``redirect_uri``, ``go``,
``dest``, ``destination``, ``callback``, ``continue``, ``ref``).

The :func:`check_open_redirect` function is the public entry point.  It
expects an HTTP transport callable (``requests.Session.get`` or a mock)
that the orchestrator wraps with the existing governance gateway
(authorization → scope → rate limiter), so this module never touches the
network on its own.

The decision logic lives in
:mod:`toolkit.analysis.classifiers.open_redirect` to keep classification
side-effect-free and unit-testable in isolation.
"""

from __future__ import annotations

import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

# Parameters most commonly bound to redirect logic.  The list is fixed so
# behaviour is deterministic and property-testable.
DEFAULT_REDIRECT_PARAMS: tuple[str, ...] = (
    "next", "url", "return", "redirect", "redirect_uri", "redirect_url",
    "go", "dest", "destination", "callback", "continue", "ref", "back",
    "returnTo", "return_url", "successUrl", "failUrl",
)

# Canary host every payload tries to bounce to.  Using a literal value
# keeps the check deterministic and lets the analyzer pattern-match the
# Location header.
CANARY_HOST = "evil.example.com"

# Deterministic payload set.  Each variant exercises a different bypass
# trick observed in the wild.
PAYLOADS: tuple[str, ...] = (
    f"https://{CANARY_HOST}/",
    f"//{CANARY_HOST}/",
    f"/\\{CANARY_HOST}",
    f"https:{CANARY_HOST}",
    f"https://target.local@{CANARY_HOST}/",
    f"https://{CANARY_HOST}.target.local/",
    f"//{CANARY_HOST}%2F.",
)


@dataclass(frozen=True)
class RedirectAttempt:
    parameter: str
    payload: str
    final_url: str | None
    status: int | None
    location: str | None
    error: str | None = None


@dataclass(frozen=True)
class OpenRedirectResult:
    target_url: str
    attempts: list[RedirectAttempt] = field(default_factory=list)


def _inject(target_url: str, parameter: str, payload: str) -> str:
    """Return *target_url* with *parameter* set to *payload* (replacing if present)."""
    parsed = urllib.parse.urlparse(target_url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(k, v) for k, v in query if k != parameter]
    query.append((parameter, payload))
    new_query = urllib.parse.urlencode(query, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def check_open_redirect(
    target_url: str,
    *,
    transport: Callable[[str], "TransportResponse"],
    parameters: tuple[str, ...] = DEFAULT_REDIRECT_PARAMS,
    payloads: tuple[str, ...] = PAYLOADS,
) -> OpenRedirectResult:
    """Probe *target_url* for open-redirect parameters.

    *transport* must be a callable that takes a URL and returns an object
    exposing ``status``, ``location`` (header) and ``url`` (final URL,
    after redirects if the caller chose to follow them).  The orchestrator
    is responsible for wrapping this transport with the governance
    gateway; this function is intentionally side-effect-free.
    """
    attempts: list[RedirectAttempt] = []
    for param in parameters:
        for payload in payloads:
            url = _inject(target_url, param, payload)
            try:
                resp = transport(url)
                attempts.append(
                    RedirectAttempt(
                        parameter=param,
                        payload=payload,
                        final_url=getattr(resp, "url", None),
                        status=getattr(resp, "status", None),
                        location=getattr(resp, "location", None),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                attempts.append(
                    RedirectAttempt(
                        parameter=param,
                        payload=payload,
                        final_url=None,
                        status=None,
                        location=None,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
    return OpenRedirectResult(target_url=target_url, attempts=attempts)


# Lightweight dataclass kept only for type hints; users can pass any
# duck-typed object.
@dataclass(frozen=True)
class TransportResponse:
    status: int
    url: str | None = None
    location: str | None = None
