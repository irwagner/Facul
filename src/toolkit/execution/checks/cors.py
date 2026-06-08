"""
CORS misconfiguration detector.

Sends OPTIONS pre-flight + GET requests with a controlled ``Origin``
header and inspects the ``Access-Control-Allow-Origin`` (ACAO) /
``Access-Control-Allow-Credentials`` (ACAC) response headers.

Detection scenarios (decision logic in
:mod:`toolkit.analysis.classifiers.cors`):

    * Origin reflection (server echoes whatever Origin was sent) +
      ACAC=true → **critical** (any site can read authenticated data).
    * ACAO=``*`` + ACAC=true → impossible per spec, but tested anyway.
    * ACAO=``null`` reflection accepted → exploitable from a sandboxed
      iframe / data: URI.
    * Subdomain match without strict allow-list (``foo.target.com``
      reflects ``evil.foo.target.com``) → **medium**.
    * Pre-flight allows ``*`` methods or sensitive headers
      (``Authorization``, ``Cookie``).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

# Origins to test.  Each one targets a specific misconfiguration class.
DEFAULT_ORIGINS: tuple[str, ...] = (
    "https://evil.example.com",
    "https://attacker.example.org",
    "null",  # null origin
    "https://target.com.evil.example.com",  # subdomain trick
    "https://eviltarget.com",  # prefix match trick (target=target.com)
    "http://evil.example.com",  # downgrade
    "file://",
)


@dataclass(frozen=True)
class CorsProbe:
    origin: str
    method: str  # "GET" or "OPTIONS"
    status: int | None
    acao: str | None
    acac: str | None
    allow_methods: str | None
    allow_headers: str | None
    error: str | None = None


@dataclass(frozen=True)
class CorsResult:
    target_url: str
    probes: list[CorsProbe] = field(default_factory=list)


def check_cors(
    target_url: str,
    *,
    transport: Callable[..., "TransportResponse"],
    origins: tuple[str, ...] = DEFAULT_ORIGINS,
) -> CorsResult:
    """Probe *target_url* with each origin and return a :class:`CorsResult`."""
    probes: list[CorsProbe] = []
    for origin in origins:
        for method in ("GET", "OPTIONS"):
            try:
                resp = transport(target_url, method=method, headers={"Origin": origin})
                headers = {k.lower(): v for k, v in (getattr(resp, "headers", {}) or {}).items()}
                probes.append(
                    CorsProbe(
                        origin=origin,
                        method=method,
                        status=getattr(resp, "status", None),
                        acao=headers.get("access-control-allow-origin"),
                        acac=headers.get("access-control-allow-credentials"),
                        allow_methods=headers.get("access-control-allow-methods"),
                        allow_headers=headers.get("access-control-allow-headers"),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                probes.append(
                    CorsProbe(
                        origin=origin, method=method, status=None,
                        acao=None, acac=None, allow_methods=None, allow_headers=None,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                )
    return CorsResult(target_url=target_url, probes=probes)


@dataclass(frozen=True)
class TransportResponse:  # duck-type hint
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: str | bytes = ""
