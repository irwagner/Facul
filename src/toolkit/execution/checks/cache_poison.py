"""
Cache-poisoning detector via header injection.

Sends a baseline GET, then re-issues the same GET with each of the
"unkeyed" headers commonly abused for cache poisoning.  Detection is
strictly observational:

    * Response **status** differs from baseline.
    * Response **body size** differs by more than ``size_diff_threshold``
      bytes (default 50).
    * The injected **header value is reflected** anywhere in the body.
    * A new ``Vary`` / ``X-Cache-Key`` / ``X-Forwarded-Host`` header
      appears in the response and contains the injected value.

Decision logic lives in
:mod:`toolkit.analysis.classifiers.cache_poison`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

# Headers most useful for unkeyed cache poisoning.  Order is irrelevant
# but the list is fixed for determinism.
DEFAULT_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Forwarded-Host", "evil.example.com"),
    ("X-Forwarded-Proto", "http"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Forwarded-Port", "8080"),
    ("X-Original-URL", "/admin"),
    ("X-Rewrite-URL", "/admin"),
    ("X-Real-IP", "127.0.0.1"),
    ("X-Originating-IP", "127.0.0.1"),
    ("X-Custom-IP-Authorization", "127.0.0.1"),
    ("X-Forwarded-Server", "evil.example.com"),
    ("X-Host", "evil.example.com"),
    ("X-Backend-Server", "evil.example.com"),
    ("X-HTTP-Host-Override", "evil.example.com"),
    ("Forwarded", "for=127.0.0.1; host=evil.example.com"),
    ("Referer", "https://evil.example.com/"),
    ("X-Original-URL", "/admin"),
    ("X-Internal", "1"),
    ("X-Debug", "1"),
)


@dataclass(frozen=True)
class CacheProbe:
    header: str
    value: str
    status: int | None
    body_size: int
    body_excerpt: str
    new_headers: dict[str, str]
    error: str | None = None


@dataclass(frozen=True)
class CachePoisonResult:
    target_url: str
    baseline_status: int | None
    baseline_size: int
    baseline_body_excerpt: str
    probes: list[CacheProbe] = field(default_factory=list)


def check_cache_poison(
    target_url: str,
    *,
    transport: Callable[..., "TransportResponse"],
    headers: tuple[tuple[str, str], ...] = DEFAULT_HEADERS,
) -> CachePoisonResult:
    """Probe *target_url* with each header pair via *transport*.

    *transport* must accept ``(url, headers=...)`` and return an object
    exposing ``status``, ``body``, ``headers``.  No network I/O is
    performed inside this function.
    """
    base = transport(target_url, headers={})
    base_body = _decode(getattr(base, "body", b""))
    baseline = CacheProbe(
        header="<baseline>",
        value="",
        status=getattr(base, "status", None),
        body_size=len(base_body),
        body_excerpt=base_body[:300],
        new_headers=dict(getattr(base, "headers", {}) or {}),
    )

    probes: list[CacheProbe] = []
    for name, value in headers:
        try:
            resp = transport(target_url, headers={name: value})
            body = _decode(getattr(resp, "body", b""))
            probes.append(
                CacheProbe(
                    header=name,
                    value=value,
                    status=getattr(resp, "status", None),
                    body_size=len(body),
                    body_excerpt=body[:300],
                    new_headers=dict(getattr(resp, "headers", {}) or {}),
                )
            )
        except Exception as exc:  # noqa: BLE001
            probes.append(
                CacheProbe(
                    header=name,
                    value=value,
                    status=None,
                    body_size=0,
                    body_excerpt="",
                    new_headers={},
                    error=f"{type(exc).__name__}: {exc}",
                )
            )

    return CachePoisonResult(
        target_url=target_url,
        baseline_status=baseline.status,
        baseline_size=baseline.body_size,
        baseline_body_excerpt=baseline.body_excerpt,
        probes=probes,
    )


def _decode(b) -> str:
    if isinstance(b, bytes):
        return b.decode("utf-8", errors="replace")
    return str(b or "")


@dataclass(frozen=True)
class TransportResponse:  # duck-type hint
    status: int
    body: str | bytes = ""
    headers: dict[str, str] = field(default_factory=dict)
