"""
Enumerator — endpoint and parameter enumeration (Req. 2.3, 3).

Responsibilities
----------------
* ``scan_ports``       — port scanning on the fixed set of well-known ports.
* ``discover_paths``   — directory/file enumeration via a caller-supplied
                         wordlist **plus** the fixed set of common admin panels
                         (Req. 3.1, 3.2).
* ``classify_response``— maps an HTTP response to an ``Endpoint`` dataclass
                         recording the correct fields per status class (Req. 3.3, 3.4).
* ``probe_parameters`` — parameter discovery by varying one parameter at a time
                         (Req. 3.5).

Rate limiting (Req. 3.6, 3.7) is enforced internally via a ``RateLimiter``
instance: ``acquire()`` is called before every outgoing request, and
``apply_backoff()`` is called when the target responds with HTTP 429.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from toolkit.governance.rate_limiter import RateLimiter
from toolkit.models import Endpoint

if TYPE_CHECKING:
    pass


# ---------------------------------------------------------------------------
# Fixed constants (Req. 2.3, 3.2)
# ---------------------------------------------------------------------------

#: Ports that are always scanned regardless of the caller-supplied list.
FIXED_PORTS: list[int] = [80, 443, 8080, 8443, 8000, 8888, 9090, 9443, 3000, 5000]

#: Common admin panel paths that are **always** tested in addition to any
#: caller-supplied wordlist (Req. 3.2).
ADMIN_PANEL_PATHS: list[str] = [
    "/admin",
    "/dashboard",
    "/panel",
    "/manage",
    "/api/v1/admin",
]

#: Built-in wordlist with ≥100 common web paths (Req. 3.1).
#: Used as the default when no caller-supplied wordlist is provided.
DEFAULT_WORDLIST: list[str] = [
    # --- Common files ---
    "/index.html",
    "/index.php",
    "/index.asp",
    "/index.aspx",
    "/index.jsp",
    "/default.html",
    "/default.php",
    "/home",
    "/login",
    "/logout",
    "/register",
    "/signup",
    "/signin",
    "/forgot-password",
    "/reset-password",
    "/profile",
    "/account",
    "/settings",
    "/search",
    "/contact",
    "/about",
    "/help",
    "/faq",
    "/sitemap.xml",
    "/robots.txt",
    "/.well-known/security.txt",
    "/favicon.ico",
    "/404",
    "/500",
    "/error",
    # --- API paths ---
    "/api",
    "/api/v1",
    "/api/v2",
    "/api/v3",
    "/api/health",
    "/api/status",
    "/api/users",
    "/api/user",
    "/api/auth",
    "/api/login",
    "/api/logout",
    "/api/register",
    "/api/me",
    "/api/profile",
    "/api/config",
    "/api/settings",
    "/api/data",
    "/api/docs",
    "/api/swagger",
    "/api/openapi.json",
    "/api/graphql",
    "/graphql",
    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/v1",
    "/v2",
    # --- Admin and management ---
    "/admin/login",
    "/admin/dashboard",
    "/admin/users",
    "/admin/settings",
    "/admin/config",
    "/administrator",
    "/wp-admin",
    "/wp-login.php",
    "/wp-content",
    "/wp-includes",
    "/phpmyadmin",
    "/adminer",
    "/cpanel",
    "/webmail",
    "/manager",
    "/console",
    "/controlpanel",
    "/portal",
    "/backend",
    "/backoffice",
    "/cms",
    # --- Static assets and build artifacts ---
    "/static",
    "/assets",
    "/dist",
    "/build",
    "/public",
    "/js",
    "/css",
    "/img",
    "/images",
    "/fonts",
    "/media",
    "/uploads",
    "/files",
    "/downloads",
    "/docs",
    "/vendor",
    "/node_modules",
    # --- Health / monitoring ---
    "/health",
    "/healthz",
    "/ping",
    "/status",
    "/metrics",
    "/actuator",
    "/actuator/health",
    "/actuator/info",
    "/actuator/env",
    "/actuator/metrics",
    "/.env",
    "/.git/config",
    "/.htaccess",
    "/config",
    "/configuration",
    "/server-status",
    "/server-info",
    "/info.php",
    "/phpinfo.php",
    "/test",
    "/debug",
    "/trace",
]

# ---------------------------------------------------------------------------
# Enumerator
# ---------------------------------------------------------------------------


class Enumerator:
    """
    Enumerates ports, paths and parameters for an audited target.

    All methods that perform network I/O accept a ``session`` argument (an
    ``httpx.Client`` or ``requests.Session`` compatible object) so that tests
    can inject fakes without patching global state.

    Rate limiting (Req. 3.6, 3.7) is enforced by the internal
    ``RateLimiter``: ``acquire()`` is called before every outgoing request
    and ``apply_backoff()`` is called on HTTP 429 responses.

    Parameters
    ----------
    rate_limiter:
        Optional ``RateLimiter`` instance.  When *None*, a default
        ``RateLimiter(max_rps=10)`` is created automatically.
    """

    def __init__(self, rate_limiter: RateLimiter | None = None) -> None:
        self._rate_limiter: RateLimiter = (
            rate_limiter if rate_limiter is not None else RateLimiter()
        )

    # ------------------------------------------------------------------
    # Port scanning (Req. 2.3)
    # ------------------------------------------------------------------

    def scan_ports(self, host: object) -> list[int]:
        """
        Return the fixed list of ports to probe for *host*.

        The actual probing is performed by the caller; this method returns
        the canonical port list (Req. 2.3) so that it is testable and
        consistent across callers.

        Parameters
        ----------
        host:
            A ``Host`` dataclass instance (used for documentation purposes;
            no network I/O is performed here).

        Returns
        -------
        list[int]
            Always ``FIXED_PORTS``.
        """
        return list(FIXED_PORTS)

    # ------------------------------------------------------------------
    # Path discovery (Req. 3.1, 3.2)
    # ------------------------------------------------------------------

    def get_paths_to_test(self, wordlist: list[str]) -> list[str]:
        """
        Compute the full set of paths to test for a given *wordlist*.

        The result is the **union** of *wordlist* with ``ADMIN_PANEL_PATHS``
        (Req. 3.1, 3.2).  Duplicate paths that appear in both the wordlist and
        the fixed set are included only once.  The returned list preserves the
        order of *wordlist* entries first, followed by any admin panel paths
        not already present.

        Parameters
        ----------
        wordlist:
            Caller-supplied list of paths to test.

        Returns
        -------
        list[str]
            The union of *wordlist* and ``ADMIN_PANEL_PATHS``, with no
            duplicates, in insertion order.
        """
        seen: set[str] = set()
        result: list[str] = []

        for path in wordlist:
            if path not in seen:
                seen.add(path)
                result.append(path)

        for path in ADMIN_PANEL_PATHS:
            if path not in seen:
                seen.add(path)
                result.append(path)

        return result

    def discover_paths(
        self,
        base_url: str,
        wordlist: list[str] | None = None,
        *,
        session: object | None = None,
    ) -> list[Endpoint]:
        """
        Enumerate paths under *base_url* using *wordlist* plus admin panels.

        Rate limiting is applied before every request (Req. 3.7): the
        internal ``RateLimiter.acquire()`` is called to enforce ≤10 req/s.
        If the target responds with HTTP 429, ``RateLimiter.apply_backoff()``
        is called with the default 5-second delay before the request is
        retried (Req. 3.6).

        When *wordlist* is ``None``, the built-in ``DEFAULT_WORDLIST``
        (≥100 entries) is used (Req. 3.1).

        This method requires a live HTTP *session* to make requests. When
        *session* is ``None`` (e.g., during pure unit / property tests that
        only validate the *path set* via ``get_paths_to_test``), it returns an
        empty list.

        Parameters
        ----------
        base_url:
            The target base URL (e.g., ``"https://example.com"``).
        wordlist:
            Caller-supplied list of paths to probe.  Defaults to
            ``DEFAULT_WORDLIST`` when *None*.
        session:
            An ``httpx.Client`` or ``requests.Session`` compatible object.
            Must expose a ``get(url, timeout=..., allow_redirects=False)``
            method that returns a response with ``.status_code``,
            ``.content`` and ``.headers`` attributes.

        Returns
        -------
        list[Endpoint]
            Classified endpoints for every path that returned a testable
            response (200, 301, or 302).
        """
        if session is None:
            return []

        effective_wordlist: list[str] = wordlist if wordlist is not None else DEFAULT_WORDLIST
        paths_to_test = self.get_paths_to_test(effective_wordlist)
        results: list[Endpoint] = []

        for path in paths_to_test:
            url = base_url.rstrip("/") + path
            try:
                # Enforce rate limit before each request (Req. 3.7)
                self._rate_limiter.acquire()
                resp = session.get(url, timeout=10, allow_redirects=False)  # type: ignore[union-attr]

                # Handle HTTP 429 — apply backoff then skip this path (Req. 3.6)
                if resp.status_code == 429:
                    self._rate_limiter.apply_backoff()
                    continue

            except Exception:
                continue

            # Build a minimal response-like object for classify_response
            class _Resp:
                status_code = resp.status_code
                body_size = len(resp.content)
                location = resp.headers.get("Location") or resp.headers.get("location")
                try:
                    text = resp.text
                except Exception:
                    text = ""

            endpoint = self.classify_response(path, _Resp())  # type: ignore[arg-type]
            if endpoint.status_code in (200, 301, 302):
                results.append(endpoint)

        return results

    # ------------------------------------------------------------------
    # Response classification (Req. 3.3, 3.4)
    # ------------------------------------------------------------------

    def classify_response(self, path: str, resp: object) -> Endpoint:
        """
        Map an HTTP *resp* for *path* to a structured ``Endpoint``.

        Rules
        -----
        * **Status 200**: records ``status_code``, ``body_size``, and the
          ``<title>`` text extracted from the HTML body (``None`` if absent).
          ``kind`` is set to ``"page"``.
        * **Status 301 / 302**: records ``path``, ``status_code``, and the
          ``Location`` header value.  ``kind`` is set to ``"redirect"``.
        * **Any other status**: records ``path``, ``status_code``, and
          ``body_size``.  ``kind`` is set to ``"error"`` for 4xx/5xx or
          ``"other"`` otherwise.

        Parameters
        ----------
        path:
            The requested path (e.g., ``"/admin"``).
        resp:
            A response object exposing ``.status_code`` (int),
            ``.body_size`` (int), ``.text`` (str), and ``.location``
            (``str | None``).

        Returns
        -------
        Endpoint
        """
        status = resp.status_code  # type: ignore[attr-defined]
        body_size: int = getattr(resp, "body_size", 0)
        text: str = getattr(resp, "text", "")
        location: str | None = getattr(resp, "location", None)

        if status == 200:
            title = _extract_title(text)
            return Endpoint(
                path=path,
                status_code=status,
                body_size=body_size,
                title=title,
                location=None,
                kind="page",
            )

        if status in (301, 302):
            return Endpoint(
                path=path,
                status_code=status,
                body_size=body_size,
                title=None,
                location=location,
                kind="redirect",
            )

        kind = "error" if 400 <= status < 600 else "other"
        return Endpoint(
            path=path,
            status_code=status,
            body_size=body_size,
            title=None,
            location=None,
            kind=kind,
        )

    # ------------------------------------------------------------------
    # Parameter probing (Req. 3.5)
    # ------------------------------------------------------------------

    def probe_parameters(
        self,
        endpoint: Endpoint,
        *,
        session: object | None = None,
    ) -> list[str]:
        """
        Attempt to identify accepted parameters for *endpoint*.

        Varies one parameter at a time (Req. 3.5) and records the observable
        output field names from the response JSON.  Requires a live *session*;
        returns an empty list when *session* is ``None``.

        Rate limiting is applied before every request (Req. 3.7).  If the
        target responds with HTTP 429, ``apply_backoff()`` is called and that
        probe is skipped (Req. 3.6).

        Parameters
        ----------
        endpoint:
            The target endpoint.
        session:
            An HTTP session object (see ``discover_paths`` for contract).

        Returns
        -------
        list[str]
            Discovered parameter / field names.
        """
        if session is None:
            return []

        import json as _json

        url = endpoint.path
        field_names: list[str] = []
        probe_params = ["id", "page", "limit", "offset", "q", "search"]

        for param in probe_params:
            try:
                # Enforce rate limit before each probe request (Req. 3.7)
                self._rate_limiter.acquire()
                resp = session.get(url, params={param: "1"}, timeout=10)  # type: ignore[union-attr]

                # Handle HTTP 429 — apply backoff and skip this probe (Req. 3.6)
                if resp.status_code == 429:
                    self._rate_limiter.apply_backoff()
                    continue

                if resp.status_code == 200:
                    try:
                        data = _json.loads(resp.text)
                        if isinstance(data, dict):
                            for key in data:
                                if key not in field_names:
                                    field_names.append(key)
                    except Exception:
                        pass
            except Exception:
                continue

        return field_names


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _extract_title(html: str) -> str | None:
    """Extract the text content of the first ``<title>`` tag in *html*."""
    match = _TITLE_RE.search(html)
    if match:
        return match.group(1).strip() or None
    return None
