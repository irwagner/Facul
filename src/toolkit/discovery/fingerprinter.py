"""
Fingerprinter — identifies web server, framework and CDN technologies
for each active host and open port (Req. 2.4).

For each open port, an HTTP GET request is made to the service.
Response headers and the HTML body are inspected to detect:
  - Web server  (``Server`` header)
  - CDN         (``X-Cache``, ``Via``, ``CF-RAY``, ``X-Amz-Cf-Id``,
                 ``X-CDN``, ``X-Served-By``, ``X-Varnish``, ``Fastly-*``)
  - Framework   (``X-Powered-By`` header, ``<meta name="generator"`` in body)

SSL warnings are suppressed with ``urllib3.disable_warnings`` because
self-signed or internal certificates are common in audit targets.

Returns a deduplicated list of :class:`~toolkit.models.Technology` objects.
"""

from __future__ import annotations

import re
from typing import Optional

import urllib3

# Suppress SSL verification warnings (Req. 2.4 / common audit practice)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
from requests.exceptions import RequestException

from toolkit.models import Host, Technology


# ---------------------------------------------------------------------------
# Detection tables
# ---------------------------------------------------------------------------

# (pattern, canonical_name)  — matched case-insensitively against header value
_SERVER_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"nginx", re.I), "nginx"),
    (re.compile(r"apache", re.I), "Apache"),
    (re.compile(r"microsoft-iis(?:/(\S+))?", re.I), "IIS"),
    (re.compile(r"lighttpd(?:/(\S+))?", re.I), "lighttpd"),
    (re.compile(r"openresty(?:/(\S+))?", re.I), "OpenResty"),
    (re.compile(r"caddy(?:/(\S+))?", re.I), "Caddy"),
    (re.compile(r"gunicorn(?:/(\S+))?", re.I), "Gunicorn"),
    (re.compile(r"uvicorn(?:/(\S+))?", re.I), "Uvicorn"),
    (re.compile(r"tornado(?:/(\S+))?", re.I), "Tornado"),
    (re.compile(r"node(?:\.js)?", re.I), "Node.js"),
    (re.compile(r"tomcat(?:/(\S+))?", re.I), "Apache Tomcat"),
    (re.compile(r"jetty(?:/(\S+))?", re.I), "Jetty"),
    (re.compile(r"iplanet", re.I), "iPlanet"),
    (re.compile(r"kestrel", re.I), "Kestrel"),
    (re.compile(r"envoy", re.I), "Envoy"),
]

# Maps response header name → CDN name detected when the header is present
_CDN_HEADERS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-amz-cf-id": "CloudFront",
    "x-amz-request-id": "Amazon S3",
    "x-cache": None,          # value-based detection below
    "via": None,               # value-based detection below
    "x-cdn": None,             # value is usually the CDN name
    "x-served-by": None,       # Fastly
    "x-varnish": "Varnish",
    "x-fastly-request-id": "Fastly",
    "surrogate-key": "Fastly",
    "x-sucuri-id": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-edge-location": "Akamai",
    "x-azure-ref": "Azure CDN",
    "x-msedge-ref": "Azure CDN",
}

# Sub-patterns for headers whose *value* indicates a specific CDN
_CDN_VALUE_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    # header_name_lower, pattern, cdn_name
    ("x-cache", re.compile(r"cloudfront", re.I), "CloudFront"),
    ("x-cache", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("x-cache", re.compile(r"fastly", re.I), "Fastly"),
    ("x-cache", re.compile(r"varnish", re.I), "Varnish"),
    ("x-cache", re.compile(r"akamai", re.I), "Akamai"),
    ("via", re.compile(r"cloudfront", re.I), "CloudFront"),
    ("via", re.compile(r"cloudflare", re.I), "Cloudflare"),
    ("via", re.compile(r"fastly", re.I), "Fastly"),
    ("via", re.compile(r"varnish", re.I), "Varnish"),
    ("via", re.compile(r"akamai", re.I), "Akamai"),
    ("via", re.compile(r"squid", re.I), "Squid"),
    ("x-cdn", re.compile(r"(.+)"), None),       # value itself is the name (capture group 1)
    ("x-served-by", re.compile(r"cache-(.+)", re.I), "Fastly"),
]

# X-Powered-By → (name, version_group, category)
_POWERED_BY_PATTERNS: list[tuple[re.Pattern[str], str, int | None, str]] = [
    (re.compile(r"php(?:/(\S+))?", re.I), "PHP", 1, "framework"),
    (re.compile(r"asp\.net(?: mvc (\S+))?", re.I), "ASP.NET", 1, "framework"),
    (re.compile(r"express(?:/(\S+))?", re.I), "Express", 1, "framework"),
    (re.compile(r"next\.js(?:/(\S+))?", re.I), "Next.js", 1, "framework"),
    (re.compile(r"django(?:/(\S+))?", re.I), "Django", 1, "framework"),
    (re.compile(r"rails(?:/(\S+))?", re.I), "Ruby on Rails", 1, "framework"),
    (re.compile(r"laravel", re.I), "Laravel", None, "framework"),
    (re.compile(r"wordpress", re.I), "WordPress", None, "framework"),
    (re.compile(r"drupal(?:/(\S+))?", re.I), "Drupal", 1, "framework"),
    (re.compile(r"joomla(?:/(\S+))?", re.I), "Joomla", 1, "framework"),
    (re.compile(r"spring(?:/(\S+))?", re.I), "Spring", 1, "framework"),
    (re.compile(r"quarkus(?:/(\S+))?", re.I), "Quarkus", 1, "framework"),
    (re.compile(r"nuxt(?:\.js)?(?:/(\S+))?", re.I), "Nuxt.js", 1, "framework"),
    (re.compile(r"vue(?:\.js)?(?:/(\S+))?", re.I), "Vue.js", 1, "framework"),
]

# <meta name="generator" content="..."> detection
_GENERATOR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"wordpress\s*([\d.]+)?", re.I), "WordPress"),
    (re.compile(r"drupal\s*([\d.]+)?", re.I), "Drupal"),
    (re.compile(r"joomla!\s*([\d.]+)?", re.I), "Joomla"),
    (re.compile(r"ghost\s*([\d.]+)?", re.I), "Ghost"),
    (re.compile(r"hugo\s*([\d.]+)?", re.I), "Hugo"),
    (re.compile(r"jekyll\s*([\d.]+)?", re.I), "Jekyll"),
    (re.compile(r"gatsby\s*([\d.]+)?", re.I), "Gatsby"),
    (re.compile(r"next\.js\s*([\d.]+)?", re.I), "Next.js"),
    (re.compile(r"nuxt\s*([\d.]+)?", re.I), "Nuxt.js"),
    (re.compile(r"vite\s*([\d.]+)?", re.I), "Vite"),
]

# Regex to extract the "generator" meta content from HTML body
_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
    re.I,
)

# Regex to extract a version from a Server header value like "nginx/1.24.0"
_SERVER_VERSION_RE = re.compile(r"/(\S+)")


# ---------------------------------------------------------------------------
# HTTPS ports
# ---------------------------------------------------------------------------

_HTTPS_PORTS = {443, 8443, 9443}


# ---------------------------------------------------------------------------
# Fingerprinter
# ---------------------------------------------------------------------------

class Fingerprinter:
    """
    Identifies web server, framework, and CDN technologies for an active host.

    Uses passive header inspection and light HTML body parsing only —
    no active exploits or intrusive probing.
    """

    def __init__(self, timeout: int = 5) -> None:
        self._timeout = timeout

    def fingerprint(self, host: Host, open_ports: list[int]) -> list[Technology]:
        """
        Probe each open port via HTTP/HTTPS and return identified technologies.

        Args:
            host:        The active host to fingerprint.
            open_ports:  List of TCP ports confirmed open on the host.

        Returns:
            A deduplicated list of :class:`Technology` objects with ``name``,
            ``version`` (or ``None``), and ``category`` fields populated.
        """
        seen: dict[tuple[str, str], Technology] = {}

        for port in open_ports:
            scheme = "https" if port in _HTTPS_PORTS else "http"
            url = f"{scheme}://{host.hostname}:{port}/"

            try:
                response = requests.get(
                    url,
                    timeout=self._timeout,
                    verify=False,
                    allow_redirects=True,
                )
            except RequestException:
                # Connection refused, timeout, SSL error, etc. — skip this port.
                continue

            headers = {k.lower(): v for k, v in response.headers.items()}

            techs = (
                self._detect_web_server(headers)
                + self._detect_cdn(headers)
                + self._detect_framework(headers, response.text)
            )

            for tech in techs:
                key = (tech.category, tech.name.lower())
                if key not in seen:
                    seen[key] = tech

        return list(seen.values())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _detect_web_server(self, headers: dict[str, str]) -> list[Technology]:
        server_value = headers.get("server", "")
        if not server_value:
            return []

        for pattern, canonical_name in _SERVER_PATTERNS:
            m = pattern.search(server_value)
            if m:
                version: Optional[str] = None
                # Try to grab the version from the header text (e.g. "nginx/1.24.0")
                vm = _SERVER_VERSION_RE.search(server_value)
                if vm:
                    version = vm.group(1)
                # Some patterns have an explicit capture group for the version
                try:
                    if m.lastindex and m.group(1):
                        version = m.group(1)
                except IndexError:
                    pass
                return [Technology(name=canonical_name, version=version, category="web_server")]

        # Unrecognised server token — still record it as "other" so nothing is lost
        first_token = server_value.split()[0] if server_value.split() else server_value
        # Strip version if present
        name_part = first_token.split("/")[0]
        version_part: Optional[str] = None
        if "/" in first_token:
            version_part = first_token.split("/", 1)[1]
        return [Technology(name=name_part, version=version_part, category="web_server")]

    def _detect_cdn(self, headers: dict[str, str]) -> list[Technology]:
        results: list[Technology] = []
        found_cdns: set[str] = set()

        # Direct header presence → certain CDN names
        for header_lc, cdn_name in _CDN_HEADERS.items():
            if header_lc in headers and cdn_name is not None:
                if cdn_name not in found_cdns:
                    results.append(
                        Technology(name=cdn_name, version=None, category="cdn")
                    )
                    found_cdns.add(cdn_name)

        # Value-based patterns
        for header_lc, pattern, cdn_name in _CDN_VALUE_PATTERNS:
            if header_lc not in headers:
                continue
            value = headers[header_lc]
            m = pattern.search(value)
            if not m:
                continue
            # When cdn_name is None, use the first capture group from the pattern
            resolved_name = cdn_name
            if resolved_name is None:
                try:
                    resolved_name = m.group(1).strip() if m.group(1) else None
                except IndexError:
                    resolved_name = None
            if resolved_name and resolved_name not in found_cdns:
                results.append(
                    Technology(name=resolved_name, version=None, category="cdn")
                )
                found_cdns.add(resolved_name)

        return results

    def _detect_framework(
        self, headers: dict[str, str], body: str
    ) -> list[Technology]:
        results: list[Technology] = []

        # --- X-Powered-By header ---
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            for pattern, name, version_group, category in _POWERED_BY_PATTERNS:
                m = pattern.search(powered_by)
                if m:
                    version: Optional[str] = None
                    if version_group is not None:
                        try:
                            version = m.group(version_group)
                        except IndexError:
                            pass
                    results.append(
                        Technology(name=name, version=version, category=category)  # type: ignore[arg-type]
                    )
                    break
            else:
                # Unrecognised value — keep it as-is under "other"
                results.append(
                    Technology(name=powered_by, version=None, category="other")
                )

        # --- <meta name="generator"> in HTML body ---
        meta_match = _META_GENERATOR_RE.search(body)
        if meta_match:
            generator_value = meta_match.group(1).strip()
            for pattern, name in _GENERATOR_PATTERNS:
                gm = pattern.search(generator_value)
                if gm:
                    version_from_meta: Optional[str] = None
                    try:
                        version_from_meta = gm.group(1)
                    except IndexError:
                        pass
                    results.append(
                        Technology(
                            name=name,
                            version=version_from_meta,
                            category="framework",
                        )
                    )
                    break
            else:
                # Unknown generator — record as "other"
                results.append(
                    Technology(name=generator_value, version=None, category="other")
                )

        return results
