"""
Historical URL discovery via Wayback Machine and AlienVault OTX URL list.

Surfaces URLs that were once reachable on a target.  Useful to find
forgotten admin panels, debug pages, deprecated APIs and parameter sets
that no longer appear in the live site.
"""

from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

_USER_AGENT = "web-security-audit-toolkit/0.2"
_DEFAULT_TIMEOUT_S = 20.0


@dataclass(frozen=True)
class HistoricalUrls:
    domain: str
    urls: list[str] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "total": len(self.urls),
            "sources": self.sources,
            "errors": self.errors,
            "urls": self.urls,
        }


def _http_get(url: str, *, timeout: float) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_wayback(domain: str, *, timeout: float = _DEFAULT_TIMEOUT_S) -> list[str]:
    """Query Wayback Machine CDX API for *domain* (and subdomains).

    Returns a deduplicated list of original URLs seen by the archive.
    """
    api = (
        "http://web.archive.org/cdx/search/cdx"
        f"?url=*.{urllib.parse.quote(domain)}/*"
        "&output=json&fl=original&collapse=urlkey&limit=10000"
    )
    body = _http_get(api, timeout=timeout)
    data = json.loads(body.decode("utf-8") or "[]")
    if not isinstance(data, list) or len(data) <= 1:
        return []
    # First row is header (["original"])
    rows = data[1:]
    out: list[str] = []
    seen: set[str] = set()
    for row in rows:
        if isinstance(row, list) and row:
            u = str(row[0])
            if u and u not in seen:
                seen.add(u)
                out.append(u)
    return out


def fetch_otx_urls(domain: str, *, timeout: float = _DEFAULT_TIMEOUT_S) -> list[str]:
    """Query AlienVault OTX URL list for *domain*."""
    out: set[str] = set()
    page = 1
    while page <= 5:  # bounded to keep audits fast
        api = (
            "https://otx.alienvault.com/api/v1/indicators/domain/"
            f"{urllib.parse.quote(domain)}/url_list?limit=500&page={page}"
        )
        body = _http_get(api, timeout=timeout)
        data = json.loads(body.decode("utf-8") or "{}")
        url_list = data.get("url_list") or []
        if not url_list:
            break
        for entry in url_list:
            u = entry.get("url") if isinstance(entry, dict) else None
            if u:
                out.add(str(u))
        if not data.get("has_next"):
            break
        page += 1
    return sorted(out)


def collect(
    domain: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT_S,
    use_wayback: bool = True,
    use_otx: bool = True,
) -> HistoricalUrls:
    """Aggregate historical URLs across all enabled sources."""
    urls: set[str] = set()
    sources: dict[str, int] = {}
    errors: dict[str, str] = {}

    if use_wayback:
        try:
            wb = fetch_wayback(domain, timeout=timeout)
            sources["wayback"] = len(wb)
            urls.update(wb)
        except Exception as exc:  # noqa: BLE001
            errors["wayback"] = f"{type(exc).__name__}: {exc}"

    if use_otx:
        try:
            otx = fetch_otx_urls(domain, timeout=timeout)
            sources["otx"] = len(otx)
            urls.update(otx)
        except Exception as exc:  # noqa: BLE001
            errors["otx"] = f"{type(exc).__name__}: {exc}"

    return HistoricalUrls(
        domain=domain,
        urls=sorted(urls),
        sources=sources,
        errors=errors,
    )


def extract_parameters(urls: list[str]) -> dict[str, set[str]]:
    """Pull query parameter names per path from a URL list.

    Returns mapping of ``"<host><path>" → {param1, param2, ...}``.  Useful
    to seed the parameter-fuzzing checks with names already known to be
    accepted by the target.
    """
    out: dict[str, set[str]] = {}
    for u in urls:
        try:
            p = urllib.parse.urlparse(u)
        except Exception:  # noqa: BLE001
            continue
        if not p.query:
            continue
        key = f"{p.netloc}{p.path}"
        params = set()
        for piece in p.query.split("&"):
            name = piece.split("=", 1)[0].strip()
            if name:
                params.add(name)
        if params:
            out.setdefault(key, set()).update(params)
    return out
