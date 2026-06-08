"""
Subdomain enumeration via multiple passive OSINT sources.

This module aggregates **passive** subdomain discovery from public data
sources, complementing :class:`toolkit.discovery.surface_mapper.SurfaceMapper`
(which currently uses crt.sh + DNS).  No traffic is sent to the target —
all queries hit third-party catalogues that index publicly-issued
certificates, DNS history and threat-intel feeds.

Sources implemented:
    * crt.sh                     — Certificate Transparency JSON API
    * HackerTarget               — public hostsearch DNS records
    * RapidDNS                   — passive subdomain catalog
    * AlienVault OTX             — threat-intel passive DNS
    * Anubis (jldc.me)           — passive aggregator
    * urlscan.io                 — recently-scanned URLs catalog

All queries respect a per-source timeout of 15 s and degrade gracefully
when a source is unreachable.  The aggregator returns a deduplicated list
of host names along with a per-source breakdown that can be persisted in
the audit log.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)

_USER_AGENT = "web-security-audit-toolkit/0.2"
_DEFAULT_TIMEOUT_S = 15.0
_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9][-a-zA-Z0-9_.]*[a-zA-Z0-9]$")


@dataclass(frozen=True)
class SourceResult:
    """Result of a single source query."""

    name: str
    subdomains: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.error is None


@dataclass(frozen=True)
class AggregatedResult:
    """Aggregated result from all sources."""

    domain: str
    sources: list[SourceResult]
    subdomains: list[str]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "total_unique_subdomains": len(self.subdomains),
            "subdomains": self.subdomains,
            "sources": [
                {
                    "name": s.name,
                    "succeeded": s.succeeded,
                    "count": len(s.subdomains),
                    "error": s.error,
                }
                for s in self.sources
            ],
        }


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------


def _http_get(url: str, *, timeout: float = _DEFAULT_TIMEOUT_S) -> bytes:
    """GET *url* and return the raw body.

    Raises any underlying ``urllib`` error so callers can wrap it as a
    :class:`SourceResult` with ``error`` set.
    """
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _normalize(domain: str, candidate: str) -> str | None:
    """Return *candidate* if it is a valid hostname under *domain*."""
    candidate = candidate.strip().lower().lstrip("*.")
    if not candidate or candidate == domain:
        return candidate or None
    if not (candidate == domain or candidate.endswith("." + domain)):
        return None
    if not _HOSTNAME_RE.match(candidate):
        return None
    return candidate


# ---------------------------------------------------------------------------
# Source: crt.sh (Certificate Transparency)
# ---------------------------------------------------------------------------


def fetch_crtsh(domain: str, *, timeout: float = _DEFAULT_TIMEOUT_S) -> SourceResult:
    """Query crt.sh JSON API for certificates covering *domain* and below."""
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    found: set[str] = set()
    try:
        body = _http_get(url, timeout=timeout)
        data = json.loads(body.decode("utf-8") or "[]")
        for entry in data:
            value: str = entry.get("name_value", "") or ""
            for line in value.splitlines():
                norm = _normalize(domain, line)
                if norm:
                    found.add(norm)
    except Exception as exc:  # noqa: BLE001
        return SourceResult(name="crtsh", error=f"{type(exc).__name__}: {exc}")
    return SourceResult(name="crtsh", subdomains=sorted(found))


# ---------------------------------------------------------------------------
# Source: HackerTarget hostsearch
# ---------------------------------------------------------------------------


def fetch_hackertarget(
    domain: str, *, timeout: float = _DEFAULT_TIMEOUT_S
) -> SourceResult:
    """Query HackerTarget hostsearch (returns ``host,IP`` lines)."""
    url = f"https://api.hackertarget.com/hostsearch/?q={urllib.parse.quote(domain)}"
    found: set[str] = set()
    try:
        body = _http_get(url, timeout=timeout).decode("utf-8")
        if "API count exceeded" in body or "error check your search" in body.lower():
            return SourceResult(
                name="hackertarget",
                error="rate limit or invalid response",
            )
        for line in body.splitlines():
            host = line.split(",", 1)[0]
            norm = _normalize(domain, host)
            if norm:
                found.add(norm)
    except Exception as exc:  # noqa: BLE001
        return SourceResult(name="hackertarget", error=f"{type(exc).__name__}: {exc}")
    return SourceResult(name="hackertarget", subdomains=sorted(found))


# ---------------------------------------------------------------------------
# Source: RapidDNS
# ---------------------------------------------------------------------------


def fetch_rapiddns(
    domain: str, *, timeout: float = _DEFAULT_TIMEOUT_S
) -> SourceResult:
    """Query RapidDNS subdomain HTML page and parse hostnames."""
    url = f"https://rapiddns.io/subdomain/{urllib.parse.quote(domain)}?full=1#result"
    found: set[str] = set()
    try:
        body = _http_get(url, timeout=timeout).decode("utf-8", errors="ignore")
        # RapidDNS lists names inside <td> tags
        for match in re.findall(r"<td[^>]*>\s*([^<\s]+\." + re.escape(domain) + r")\s*</td>", body, re.IGNORECASE):
            norm = _normalize(domain, match)
            if norm:
                found.add(norm)
    except Exception as exc:  # noqa: BLE001
        return SourceResult(name="rapiddns", error=f"{type(exc).__name__}: {exc}")
    return SourceResult(name="rapiddns", subdomains=sorted(found))


# ---------------------------------------------------------------------------
# Source: AlienVault OTX
# ---------------------------------------------------------------------------


def fetch_alienvault(
    domain: str, *, timeout: float = _DEFAULT_TIMEOUT_S
) -> SourceResult:
    """Query AlienVault OTX passive DNS API."""
    url = (
        "https://otx.alienvault.com/api/v1/indicators/domain/"
        f"{urllib.parse.quote(domain)}/passive_dns"
    )
    found: set[str] = set()
    try:
        body = _http_get(url, timeout=timeout)
        data = json.loads(body.decode("utf-8") or "{}")
        for record in data.get("passive_dns") or []:
            host = record.get("hostname") or ""
            norm = _normalize(domain, host)
            if norm:
                found.add(norm)
    except Exception as exc:  # noqa: BLE001
        return SourceResult(name="alienvault", error=f"{type(exc).__name__}: {exc}")
    return SourceResult(name="alienvault", subdomains=sorted(found))


# ---------------------------------------------------------------------------
# Source: Anubis (jldc.me)
# ---------------------------------------------------------------------------


def fetch_anubis(domain: str, *, timeout: float = _DEFAULT_TIMEOUT_S) -> SourceResult:
    """Query Anubis subdomain aggregator."""
    url = f"https://jldc.me/anubis/subdomains/{urllib.parse.quote(domain)}"
    found: set[str] = set()
    try:
        body = _http_get(url, timeout=timeout)
        data = json.loads(body.decode("utf-8") or "[]")
        if isinstance(data, list):
            for host in data:
                norm = _normalize(domain, str(host))
                if norm:
                    found.add(norm)
    except Exception as exc:  # noqa: BLE001
        return SourceResult(name="anubis", error=f"{type(exc).__name__}: {exc}")
    return SourceResult(name="anubis", subdomains=sorted(found))


# ---------------------------------------------------------------------------
# Source: urlscan.io
# ---------------------------------------------------------------------------


def fetch_urlscan(
    domain: str, *, timeout: float = _DEFAULT_TIMEOUT_S
) -> SourceResult:
    """Query urlscan.io public search for hosts under *domain*."""
    query = f"domain:{domain}"
    url = f"https://urlscan.io/api/v1/search/?q={urllib.parse.quote(query)}&size=200"
    found: set[str] = set()
    try:
        body = _http_get(url, timeout=timeout)
        data = json.loads(body.decode("utf-8") or "{}")
        for result in data.get("results") or []:
            page = result.get("page") or {}
            for key in ("domain", "apexDomain"):
                norm = _normalize(domain, str(page.get(key) or ""))
                if norm:
                    found.add(norm)
            task = result.get("task") or {}
            norm = _normalize(domain, str(task.get("domain") or ""))
            if norm:
                found.add(norm)
    except Exception as exc:  # noqa: BLE001
        return SourceResult(name="urlscan", error=f"{type(exc).__name__}: {exc}")
    return SourceResult(name="urlscan", subdomains=sorted(found))


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


_DEFAULT_SOURCES: tuple[Callable[[str], SourceResult], ...] = (
    fetch_crtsh,
    fetch_hackertarget,
    fetch_rapiddns,
    fetch_alienvault,
    fetch_anubis,
    fetch_urlscan,
)


def aggregate_subdomains(
    domain: str,
    *,
    sources: tuple[Callable[[str], SourceResult], ...] | None = None,
    timeout: float = _DEFAULT_TIMEOUT_S,
) -> AggregatedResult:
    """Aggregate subdomains from every passive source.

    Args:
        domain: Root domain to enumerate.
        sources: Override the default tuple of fetchers (useful for tests).
        timeout: Per-source timeout in seconds.

    Returns:
        :class:`AggregatedResult` with deduplicated subdomain list and a
        per-source breakdown.
    """
    chosen = sources or _DEFAULT_SOURCES
    results: list[SourceResult] = []
    union: set[str] = set()

    for fetcher in chosen:
        try:
            res = fetcher(domain, timeout=timeout)  # type: ignore[call-arg]
        except TypeError:
            # Fetcher does not accept timeout kwarg (e.g. test stub)
            res = fetcher(domain)
        except Exception as exc:  # noqa: BLE001
            res = SourceResult(
                name=getattr(fetcher, "__name__", "unknown"),
                error=f"{type(exc).__name__}: {exc}",
            )
        results.append(res)
        union.update(res.subdomains)

    return AggregatedResult(
        domain=domain,
        sources=results,
        subdomains=sorted(union),
    )
