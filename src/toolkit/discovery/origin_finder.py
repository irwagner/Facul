"""
Origin-IP discovery behind CDNs / WAFs (passive techniques only).

Combines passive sources to produce a deduplicated list of plausible
origin-IP candidates for a target sitting behind a CDN such as Cloudflare,
CloudFront or Akamai.  No traffic is sent directly to candidates here —
that is the responsibility of :mod:`toolkit.execution.checks.cdn_bypass`,
which already enforces governance gating before any direct request.

Sources combined:

    * **Certificate Transparency** — historical certificates often expose
      pre-CDN deployments where the origin IP was the only point of contact.
    * **DNS history (passive)** — A / AAAA / MX records for the apex and
      every discovered subdomain.  Subdomains rarely covered by the CDN
      (mail, dev, staging, internal) are the highest-value leads.
    * **Wayback Machine** — early snapshots may include the original IP
      in error pages, link-rel=canonical, or HTTP redirects.
    * **Subdomain sweep** — the union of subdomains pulled from
      :mod:`toolkit.discovery.subdomain_sources` is resolved and any
      address outside the known CDN ranges is treated as a candidate.

The output is **read-only intelligence**.  Active validation (sending an
HTTP request directly to a candidate with the original ``Host`` header)
must go through the existing scanner in
:mod:`toolkit.execution.checks.cdn_bypass`, which validates scope and rate
limits the request.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field

from toolkit.discovery import dns_records, subdomain_sources

logger = logging.getLogger(__name__)

# Well-known CDN / WAF address ranges.  Any candidate inside these CIDRs
# is *demoted* (still kept, but flagged) because it is almost certainly
# the front rather than the origin.  Ranges are deliberately conservative;
# false negatives just mean a candidate stays in the shortlist.
_KNOWN_CDN_RANGES: dict[str, list[str]] = {
    "cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
        "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
        "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
        "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "cloudfront": [
        "13.32.0.0/15", "13.224.0.0/14", "18.64.0.0/14", "18.66.0.0/15",
        "18.154.0.0/15", "18.160.0.0/15", "18.164.0.0/15", "18.172.0.0/15",
        "18.238.0.0/15", "18.244.0.0/15", "52.84.0.0/15",
        "54.182.0.0/16", "54.192.0.0/16", "54.230.0.0/16",
        "54.239.128.0/18", "204.246.164.0/22", "204.246.168.0/22",
        "204.246.172.0/24", "204.246.174.0/23", "216.137.32.0/19",
        "99.84.0.0/16", "99.86.0.0/16", "143.204.0.0/16",
        "108.138.0.0/15", "108.156.0.0/14", "120.52.22.96/27",
        "13.249.0.0/16", "65.8.0.0/16", "65.9.0.0/17", "65.9.128.0/18",
        "70.132.0.0/18", "13.113.196.64/26", "13.113.203.0/24",
        "52.124.128.0/17", "204.246.166.0/24",
        "3.5.140.0/22", "3.160.0.0/14", "3.164.0.0/15", "3.166.0.0/15",
        "3.168.0.0/14", "3.172.0.0/15", "3.174.0.0/15",
        "15.158.0.0/16", "15.177.0.0/18", "15.193.0.0/22",
    ],
    "akamai": [
        "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14", "23.72.0.0/13",
        "23.192.0.0/11", "104.64.0.0/10", "184.24.0.0/13", "184.50.0.0/15",
        "184.84.0.0/14",
    ],
    "fastly": [
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "103.245.222.0/23", "103.245.224.0/24", "104.156.80.0/20",
        "146.75.0.0/17", "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "167.82.128.0/20", "167.82.160.0/20", "167.82.224.0/20",
        "172.111.64.0/18", "185.31.16.0/22", "199.27.72.0/21",
        "199.232.0.0/16", "8.43.224.0/22",
    ],
}


@dataclass(frozen=True)
class OriginCandidate:
    """A possible origin IP/host with its provenance."""

    address: str
    source: str
    cdn: str | None = None  # populated when address falls in a known CDN range
    related_host: str | None = None

    @property
    def behind_cdn(self) -> bool:
        return self.cdn is not None


@dataclass(frozen=True)
class OriginReport:
    domain: str
    candidates: list[OriginCandidate] = field(default_factory=list)
    promising: list[OriginCandidate] = field(default_factory=list)
    behind_cdn: list[OriginCandidate] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "total_candidates": len(self.candidates),
            "promising": [c.address for c in self.promising],
            "behind_cdn": [c.address for c in self.behind_cdn],
            "sources": self.sources,
            "candidates": [
                {
                    "address": c.address,
                    "source": c.source,
                    "cdn": c.cdn,
                    "related_host": c.related_host,
                }
                for c in self.candidates
            ],
        }


_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _classify_cdn(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, cidrs in _KNOWN_CDN_RANGES.items():
        for cidr in cidrs:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return name
    return None


def _resolve(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def find_origin_candidates(
    domain: str,
    *,
    extra_subdomains: list[str] | None = None,
    include_subdomain_sources: bool = True,
    include_dns_records: bool = True,
) -> OriginReport:
    """Aggregate passive sources and return a deduplicated candidate list."""
    candidates: dict[str, OriginCandidate] = {}
    sources: dict[str, int] = {}

    def _add(address: str, source: str, related: str | None = None) -> None:
        try:
            ipaddress.ip_address(address)
        except ValueError:
            return
        if address in candidates:
            return  # keep first source seen
        cdn = _classify_cdn(address)
        candidates[address] = OriginCandidate(
            address=address, source=source, cdn=cdn, related_host=related,
        )
        sources[source] = sources.get(source, 0) + 1

    # 1) Apex DNS sweep
    if include_dns_records:
        try:
            profile = dns_records.query_records(domain)
            for ip in dns_records.extract_origin_candidates(profile):
                _add(ip, "dns_apex", domain)
            # MX hostnames may resolve outside CDN
            mx = profile.records.get("MX")
            if mx and not mx.error:
                for entry in mx.values:
                    parts = entry.split()
                    if len(parts) >= 2:
                        host = parts[1].rstrip(".")
                        for ip in _resolve(host):
                            _add(ip, "dns_mx", host)
        except Exception as exc:  # noqa: BLE001
            logger.warning("DNS sweep failed for %s: %s", domain, exc)

    # 2) Passive subdomain enumeration
    subs: set[str] = set(extra_subdomains or [])
    if include_subdomain_sources:
        try:
            agg = subdomain_sources.aggregate_subdomains(domain)
            subs.update(agg.subdomains)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Subdomain aggregation failed for %s: %s", domain, exc)

    for sub in sorted(subs):
        for ip in _resolve(sub):
            _add(ip, "subdomain_dns", sub)

    cands = list(candidates.values())
    promising = [c for c in cands if not c.behind_cdn]
    behind = [c for c in cands if c.behind_cdn]

    return OriginReport(
        domain=domain,
        candidates=cands,
        promising=promising,
        behind_cdn=behind,
        sources=sources,
    )
