"""
DNS record enumeration (A, AAAA, MX, NS, TXT, SOA, CNAME, CAA).

Pulls the full DNS record set for a domain to expose:
    * Backend/origin candidates (A, AAAA, MX)
    * Mail and infrastructure providers (MX, NS, CNAME)
    * SPF / DKIM / DMARC posture (TXT)
    * CAA policy
    * Zone authority (SOA)

Implemented with ``dnspython``.  All queries are bounded by a configurable
timeout and never fail the whole sweep when a single record type is
unavailable for the domain.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Iterable

logger = logging.getLogger(__name__)

# Default record types to query.  ``DMARC`` is queried as ``_dmarc.<domain>``
# TXT and ``DKIM`` requires per-selector lookup so it is not part of the
# default sweep — callers can call :func:`query_dkim` separately.
DEFAULT_RECORD_TYPES: tuple[str, ...] = (
    "A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA",
)

_DEFAULT_TIMEOUT_S = 5.0


@dataclass(frozen=True)
class DnsRecordSet:
    """Per-record-type DNS query result."""

    record_type: str
    values: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass(frozen=True)
class DnsProfile:
    """Aggregated DNS profile for a single domain."""

    domain: str
    records: dict[str, DnsRecordSet]
    has_spf: bool
    has_dmarc: bool
    has_caa: bool
    cname_chain: list[str]

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "has_spf": self.has_spf,
            "has_dmarc": self.has_dmarc,
            "has_caa": self.has_caa,
            "cname_chain": self.cname_chain,
            "records": {
                rt: {"values": rs.values, "error": rs.error}
                for rt, rs in self.records.items()
            },
        }


def _query_one(
    resolver,
    name: str,
    record_type: str,
    timeout: float,
) -> DnsRecordSet:
    try:
        answers = resolver.resolve(name, record_type, lifetime=timeout)
    except Exception as exc:  # noqa: BLE001 — dnspython has many subclasses
        return DnsRecordSet(record_type=record_type, error=type(exc).__name__)
    values: list[str] = []
    for rdata in answers:
        try:
            values.append(rdata.to_text().strip('"'))
        except Exception:  # noqa: BLE001
            values.append(repr(rdata))
    return DnsRecordSet(record_type=record_type, values=values)


def query_records(
    domain: str,
    *,
    record_types: Iterable[str] = DEFAULT_RECORD_TYPES,
    timeout: float = _DEFAULT_TIMEOUT_S,
    resolver=None,
) -> DnsProfile:
    """Run a full DNS sweep for *domain* and return a :class:`DnsProfile`."""
    import dns.resolver  # local import keeps module optional at import time

    res = resolver or dns.resolver.Resolver()
    records: dict[str, DnsRecordSet] = {}
    for rt in record_types:
        records[rt] = _query_one(res, domain, rt, timeout)

    # SPF lives in TXT: any value starting with "v=spf1"
    has_spf = any(
        v.lower().startswith("v=spf1")
        for v in records.get("TXT", DnsRecordSet("TXT")).values
    )

    # DMARC is _dmarc.<domain> TXT
    dmarc = _query_one(res, f"_dmarc.{domain}", "TXT", timeout)
    records["DMARC"] = dmarc
    has_dmarc = any(v.lower().startswith("v=dmarc1") for v in dmarc.values)

    has_caa = bool(records.get("CAA", DnsRecordSet("CAA")).values)

    cname_chain: list[str] = []
    cur = domain
    seen = {cur}
    for _ in range(8):  # bounded to prevent loops
        rs = _query_one(res, cur, "CNAME", timeout)
        if not rs.values or rs.error:
            break
        target = rs.values[0].rstrip(".").lower()
        if not target or target in seen:
            break
        cname_chain.append(target)
        seen.add(target)
        cur = target

    return DnsProfile(
        domain=domain,
        records=records,
        has_spf=has_spf,
        has_dmarc=has_dmarc,
        has_caa=has_caa,
        cname_chain=cname_chain,
    )


def query_dkim(
    domain: str,
    selectors: Iterable[str] = ("default", "google", "selector1", "selector2", "k1"),
    *,
    timeout: float = _DEFAULT_TIMEOUT_S,
    resolver=None,
) -> dict[str, DnsRecordSet]:
    """Probe *domain* for DKIM records under common selectors."""
    import dns.resolver

    res = resolver or dns.resolver.Resolver()
    out: dict[str, DnsRecordSet] = {}
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        out[sel] = _query_one(res, name, "TXT", timeout)
    return out


def extract_origin_candidates(profile: DnsProfile) -> list[str]:
    """Pull plausible origin IPs / hosts from a DNS profile.

    Uses A and AAAA records, plus MX hosts whose A-record could double as
    origin (common misconfiguration where mail and web share a host).
    """
    out: list[str] = []
    a = profile.records.get("A")
    if a and not a.error:
        out.extend(a.values)
    aaaa = profile.records.get("AAAA")
    if aaaa and not aaaa.error:
        out.extend(aaaa.values)
    mx = profile.records.get("MX")
    if mx and not mx.error:
        for entry in mx.values:
            # MX values look like "10 mail.example.com." — keep the host
            parts = entry.split()
            if len(parts) >= 2:
                out.append(parts[1].rstrip("."))
    # Deduplicate while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped
