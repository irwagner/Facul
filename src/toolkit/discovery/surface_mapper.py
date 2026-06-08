"""
SurfaceMapper — attack surface discovery (Req. 2.1, 2.2, 2.5, 2.6, 2.7).

Conducts:
  - Passive subdomain enumeration (DNS + Certificate Transparency)
  - Active host identification (TCP SYN / ICMP echo, 5 s timeout)
  - Surface map assembly with scope enforcement

The ``build_surface_map`` method is the core function covered by Property 4
and is the primary focus of this module.  It accepts a pre-built list of
:class:`~toolkit.models.Host` objects together with ports and technology
data, applies the :class:`~toolkit.governance.scope.ScopeValidator`, and
returns an :class:`~toolkit.models.AttackSurfaceMap` that:

  * contains **only** hosts that are within the authorised scope,
  * preserves the ports and technologies of every included host,
  * records one :class:`~toolkit.models.Exclusion` (host, reason, timestamp)
    for every host that is excluded.

(Req. 2.5, 2.6)
"""

from __future__ import annotations

import logging
import socket
import warnings
from datetime import datetime
from typing import TYPE_CHECKING

from toolkit.models import AttackSurfaceMap, Exclusion, Host, Technology

if TYPE_CHECKING:
    from toolkit.governance.audit_logger import AuditLogger
    from toolkit.governance.scope import ScopeValidator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TCP probe timeout (Req. 2.2)
# ---------------------------------------------------------------------------
_PROBE_TIMEOUT_S = 5.0

# Well-known ports to probe when checking host liveness
_PROBE_PORTS = [80, 443, 8080, 8443]

# Certificate Transparency log endpoint (crt.sh JSON API)
_CT_LOG_URL_TEMPLATE = "https://crt.sh/?q=%.{domain}&output=json"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _tcp_probe(hostname: str, ip: str) -> bool:
    """
    Attempt a TCP SYN (connect) on each probe port within the timeout.

    Returns ``True`` if any port accepts the connection within
    ``_PROBE_TIMEOUT_S`` seconds; ``False`` otherwise (Req. 2.2).

    Args:
        hostname: Human-readable name (used only for logging).
        ip: Resolved IP address to connect to.

    Returns:
        ``True`` if at least one TCP connection succeeded.
    """
    for port in _PROBE_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=_PROBE_TIMEOUT_S):
                return True
        except OSError:
            # Connection refused, timed out, or unreachable — try next port
            continue
    return False


class SurfaceMapper:
    """
    Conducts attack-surface discovery for an authorised target.

    ``enumerate_subdomains`` performs passive enumeration via DNS and
    Certificate Transparency.  ``identify_active_hosts`` probes each
    subdomain for liveness via TCP SYN (connect) with a 5-second timeout
    (Req. 2.1, 2.2).  ``build_surface_map`` assembles the final map with
    scope enforcement (Req. 2.5, 2.6).
    """

    # ------------------------------------------------------------------
    # Passive subdomain enumeration (Req. 2.1, 2.7)
    # ------------------------------------------------------------------

    def enumerate_subdomains(self, domain: str) -> list[str]:
        """
        Passively enumerate sub-domains via DNS and Certificate Transparency.

        Strategy (Req. 2.1):
        1. Query Certificate Transparency logs via the crt.sh public JSON API
           to obtain names that have appeared in publicly-trusted certificates.
        2. Attempt to resolve each candidate name with a DNS A-record query
           to confirm it exists in DNS.

        When enumeration yields zero results a warning is logged and the
        caller is expected to prompt the auditor (Req. 2.7).

        Args:
            domain: The root domain to enumerate (e.g. ``"example.com"``).

        Returns:
            Deduplicated list of sub-domain names discovered.  May be empty.
        """
        import json

        try:
            import urllib.request
        except ImportError:  # pragma: no cover
            warnings.warn(
                f"urllib.request is unavailable; cannot enumerate subdomains for {domain!r}.",
                stacklevel=2,
            )
            return []

        subdomains: list[str] = []

        # --- Step 1: Certificate Transparency (crt.sh) ---
        ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            req = urllib.request.Request(
                ct_url,
                headers={"User-Agent": "web-security-audit-toolkit/0.1"},
            )
            with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT_S) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                seen: set[str] = set()
                for entry in data:
                    # Each entry may contain a "name_value" field with the
                    # common name or SAN; multiple names separated by newlines.
                    name_value: str = entry.get("name_value", "")
                    for candidate in name_value.splitlines():
                        candidate = candidate.strip().lstrip("*.")
                        if candidate and candidate.endswith(f".{domain}") or candidate == domain:
                            if candidate not in seen:
                                seen.add(candidate)
                                subdomains.append(candidate)
        except Exception as exc:  # noqa: BLE001
            logger.warning("CT log query failed for %r: %s", domain, exc)

        # --- Step 2: DNS resolution to filter live names ---
        # We keep names that resolve successfully; names that fail DNS are
        # still returned (passive enumeration) but logged at DEBUG level.
        validated: list[str] = []
        for name in subdomains:
            try:
                socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)
                validated.append(name)
            except OSError:
                # Not DNS-resolvable right now; include anyway (Req. 2.1 — passive)
                validated.append(name)

        # Deduplicate while preserving order
        result: list[str] = list(dict.fromkeys(validated))

        if not result:
            warnings.warn(
                f"enumerate_subdomains: no subdomains found for {domain!r}. "
                "Verify the target domain and DNS resolution before proceeding.",
                UserWarning,
                stacklevel=2,
            )

        return result

    # ------------------------------------------------------------------
    # Active host identification (Req. 2.2)
    # ------------------------------------------------------------------

    def identify_active_hosts(self, subdomains: list[str]) -> list[Host]:
        """
        Identify active hosts from a list of sub-domain names.

        A host is considered active if it responds to a TCP SYN (connection
        attempt) on any of the well-known probe ports within 5 seconds
        (Req. 2.2).  Each name is also resolved to an IP address; if
        resolution fails, the host is skipped and logged at DEBUG level.

        Args:
            subdomains: Candidate host names to probe.

        Returns:
            List of :class:`~toolkit.models.Host` instances.  Only hosts
            where a TCP connection succeeds within the timeout are marked
            ``is_active=True``; hosts that fail resolution are excluded
            entirely.
        """
        hosts: list[Host] = []

        for hostname in subdomains:
            # Resolve hostname → IP
            try:
                ip = socket.gethostbyname(hostname)
            except OSError:
                logger.debug("DNS resolution failed for %r; skipping.", hostname)
                continue

            # Probe liveness: attempt TCP connect on probe ports
            is_active = _tcp_probe(hostname, ip)

            hosts.append(
                Host(
                    hostname=hostname,
                    ip=ip,
                    is_active=is_active,
                )
            )

        return hosts

    # ------------------------------------------------------------------
    # Core pure method — fully tested by Property 4
    # ------------------------------------------------------------------

    def build_surface_map(
        self,
        hosts: list[Host],
        ports: dict[str, list[int]],
        techs: dict[str, list[Technology]],
        scope: "ScopeValidator",
        logger: "AuditLogger",
    ) -> AttackSurfaceMap:
        """
        Assemble an :class:`~toolkit.models.AttackSurfaceMap` from discovery
        data, excluding any host that is outside the authorised scope
        (Req. 2.5, 2.6).

        For every host in *hosts*:

        * If ``scope.in_scope(host.hostname)`` is ``True``, the host is
          included in ``active_hosts``.  Its ``open_ports`` are updated from
          *ports* (if present) and its ``technologies`` from *techs* (if
          present), while the rest of the :class:`Host` attributes are
          preserved unchanged.
        * If the host is **not** in scope, it is excluded and an
          :class:`~toolkit.models.Exclusion` record is appended, containing:
          the host name, a reason string, and an ISO 8601 timestamp.  An
          ``AuditEvent`` with ``event_type="exclusion"`` is also logged.

        The ``subdomains`` field of the resulting map is derived from the
        ``hostname`` of every host in *hosts* (both included and excluded),
        matching the expectation that the caller supplies the full list of
        discovered hosts.

        The ``technologies_by_host`` mapping in the result contains only
        in-scope hosts and is built from *techs*; if a host has no entry in
        *techs*, an empty list is used.

        Args:
            hosts:  All discovered hosts (mix of in-scope and out-of-scope).
            ports:  Mapping from hostname → list of open ports discovered by
                    the Enumerator.
            techs:  Mapping from hostname → list of identified technologies.
            scope:  Pre-configured :class:`~toolkit.governance.scope.ScopeValidator`.
            logger: :class:`~toolkit.governance.audit_logger.AuditLogger`
                    instance for recording exclusion events (Req. 2.6).

        Returns:
            :class:`~toolkit.models.AttackSurfaceMap` with in-scope hosts
            and one :class:`Exclusion` per excluded host.
        """
        from toolkit.models import AuditEvent

        active_hosts: list[Host] = []
        excluded: list[Exclusion] = []
        technologies_by_host: dict[str, list[Technology]] = {}
        subdomains: list[str] = [h.hostname for h in hosts]

        for host in hosts:
            if scope.in_scope(host.hostname):
                # Merge port / tech data from enumerator/fingerprinter
                updated_ports = ports.get(host.hostname, host.open_ports)
                updated_techs = techs.get(host.hostname, host.technologies)

                included_host = Host(
                    hostname=host.hostname,
                    ip=host.ip,
                    is_active=host.is_active,
                    open_ports=list(updated_ports),
                    technologies=list(updated_techs),
                )
                active_hosts.append(included_host)
                technologies_by_host[host.hostname] = list(updated_techs)
            else:
                timestamp = datetime.now().isoformat()
                reason = (
                    f"Host {host.hostname!r} is outside the authorised scope"
                )
                exclusion = Exclusion(
                    host=host.hostname,
                    reason=reason,
                    timestamp=timestamp,
                )
                excluded.append(exclusion)

                # Log the exclusion event (Req. 2.6)
                audit_event = AuditEvent(
                    timestamp=timestamp,
                    event_type="exclusion",
                    target=host.hostname,
                    module="SurfaceMapper",
                    detail={
                        "reason": reason,
                        "host_ip": host.ip,
                    },
                )
                logger.log(audit_event)

        return AttackSurfaceMap(
            subdomains=subdomains,
            active_hosts=active_hosts,
            technologies_by_host=technologies_by_host,
            excluded=excluded,
        )
