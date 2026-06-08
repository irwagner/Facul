"""
CDN bypass classifier (Req. 6.3, 6.5).

``analyze_cdn_bypass`` interprets a ``CdnBypassResult`` produced by
``check_cdn_bypass`` and returns a list of standardised ``Finding`` objects.

Decision logic
--------------
* **Confirmed (high severity)** — for each reachable candidate, iff:
    - The HTTP status code from the direct-IP probe equals the CDN status code,
      AND
    - The response body size via direct IP is within 10% of the CDN body size.
  The 10% tolerance is calculated as: ``|direct_size - cdn_size| / cdn_size <= 0.10``
  (or, when cdn_size == 0 and direct_size == 0, they are considered equivalent).
  One Finding is emitted per confirmed bypass candidate.

* **Not vulnerable (low confidence)** — when no reachable candidates exist
  (either the result has no candidates at all, or all candidates were
  unreachable).  Low confidence reflects that the check was limited to
  passive techniques (Req. 6.5).

Requirements: 6.3, 6.5
"""

from __future__ import annotations

import logging

from toolkit.execution.checks.cdn_bypass import CdnBypassResult
from toolkit.models import Finding

__all__ = ["analyze_cdn_bypass"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_FINDING_ID_PREFIX = "CDNBYPASS"
_BODY_SIZE_TOLERANCE = 0.10  # 10% tolerance (Req. 6.3)

# Finding ID counter (monotonic within a process lifetime)
_finding_counter: int = 0


def _next_finding_id() -> str:
    global _finding_counter
    _finding_counter += 1
    return f"{_FINDING_ID_PREFIX}-{_finding_counter:03d}"


# ---------------------------------------------------------------------------
# Equivalence check
# ---------------------------------------------------------------------------

def _body_sizes_equivalent(cdn_size: int, direct_size: int) -> bool:
    """Return True iff *direct_size* is within 10% of *cdn_size* (Req. 6.3).

    When both sizes are zero, they are considered equivalent (empty responses
    on both sides indicate the same content).  When *cdn_size* is zero but
    *direct_size* is not, they are NOT equivalent (CDN returns empty but the
    origin does not — different responses).

    Parameters
    ----------
    cdn_size:
        Response body size in bytes obtained via the CDN.
    direct_size:
        Response body size in bytes obtained via the direct IP probe.
    """
    if cdn_size == 0 and direct_size == 0:
        return True
    if cdn_size == 0:
        # Avoid division by zero; CDN returned 0 bytes but IP didn't — not equivalent
        return False
    return abs(direct_size - cdn_size) / cdn_size <= _BODY_SIZE_TOLERANCE


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def analyze_cdn_bypass(
    result: CdnBypassResult,
    cdn_response_data: dict,
) -> list[Finding]:
    """Classify a ``CdnBypassResult`` into a list of standardised ``Finding`` objects.

    Parameters
    ----------
    result:
        The ``CdnBypassResult`` returned by ``check_cdn_bypass``.  It contains
        the domain name and the list of IP candidates that were probed.
    cdn_response_data:
        A dict with the CDN baseline response data.  Expected keys:

        * ``"status_code"`` (``int``) — HTTP status code from the CDN response.
        * ``"body_size"`` (``int``) — response body size in bytes from the CDN.

        Any additional keys are silently ignored.

    Returns
    -------
    list[Finding]
        A list containing:

        * One **confirmed / high severity** Finding per reachable candidate that
          satisfies the bypass equivalence condition (same status code AND body
          size within 10%).
        * A single **not_vulnerable / low confidence** Finding when there are
          no reachable candidates (empty candidates list, or all candidates
          unreachable).

    Algorithm
    ---------
    1. Extract CDN baseline status and body size from *cdn_response_data*.
    2. Collect reachable candidates from *result*.
    3. If no reachable candidates → return ``[not_vulnerable_finding]``.
    4. For each reachable candidate:
       a. Compare status codes.
       b. Compare body sizes within 10% tolerance.
       c. If both conditions met → append a confirmed Finding.
    5. If no candidate triggered a confirmed finding, still return an empty
       list (not vulnerable via the candidates that were tested).

    Requirements: 6.3, 6.5
    """
    cdn_status: int | None = cdn_response_data.get("status_code")
    cdn_body_size: int | None = cdn_response_data.get("body_size")

    reachable = result.reachable_candidates

    # No reachable candidates → not_vulnerable with low confidence (Req. 6.5)
    if not reachable:
        logger.info(
            "CDN bypass analysis: no reachable candidates for domain=%s — not_vulnerable",
            result.domain,
        )
        return [_not_vulnerable_finding(result.domain)]

    findings: list[Finding] = []

    for candidate in reachable:
        ip: str = candidate["ip"]
        direct_status: int | None = candidate.get("status")
        direct_body_size: int | None = candidate.get("body_size")

        # Skip candidates with missing data (should not happen for reachable ones)
        if direct_status is None or direct_body_size is None:
            logger.warning(
                "CDN bypass: reachable candidate %s has missing status/body_size; skipping",
                ip,
            )
            continue

        # Skip if CDN baseline data is missing
        if cdn_status is None or cdn_body_size is None:
            logger.warning(
                "CDN bypass: cdn_response_data is missing status_code/body_size; skipping candidate %s",
                ip,
            )
            continue

        status_match = direct_status == cdn_status
        sizes_equiv = _body_sizes_equivalent(cdn_body_size, direct_body_size)

        if status_match and sizes_equiv:
            logger.info(
                "CDN bypass CONFIRMED: ip=%s domain=%s direct_status=%d cdn_status=%d "
                "direct_body_size=%d cdn_body_size=%d",
                ip,
                result.domain,
                direct_status,
                cdn_status,
                direct_body_size,
                cdn_body_size,
            )
            findings.append(
                _confirmed_finding(
                    domain=result.domain,
                    ip=ip,
                    cdn_status=cdn_status,
                    cdn_body_size=cdn_body_size,
                    direct_status=direct_status,
                    direct_body_size=direct_body_size,
                )
            )
        else:
            logger.debug(
                "CDN bypass: ip=%s domain=%s — not equivalent (status_match=%s, sizes_equiv=%s)",
                ip,
                result.domain,
                status_match,
                sizes_equiv,
            )

    return findings


# ---------------------------------------------------------------------------
# Finding factories
# ---------------------------------------------------------------------------

def _confirmed_finding(
    domain: str,
    ip: str,
    cdn_status: int,
    cdn_body_size: int,
    direct_status: int,
    direct_body_size: int,
) -> Finding:
    """Build a confirmed high-severity Finding for a CDN bypass candidate."""
    size_diff_pct = (
        abs(direct_body_size - cdn_body_size) / cdn_body_size * 100
        if cdn_body_size > 0
        else 0.0
    )
    evidence = (
        f"Direct IP probe to {ip} (Host: {domain}) returned equivalent response: "
        f"status {direct_status} (CDN: {cdn_status}), "
        f"body size {direct_body_size} bytes (CDN: {cdn_body_size} bytes, "
        f"diff: {size_diff_pct:.1f}%). "
        f"Discovery method: passive IP candidate (direct HTTP with Host header)."
    )

    return Finding(
        id=_next_finding_id(),
        title="CDN CloudFront Bypass — Origin IP Exposed",
        summary=(
            f"The real origin server IP {ip!r} for domain {domain!r} was reachable "
            "directly, bypassing CloudFront CDN protection. The direct response is "
            "equivalent to the CDN response (same HTTP status and body size within 10%)."
        ),
        severity="high",
        confidence="high",
        status="confirmed",
        affected_endpoint=f"http://{ip}/ (Host: {domain})",
        evidence=evidence,
        impact=(
            "An attacker who discovers the origin IP can send requests directly to "
            "the origin server, bypassing CloudFront WAF, DDoS protection, rate "
            "limiting, and geo-blocking rules. This exposes the server to direct "
            "attacks and potential IP-based targeting."
        ),
        remediation=(
            "Configure the Security Group or firewall to accept HTTP/HTTPS traffic "
            "only from CloudFront IP ranges. Steps:\n"
            "1. Obtain the current CloudFront IP range list:\n"
            "   curl https://ip-ranges.amazonaws.com/ip-ranges.json | "
            "jq '[.prefixes[] | select(.service==\"CLOUDFRONT\") | .ip_prefix]'\n"
            "2. Update the EC2 Security Group inbound rules to allow ports 80 and 443 "
            "only from those CIDR ranges.\n"
            "3. Deny all other inbound traffic on ports 80/443.\n"
            "4. Verify by attempting a direct connection to the origin IP — it should "
            "be refused or return a connection timeout."
        ),
        next_steps=[
            f"Restrict Security Group/firewall rules on the origin server to allow "
            "HTTP/HTTPS only from CloudFront CIDR ranges.",
            "Verify that no other origin IPs are discoverable via passive techniques "
            "(SPF records, MX records, certificate transparency logs, historical DNS).",
            "Enable CloudFront origin access controls and validate that all traffic "
            "reaches the origin through CloudFront.",
            "Re-run this check after applying firewall changes to confirm the bypass "
            "is no longer possible.",
        ],
        references=[
            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            "OWASP A05:2021 - Security Misconfiguration",
            "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html",
        ],
    )


def _not_vulnerable_finding(domain: str) -> Finding:
    """Build a not-vulnerable Finding with low confidence when no candidates exist."""
    return Finding(
        id=_next_finding_id(),
        title="CDN CloudFront Bypass — No Origin IP Identified",
        summary=(
            f"No reachable origin IP candidates were identified for domain {domain!r} "
            "via passive techniques (historical DNS, certificate transparency, SPF/MX). "
            "The CDN bypass check was limited to passive discovery."
        ),
        severity="low",
        confidence="low",
        status="not_vulnerable",
        affected_endpoint=domain,
        evidence=(
            "No origin IP candidates were found via passive reconnaissance techniques, "
            "or all identified candidates were unreachable (connection refused or timed out). "
            "Low confidence reflects the inherent limitation of passive-only discovery."
        ),
        impact=(
            "Unable to confirm whether the origin server IP is discoverable or directly "
            "reachable. The low confidence result does not guarantee that no bypass exists."
        ),
        remediation=(
            "Although no bypass was confirmed, apply defence-in-depth measures:\n"
            "1. Ensure the origin Security Group/firewall only accepts HTTP/HTTPS "
            "traffic from CloudFront IP ranges.\n"
            "2. Periodically audit DNS records, SPF/MX entries, and certificate "
            "transparency logs for inadvertent origin IP leaks.\n"
            "3. Use a WAF in front of CloudFront for additional protection."
        ),
        next_steps=[
            "Manually verify that historical DNS records and certificate transparency "
            "logs do not reveal the origin IP.",
            "Check SPF and MX records for any IP addresses that could be the origin server.",
            "Consider using a service like Shodan or Censys to search for exposed "
            "origin IPs (with appropriate authorization).",
        ],
        references=[
            "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            "OWASP A05:2021 - Security Misconfiguration",
        ],
    )
