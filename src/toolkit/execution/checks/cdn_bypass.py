"""
CDN CloudFront bypass check — passive candidate selection and direct IP probing.

Requirement coverage: 6.1, 6.2

``select_candidates`` deduplicates a list of IP strings and returns at most
the first 5 unique candidates (Req. 6.1).

``check_cdn_bypass`` makes a direct HTTP request to each candidate IP with the
``Host`` header set to the target domain, using a 10-second connection timeout.
If the connection is refused or times out, the candidate is marked as
"unreachable" and the check continues with the remaining candidates (Req. 6.2).

The raw per-candidate results are returned as a ``CdnBypassResult`` and are
intended to be interpreted by the Analyzer (``analyze_cdn_bypass``) to decide
whether a bypass is confirmed.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import requests
import requests.exceptions

logger = logging.getLogger(__name__)

# Connection timeout used for direct-IP probes (Req. 6.2)
_PROBE_TIMEOUT_S: float = 10.0

# Maximum number of unique IP candidates to evaluate (Req. 6.1)
_MAX_CANDIDATES: int = 5


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CdnBypassResult:
    """
    Aggregated result of ``check_cdn_bypass`` (Req. 6.1, 6.2).

    Attributes
    ----------
    domain:
        The target domain whose origin IP was probed.
    candidates_tested:
        Ordered list of per-candidate result dicts.  Each dict has the keys:

        * ``ip``        — the candidate IP address (str)
        * ``status``    — HTTP status code (int) or ``None`` if unreachable
        * ``body_size`` — response body size in bytes (int) or ``None`` if unreachable
        * ``reachable`` — ``True`` if a response was received, ``False`` otherwise

    Helper properties
    -----------------
    reachable_candidates:
        Filtered view of ``candidates_tested`` where ``reachable is True``.
    unreachable_candidates:
        Filtered view of ``candidates_tested`` where ``reachable is False``.
    """

    domain: str
    candidates_tested: list[dict] = field(default_factory=list)

    @property
    def reachable_candidates(self) -> list[dict]:
        """Return only the candidates that were successfully reached."""
        return [c for c in self.candidates_tested if c["reachable"]]

    @property
    def unreachable_candidates(self) -> list[dict]:
        """Return only the candidates that could not be reached."""
        return [c for c in self.candidates_tested if not c["reachable"]]


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------


def select_candidates(ip_candidates: list[str]) -> list[str]:
    """
    Return a deduplicated list of IP candidates, limited to at most 5 (Req. 6.1).

    Uniqueness is determined by exact string equality. The original order is
    preserved: the first occurrence of each IP is kept.

    Parameters
    ----------
    ip_candidates:
        Arbitrary list of IP address strings, possibly containing duplicates.

    Returns
    -------
    list[str]
        Unique IPs from *ip_candidates*, at most ``_MAX_CANDIDATES`` entries.
    """
    seen: dict[str, None] = {}
    for ip in ip_candidates:
        if ip not in seen:
            seen[ip] = None
        if len(seen) == _MAX_CANDIDATES:
            break
    return list(seen.keys())


def check_cdn_bypass(
    domain: str,
    ip_candidates: list[str],
    session: object | None = None,
    timeout: float = _PROBE_TIMEOUT_S,
) -> CdnBypassResult:
    """
    Probe each candidate IP directly with the ``Host`` header set to *domain*.

    Selects at most 5 unique candidates from *ip_candidates* (Req. 6.1), then
    for each selected IP:

    - Makes an HTTP GET request to ``http://<ip>/`` with the ``Host`` header
      set to *domain* and a connection timeout of *timeout* seconds (Req. 6.2).
    - If the connection is refused (``ConnectionError``) or times out
      (``Timeout``), the candidate IP is added to ``unreachable`` and
      evaluation continues with the next candidate (Req. 6.2).
    - If the request succeeds (any HTTP status), the response status code and
      body size are recorded in ``responses[ip]``.

    The function does **not** interpret whether a bypass is confirmed; that
    decision belongs to the Analyzer (``analyze_cdn_bypass``).

    Parameters
    ----------
    domain:
        The target domain used as the ``Host`` header value.
    ip_candidates:
        List of IP addresses to probe.  Duplicates are removed automatically
        and the list is capped to 5 unique entries (Req. 6.1).
    session:
        Optional session or logger object; accepted for interface consistency
        but not used internally (logging is done via the module-level logger).
    timeout:
        Per-request timeout in seconds (default 10, per Req. 6.2).

    Returns
    -------
    CdnBypassResult
        Contains ``domain``, ``candidates`` (unique, ≤5), ``responses`` (dict
        mapping reachable IP → response data), and ``unreachable`` (IPs that
        could not be reached).
    """
    selected = select_candidates(ip_candidates)
    result = CdnBypassResult(domain=domain)

    for ip in selected:
        url = f"http://{ip}/"
        headers = {"Host": domain}

        try:
            resp = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                allow_redirects=False,
                verify=False,  # noqa: S501 — direct-IP probes may lack valid TLS
            )
            body_size = len(resp.content)
            logger.info(
                "CDN bypass probe: ip=%s domain=%s status=%d body_size=%d",
                ip,
                domain,
                resp.status_code,
                body_size,
            )
            result.candidates_tested.append({
                "ip": ip,
                "status": resp.status_code,
                "body_size": body_size,
                "reachable": True,
            })

        except requests.exceptions.Timeout:
            logger.warning(
                "CDN bypass probe: ip=%s domain=%s — connection timed out after %ss",
                ip,
                domain,
                timeout,
            )
            result.candidates_tested.append({
                "ip": ip,
                "status": None,
                "body_size": None,
                "reachable": False,
            })

        except requests.exceptions.ConnectionError as exc:
            logger.warning(
                "CDN bypass probe: ip=%s domain=%s — connection refused: %s",
                ip,
                domain,
                exc,
            )
            result.candidates_tested.append({
                "ip": ip,
                "status": None,
                "body_size": None,
                "reachable": False,
            })

        except requests.exceptions.RequestException as exc:
            logger.error(
                "CDN bypass probe: ip=%s domain=%s — request error: %s",
                ip,
                domain,
                exc,
            )
            result.candidates_tested.append({
                "ip": ip,
                "status": None,
                "body_size": None,
                "reachable": False,
            })

    return result
