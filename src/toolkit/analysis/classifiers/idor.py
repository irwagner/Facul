"""
IDOR (Insecure Direct Object Reference) classifier (Req. 8.2, 8.3, 8.5).

``analyze_idor`` interprets the list of ``IdorProbe`` results produced by the
IDOR scanner check and classifies each probe according to the following rules:

* **IDOR confirmed** (high severity, ``status="confirmed"``) — iff the probe
  returned HTTP 200 AND the response body contains a user-identifier field
  (``id``, ``userId``, or ``user_id``) whose value differs from the
  authenticated user's identifier (``auth_user_id``).

* **Access control ok** (``status="not_vulnerable"``) — when the probe
  returned a 4xx HTTP status code.

* **Inconclusive** (``status="inconclusive"``) — returned as a *single*
  finding when ALL probes returned non-2xx status codes (or had network
  errors), indicating the authentication token may be invalid.

Evidence always uses field names only — no PII values are exposed — by
delegating to :func:`~toolkit.analysis.classifiers.masking.mask_evidence_for_idor`.

Requirements: 8.2, 8.3, 8.5
"""

from __future__ import annotations

import json
import logging

from toolkit.analysis.classifiers.masking import mask_evidence_for_idor
from toolkit.execution.checks.idor import IdorProbe
from toolkit.models import Finding

__all__ = ["analyze_idor"]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# User-identifier field names (Req. 8.2)
# ---------------------------------------------------------------------------

_USER_ID_FIELDS: frozenset[str] = frozenset({"id", "userId", "user_id"})

# Finding ID counter (simple monotonic sequence within a process lifetime)
_finding_counter: int = 0


def _next_finding_id() -> str:
    global _finding_counter
    _finding_counter += 1
    return f"IDOR-{_finding_counter:03d}"


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def analyze_idor(
    probes: list[IdorProbe],
    auth_user_id: str,
) -> list[Finding]:
    """Classify IDOR probe results into a list of Findings.

    Parameters
    ----------
    probes:
        The list of :class:`~toolkit.execution.checks.idor.IdorProbe` results
        produced by ``check_idor``.
    auth_user_id:
        The identifier of the currently authenticated user.  Used to detect
        when a response body contains a *different* user's identifier.

    Returns
    -------
    list[Finding]
        A list of :class:`~toolkit.models.Finding` objects.  The list may
        contain:

        * Zero or more **confirmed** IDOR findings (one per vulnerable probe).
        * Zero or more **not_vulnerable** records (one per 4xx probe).
        * A single **inconclusive** finding when all probes are non-2xx.

    Algorithm
    ---------
    1. Separate probes into three buckets:
       - ``confirmed_probes``: status 200 with a different user-id field
       - ``access_control_probes``: 4xx status codes
       - all remaining probes are non-2xx (including errors/None)
    2. If every probe belongs to the third bucket → return inconclusive.
    3. Otherwise build one Finding per confirmed probe and one Finding per
       4xx probe.

    Requirements: 8.2, 8.3, 8.5
    """
    if not probes:
        # No probes at all → inconclusive (nothing to evaluate)
        return [_make_inconclusive_finding(probes)]

    findings: list[Finding] = []

    # Classify each probe
    has_2xx = False
    has_4xx = False
    confirmed_findings: list[Finding] = []
    access_control_findings: list[Finding] = []

    for probe in probes:
        status = probe.status_code

        if status is not None and 200 <= status < 300:
            has_2xx = True
            finding = _classify_2xx_probe(probe, auth_user_id)
            if finding is not None:
                confirmed_findings.append(finding)
            # A 2xx probe that does NOT trigger IDOR is not appended as not_vulnerable
            # (it's simply not a vulnerability indicator for that variation).

        elif status is not None and 400 <= status < 500:
            has_4xx = True
            access_control_findings.append(_make_access_control_finding(probe))

        # Non-2xx, non-4xx (5xx, None/errors): counted as non-2xx below

    # Req. 8.5: if ALL probes are non-2xx → inconclusive
    if not has_2xx and not has_4xx:
        return [_make_inconclusive_finding(probes)]

    findings.extend(confirmed_findings)
    findings.extend(access_control_findings)
    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_response_body(response_body: str | None) -> dict | None:
    """
    Attempt to parse *response_body* as JSON and return the top-level dict.
    Returns ``None`` if parsing fails or the body is empty/not a dict.
    """
    if not response_body:
        return None
    try:
        parsed = json.loads(response_body)
        if isinstance(parsed, dict):
            return parsed
    except (json.JSONDecodeError, ValueError):
        pass
    return None


def _extract_user_id_value(body: dict) -> tuple[str | None, str | None]:
    """
    Search for a user-identifier field in *body*.

    Returns ``(field_name, str_value)`` for the first match found, or
    ``(None, None)`` when no user-identifier field is present.

    Req. 8.2: checked fields are ``id``, ``userId``, ``user_id``.
    """
    for field_name in ("id", "userId", "user_id"):
        if field_name in body:
            value = body[field_name]
            return field_name, str(value)
    return None, None


def _classify_2xx_probe(
    probe: IdorProbe,
    auth_user_id: str,
) -> Finding | None:
    """
    Classify a probe that returned HTTP 200.

    Returns a **confirmed** IDOR Finding if the response body contains a
    user-identifier field whose value differs from *auth_user_id*; otherwise
    returns ``None``.

    Requirements: 8.2
    """
    body_dict = _parse_response_body(probe.response_body)
    if body_dict is None:
        # Cannot parse body — not a confirming condition
        return None

    field_name, id_value = _extract_user_id_value(body_dict)
    if field_name is None or id_value is None:
        # No user-id field present — not a confirming condition
        return None

    if id_value == str(auth_user_id):
        # Same user — not an IDOR
        return None

    # IDOR confirmed: status 200 + user-id field with different value
    evidence = mask_evidence_for_idor(body_dict, auth_user_id)

    return Finding(
        id=_next_finding_id(),
        title="IDOR — Insecure Direct Object Reference",
        summary=(
            f"Authenticated request to {probe.endpoint!r} with identifier variation "
            f"{probe.variation_value!r} returned HTTP 200 and exposed data belonging "
            "to a different user."
        ),
        severity="high",
        confidence="high",
        status="confirmed",
        affected_endpoint=probe.endpoint,
        evidence=evidence,
        impact=(
            "Unauthorized access to other users' data. An attacker can enumerate "
            "user resources by varying the identifier in the request URL."
        ),
        remediation=(
            "Validate that the requested resource belongs to the authenticated user "
            "before returning data. Example: assert resource.owner_id == current_user.id"
        ),
        next_steps=[
            "Reproduce the finding manually to confirm the data exposure.",
            "Implement server-side ownership check on the affected endpoint.",
            "Review all endpoints that accept user-controlled identifiers.",
        ],
        references=[
            "CWE-639: Authorization Bypass Through User-Controlled Key",
            "OWASP API Security Top 10: API1:2023 Broken Object Level Authorization",
        ],
    )


def _make_access_control_finding(probe: IdorProbe) -> Finding:
    """
    Build a *not_vulnerable* Finding for a probe that returned a 4xx status.

    Requirements: 8.3
    """
    return Finding(
        id=_next_finding_id(),
        title="IDOR Check — Access Control OK",
        summary=(
            f"Request to {probe.endpoint!r} with variation {probe.variation_value!r} "
            f"returned HTTP {probe.status_code}, indicating access control is working."
        ),
        severity="low",
        confidence="high",
        status="not_vulnerable",
        affected_endpoint=probe.endpoint,
        evidence=f"HTTP {probe.status_code} response for identifier variation {probe.variation_value!r}.",
        impact="No impact — access was denied.",
        remediation="No action required for this variation.",
        next_steps=[
            "Continue testing other endpoint variations.",
        ],
        references=[],
    )


def _make_inconclusive_finding(probes: list[IdorProbe]) -> Finding:
    """
    Build an *inconclusive* Finding when all probes are non-2xx.

    Requirements: 8.5
    """
    endpoint = probes[0].endpoint if probes else "unknown"
    status_codes = [str(p.status_code) for p in probes if p.status_code is not None]
    status_summary = ", ".join(status_codes) if status_codes else "none (network errors)"

    return Finding(
        id=_next_finding_id(),
        title="IDOR Check — Inconclusive",
        summary=(
            "All IDOR probe requests returned non-2xx status codes. "
            "The authentication token may be invalid or the endpoint may be unavailable."
        ),
        severity="low",
        confidence="low",
        status="inconclusive",
        affected_endpoint=endpoint,
        evidence=f"Observed status codes: {status_summary}.",
        impact="Unable to determine whether an IDOR vulnerability exists.",
        remediation=(
            "Verify that the authentication token is valid and that the endpoint "
            "is accessible before re-running the IDOR check."
        ),
        next_steps=[
            "Confirm that the auth token is valid by testing an authenticated request manually.",
            "Re-run the IDOR check with a valid token.",
        ],
        references=[
            "CWE-639: Authorization Bypass Through User-Controlled Key",
        ],
    )
