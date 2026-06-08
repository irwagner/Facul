"""
HTTP security headers classifier (Req. 7.2, 7.3, 7.4, 7.5).

``analyze_headers`` inspects a ``HeadersResult`` — the structured output of
the headers Scanner check — and produces a list of ``Finding`` objects, one
per absent or misconfigured security header.

Rules per header
----------------
* ``Content-Security-Policy``   — present AND ≥1 directive; additionally warns
                                  (medium severity) when ``unsafe-inline`` or
                                  ``unsafe-eval`` appears.
* ``Strict-Transport-Security`` — present AND contains ``max-age`` ≥ 31 536 000.
* ``X-Frame-Options``           — value is ``DENY`` or ``SAMEORIGIN``
                                  (case-insensitive).
* ``X-Content-Type-Options``    — value is ``nosniff`` (case-insensitive).
* ``Referrer-Policy``           — present with a non-empty, non-whitespace
                                  value.
* ``Permissions-Policy``        — present AND ≥1 directive (at least one
                                  non-whitespace token separated by ``=``).

Every absent or misconfigured header generates a ``Finding`` with:
* ``severity``: ``"medium"``
* ``confidence``: ``"high"``
* ``status``: ``"confirmed"``

Requirements: 7.2, 7.3, 7.4, 7.5
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from toolkit.models import Finding

__all__ = [
    "HeadersResult",
    "analyze_headers",
]


# ---------------------------------------------------------------------------
# Input model
# ---------------------------------------------------------------------------

@dataclass
class HeadersResult:
    """Structured result returned by the Scanner's security-headers check.

    Attributes
    ----------
    url:
        The URL that was requested (used as ``affected_endpoint`` in findings).
    headers:
        Dict of response header names (lowercased keys) to their raw string
        values.  The Scanner normalises keys to lowercase for consistent
        look-up.
    status:
        Either ``"ok"`` when the request succeeded or ``"check_failed"`` when
        the GET request could not be completed (Req. 7.1).
    """

    url: str
    headers: dict[str, str] = field(default_factory=dict)
    status: str = "ok"  # "ok" | "check_failed"


# ---------------------------------------------------------------------------
# Internal constants
# ---------------------------------------------------------------------------

# Canonical (lowercase) header names required by Req. 7.2
_REQUIRED_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)

# Minimum HSTS max-age value in seconds (1 year – Req. 7.2)
_MIN_HSTS_MAX_AGE = 31_536_000

# CSP unsafe directives that trigger a medium-severity warning (Req. 7.5)
_CSP_UNSAFE_PATTERNS = ("unsafe-inline", "unsafe-eval")

# Nginx remediation snippets per header (Req. 7.6 / 11.3)
_NGINX_DIRECTIVES: dict[str, str] = {
    "content-security-policy": (
        "add_header Content-Security-Policy "
        "\"default-src 'self'; script-src 'self'; style-src 'self';\" always;"
    ),
    "strict-transport-security": (
        "add_header Strict-Transport-Security "
        "\"max-age=31536000; includeSubDomains; preload\" always;"
    ),
    "x-frame-options": (
        "add_header X-Frame-Options \"DENY\" always;"
    ),
    "x-content-type-options": (
        "add_header X-Content-Type-Options \"nosniff\" always;"
    ),
    "referrer-policy": (
        "add_header Referrer-Policy \"no-referrer-when-downgrade\" always;"
    ),
    "permissions-policy": (
        "add_header Permissions-Policy "
        "\"camera=(), microphone=(), geolocation=()\" always;"
    ),
}

# Security justifications per header
_JUSTIFICATIONS: dict[str, str] = {
    "content-security-policy": (
        "Content-Security-Policy restricts the sources from which resources "
        "can be loaded, mitigating XSS and data injection attacks."
    ),
    "strict-transport-security": (
        "Strict-Transport-Security enforces HTTPS usage, preventing "
        "protocol-downgrade and man-in-the-middle attacks."
    ),
    "x-frame-options": (
        "X-Frame-Options prevents the page from being embedded in an iframe, "
        "protecting against clickjacking attacks."
    ),
    "x-content-type-options": (
        "X-Content-Type-Options prevents MIME-type sniffing, reducing the "
        "risk of drive-by download attacks."
    ),
    "referrer-policy": (
        "Referrer-Policy controls how much referrer information is included "
        "with requests, protecting sensitive URL data."
    ),
    "permissions-policy": (
        "Permissions-Policy controls access to browser features (camera, "
        "microphone, geolocation), reducing the attack surface."
    ),
}

# Human-readable display names per header
_DISPLAY_NAMES: dict[str, str] = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

# CWE / OWASP references per header
_REFERENCES: dict[str, list[str]] = {
    "content-security-policy": [
        "CWE-693",
        "OWASP A05:2021 - Security Misconfiguration",
    ],
    "strict-transport-security": [
        "CWE-319",
        "OWASP A02:2021 - Cryptographic Failures",
    ],
    "x-frame-options": [
        "CWE-1021",
        "OWASP A05:2021 - Security Misconfiguration",
    ],
    "x-content-type-options": [
        "CWE-693",
        "OWASP A05:2021 - Security Misconfiguration",
    ],
    "referrer-policy": [
        "CWE-200",
        "OWASP A05:2021 - Security Misconfiguration",
    ],
    "permissions-policy": [
        "CWE-693",
        "OWASP A05:2021 - Security Misconfiguration",
    ],
}


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _validate_csp(value: str) -> list[str]:
    """Return a list of issue descriptions for a CSP header value.

    An empty list means the header is fully valid.

    Rules
    -----
    * Must contain at least one directive (Req. 7.2).
    * Must not contain ``unsafe-inline`` or ``unsafe-eval`` (Req. 7.5).
    """
    issues: list[str] = []
    # Check for at least one directive: a CSP directive looks like
    # "keyword" or "keyword value" separated by ";".  A minimal valid
    # value is any non-empty, non-whitespace string with at least one
    # non-semicolon token.
    directives = [d.strip() for d in value.split(";") if d.strip()]
    if not directives:
        issues.append("Content-Security-Policy has no directives")

    # Check for unsafe directives (Req. 7.5)
    value_lower = value.lower()
    for unsafe in _CSP_UNSAFE_PATTERNS:
        if unsafe in value_lower:
            issues.append(
                f"Content-Security-Policy contains '{unsafe}', "
                "which weakens XSS protection"
            )

    return issues


def _validate_hsts(value: str) -> list[str]:
    """Return a list of issue descriptions for a HSTS header value.

    Rules
    -----
    * ``max-age`` must be present and ≥ 31 536 000 (Req. 7.2, 7.4).
    """
    issues: list[str] = []
    match = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
    if not match:
        issues.append(
            "Strict-Transport-Security is missing the 'max-age' directive"
        )
    else:
        max_age = int(match.group(1))
        if max_age < _MIN_HSTS_MAX_AGE:
            issues.append(
                f"Strict-Transport-Security max-age is {max_age}, "
                f"which is below the required minimum of {_MIN_HSTS_MAX_AGE}"
            )
    return issues


def _validate_x_frame_options(value: str) -> list[str]:
    """Return issues for X-Frame-Options.

    Valid values: ``DENY`` or ``SAMEORIGIN`` (case-insensitive, Req. 7.2).
    """
    normalised = value.strip().upper()
    if normalised not in ("DENY", "SAMEORIGIN"):
        return [
            f"X-Frame-Options value '{value}' is invalid; "
            "expected 'DENY' or 'SAMEORIGIN'"
        ]
    return []


def _validate_x_content_type_options(value: str) -> list[str]:
    """Return issues for X-Content-Type-Options.

    Valid value: ``nosniff`` (case-insensitive, Req. 7.2).
    """
    if value.strip().lower() != "nosniff":
        return [
            f"X-Content-Type-Options value '{value}' is invalid; "
            "expected 'nosniff'"
        ]
    return []


def _validate_referrer_policy(value: str) -> list[str]:
    """Return issues for Referrer-Policy.

    Valid if non-empty and non-whitespace (Req. 7.2).
    """
    if not value.strip():
        return ["Referrer-Policy value is empty"]
    return []


def _validate_permissions_policy(value: str) -> list[str]:
    """Return issues for Permissions-Policy.

    Valid if at least one directive is present.  A directive is a token
    of the form ``feature=value`` or ``feature=()``.
    """
    # A directive contains at least one non-whitespace character followed
    # by "=" — a common enough pattern for the Permissions-Policy syntax.
    directives = [d.strip() for d in value.split(",") if d.strip()]
    if not directives:
        return ["Permissions-Policy has no directives"]
    # At least one token must look like a directive (contains "=")
    has_valid_directive = any("=" in d for d in directives)
    if not has_valid_directive:
        return [
            "Permissions-Policy appears to have no valid directives "
            "(expected 'feature=value' pairs)"
        ]
    return []


# ---------------------------------------------------------------------------
# Finding factory
# ---------------------------------------------------------------------------

_finding_counter: dict[str, int] = {}


def _make_finding(
    header_key: str,
    issue: str,
    url: str,
    *,
    suffix: str = "",
) -> Finding:
    """Create a medium-severity Finding for a header issue."""
    # Stable counter per header key to generate unique IDs within a call
    count = _finding_counter.get(header_key, 0) + 1
    _finding_counter[header_key] = count

    display = _DISPLAY_NAMES.get(header_key, header_key)
    finding_id = f"HDR-{display.upper().replace('-', '')}-{count:03d}"

    if suffix:
        title = f"Misconfigured {display}: {suffix}"
    else:
        title = f"Missing or misconfigured {display} header"

    remediation = (
        f"{_NGINX_DIRECTIVES.get(header_key, 'Configure the header in Nginx.')}\n"
        f"Security justification: {_JUSTIFICATIONS.get(header_key, '')}"
    )

    return Finding(
        id=finding_id,
        title=title,
        summary=issue,
        severity="medium",
        confidence="high",
        status="confirmed",
        affected_endpoint=url,
        evidence=issue,
        impact=_JUSTIFICATIONS.get(header_key, "Missing security header."),
        remediation=remediation,
        next_steps=[
            f"Add the {display} header to the Nginx server configuration.",
            "Re-run the security headers check after applying the fix.",
        ],
        references=list(_REFERENCES.get(header_key, [])),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_headers(result: HeadersResult) -> list[Finding]:
    """Classify HTTP security headers and return findings for issues found.

    For each of the six mandatory security headers, this function checks
    presence and validity according to the rules defined in Req. 7.2–7.5.
    A ``Finding`` with medium severity is emitted for every absent or
    misconfigured header.

    Parameters
    ----------
    result:
        The ``HeadersResult`` produced by the Scanner's
        ``check_security_headers`` function.  When ``result.status`` is
        ``"check_failed"`` the function returns an empty list (the Scanner
        already recorded the failure).

    Returns
    -------
    list[Finding]
        Zero or more findings, one per absent or misconfigured header.
    """
    # Reset per-call counter to ensure deterministic IDs within a single call
    _finding_counter.clear()

    if result.status == "check_failed":
        return []

    # Normalise header names to lowercase for consistent look-up
    normalised = {k.lower(): v for k, v in result.headers.items()}

    findings: list[Finding] = []

    for header_key in _REQUIRED_HEADERS:
        if header_key not in normalised:
            # Header is absent — Req. 7.3
            issue = f"Header '{_DISPLAY_NAMES.get(header_key, header_key)}' is absent"
            findings.append(_make_finding(header_key, issue, result.url))
            continue

        value = normalised[header_key]

        # Per-header validation
        if header_key == "content-security-policy":
            for issue in _validate_csp(value):
                findings.append(
                    _make_finding(header_key, issue, result.url, suffix="unsafe directive")
                    if any(u in issue for u in _CSP_UNSAFE_PATTERNS)
                    else _make_finding(header_key, issue, result.url)
                )

        elif header_key == "strict-transport-security":
            for issue in _validate_hsts(value):
                findings.append(_make_finding(header_key, issue, result.url))

        elif header_key == "x-frame-options":
            for issue in _validate_x_frame_options(value):
                findings.append(_make_finding(header_key, issue, result.url))

        elif header_key == "x-content-type-options":
            for issue in _validate_x_content_type_options(value):
                findings.append(_make_finding(header_key, issue, result.url))

        elif header_key == "referrer-policy":
            for issue in _validate_referrer_policy(value):
                findings.append(_make_finding(header_key, issue, result.url))

        elif header_key == "permissions-policy":
            for issue in _validate_permissions_policy(value):
                findings.append(_make_finding(header_key, issue, result.url))

    return findings
