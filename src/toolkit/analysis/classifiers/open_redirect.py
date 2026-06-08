"""
Open-redirect classifier (decision-only, no side effects).

A redirect attempt is considered confirmed when:
    * status is 3xx (or 200 for client-side meta-refresh fallback),
    * the ``Location`` header (or final URL) starts with the attacker
      canary host with **scheme + host** matching, ignoring leading slashes
      and protocol-relative quirks.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field

from toolkit.execution.checks.open_redirect import (
    CANARY_HOST,
    OpenRedirectResult,
    RedirectAttempt,
)


@dataclass(frozen=True)
class OpenRedirectFinding:
    target_url: str
    parameter: str
    payload: str
    confirmed_via: str  # "location_header" | "final_url"
    severity: str = "high"
    confidence: str = "high"


def _resolves_to_canary(value: str | None) -> bool:
    if not value:
        return False
    v = value.strip()
    # Common bypass tricks — accept ``//host`` and ``\\host``.
    if v.startswith("//") or v.startswith("\\\\"):
        v = "https:" + v.replace("\\\\", "//", 1)
    try:
        parsed = urllib.parse.urlparse(v)
    except Exception:  # noqa: BLE001
        return False
    host = (parsed.hostname or "").lower()
    return host == CANARY_HOST or host.endswith("." + CANARY_HOST)


def classify_attempt(attempt: RedirectAttempt) -> OpenRedirectFinding | None:
    if attempt.error:
        return None
    if _resolves_to_canary(attempt.location):
        return OpenRedirectFinding(
            target_url="",
            parameter=attempt.parameter,
            payload=attempt.payload,
            confirmed_via="location_header",
        )
    if _resolves_to_canary(attempt.final_url):
        return OpenRedirectFinding(
            target_url="",
            parameter=attempt.parameter,
            payload=attempt.payload,
            confirmed_via="final_url",
        )
    return None


@dataclass(frozen=True)
class OpenRedirectClassification:
    target_url: str
    findings: list[OpenRedirectFinding] = field(default_factory=list)
    is_vulnerable: bool = False


def analyze_open_redirect(result: OpenRedirectResult) -> OpenRedirectClassification:
    findings: list[OpenRedirectFinding] = []
    for attempt in result.attempts:
        f = classify_attempt(attempt)
        if f is not None:
            findings.append(
                OpenRedirectFinding(
                    target_url=result.target_url,
                    parameter=f.parameter,
                    payload=f.payload,
                    confirmed_via=f.confirmed_via,
                )
            )
    return OpenRedirectClassification(
        target_url=result.target_url,
        findings=findings,
        is_vulnerable=bool(findings),
    )
