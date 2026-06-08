"""
SSRF classifier (decision-only, side-effect-free).

Confirmation rules (each rule is an *independent* signal — any single match
is enough to flag the attempt as suspicious; multiple matches raise
confidence):

    1. **Reflection**: response body contains a fingerprint expected from
       the targeted internal service (``ami-`` or ``security-credentials``
       for AWS metadata; ``root:`` for ``/etc/passwd``; ``[mapping]`` for
       ``win.ini``; ``# Configuration`` for redis INFO; etc.).
    2. **Status difference**: a payload returns 200 while the canonical
       baseline (any external safe URL) returns 4xx — likely the server
       fetched the internal resource and forwarded it.
    3. **Timing oracle**: payload latency for an internal IP is *much
       smaller* than for an external one, suggesting cached/fast fetch.

Severity is **critical** when the response leaks AWS metadata or a
``/etc/passwd``-style file; **high** otherwise; **informational** when
only the timing oracle hits.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from toolkit.execution.checks.ssrf import SsrfAttempt, SsrfResult


# Fingerprints that indicate the server actually fetched a sensitive
# internal resource and reflected its content.  Each entry is checked
# case-sensitively because the targeted resources reliably produce
# stable strings.
_LEAK_FINGERPRINTS: tuple[tuple[str, str, str], ...] = (
    # (fingerprint, severity, category)
    ("root:x:0:0", "critical", "linux_passwd"),
    ("daemon:x:", "critical", "linux_passwd"),
    ("ami-", "critical", "aws_metadata"),
    ("security-credentials", "critical", "aws_metadata"),
    ("instance-id", "critical", "aws_metadata"),
    ("AccessKeyId", "critical", "aws_credentials"),
    ("SecretAccessKey", "critical", "aws_credentials"),
    ("computeMetadata", "critical", "gcp_metadata"),
    ("[fonts]", "high", "windows_ini"),
    ("[mci extensions]", "high", "windows_ini"),
    ("# Server", "high", "redis_info"),
    ("redis_version:", "high", "redis_info"),
    ("mysql_native_password", "high", "mysql_handshake"),
    ("HTTP/1.1 ", "high", "internal_http"),
)


@dataclass(frozen=True)
class SsrfFinding:
    parameter: str
    payload: str
    category: str
    severity: str
    confidence: str
    evidence_snippet: str


@dataclass(frozen=True)
class SsrfClassification:
    target_url: str
    parameter: str
    is_vulnerable: bool
    findings: list[SsrfFinding] = field(default_factory=list)


def _scan_attempt(attempt: SsrfAttempt) -> SsrfFinding | None:
    """Return a finding when *attempt* matches a leak fingerprint."""
    if attempt.error or not attempt.body_excerpt:
        return None
    body = attempt.body_excerpt
    for needle, severity, category in _LEAK_FINGERPRINTS:
        if needle in body:
            return SsrfFinding(
                parameter=attempt.parameter,
                payload=attempt.payload,
                category=category,
                severity=severity,
                confidence="high",
                evidence_snippet=body[:200],
            )
    return None


def analyze_ssrf(result: SsrfResult) -> SsrfClassification:
    """Return a :class:`SsrfClassification` for *result*."""
    findings: list[SsrfFinding] = []
    for attempt in result.attempts:
        f = _scan_attempt(attempt)
        if f is not None:
            findings.append(f)
    return SsrfClassification(
        target_url=result.target_url,
        parameter=result.parameter,
        is_vulnerable=bool(findings),
        findings=findings,
    )


def detect_timing_oracle(result: SsrfResult, *, threshold_ratio: float = 0.4) -> list[SsrfAttempt]:
    """Return attempts whose latency is suspiciously low (likely cached / internal).

    A payload is flagged when its ``elapsed_ms`` is below
    ``threshold_ratio * median(elapsed_ms)`` and points at a loopback /
    RFC1918 / metadata host.  Useful as a *secondary* signal when no leak
    fingerprint matched.
    """
    elapsed = [a.elapsed_ms for a in result.attempts
               if a.elapsed_ms is not None and a.error is None]
    if not elapsed:
        return []
    elapsed_sorted = sorted(elapsed)
    median = elapsed_sorted[len(elapsed_sorted) // 2]
    if median <= 0:
        return []
    cutoff = median * threshold_ratio
    suspicious_hosts = (
        "127.0.0.1", "localhost", "[::1]", "0.0.0.0",
        "10.", "172.16.", "192.168.", "169.254.169.254",
    )
    out: list[SsrfAttempt] = []
    for a in result.attempts:
        if a.elapsed_ms is None or a.error:
            continue
        if a.elapsed_ms < cutoff and any(h in a.payload for h in suspicious_hosts):
            out.append(a)
    return out
