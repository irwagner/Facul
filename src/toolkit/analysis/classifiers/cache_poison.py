"""
Cache-poisoning classifier.

Decision rules:

    * **Reflection**: the injected header value appears in the response
      body.  Severity **high** if the value is also present in a
      response header used as cache key (Vary / X-Cache-Key /
      X-Forwarded-Host); severity **medium** otherwise.
    * **Status diff**: probe status differs from baseline.  Severity
      **medium** when the diff is 4xx → 2xx or vice-versa; informational
      otherwise.
    * **Size diff**: body size differs by more than ``size_threshold``
      bytes.  Informational on its own; medium when combined with
      reflection.

Findings include the exact header pair used so that the operator can
reproduce the request via ``curl`` or Burp Repeater.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from toolkit.execution.checks.cache_poison import CachePoisonResult, CacheProbe


_CACHE_KEY_HEADERS = (
    "vary", "x-cache-key", "x-cache", "x-forwarded-host",
    "x-amz-cf-id", "x-served-by",
)


@dataclass(frozen=True)
class CachePoisonFinding:
    target_url: str
    header: str
    value: str
    severity: str
    confidence: str
    reason: str


@dataclass(frozen=True)
class CachePoisonClassification:
    target_url: str
    is_vulnerable: bool
    findings: list[CachePoisonFinding] = field(default_factory=list)


def _classify_probe(
    target_url: str,
    probe: CacheProbe,
    baseline_status: int | None,
    baseline_size: int,
    *,
    size_threshold: int = 50,
) -> CachePoisonFinding | None:
    if probe.error:
        return None

    reasons: list[str] = []
    severity = "informational"
    confidence = "low"

    # 1. Reflection check
    reflected = probe.value and (probe.value in (probe.body_excerpt or ""))
    # 2. New header echoes the injected value
    header_echo = False
    for k, v in (probe.new_headers or {}).items():
        if k.lower() in _CACHE_KEY_HEADERS and probe.value.lower() in str(v or "").lower():
            header_echo = True
            break

    if reflected:
        reasons.append("injected value reflected in body")
        severity = "high" if header_echo else "medium"
        confidence = "high" if header_echo else "medium"
    if header_echo and not reflected:
        reasons.append("injected value echoed in cache-key header")
        severity = "medium"
        confidence = "medium"

    # 3. Status diff
    if baseline_status is not None and probe.status is not None and probe.status != baseline_status:
        reasons.append(f"status diff (baseline={baseline_status}, probe={probe.status})")
        if (baseline_status // 100) != (probe.status // 100):
            severity = "medium" if severity == "informational" else severity
            confidence = "medium" if confidence == "low" else confidence

    # 4. Size diff
    if abs(probe.body_size - baseline_size) > size_threshold:
        reasons.append(f"body size diff ({probe.body_size - baseline_size:+d} bytes)")

    if not reasons:
        return None
    return CachePoisonFinding(
        target_url=target_url,
        header=probe.header,
        value=probe.value,
        severity=severity,
        confidence=confidence,
        reason="; ".join(reasons),
    )


def analyze_cache_poison(result: CachePoisonResult) -> CachePoisonClassification:
    findings: list[CachePoisonFinding] = []
    for p in result.probes:
        finding = _classify_probe(
            result.target_url, p,
            result.baseline_status, result.baseline_size,
        )
        if finding is not None:
            findings.append(finding)
    return CachePoisonClassification(
        target_url=result.target_url,
        is_vulnerable=any(f.severity in ("medium", "high", "critical") for f in findings),
        findings=findings,
    )
