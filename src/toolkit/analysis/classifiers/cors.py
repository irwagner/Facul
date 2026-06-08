"""
CORS misconfiguration classifier.

Severity ladder:

    * **critical** — Origin reflection (server echoes attacker origin)
      with ``Access-Control-Allow-Credentials: true``.  Authenticated
      cross-origin read.
    * **high** — Origin reflection without credentials, OR
      ``Access-Control-Allow-Origin: *`` exposed for an authenticated
      endpoint, OR ``null`` origin accepted with credentials.
    * **medium** — Pre-flight allows ``*`` methods or sensitive headers
      (``Authorization``, ``Cookie``) for arbitrary origin.
    * **low** — Subdomain reflection where the attacker controls a
      same-suffix host.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from toolkit.execution.checks.cors import CorsProbe, CorsResult


_SENSITIVE_HEADERS = {"authorization", "cookie", "x-api-key", "x-csrf-token"}


@dataclass(frozen=True)
class CorsFinding:
    origin: str
    method: str
    severity: str
    confidence: str
    reason: str


@dataclass(frozen=True)
class CorsClassification:
    target_url: str
    is_vulnerable: bool
    findings: list[CorsFinding] = field(default_factory=list)


def _normalise(value: str | None) -> str:
    return (value or "").strip().lower()


def _classify_probe(probe: CorsProbe) -> CorsFinding | None:
    if probe.error:
        return None

    # OPTIONS pre-flight findings rely on Allow-Methods / Allow-Headers,
    # not on ACAO, so check those first.
    if probe.method == "OPTIONS":
        if probe.allow_headers and any(
            h.strip().lower() in _SENSITIVE_HEADERS
            for h in probe.allow_headers.split(",")
        ):
            return CorsFinding(
                origin=probe.origin, method=probe.method,
                severity="medium", confidence="medium",
                reason=f"OPTIONS allows sensitive headers: {probe.allow_headers}",
            )

    if probe.acao is None:
        return None
    acao = _normalise(probe.acao)
    acac = _normalise(probe.acac) == "true"
    requested = _normalise(probe.origin)

    # Origin reflection
    if requested and acao == requested:
        if acac:
            return CorsFinding(
                origin=probe.origin, method=probe.method,
                severity="critical", confidence="high",
                reason="Origin reflected with Access-Control-Allow-Credentials: true",
            )
        return CorsFinding(
            origin=probe.origin, method=probe.method,
            severity="high", confidence="high",
            reason="Origin reflected (no credentials) — readable cross-origin",
        )

    # Wildcard with credentials (some servers ignore the spec)
    if acao == "*" and acac:
        return CorsFinding(
            origin=probe.origin, method=probe.method,
            severity="critical", confidence="high",
            reason="ACAO=* combined with ACAC=true (spec violation; some browsers honour it)",
        )

    # null origin accepted with credentials → sandboxed iframe attack
    if requested == "null" and acao == "null" and acac:
        return CorsFinding(
            origin=probe.origin, method=probe.method,
            severity="critical", confidence="high",
            reason="null origin accepted with credentials",
        )

    # ACAO=* on any endpoint that returns user data
    if acao == "*":
        return CorsFinding(
            origin=probe.origin, method=probe.method,
            severity="medium", confidence="medium",
            reason="ACAO=* — public read enabled (verify endpoint exposes user data)",
        )

    return None


def analyze_cors(result: CorsResult) -> CorsClassification:
    findings: list[CorsFinding] = []
    for p in result.probes:
        finding = _classify_probe(p)
        if finding is not None:
            findings.append(finding)
    return CorsClassification(
        target_url=result.target_url,
        is_vulnerable=any(f.severity in ("medium", "high", "critical") for f in findings),
        findings=findings,
    )
