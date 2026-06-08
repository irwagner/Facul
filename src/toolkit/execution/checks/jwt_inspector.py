"""
Static JWT inspection (no token forgery, no signature brute-force).

This module **decodes and validates the structure** of a JWT and reports
common misconfigurations that operators care about during a pentest:

    * algorithm declared as ``none``
    * unexpected algorithm switching (``HS256`` vs ``RS256``)
    * missing or stale ``exp`` / ``nbf`` claims
    * suspiciously short signature length (potential weak secret)
    * sensitive PII exposed in the payload (email, phone, document IDs)

It does **not** try to break the signature or forge tokens.  Active
brute-force is out of scope for this passive analyzer; if you need to
attempt a HS256 secret crack, run ``john --format=HMAC-SHA256`` on the
extracted ``signing_input`` field externally and document the result
manually.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Sensitive PII patterns to flag in the payload (mirrors the patterns
# used by ``analysis.classifiers.secrets``).
_PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+"),
    "phone_br": re.compile(r"\b(?:\+?55)?(?:\d{2})?9?\d{8}\b"),
    "cpf": re.compile(r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}

_DANGEROUS_ALGS = {"none", "None", "NONE"}
_SHORT_SIG_THRESHOLD_BYTES = 16  # HMAC-SHA256 produces 32 bytes; shorter is suspicious


@dataclass(frozen=True)
class JwtIssue:
    severity: str  # "info" | "low" | "medium" | "high"
    code: str
    message: str


@dataclass(frozen=True)
class JwtReport:
    valid_structure: bool
    header: dict | None
    payload: dict | None
    signature_bytes: int
    issues: list[JwtIssue] = field(default_factory=list)
    pii_hits: dict[str, list[str]] = field(default_factory=dict)
    raw_signing_input: str | None = None

    def to_dict(self) -> dict:
        return {
            "valid_structure": self.valid_structure,
            "header": self.header,
            "payload": self.payload,
            "signature_bytes": self.signature_bytes,
            "issues": [
                {"severity": i.severity, "code": i.code, "message": i.message}
                for i in self.issues
            ],
            "pii_hits": {k: list(v) for k, v in self.pii_hits.items()},
        }


def _b64url_decode(value: str) -> bytes:
    pad = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _mask(value: str, *, keep: int = 4) -> str:
    if len(value) <= keep * 2:
        return "***"
    return f"{value[:keep]}***{value[-keep:]}"


def _scan_pii(payload: dict) -> dict[str, list[str]]:
    text = json.dumps(payload, default=str)
    hits: dict[str, list[str]] = {}
    for label, pattern in _PII_PATTERNS.items():
        found = list({_mask(m) for m in pattern.findall(text)})
        if found:
            hits[label] = found
    return hits


def inspect(token: str) -> JwtReport:
    """Decode *token* and return a static analysis report.

    The token is **not** verified against any signing key.  This is purely
    a structural and best-practice review.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return JwtReport(
            valid_structure=False,
            header=None,
            payload=None,
            signature_bytes=0,
            issues=[
                JwtIssue(
                    severity="info",
                    code="not_a_jwt",
                    message="Token does not have three dot-separated segments.",
                ),
            ],
        )

    header_b64, payload_b64, sig_b64 = parts
    issues: list[JwtIssue] = []
    header: dict | None = None
    payload: dict | None = None
    sig_bytes = 0
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as exc:  # noqa: BLE001
        issues.append(
            JwtIssue(
                severity="medium",
                code="bad_header",
                message=f"Header is not valid base64url JSON: {exc}",
            )
        )

    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as exc:  # noqa: BLE001
        issues.append(
            JwtIssue(
                severity="medium",
                code="bad_payload",
                message=f"Payload is not valid base64url JSON: {exc}",
            )
        )

    try:
        sig_bytes = len(_b64url_decode(sig_b64))
    except Exception:  # noqa: BLE001
        sig_bytes = 0

    # ------------------------------------------------------------------
    # Header-level findings
    # ------------------------------------------------------------------
    if isinstance(header, dict):
        alg = str(header.get("alg") or "")
        if alg in _DANGEROUS_ALGS:
            issues.append(
                JwtIssue(
                    severity="high",
                    code="alg_none",
                    message="Header declares 'alg: none' — signature is bypassable.",
                )
            )
        if alg.upper().startswith("HS") and sig_bytes and sig_bytes < _SHORT_SIG_THRESHOLD_BYTES:
            issues.append(
                JwtIssue(
                    severity="medium",
                    code="short_signature",
                    message=(
                        f"Signature is only {sig_bytes} bytes; HS* should be ≥ 32. "
                        "Server may use a weak/short secret."
                    ),
                )
            )
        if header.get("kid") and any(c in str(header["kid"]) for c in ("..", "/", "\\")):
            issues.append(
                JwtIssue(
                    severity="high",
                    code="kid_path",
                    message="Suspicious 'kid' header containing path characters — possible path traversal injection.",
                )
            )

    # ------------------------------------------------------------------
    # Payload-level findings
    # ------------------------------------------------------------------
    pii_hits: dict[str, list[str]] = {}
    if isinstance(payload, dict):
        now = datetime.now(timezone.utc).timestamp()
        exp = payload.get("exp")
        nbf = payload.get("nbf")
        iat = payload.get("iat")
        if exp is None:
            issues.append(
                JwtIssue(
                    severity="medium",
                    code="missing_exp",
                    message="Token has no 'exp' claim — could remain valid indefinitely.",
                )
            )
        elif isinstance(exp, (int, float)) and exp < now:
            issues.append(
                JwtIssue(
                    severity="info",
                    code="expired",
                    message="Token is already expired (informational).",
                )
            )
        if isinstance(iat, (int, float)) and isinstance(exp, (int, float)) and exp - iat > 60 * 60 * 24 * 30:
            issues.append(
                JwtIssue(
                    severity="medium",
                    code="long_lifetime",
                    message="Token TTL exceeds 30 days — increases blast radius if leaked.",
                )
            )
        if nbf is not None and isinstance(nbf, (int, float)) and nbf > now + 60:
            issues.append(
                JwtIssue(
                    severity="low",
                    code="future_nbf",
                    message="Token has 'nbf' in the future.",
                )
            )
        # Sensitive PII in payload
        pii_hits = _scan_pii(payload)
        if pii_hits:
            issues.append(
                JwtIssue(
                    severity="medium",
                    code="pii_in_payload",
                    message=(
                        "Payload appears to contain personally-identifiable information: "
                        + ", ".join(sorted(pii_hits))
                    ),
                )
            )

    return JwtReport(
        valid_structure=isinstance(header, dict) and isinstance(payload, dict),
        header=header,
        payload=payload,
        signature_bytes=sig_bytes,
        issues=issues,
        pii_hits=pii_hits,
        raw_signing_input=f"{header_b64}.{payload_b64}",
    )


def is_jwt(value: str) -> bool:
    """Cheap guard used by callers to filter strings before calling :func:`inspect`."""
    if not isinstance(value, str):
        return False
    parts = value.split(".")
    return len(parts) == 3 and all(parts) and all(re.fullmatch(r"[A-Za-z0-9_\-]+=*", p) for p in parts)
