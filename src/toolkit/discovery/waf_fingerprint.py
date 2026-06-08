"""
WAF / CDN fingerprinting from HTTP responses.

Inspects response headers and well-known cookies to identify the CDN /
WAF in front of a target.  The function is **pure**: callers pass a dict
of headers (and optionally a body sample); no network I/O occurs here.

Recognises (non-exhaustive list):
    Cloudflare, AWS CloudFront, Akamai, Fastly, Sucuri, Imperva/Incapsula,
    Azure Front Door, F5 BIG-IP, Barracuda, ModSecurity, AWS WAF, Wallarm,
    Stackpath, Edgecast, Wordfence, Webroot, Reblaze, Distil, Wallarm.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Each rule tests a header (name, value pattern) or a cookie name.
# Order is irrelevant; matches accumulate.
_HEADER_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("cloudflare", "server", re.compile(r"cloudflare", re.I)),
    ("cloudflare", "cf-ray", re.compile(r".+")),
    ("cloudflare", "cf-cache-status", re.compile(r".+")),
    ("cloudfront", "via", re.compile(r"CloudFront", re.I)),
    ("cloudfront", "x-amz-cf-id", re.compile(r".+")),
    ("cloudfront", "x-amz-cf-pop", re.compile(r".+")),
    ("akamai", "server", re.compile(r"AkamaiGHost|akamai", re.I)),
    ("akamai", "x-akamai-transformed", re.compile(r".+")),
    ("fastly", "x-served-by", re.compile(r"cache-.+")),
    ("fastly", "x-fastly-request-id", re.compile(r".+")),
    ("fastly", "fastly-debug-digest", re.compile(r".+")),
    ("sucuri", "x-sucuri-id", re.compile(r".+")),
    ("sucuri", "server", re.compile(r"Sucuri", re.I)),
    ("incapsula", "x-iinfo", re.compile(r".+")),
    ("incapsula", "x-cdn", re.compile(r"Incapsula|Imperva", re.I)),
    ("azure_front_door", "x-azure-ref", re.compile(r".+")),
    ("aws_waf", "x-amzn-requestid", re.compile(r".+")),
    ("aws_waf", "x-amzn-trace-id", re.compile(r".+")),
    ("f5_bigip", "server", re.compile(r"BigIP|BIG-IP", re.I)),
    ("modsecurity", "server", re.compile(r"mod_security|ModSecurity", re.I)),
    ("barracuda", "server", re.compile(r"Barracuda", re.I)),
    ("stackpath", "x-cache", re.compile(r"stackpath|fireblade", re.I)),
    ("edgecast", "server", re.compile(r"ECS|ECAcc", re.I)),
    ("wordfence", "x-wordfence", re.compile(r".+")),
    ("reblaze", "x-reblaze-protected", re.compile(r".+")),
]

_COOKIE_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("cloudflare", re.compile(r"^__cfduid|^__cflb|^__cf_bm", re.I)),
    ("incapsula", re.compile(r"^visid_incap_|^incap_ses_", re.I)),
    ("akamai", re.compile(r"^ak_bmsc|^bm_sv|^bm_sz", re.I)),
    ("sucuri", re.compile(r"^sucuri_", re.I)),
    ("f5_bigip", re.compile(r"^BIGipServer", re.I)),
    ("barracuda", re.compile(r"^barra_counter_session", re.I)),
    ("citrix", re.compile(r"^NSC_", re.I)),
]


@dataclass(frozen=True)
class WafFingerprint:
    detected: list[str] = field(default_factory=list)
    confidence: str = "low"
    matched_signals: list[str] = field(default_factory=list)
    is_protected: bool = False

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "confidence": self.confidence,
            "matched_signals": self.matched_signals,
            "is_protected": self.is_protected,
        }


def _split_cookies(set_cookie: str) -> list[str]:
    out: list[str] = []
    for piece in set_cookie.split(","):
        name = piece.split("=", 1)[0].strip()
        if name:
            out.append(name)
    return out


def fingerprint(headers: dict[str, str], cookies: list[str] | None = None) -> WafFingerprint:
    """Identify CDN / WAF vendors from *headers* and ``Set-Cookie`` names."""
    detected: dict[str, int] = {}
    signals: list[str] = []

    norm = {k.lower(): str(v) for k, v in headers.items()}

    for vendor, header, pattern in _HEADER_RULES:
        value = norm.get(header.lower())
        if value and pattern.search(value):
            detected[vendor] = detected.get(vendor, 0) + 1
            signals.append(f"{header}={value!r} matched {vendor}")

    cookie_names = list(cookies or [])
    sc = norm.get("set-cookie")
    if sc:
        cookie_names.extend(_split_cookies(sc))

    for vendor, pattern in _COOKIE_RULES:
        for name in cookie_names:
            if pattern.match(name):
                detected[vendor] = detected.get(vendor, 0) + 1
                signals.append(f"cookie {name!r} matched {vendor}")

    if not detected:
        return WafFingerprint()

    confidence = "low"
    max_hits = max(detected.values())
    if max_hits >= 3:
        confidence = "high"
    elif max_hits == 2:
        confidence = "medium"

    ordered = sorted(detected, key=lambda v: (-detected[v], v))
    return WafFingerprint(
        detected=ordered,
        confidence=confidence,
        matched_signals=signals,
        is_protected=True,
    )
