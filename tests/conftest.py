"""
Reusable Hypothesis strategies for the Web Security Audit Toolkit test suite.

These composite strategies generate structurally valid instances of the real
dataclass models defined in ``src/toolkit/models.py``.

Strategy catalogue
------------------
authorization_strategy()        → Authorization
finding_strategy()              → Finding
nuclei_finding_strategy()       → NucleiFinding
session_state_strategy()        → SessionState
http_headers_strategy()         → dict[str, str] of HTTP response headers
identifier_strategy()           → int or UUID-string identifier
bundle_content_strategy()       → str of JavaScript bundle content
"""

from __future__ import annotations

import string
import uuid as _uuid_mod
from datetime import date, timedelta

from hypothesis import strategies as st
from hypothesis.strategies import composite

from toolkit.models import (
    AttackSurfaceMap,
    Authorization,
    Exclusion,
    Finding,
    Host,
    NucleiFinding,
    OperationRecord,
    SessionState,
    Technology,
)

# ---------------------------------------------------------------------------
# Primitive helpers
# ---------------------------------------------------------------------------

# Printable ASCII strings that work well as domain names / identifiers
_safe_text = st.text(
    alphabet=string.ascii_lowercase + string.digits + "-",
    min_size=1,
    max_size=63,
)

_domain_strategy = st.builds(
    lambda label, tld: f"{label}.{tld}",
    label=_safe_text,
    tld=st.sampled_from(["com", "org", "net", "edu", "io"]),
)

_institution_strategy = st.text(
    alphabet=string.ascii_letters + string.digits + " _-",
    min_size=2,
    max_size=80,
)

# Dates that span realistic authorization windows (from 3 years ago to today)
_today = date.today()
_auth_date_strategy = st.dates(
    min_value=_today - timedelta(days=3 * 365),
    max_value=_today,
)

_severity_strategy = st.sampled_from(["low", "medium", "high", "critical"])
_confidence_strategy = st.sampled_from(["low", "medium", "high"])
_status_strategy = st.sampled_from(
    ["confirmed", "not_vulnerable", "inconclusive", "check_failed"]
)

_finding_id_strategy = st.builds(
    lambda prefix, num: f"{prefix}-{num:03d}",
    prefix=st.sampled_from(
        ["SRCMAP", "SECRET", "CDNBYP", "HDRCHK", "IDOR", "BIZLOG", "NUCL"]
    ),
    num=st.integers(min_value=1, max_value=999),
)

_url_strategy = st.builds(
    lambda domain, path: f"https://{domain}/{path}",
    domain=_domain_strategy,
    path=st.text(
        alphabet=string.ascii_lowercase + string.digits + "/-_",
        min_size=0,
        max_size=80,
    ),
)

_iso_timestamp_strategy = st.datetimes().map(lambda dt: dt.isoformat())

# ---------------------------------------------------------------------------
# authorization_strategy
# ---------------------------------------------------------------------------

@composite
def authorization_strategy(draw: st.DrawFn) -> Authorization:
    """
    Strategy that generates a valid ``Authorization`` instance.

    Fields
    ------
    domain : str
    institution : str
    auth_date : date
    authorized_domains : list[str]
    authorized_cidrs : list[str]

    Notes
    -----
    Corresponds to the Authorization dataclass (task 1.2, Req. 1.1).
    """
    domain = draw(_domain_strategy)
    institution = draw(_institution_strategy)
    auth_date = draw(_auth_date_strategy)
    extra_domains = draw(st.lists(_domain_strategy, min_size=0, max_size=5))
    authorized_domains = list({domain} | set(extra_domains))
    authorized_cidrs = draw(
        st.lists(
            st.builds(
                lambda a, b, c, d, prefix: f"{a}.{b}.{c}.{d}/{prefix}",
                a=st.integers(min_value=1, max_value=254),
                b=st.integers(min_value=0, max_value=255),
                c=st.integers(min_value=0, max_value=255),
                d=st.integers(min_value=0, max_value=254),
                prefix=st.integers(min_value=16, max_value=32),
            ),
            min_size=0,
            max_size=3,
        )
    )
    return Authorization(
        domain=domain,
        institution=institution,
        auth_date=auth_date,
        authorized_domains=authorized_domains,
        authorized_cidrs=authorized_cidrs,
    )


# ---------------------------------------------------------------------------
# finding_strategy
# ---------------------------------------------------------------------------

@composite
def finding_strategy(draw: st.DrawFn) -> Finding:
    """
    Strategy that generates a valid ``Finding`` instance.

    Fields
    ------
    id : str
    title : str
    summary : str
    severity : Literal["low", "medium", "high", "critical"]
    confidence : Literal["low", "medium", "high"]
    status : Literal["confirmed", "not_vulnerable", "inconclusive", "check_failed"]
    affected_endpoint : str | None
    evidence : str
    impact : str
    remediation : str
    next_steps : list[str]
    references : list[str]

    Notes
    -----
    Corresponds to the Finding dataclass (task 1.2, Req. 11.3).
    """
    finding_id = draw(_finding_id_strategy)
    title = draw(st.text(min_size=5, max_size=100))
    summary = draw(st.text(min_size=10, max_size=300))
    severity = draw(_severity_strategy)
    confidence = draw(_confidence_strategy)
    status = draw(_status_strategy)
    affected_endpoint = draw(st.one_of(st.none(), _url_strategy))
    evidence = draw(st.text(min_size=0, max_size=500))
    impact = draw(st.text(min_size=5, max_size=200))
    remediation = draw(st.text(min_size=5, max_size=300))
    next_steps = draw(
        st.lists(st.text(min_size=5, max_size=100), min_size=0, max_size=5)
    )
    references = draw(
        st.lists(
            st.text(
                alphabet=string.ascii_letters + string.digits + ":/.-_",
                min_size=3,
                max_size=60,
            ),
            min_size=0,
            max_size=5,
        )
    )
    return Finding(
        id=finding_id,
        title=title,
        summary=summary,
        severity=severity,
        confidence=confidence,
        status=status,
        affected_endpoint=affected_endpoint,
        evidence=evidence,
        impact=impact,
        remediation=remediation,
        next_steps=next_steps,
        references=references,
    )


# ---------------------------------------------------------------------------
# nuclei_finding_strategy
# ---------------------------------------------------------------------------

@composite
def nuclei_finding_strategy(draw: st.DrawFn) -> NucleiFinding:
    """
    Strategy that generates a valid ``NucleiFinding`` instance.

    Fields
    ------
    template_id : str
    host : str
    matched_at : str | None
    severity : str
    name : str | None
    tags : list[str]
    info : dict
    timestamp : str | None
    extra : dict

    Notes
    -----
    Corresponds to the NucleiFinding dataclass (task 1.2, Req. 10.3, 10.5).
    The ``extra`` dict simulates unknown fields that must survive a round-trip.
    """
    template_id = draw(
        st.builds(
            lambda category, name: f"{category}/{name}",
            category=st.sampled_from(["cve", "misconfig", "exposure", "headers", "info"]),
            name=_safe_text,
        )
    )
    host = draw(_domain_strategy)
    matched_at = draw(st.one_of(st.none(), _url_strategy))
    severity = draw(st.sampled_from(["info", "low", "medium", "high", "critical"]))
    name = draw(st.one_of(st.none(), st.text(min_size=3, max_size=80)))
    tags = draw(st.lists(_safe_text, min_size=0, max_size=6))

    # Build a minimal info block (mirrors Nuclei JSON structure)
    info: dict = {
        "name": name,
        "severity": severity,
        "tags": tags,
    }
    optional_info_keys = draw(
        st.fixed_dictionaries(
            {},
            optional={
                "description": st.text(min_size=0, max_size=200),
                "reference": st.lists(st.text(min_size=3, max_size=60), max_size=3),
            },
        )
    )
    info.update(optional_info_keys)

    timestamp = draw(st.one_of(st.none(), _iso_timestamp_strategy))

    # extra: arbitrary unknown fields that must be preserved round-trip
    extra = draw(
        st.fixed_dictionaries(
            {},
            optional={
                "curl-command": st.text(min_size=0, max_size=100),
                "ip": st.builds(
                    lambda a, b, c, d: f"{a}.{b}.{c}.{d}",
                    a=st.integers(1, 254),
                    b=st.integers(0, 255),
                    c=st.integers(0, 255),
                    d=st.integers(1, 254),
                ),
            },
        )
    )

    return NucleiFinding(
        template_id=template_id,
        host=host,
        matched_at=matched_at,
        severity=severity,
        name=name,
        tags=tags,
        info=info,
        timestamp=timestamp,
        extra=extra,
    )


# ---------------------------------------------------------------------------
# session_state_strategy
# ---------------------------------------------------------------------------

# The seven canonical phase names used throughout the design
_PHASE_NAMES = [
    "authorization",
    "surface_discovery",
    "passive_checks",
    "endpoint_enumeration",
    "nuclei_and_idor",
    "business_logic",
    "report_generation",
]


@composite
def session_state_strategy(draw: st.DrawFn) -> SessionState:
    """
    Strategy that generates a valid ``SessionState`` instance.

    Fields
    ------
    authorization : Authorization
    working_dir : str
    completed_phases : list[str]
    findings : list[Finding]
    tested_targets : list[str]
    surface_map : None   (AttackSurfaceMap generation kept minimal for strategy use)
    operations_log : list[OperationRecord]

    Notes
    -----
    Corresponds to the SessionState dataclass (task 1.2, Req. 12.3).
    """
    auth = draw(authorization_strategy())
    working_dir = draw(
        st.builds(
            lambda name: f"/tmp/audit_{name}",
            name=_safe_text,
        )
    )
    # Completed phases are an ordered subset of the canonical phase list
    num_completed = draw(st.integers(min_value=0, max_value=len(_PHASE_NAMES)))
    completed_phases = _PHASE_NAMES[:num_completed]

    findings = draw(st.lists(finding_strategy(), min_size=0, max_size=10))
    tested_targets = draw(st.lists(_domain_strategy, min_size=0, max_size=5))

    # OperationRecord instances
    operations_log = draw(
        st.lists(
            st.builds(
                lambda phase, action, timestamp: OperationRecord(
                    phase=phase, action=action, timestamp=timestamp
                ),
                phase=st.sampled_from(_PHASE_NAMES),
                action=st.text(min_size=3, max_size=60),
                timestamp=_iso_timestamp_strategy,
            ),
            min_size=0,
            max_size=20,
        )
    )

    return SessionState(
        authorization=auth,
        working_dir=working_dir,
        completed_phases=completed_phases,
        findings=findings,
        tested_targets=tested_targets,
        surface_map=None,  # kept None to keep strategy complexity manageable
        operations_log=operations_log,
    )


# ---------------------------------------------------------------------------
# http_headers_strategy
# ---------------------------------------------------------------------------

# Common security-relevant header names
_SECURITY_HEADER_NAMES = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cache-Control",
    "Content-Type",
    "Server",
    "X-Powered-By",
]

_header_value_strategy = st.text(
    alphabet=string.printable.replace("\n", "").replace("\r", ""),
    min_size=1,
    max_size=200,
)


@composite
def http_headers_strategy(draw: st.DrawFn) -> dict:
    """
    Generates a dict[str, str] of HTTP response headers.

    Always includes ``Content-Type``; randomly includes other standard headers
    and up to 3 arbitrary custom headers (``X-Custom-*``).
    """
    headers: dict[str, str] = {}

    # Content-Type is always present
    headers["Content-Type"] = draw(
        st.sampled_from([
            "text/html; charset=utf-8",
            "application/json",
            "application/json; charset=utf-8",
            "text/plain",
        ])
    )

    # Randomly add well-known security headers
    for header_name in _SECURITY_HEADER_NAMES:
        if draw(st.booleans()):
            headers[header_name] = draw(_header_value_strategy)

    # Randomly add custom headers
    num_custom = draw(st.integers(min_value=0, max_value=3))
    for i in range(num_custom):
        key = draw(
            st.builds(
                lambda s: f"X-Custom-{s}",
                s=st.text(
                    alphabet=string.ascii_letters + string.digits + "-",
                    min_size=1,
                    max_size=20,
                ),
            )
        )
        headers[key] = draw(_header_value_strategy)

    return headers


# ---------------------------------------------------------------------------
# identifier_strategy
# ---------------------------------------------------------------------------

@composite
def identifier_strategy(draw: st.DrawFn) -> int | str:
    """
    Generates either a positive integer identifier or a UUID string.

    This mirrors the two identifier types accepted by the IDOR check
    (Requirement 8.1): numeric IDs and UUIDs.
    """
    is_uuid = draw(st.booleans())
    if is_uuid:
        return str(_uuid_mod.UUID(int=draw(st.integers(min_value=1, max_value=2**128 - 1))))
    return draw(st.integers(min_value=1, max_value=10_000_000))


# ---------------------------------------------------------------------------
# bundle_content_strategy
# ---------------------------------------------------------------------------

# BIP-39 English wordlist — tiny representative sample (100 words)
# The full list has 2048 words; task 1.2 / classifier task 13.4 will use it.
_BIP39_SAMPLE = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb",
    "abstract", "absurd", "abuse", "access", "accident", "account", "accuse",
    "achieve", "acid", "acoustic", "acquire", "across", "act", "action",
    "actor", "actress", "actual", "adapt", "add", "addict", "address",
    "adjust", "admit", "adult", "advance", "advice", "aerobic", "afford",
    "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air",
    "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien",
    "all", "alley", "allow", "almost", "alone", "alpha", "already",
    "also", "alter", "always", "amateur", "amazing", "among", "amount",
    "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
    "animal", "ankle", "announce", "annual", "another", "answer", "antenna",
    "antique", "anxiety", "any", "apart", "apology", "appear", "apple",
    "approve", "april", "arcade", "arctic", "area", "arena", "argue",
    "arm", "armed", "armor", "army", "around", "arrange", "arrest",
    "arrive", "arrow", "art",
]


@composite
def bundle_content_strategy(draw: st.DrawFn) -> str:
    """
    Generates a string representing the text content of a JavaScript bundle.

    Randomly decides whether to inject a recognisable secret pattern so that
    property tests can verify both detection and true-negative cases.

    Possible injected patterns
    --------------------------
    * Ethereum private key  : ``0x`` + 64 hex chars
    * Ethereum address      : ``0x`` + 40 hex chars
    * API key               : ``apiKey="<16+ alphanum chars>"``
    * BIP-39 mnemonic       : 12 or 24 space-separated words from the sample list
    * None (clean bundle)
    """
    _hex_chars = "0123456789abcdef"

    # Base bundle: some innocuous JS code
    base = draw(
        st.builds(
            lambda fn_name, body: (
                f"(function(){{"
                f'var {fn_name}=function(){{return "{body}";}};'
                f"}})();"
            ),
            fn_name=st.text(
                alphabet=string.ascii_lowercase, min_size=3, max_size=12
            ),
            body=st.text(
                alphabet=string.printable.replace('"', "").replace("\\", ""),
                min_size=0,
                max_size=200,
            ),
        )
    )

    secret_type = draw(
        st.sampled_from(["none", "eth_privkey", "eth_address", "api_key", "mnemonic"])
    )

    if secret_type == "eth_privkey":
        key_hex = draw(st.text(alphabet=_hex_chars, min_size=64, max_size=64))
        secret_fragment = f'privateKey:"0x{key_hex}"'
    elif secret_type == "eth_address":
        addr_hex = draw(st.text(alphabet=_hex_chars, min_size=40, max_size=40))
        secret_fragment = f'contractAddress:"0x{addr_hex}"'
    elif secret_type == "api_key":
        key_value = draw(
            st.text(
                alphabet=string.ascii_letters + string.digits,
                min_size=16,
                max_size=40,
            )
        )
        secret_fragment = f'apiKey:"{key_value}"'
    elif secret_type == "mnemonic":
        word_count = draw(st.sampled_from([12, 24]))
        words = draw(
            st.lists(
                st.sampled_from(_BIP39_SAMPLE),
                min_size=word_count,
                max_size=word_count,
            )
        )
        mnemonic = " ".join(words)
        secret_fragment = f'mnemonic:"{mnemonic}"'
    else:
        secret_fragment = ""

    if secret_fragment:
        return base + secret_fragment
    return base
