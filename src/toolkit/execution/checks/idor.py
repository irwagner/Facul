"""
IDOR (Insecure Direct Object Reference) check (Req. 8.1, 8.6).

``check_idor`` accepts a resource endpoint containing a numeric identifier or
UUID, generates exactly 5 identifier variations, makes authenticated GET
requests with the current user's token, and returns a list of ``IdorProbe``
results.

Scope is validated before every network request via ``ScopeValidator``.

Identifier variation set (Req. 8.1, 8.6):
  - original + 1
  - original - 1
  - random UUID
  - 0
  - -1 (negative integer)

Maximum variations per endpoint: 5 (Req. 8.6)
"""

from __future__ import annotations

import logging
import re
import uuid as _uuid_mod
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

import requests

from toolkit.governance.audit_logger import AuditLogger
from toolkit.governance.scope import ScopeValidator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class IdorProbe:
    """Result of probing a single identifier variation against an endpoint."""

    endpoint: str          # The full URL probed (with the variation substituted)
    variation_value: str   # The identifier variation used (as string for uniformity)
    status_code: int | None  # None when a network/scope error occurred
    response_body: str | None  # Raw response body (None on error or non-2xx)
    error: str | None = None   # Description when a network/scope error occurred


# ---------------------------------------------------------------------------
# Identifier variation generation
# ---------------------------------------------------------------------------

# Regex patterns to detect and replace identifiers in endpoint paths.
# Matches path segments that are:
#   - a UUID (8-4-4-4-12 hex)
#   - a decimal integer (including negative integers)
_UUID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    re.IGNORECASE,
)
_INT_PATTERN = re.compile(r"(?<![0-9a-f\-])(-?\d+)(?![0-9a-f\-])")


def _detect_identifier(endpoint: str) -> str | None:
    """
    Detect the first identifier in the endpoint path.

    Returns the matched identifier string or ``None`` when no identifier is
    found in the path.

    Detection order:
    1. UUID (8-4-4-4-12 hex format)
    2. Decimal integer
    """
    path = urlparse(endpoint).path
    uuid_match = _UUID_PATTERN.search(path)
    if uuid_match:
        return uuid_match.group(0)
    int_match = _INT_PATTERN.search(path)
    if int_match:
        return int_match.group(1)
    return None


def generate_variations(identifier: str | int) -> list[str]:
    """
    Generate exactly 5 identifier variations for IDOR testing (Req. 8.1, 8.6).

    The returned list contains **exactly** these 5 variations (as strings):
      1. ``str(original + 1)``   — increment by 1
      2. ``str(original - 1)``   — decrement by 1
      3. A random UUID string    — structural substitution
      4. ``"0"``                 — zero
      5. ``"-1"``                — negative integer

    When *identifier* is a UUID string, "original" is treated as 1 for
    arithmetic variants (so variants are "2", "0", random_uuid, "0", "-1");
    the important invariant is that **exactly 5 elements are returned** and
    the set always includes a random UUID, "0", and "-1".

    Parameters
    ----------
    identifier:
        The original resource identifier — either a positive integer or a
        UUID string (e.g. ``"550e8400-e29b-41d4-a716-446655440000"``).

    Returns
    -------
    list[str]
        A list of exactly 5 identifier variation strings.
    """
    # Determine the numeric base for arithmetic operations
    if isinstance(identifier, int):
        base = identifier
    elif isinstance(identifier, str) and _UUID_PATTERN.fullmatch(identifier):
        # For UUID identifiers treat numeric base as 1 (arbitrary but consistent)
        base = 1
    else:
        # Try to parse as integer string, fall back to 1
        try:
            base = int(identifier)
        except (ValueError, TypeError):
            base = 1

    random_uuid = str(_uuid_mod.uuid4())

    variations: list[str] = [
        str(base + 1),   # increment by 1
        str(base - 1),   # decrement by 1
        random_uuid,     # random UUID substitution
        "0",             # zero
        "-1",            # negative integer
    ]

    # Enforce the maximum of 5 (Req. 8.6) — already exactly 5, but guard
    return variations[:5]


# ---------------------------------------------------------------------------
# Public check function
# ---------------------------------------------------------------------------

def check_idor(
    endpoint: str,
    auth_token: str,
    scope_validator: ScopeValidator | None = None,
    audit_logger: AuditLogger | None = None,
    timeout: float = 10.0,
) -> list[IdorProbe]:
    """
    Test *endpoint* for IDOR vulnerabilities using authenticated requests.

    Algorithm
    ---------
    1. Detect the identifier embedded in the endpoint path.
    2. Generate exactly 5 identifier variations via ``generate_variations``.
    3. For each variation:
       a. Substitute the variation into the endpoint URL.
       b. Validate scope before dispatching the request.
       c. Make an authenticated GET request (``Authorization: Bearer <token>``).
       d. Record the result as an ``IdorProbe``.
    4. Return the list of probes (at most 5).

    Parameters
    ----------
    endpoint:
        The target resource URL containing a numeric ID or UUID, e.g.
        ``https://api.example.com/api/users/42``.
    auth_token:
        The current user's authentication token, attached as a Bearer token
        in the ``Authorization`` header.
    scope_validator:
        Optional ``ScopeValidator``. When provided, ``assert_in_scope`` is
        called before every request. Out-of-scope requests are skipped and
        recorded with an ``error`` field.
    audit_logger:
        Optional ``AuditLogger`` passed to ``assert_in_scope``. Only
        required when *scope_validator* is provided.
    timeout:
        Per-request timeout in seconds (default 10).

    Returns
    -------
    list[IdorProbe]
        A list of at most 5 ``IdorProbe`` results, one per variation.
    """
    probes: list[IdorProbe] = []

    # ------------------------------------------------------------------
    # Step 1 — detect identifier in the endpoint path
    # ------------------------------------------------------------------
    original_id = _detect_identifier(endpoint)
    if original_id is None:
        logger.warning(
            "No identifier detected in endpoint %s; cannot generate IDOR variations.",
            endpoint,
        )
        return probes

    # ------------------------------------------------------------------
    # Step 2 — generate variations
    # ------------------------------------------------------------------
    variations = generate_variations(original_id)

    # ------------------------------------------------------------------
    # Step 3 — probe each variation
    # ------------------------------------------------------------------
    for variation in variations:
        probe_url = _substitute_identifier(endpoint, original_id, variation)
        probe_host = urlparse(probe_url).netloc

        # (a) Validate scope before request
        if scope_validator is not None:
            _logger = audit_logger if audit_logger is not None else AuditLogger()
            scope_ok, scope_error = _check_scope(
                probe_host, scope_validator, _logger
            )
            if not scope_ok:
                logger.warning(
                    "Endpoint %s is out of scope; skipping IDOR probe.", probe_url
                )
                probes.append(
                    IdorProbe(
                        endpoint=probe_url,
                        variation_value=variation,
                        status_code=None,
                        response_body=None,
                        error=f"Out of scope: {scope_error}",
                    )
                )
                continue

        # (b) Make authenticated GET request
        probe = _make_authenticated_request(probe_url, variation, auth_token, timeout)
        probes.append(probe)

    return probes


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _substitute_identifier(endpoint: str, original: str, replacement: str) -> str:
    """
    Return the endpoint URL with the first occurrence of *original* replaced
    by *replacement* in the path portion.

    UUID matching is case-insensitive; integer matching targets the exact
    path segment delimited by ``/``, ``?``, ``#``, or end-of-string.
    """
    parsed = urlparse(endpoint)
    path = parsed.path

    if _UUID_PATTERN.fullmatch(original):
        # Replace UUID in path (case-insensitive)
        new_path = re.sub(re.escape(original), replacement, path, count=1, flags=re.IGNORECASE)
    else:
        # Replace the integer segment — match the exact path segment
        # delimited by '/' or end-of-string to avoid partial replacements.
        # Escape the original in case it contains special regex chars (e.g. "-1")
        new_path = re.sub(
            r"(?<=/)" + re.escape(original) + r"(?=/|$)",
            replacement,
            path,
            count=1,
        )

    # Reconstruct the URL with only the path replaced
    return parsed._replace(path=new_path).geturl()


def _check_scope(
    host: str,
    scope_validator: ScopeValidator,
    audit_logger: AuditLogger,
) -> tuple[bool, str | None]:
    """
    Return ``(True, None)`` if *host* is in scope, or ``(False, reason)``
    otherwise.
    """
    from toolkit.exceptions import ScopeError  # local import to avoid circular

    try:
        scope_validator.assert_in_scope(host, module="idor", logger=audit_logger)
        return True, None
    except ScopeError as exc:
        return False, str(exc)


def _make_authenticated_request(
    url: str,
    variation: str,
    auth_token: str,
    timeout: float,
) -> IdorProbe:
    """
    Make a single authenticated GET request and return an ``IdorProbe``.
    """
    headers = {"Authorization": f"Bearer {auth_token}"}
    try:
        resp = requests.get(url, headers=headers, timeout=timeout, verify=False)  # noqa: S501
        status = resp.status_code
        # Capture body for all responses so the analyzer can inspect them
        body = resp.text if resp.text else None
        return IdorProbe(
            endpoint=url,
            variation_value=variation,
            status_code=status,
            response_body=body,
            error=None,
        )
    except requests.exceptions.Timeout:
        error_msg = f"Timeout probing variation {variation!r} at {url}"
        logger.error(error_msg)
        return IdorProbe(
            endpoint=url,
            variation_value=variation,
            status_code=None,
            response_body=None,
            error=error_msg,
        )
    except requests.exceptions.RequestException as exc:
        error_msg = f"Network error probing variation {variation!r} at {url}: {exc}"
        logger.error(error_msg)
        return IdorProbe(
            endpoint=url,
            variation_value=variation,
            status_code=None,
            response_body=None,
            error=error_msg,
        )
