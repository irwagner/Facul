"""
Helpers for masking sensitive data in evidence and audit payloads.

These functions reduce findings/payloads to structural field names or masked
values — never exposing PII or secrets in clear text.  They are used by the
IDOR, business logic and secrets classifiers.

Requirements: 8.4, 9.5, 9.6
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Union

__all__ = [
    "mask_secret",
    "mask_payload",
    "extract_structural_fields",
    "mask_evidence_for_idor",
    "mask_business_logic_payload",
]

# Field names (case-insensitive substring match) whose values are considered
# sensitive and must never appear in clear text.
_SENSITIVE_FIELD_SUBSTRINGS: tuple[str, ...] = (
    "password",
    "token",
    "secret",
    "key",
    "authorization",
    "private",
    "mnemonic",
    "seed",
    "credential",
    "auth",
)


def mask_secret(value: str) -> str:
    """Mask a secret value to prevent clear-text exposure.

    Returns a string with only the first 4 and last 4 characters visible and
    ``***`` in the middle.  If the value has 8 or fewer characters the entire
    value is replaced with ``***MASKED***`` to avoid leaking meaningful
    information through prefix/suffix hints.

    Args:
        value: The secret string to mask.

    Returns:
        A masked representation of *value*.

    Examples:
        >>> mask_secret("abcdefghijklmnop")
        'abcd***mnop'
        >>> mask_secret("short")
        '***MASKED***'
    """
    if len(value) <= 8:
        return "***MASKED***"
    return f"{value[:4]}***{value[-4:]}"


def _is_sensitive_key(key: str) -> bool:
    """Return True if *key* contains a sensitive-field substring (case-insensitive)."""
    lower = key.lower()
    return any(sub in lower for sub in _SENSITIVE_FIELD_SUBSTRINGS)


def mask_payload(payload: dict) -> dict:
    """Return a copy of *payload* with sensitive field values replaced.

    A field is considered sensitive when its key name contains one of the
    following substrings (case-insensitive): ``password``, ``token``,
    ``secret``, ``key``, ``authorization``, ``private``, ``mnemonic``,
    ``seed``, ``credential``, ``auth``.

    String values of sensitive fields are replaced with ``***MASKED***``.
    Non-string values (e.g. integers, booleans) are left unchanged because
    they rarely carry secret material and preserving the type is useful for
    audit log readability.

    Args:
        payload: The original request/response payload dict.

    Returns:
        A shallow copy of *payload* with sensitive string values masked.
    """
    masked: dict = {}
    for key, value in payload.items():
        if _is_sensitive_key(key) and isinstance(value, str):
            masked[key] = "***MASKED***"
        else:
            masked[key] = value
    return masked


def extract_structural_fields(response_body: Union[dict, str]) -> list[str]:
    """Extract only the top-level field names from a JSON response body.

    Values are intentionally discarded so that callers can reference the
    structure of a response (e.g. in IDOR evidence) without exposing any PII
    or sensitive data.

    If *response_body* is a string, a JSON parse is attempted first.  If
    parsing fails, an empty list is returned rather than raising an exception.

    Args:
        response_body: A dict or a JSON-encoded string representing the
            response body.

    Returns:
        A list of top-level key names, preserving insertion order.
    """
    if isinstance(response_body, str):
        try:
            parsed = json.loads(response_body)
        except (json.JSONDecodeError, ValueError):
            return []
        if not isinstance(parsed, dict):
            return []
        response_body = parsed

    if not isinstance(response_body, dict):
        return []

    return list(response_body.keys())


def mask_evidence_for_idor(
    response_body: Union[dict, str],
    auth_user_id: str,  # noqa: ARG001  — reserved for future caller-side filtering
) -> str:
    """Create a safe IDOR evidence string from a response body.

    Only the field *names* present in the response are included in the output;
    no field values are ever serialised.  This satisfies Req. 8.4 (IDOR
    evidence must not expose PII values).

    Args:
        response_body: The response body as a dict or JSON string.
        auth_user_id: The authenticated user's identifier.  Currently reserved
            for caller-side ID-diff filtering; not embedded in the output.

    Returns:
        A human-readable string in the form
        ``"Response fields: id, userId, email, balance"``.
        Returns ``"Response fields: (none)"`` when no fields are found.
    """
    fields = extract_structural_fields(response_body)
    field_list = ", ".join(fields) if fields else "(none)"
    return f"Response fields: {field_list}"


def mask_business_logic_payload(
    method: str,
    endpoint: str,
    payload: dict,
    status_code: int,
    body_size: int,
) -> dict:
    """Create an audit log record for a business logic request.

    All sensitive field values in *payload* are masked via :func:`mask_payload`
    before being stored.  The record includes an ISO 8601 timestamp generated
    at call time (UTC).

    This function fulfils the Req. 9.6 logging requirements: every business
    logic request must be logged with timestamp, HTTP method, endpoint,
    masked payload, response status code and response body size.

    Args:
        method: HTTP method string (e.g. ``"POST"``).
        endpoint: The target endpoint URL or path.
        payload: The outgoing request payload dict (may contain sensitive data).
        status_code: The HTTP response status code received.
        body_size: The response body size in bytes.

    Returns:
        A dict with keys: ``timestamp``, ``method``, ``endpoint``,
        ``payload``, ``status_code``, ``body_size``.
    """
    return {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "method": method,
        "endpoint": endpoint,
        "payload": mask_payload(payload),
        "status_code": status_code,
        "body_size": body_size,
    }
