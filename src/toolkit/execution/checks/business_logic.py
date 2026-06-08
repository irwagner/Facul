"""
Business logic vulnerability check (Req. 9.1, 9.3, 9.6).

``check_business_logic`` tests numeric parameter manipulation using a fixed
payload set and optionally fires a race condition probe with 3 simultaneous
requests within a 10-second window.

Every request is recorded in the audit log with:
  - ISO 8601 timestamp (UTC)
  - HTTP method
  - endpoint
  - sent payload (sensitive values masked via ``mask_business_logic_payload``)
  - response status code
  - response body size in bytes

Requirements: 9.1, 9.3, 9.6
"""

from __future__ import annotations

import concurrent.futures
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Union

import requests

from toolkit.analysis.classifiers.masking import mask_business_logic_payload
from toolkit.governance.audit_logger import AuditLogger
from toolkit.models import AuditEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Fixed payload set (Req. 9.1 — Property 17)
# ---------------------------------------------------------------------------

_TEST_PAYLOADS: list[Union[int, float, str]] = [
    -1,
    0,
    0.000000001,
    9007199254740991,
    "abc",
]

# Race condition parameters (Req. 9.3)
_RACE_CONCURRENCY = 3
_RACE_TIMEOUT_S = 10.0


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ParamTestResult:
    """Result of testing a single payload value against one parameter."""

    param_name: str
    payload_value: Any           # one of the 5 fixed test payloads
    status_code: int | None      # None on network error
    body_size: int               # bytes; 0 on error
    response_fields: list[str]   # top-level JSON field names (no values)
    error: str | None = None     # description when a network error occurred


@dataclass
class RaceResult:
    """Result of the race condition probe (Req. 9.3)."""

    responses: list[ParamTestResult]  # exactly 3 results (one per concurrent request)
    timed_out_count: int = 0          # requests that did not complete within 10 s


@dataclass
class BizLogicResult:
    """Aggregated result returned by ``check_business_logic``."""

    endpoint: str
    parameter_results: list[ParamTestResult] = field(default_factory=list)
    race_results: RaceResult | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_test_payloads() -> list[Union[int, float, str]]:
    """Return the fixed set of business logic test payloads (Req. 9.1).

    Returns exactly: [-1, 0, 0.000000001, 9007199254740991, "abc"]

    Returns
    -------
    list
        A new list containing the 5 fixed test values in specification order.
    """
    return list(_TEST_PAYLOADS)


def get_manipulation_payloads() -> list[Union[int, float, str]]:
    """Return the fixed set of parameter manipulation payloads (Req. 9.1).

    Returns exactly: [-1, 0, 0.000000001, 9007199254740991, "abc"]

    This is the canonical public API for Property 17 — the set of test values
    used to probe numeric parameters for business logic vulnerabilities.

    Returns
    -------
    list
        A new list containing the 5 fixed test values in specification order.
    """
    return list(_TEST_PAYLOADS)


def check_business_logic(
    endpoint: str,
    params: dict[str, Any],
    auth_token: str,
    audit_logger: AuditLogger,
    enable_race: bool = False,
    method: str = "POST",
    timeout: float = 10.0,
) -> BizLogicResult:
    """Test business logic vulnerabilities on *endpoint* (Req. 9.1, 9.3, 9.6).

    For each numeric parameter in *params*, the function substitutes the
    original value with each of the 5 fixed test payloads and sends an
    authenticated request. When *enable_race* is ``True``, an additional
    race condition probe dispatches 3 simultaneous requests using the
    original *params* values.

    Every request — parameter manipulation and race condition — is recorded
    in *audit_logger* as a ``biz_request`` ``AuditEvent`` with the fields
    required by Req. 9.6 (timestamp, method, endpoint, masked payload,
    status code, body size).

    Parameters
    ----------
    endpoint:
        Target URL to test (e.g. ``"https://example.com/api/withdraw"``).
    params:
        Original request body parameters as a dict. All keys are included in
        every request; numeric parameters are replaced one at a time by the
        test payload.
    auth_token:
        Bearer token placed in the ``Authorization`` header of every request.
    audit_logger:
        ``AuditLogger`` instance used to record every request.
    enable_race:
        When ``True``, fire exactly 3 concurrent requests after the parameter
        manipulation tests (Req. 9.3).
    method:
        HTTP method to use (default ``"POST"``).
    timeout:
        Per-request timeout in seconds (default ``10.0``).

    Returns
    -------
    BizLogicResult
        Contains all parameter test results and, when applicable, the race
        condition result.
    """
    result = BizLogicResult(endpoint=endpoint)
    headers = {"Authorization": f"Bearer {auth_token}"}

    # ------------------------------------------------------------------
    # Parameter manipulation tests (Req. 9.1)
    # ------------------------------------------------------------------
    for param_name in list(params.keys()):
        original_value = params[param_name]
        # Only test numeric (int/float) parameters per Req. 9.1
        if not isinstance(original_value, (int, float)):
            continue

        for payload_value in _TEST_PAYLOADS:
            test_payload = dict(params)
            test_payload[param_name] = payload_value

            probe = _send_request(
                method=method,
                endpoint=endpoint,
                payload=test_payload,
                headers=headers,
                timeout=timeout,
                param_name=param_name,
                payload_value=payload_value,
            )
            result.parameter_results.append(probe)
            _log_request(audit_logger, method, endpoint, test_payload, probe)

    # ------------------------------------------------------------------
    # Race condition test (Req. 9.3)
    # ------------------------------------------------------------------
    if enable_race:
        race = _run_race_condition(
            method=method,
            endpoint=endpoint,
            params=params,
            headers=headers,
            audit_logger=audit_logger,
            timeout=_RACE_TIMEOUT_S,
        )
        result.race_results = race

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _send_request(
    method: str,
    endpoint: str,
    payload: dict,
    headers: dict,
    timeout: float,
    param_name: str,
    payload_value: Any,
) -> ParamTestResult:
    """Send a single HTTP request and return a ``ParamTestResult``."""
    try:
        resp = requests.request(
            method=method,
            url=endpoint,
            json=payload,
            headers=headers,
            timeout=timeout,
            verify=False,  # noqa: S501 — audit tool in controlled academic context
        )
        body_bytes = resp.content
        body_size = len(body_bytes)
        response_fields = _extract_json_fields(resp)
        return ParamTestResult(
            param_name=param_name,
            payload_value=payload_value,
            status_code=resp.status_code,
            body_size=body_size,
            response_fields=response_fields,
        )
    except requests.exceptions.Timeout as exc:
        error_msg = f"Timeout on {method} {endpoint}: {exc}"
        logger.warning(error_msg)
        return ParamTestResult(
            param_name=param_name,
            payload_value=payload_value,
            status_code=None,
            body_size=0,
            response_fields=[],
            error=error_msg,
        )
    except requests.exceptions.RequestException as exc:
        error_msg = f"Request error on {method} {endpoint}: {exc}"
        logger.error(error_msg)
        return ParamTestResult(
            param_name=param_name,
            payload_value=payload_value,
            status_code=None,
            body_size=0,
            response_fields=[],
            error=error_msg,
        )


def _log_request(
    audit_logger: AuditLogger,
    method: str,
    endpoint: str,
    payload: dict,
    probe: ParamTestResult,
) -> None:
    """Append a ``biz_request`` audit event for a single request (Req. 9.6)."""
    log_record = mask_business_logic_payload(
        method=method,
        endpoint=endpoint,
        payload=payload,
        status_code=probe.status_code if probe.status_code is not None else -1,
        body_size=probe.body_size,
    )
    event = AuditEvent(
        timestamp=log_record["timestamp"],
        event_type="biz_request",
        target=endpoint,
        module="business_logic",
        detail=log_record,
    )
    audit_logger.log(event)


def _run_race_condition(
    method: str,
    endpoint: str,
    params: dict,
    headers: dict,
    audit_logger: AuditLogger,
    timeout: float = _RACE_TIMEOUT_S,
) -> RaceResult:
    """Fire exactly 3 concurrent requests and return a ``RaceResult`` (Req. 9.3).

    All responses received within *timeout* seconds are collected. Requests
    that time out are counted in ``RaceResult.timed_out_count`` and logged.
    """
    results: list[ParamTestResult] = []
    timed_out = 0

    # Use None as param_name/payload_value for race condition requests
    _param_name = "__race__"
    _payload_value = None

    def _task() -> ParamTestResult:
        return _send_request(
            method=method,
            endpoint=endpoint,
            payload=params,
            headers=headers,
            timeout=timeout,
            param_name=_param_name,
            payload_value=_payload_value,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=_RACE_CONCURRENCY) as executor:
        futures = [executor.submit(_task) for _ in range(_RACE_CONCURRENCY)]
        for future in concurrent.futures.as_completed(futures, timeout=timeout):
            try:
                probe = future.result()
                results.append(probe)
                _log_request(audit_logger, method, endpoint, params, probe)
            except concurrent.futures.TimeoutError:
                timed_out += 1
                error_msg = f"Race condition request timed out on {endpoint}"
                logger.warning(error_msg)
                timeout_probe = ParamTestResult(
                    param_name=_param_name,
                    payload_value=_payload_value,
                    status_code=None,
                    body_size=0,
                    response_fields=[],
                    error=error_msg,
                )
                results.append(timeout_probe)
                _log_request(audit_logger, method, endpoint, params, timeout_probe)

    # Pad to exactly _RACE_CONCURRENCY results if we got fewer (e.g. all timed out)
    while len(results) < _RACE_CONCURRENCY:
        timed_out += 1
        error_msg = f"Race condition request did not complete within {timeout}s"
        timeout_probe = ParamTestResult(
            param_name=_param_name,
            payload_value=_payload_value,
            status_code=None,
            body_size=0,
            response_fields=[],
            error=error_msg,
        )
        results.append(timeout_probe)
        _log_request(audit_logger, method, endpoint, params, timeout_probe)

    return RaceResult(responses=results[:_RACE_CONCURRENCY], timed_out_count=timed_out)


def _extract_json_fields(response: requests.Response) -> list[str]:
    """Extract top-level JSON field names from a response body (no values)."""
    try:
        data = response.json()
        if isinstance(data, dict):
            return list(data.keys())
    except (ValueError, Exception):
        pass
    return []
