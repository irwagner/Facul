"""
Business logic classifier (Req. 9.2, 9.4).

``analyze_business_logic`` interprets the :class:`~toolkit.execution.checks.business_logic.BizLogicResult`
produced by the business logic scanner check and classifies it according to
the following decision rules:

* **Parameter manipulation confirmed** (critical severity, ``status="confirmed"``)
  — iff a withdrawal request that sent a *negative* value returned HTTP 200
  AND the response body contained a balance or confirmation field
  (Req. 9.2).

* **Race condition confirmed** (critical severity, ``status="confirmed"``) —
  iff **2 or more** of the 3 simultaneous race-condition responses returned
  HTTP 200 AND contained a balance or confirmation field (Req. 9.4).

When the confirming condition is not met, a ``not_vulnerable`` finding is
returned for the corresponding check.

Evidence only references structural field names — never sensitive values —
in line with the non-exposure invariant (Req. 9.5).

Requirements: 9.2, 9.4
"""

from __future__ import annotations

import logging
from typing import Any

from toolkit.execution.checks.business_logic import (
    BizLogicResult,
    ParamTestResult,
    RaceResult,
)
from toolkit.models import Finding

__all__ = [
    "analyze_business_logic",
    "has_balance_or_confirmation_field",
    "is_parameter_manipulation",
    "is_race_condition",
    "BALANCE_CONFIRMATION_TOKENS",
]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Balance / confirmation field detection (Req. 9.2, 9.4)
# ---------------------------------------------------------------------------

# A response body field is treated as a balance/confirmation indicator when
# its (lower-cased) name contains one of these tokens. Substring matching is
# used so common variants (``new_balance``, ``available_balance``,
# ``confirmation_id``, ``confirmed``, ``confirmacao``) are all recognised.
BALANCE_CONFIRMATION_TOKENS: tuple[str, ...] = (
    "balance",
    "saldo",
    "confirm",   # matches confirmation, confirmed, confirmacao, ...
)

# Race condition decision threshold (Req. 9.4): 2 of 3 simultaneous responses.
_RACE_CONFIRM_THRESHOLD = 2

# Finding ID counter (simple monotonic sequence within a process lifetime).
_finding_counter: int = 0


def _next_finding_id() -> str:
    global _finding_counter
    _finding_counter += 1
    return f"BIZLOGIC-{_finding_counter:03d}"


# ---------------------------------------------------------------------------
# Decision predicates
# ---------------------------------------------------------------------------

def has_balance_or_confirmation_field(fields: list[str]) -> bool:
    """Return ``True`` if *fields* contains a balance or confirmation field.

    A field qualifies when its lower-cased name contains any token in
    :data:`BALANCE_CONFIRMATION_TOKENS` (``balance``, ``saldo``, ``confirm``).

    Parameters
    ----------
    fields:
        Top-level JSON field names extracted from a response body (no values).

    Returns
    -------
    bool
        ``True`` when at least one field is a balance/confirmation indicator.
    """
    for field_name in fields:
        lowered = field_name.lower()
        if any(token in lowered for token in BALANCE_CONFIRMATION_TOKENS):
            return True
    return False


def _is_negative_value(value: Any) -> bool:
    """Return ``True`` when *value* is a negative numeric payload (Req. 9.2)."""
    # bool is a subclass of int — exclude it explicitly.
    if isinstance(value, bool):
        return False
    return isinstance(value, (int, float)) and value < 0


def is_parameter_manipulation(probe: ParamTestResult) -> bool:
    """Return ``True`` iff *probe* confirms a parameter manipulation (Req. 9.2).

    The bicondition: a withdrawal request that sent a negative value returned
    HTTP 200 AND the response body contained a balance or confirmation field.
    """
    return (
        _is_negative_value(probe.payload_value)
        and probe.status_code == 200
        and has_balance_or_confirmation_field(probe.response_fields)
    )


def is_race_condition(responses: list[ParamTestResult]) -> bool:
    """Return ``True`` iff *responses* confirm a race condition (Req. 9.4).

    The bicondition: 2 or more of the (3) simultaneous responses returned HTTP
    200 AND contained a balance or confirmation field.
    """
    success_count = sum(
        1
        for r in responses
        if r.status_code == 200 and has_balance_or_confirmation_field(r.response_fields)
    )
    return success_count >= _RACE_CONFIRM_THRESHOLD


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def analyze_business_logic(result: BizLogicResult) -> list[Finding]:
    """Classify a :class:`BizLogicResult` into a list of Findings (Req. 9.2, 9.4).

    Parameters
    ----------
    result:
        The aggregated result produced by ``check_business_logic`` containing
        the parameter-manipulation probes and, optionally, the race-condition
        probe.

    Returns
    -------
    list[Finding]
        A list with:

        * One parameter-manipulation finding — ``confirmed`` (critical) when a
          negative-value withdrawal returned HTTP 200 with a balance/
          confirmation field, otherwise ``not_vulnerable``.
        * One race-condition finding when ``result.race_results`` is present —
          ``confirmed`` (critical) when ≥2 of 3 responses returned HTTP 200
          with a balance/confirmation field, otherwise ``not_vulnerable``.

    Requirements: 9.2, 9.4
    """
    findings: list[Finding] = []

    findings.append(_classify_parameter_manipulation(result))

    if result.race_results is not None:
        findings.append(_classify_race_condition(result.endpoint, result.race_results))

    return findings


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _classify_parameter_manipulation(result: BizLogicResult) -> Finding:
    """Build the parameter-manipulation finding for *result* (Req. 9.2)."""
    confirming = next(
        (p for p in result.parameter_results if is_parameter_manipulation(p)),
        None,
    )

    if confirming is not None:
        fields = ", ".join(confirming.response_fields) or "(none)"
        return Finding(
            id=_next_finding_id(),
            title="Business Logic — Parameter Manipulation",
            summary=(
                f"Withdrawal request to {result.endpoint!r} with a negative value for "
                f"parameter {confirming.param_name!r} returned HTTP 200 with a balance "
                "or confirmation field, indicating the negative amount was accepted."
            ),
            severity="critical",
            confidence="high",
            status="confirmed",
            affected_endpoint=result.endpoint,
            evidence=(
                f"Negative payload accepted; HTTP 200 response fields: {fields}."
            ),
            impact=(
                "An attacker can manipulate financial amounts (e.g. negative withdrawal) "
                "to credit their own balance or bypass intended business constraints, "
                "causing direct financial loss."
            ),
            remediation=(
                "Enforce server-side range validation on all financial parameters "
                "(reject negative and out-of-range values) and use atomic transactions "
                "for balance updates."
            ),
            next_steps=[
                "Reproduce the negative-value withdrawal manually to confirm the impact.",
                "Add server-side validation rejecting non-positive amounts.",
                "Audit all financial endpoints for equivalent input validation gaps.",
            ],
            references=[
                "CWE-840: Business Logic Errors",
                "OWASP API Security Top 10: API6:2023 Unrestricted Access to Sensitive Business Flows",
            ],
        )

    return Finding(
        id=_next_finding_id(),
        title="Business Logic — Parameter Manipulation Check",
        summary=(
            f"No parameter manipulation confirmed on {result.endpoint!r}: no negative-value "
            "withdrawal returned HTTP 200 with a balance or confirmation field."
        ),
        severity="low",
        confidence="medium",
        status="not_vulnerable",
        affected_endpoint=result.endpoint,
        evidence="No negative-value payload produced a confirming HTTP 200 response.",
        impact="No impact — negative-value manipulations were not accepted.",
        remediation="No action required; continue monitoring input validation.",
        next_steps=[
            "Continue testing other business logic flows.",
        ],
        references=[
            "CWE-840: Business Logic Errors",
        ],
    )


def _classify_race_condition(endpoint: str, race: RaceResult) -> Finding:
    """Build the race-condition finding for *race* (Req. 9.4)."""
    success_count = sum(
        1
        for r in race.responses
        if r.status_code == 200 and has_balance_or_confirmation_field(r.response_fields)
    )

    if is_race_condition(race.responses):
        return Finding(
            id=_next_finding_id(),
            title="Business Logic — Race Condition",
            summary=(
                f"{success_count} of {len(race.responses)} simultaneous requests to "
                f"{endpoint!r} returned HTTP 200 with a balance or confirmation field, "
                "indicating a race condition in the withdrawal flow."
            ),
            severity="critical",
            confidence="high",
            status="confirmed",
            affected_endpoint=endpoint,
            evidence=(
                f"{success_count}/{len(race.responses)} concurrent responses succeeded "
                f"(HTTP 200 with balance/confirmation field); "
                f"{race.timed_out_count} request(s) timed out."
            ),
            impact=(
                "Concurrent withdrawals can be processed against the same balance, "
                "allowing an attacker to withdraw more than the available funds "
                "(double-spend), causing direct financial loss."
            ),
            remediation=(
                "Use database-level locks (e.g. SELECT ... FOR UPDATE) or atomic "
                "transactions for balance updates so concurrent requests are serialised."
            ),
            next_steps=[
                "Reproduce the race condition with concurrent requests to confirm impact.",
                "Introduce row-level locking or atomic decrement on balance updates.",
                "Add idempotency keys to financial operations.",
            ],
            references=[
                "CWE-362: Concurrent Execution using Shared Resource ('Race Condition')",
                "OWASP API Security Top 10: API6:2023 Unrestricted Access to Sensitive Business Flows",
            ],
        )

    return Finding(
        id=_next_finding_id(),
        title="Business Logic — Race Condition Check",
        summary=(
            f"No race condition confirmed on {endpoint!r}: only {success_count} of "
            f"{len(race.responses)} simultaneous requests returned HTTP 200 with a "
            "balance or confirmation field (threshold is 2)."
        ),
        severity="low",
        confidence="medium",
        status="not_vulnerable",
        affected_endpoint=endpoint,
        evidence=(
            f"{success_count}/{len(race.responses)} concurrent responses succeeded; "
            f"{race.timed_out_count} request(s) timed out."
        ),
        impact="No impact — concurrent requests did not produce multiple confirmations.",
        remediation="No action required; consider locks as defence in depth.",
        next_steps=[
            "Continue testing other business logic flows.",
        ],
        references=[
            "CWE-362: Concurrent Execution using Shared Resource ('Race Condition')",
        ],
    )
