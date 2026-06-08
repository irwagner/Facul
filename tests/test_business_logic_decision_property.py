"""
Property-based tests for the business logic decision classifier.

# Feature: web-security-audit-toolkit, Property 18: Decisão de manipulação de parâmetro e race condition

**Validates: Requirements 9.2, 9.4**

Property 18: Decisão de manipulação de parâmetro e race condition
-----------------------------------------------------------------
For every response to a *negative-value* withdrawal operation, the Analyzer
confirms a parameter manipulation finding of **critical** severity **iff** the
status is 200 and the body contains a balance or confirmation field.

For every trio of race-condition responses, the Analyzer confirms a race
condition finding of **critical** severity **iff** 2 or more of the 3 responses
have status 200 with a balance/confirmation field.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from toolkit.analysis.classifiers.business_logic import (
    BALANCE_CONFIRMATION_TOKENS,
    analyze_business_logic,
    has_balance_or_confirmation_field,
)
from toolkit.execution.checks.business_logic import (
    BizLogicResult,
    ParamTestResult,
    RaceResult,
)

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

ENDPOINT = "https://bank.example.com/api/withdraw"

# Field names that ARE balance/confirmation indicators.
_balance_fields = st.sampled_from(
    ["balance", "new_balance", "available_balance", "saldo", "confirmation", "confirmed"]
)

# Field names that are NOT balance/confirmation indicators.
_neutral_fields = st.sampled_from(
    ["id", "name", "status_text", "message", "amount", "currency", "timestamp"]
)

# Negative numeric payloads (Req. 9.2 — withdrawal with negative value).
_negative_payloads = st.one_of(
    st.integers(max_value=-1),
    st.floats(min_value=-1e9, max_value=-1e-9, allow_nan=False, allow_infinity=False),
)

# Status codes, biased to include 200 frequently.
_status_codes = st.sampled_from([200, 200, 200, 201, 400, 403, 404, 500])


def _fields_with_flag(has_balance: bool) -> st.SearchStrategy[list[str]]:
    """Generate a field list whose balance/confirmation membership == has_balance."""
    if has_balance:
        return st.lists(_neutral_fields, max_size=3).flatmap(
            lambda neutral: _balance_fields.map(lambda b: neutral + [b])
        )
    # No balance field — only neutral fields (possibly empty).
    return st.lists(_neutral_fields, max_size=4)


# ---------------------------------------------------------------------------
# Property 18a — parameter manipulation bicondition
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    payload=_negative_payloads,
    status=_status_codes,
    has_balance=st.booleans(),
    extra=st.data(),
)
def test_property18_parameter_manipulation_bicondition(
    payload, status: int, has_balance: bool, extra
) -> None:
    """
    Property 18: Decisão de manipulação de parâmetro.

    **Validates: Requirements 9.2**

    A negative-value withdrawal is confirmed (critical) iff status == 200 AND
    the body contains a balance/confirmation field.
    """
    fields = extra.draw(_fields_with_flag(has_balance))

    probe = ParamTestResult(
        param_name="amount",
        payload_value=payload,
        status_code=status,
        body_size=len(str(fields)),
        response_fields=fields,
    )
    result = BizLogicResult(endpoint=ENDPOINT, parameter_results=[probe])

    findings = analyze_business_logic(result)
    # Exactly one parameter-manipulation finding when no race results.
    assert len(findings) == 1
    finding = findings[0]

    should_confirm = status == 200 and has_balance_or_confirmation_field(fields)

    if should_confirm:
        assert finding.status == "confirmed", (
            f"Expected confirmed for status={status}, fields={fields}"
        )
        assert finding.severity == "critical"
    else:
        assert finding.status == "not_vulnerable", (
            f"Expected not_vulnerable for status={status}, fields={fields}"
        )


# ---------------------------------------------------------------------------
# Property 18b — race condition bicondition (>=2 of 3)
# ---------------------------------------------------------------------------

@settings(max_examples=200)
@given(
    responses_spec=st.lists(
        st.tuples(_status_codes, st.booleans()),
        min_size=3,
        max_size=3,
    ),
    timed_out=st.integers(min_value=0, max_value=3),
    extra=st.data(),
)
def test_property18_race_condition_bicondition(
    responses_spec, timed_out: int, extra
) -> None:
    """
    Property 18: Decisão de race condition.

    **Validates: Requirements 9.4**

    A race condition is confirmed (critical) iff 2 or more of the 3 responses
    have status 200 AND a balance/confirmation field.
    """
    responses: list[ParamTestResult] = []
    success_count = 0
    for status, has_balance in responses_spec:
        fields = extra.draw(_fields_with_flag(has_balance))
        if status == 200 and has_balance_or_confirmation_field(fields):
            success_count += 1
        responses.append(
            ParamTestResult(
                param_name="__race__",
                payload_value=None,
                status_code=status,
                body_size=len(str(fields)),
                response_fields=fields,
            )
        )

    race = RaceResult(responses=responses, timed_out_count=timed_out)
    result = BizLogicResult(endpoint=ENDPOINT, race_results=race)

    findings = analyze_business_logic(result)
    # One param-manipulation finding (no param probes -> not_vulnerable) + one race finding.
    race_findings = [f for f in findings if "Race Condition" in f.title]
    assert len(race_findings) == 1
    race_finding = race_findings[0]

    should_confirm = success_count >= 2

    if should_confirm:
        assert race_finding.status == "confirmed", (
            f"Expected confirmed: success_count={success_count}, spec={responses_spec}"
        )
        assert race_finding.severity == "critical"
    else:
        assert race_finding.status == "not_vulnerable", (
            f"Expected not_vulnerable: success_count={success_count}, spec={responses_spec}"
        )


# ---------------------------------------------------------------------------
# Example / edge-case checks
# ---------------------------------------------------------------------------

def test_negative_200_with_balance_confirms_critical() -> None:
    """**Validates: Requirements 9.2** — canonical confirming case."""
    probe = ParamTestResult(
        param_name="amount",
        payload_value=-100,
        status_code=200,
        body_size=42,
        response_fields=["new_balance", "id"],
    )
    result = BizLogicResult(endpoint=ENDPOINT, parameter_results=[probe])
    findings = analyze_business_logic(result)
    assert findings[0].status == "confirmed"
    assert findings[0].severity == "critical"


def test_negative_non200_does_not_confirm() -> None:
    """A negative payload that returns 400 is not a manipulation finding."""
    probe = ParamTestResult(
        param_name="amount",
        payload_value=-100,
        status_code=400,
        body_size=10,
        response_fields=["balance"],
    )
    result = BizLogicResult(endpoint=ENDPOINT, parameter_results=[probe])
    findings = analyze_business_logic(result)
    assert findings[0].status == "not_vulnerable"


def test_positive_200_with_balance_does_not_confirm() -> None:
    """A positive payload (not a negative withdrawal) does not confirm manipulation."""
    probe = ParamTestResult(
        param_name="amount",
        payload_value=100,
        status_code=200,
        body_size=10,
        response_fields=["balance"],
    )
    result = BizLogicResult(endpoint=ENDPOINT, parameter_results=[probe])
    findings = analyze_business_logic(result)
    assert findings[0].status == "not_vulnerable"


def test_race_two_of_three_confirms_critical() -> None:
    """**Validates: Requirements 9.4** — exactly 2 of 3 successes confirms."""
    responses = [
        ParamTestResult("__race__", None, 200, 10, ["balance"]),
        ParamTestResult("__race__", None, 200, 10, ["confirmation"]),
        ParamTestResult("__race__", None, 409, 5, ["error"]),
    ]
    race = RaceResult(responses=responses, timed_out_count=0)
    result = BizLogicResult(endpoint=ENDPOINT, race_results=race)
    findings = analyze_business_logic(result)
    race_finding = next(f for f in findings if "Race Condition" in f.title)
    assert race_finding.status == "confirmed"
    assert race_finding.severity == "critical"


def test_race_one_of_three_does_not_confirm() -> None:
    """Only 1 of 3 successes does not meet the threshold."""
    responses = [
        ParamTestResult("__race__", None, 200, 10, ["balance"]),
        ParamTestResult("__race__", None, 409, 5, ["error"]),
        ParamTestResult("__race__", None, 500, 5, ["error"]),
    ]
    race = RaceResult(responses=responses, timed_out_count=0)
    result = BizLogicResult(endpoint=ENDPOINT, race_results=race)
    findings = analyze_business_logic(result)
    race_finding = next(f for f in findings if "Race Condition" in f.title)
    assert race_finding.status == "not_vulnerable"


def test_balance_token_constants_present() -> None:
    """The balance/confirmation token set includes the expected tokens."""
    assert "balance" in BALANCE_CONFIRMATION_TOKENS
    assert "saldo" in BALANCE_CONFIRMATION_TOKENS
    assert "confirm" in BALANCE_CONFIRMATION_TOKENS
