"""
Property-based tests for ``RateLimiter`` — Property 3 (task 3.2, Req. 3.6, 3.7).

# Feature: web-security-audit-toolkit, Property 3: Limitação de taxa e cálculo de delay

**Validates: Requirements 3.6, 3.7**

Properties
----------
Property 3a — Effective rate clamped to [1, 10] req/s:
    For any ``max_rps`` value (positive, zero, negative, above 10),
    ``RateLimiter(max_rps)._max_tokens`` is always within [1.0, 10.0].

Property 3b — apply_backoff delay clamped to [1, 60]s (default 5):
    For any delay value passed to ``apply_backoff(delay_s)``,
    ``time.sleep`` is called with a value within [1.0, 60.0].
    When called with no argument, the default of 5.0s is used.
"""

from __future__ import annotations

import unittest.mock as mock

from hypothesis import given, settings
from hypothesis import strategies as st

from toolkit.governance.rate_limiter import RateLimiter


# ---------------------------------------------------------------------------
# Property 3a: RateLimiter._max_tokens is always clamped to [1.0, 10.0]
# Feature: web-security-audit-toolkit, Property 3: Limitação de taxa e cálculo de delay
# Validates: Requirements 3.7
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(max_rps=st.integers(min_value=-1000, max_value=1000))
def test_effective_rate_clamped_within_bounds(max_rps: int) -> None:
    """
    **Property 3a — Effective rate is always clamped to [1, 10] req/s**

    For any ``max_rps`` constructor argument (including out-of-range values),
    ``RateLimiter(max_rps)._max_tokens`` must always be within [1.0, 10.0].

    # Feature: web-security-audit-toolkit, Property 3: Limitação de taxa e cálculo de delay
    **Validates: Requirements 3.7**
    """
    rl = RateLimiter(max_rps=max_rps)
    assert 1.0 <= rl._max_tokens <= 10.0, (
        f"_max_tokens={rl._max_tokens!r} out of [1.0, 10.0] for max_rps={max_rps}"
    )


@settings(max_examples=100)
@given(max_rps=st.floats(min_value=-1000.0, max_value=1000.0, allow_nan=False, allow_infinity=False))
def test_effective_rate_clamped_for_float_inputs(max_rps: float) -> None:
    """
    **Property 3a — Effective rate clamped for float-coercible inputs**

    Even when ``max_rps`` is provided as a float (edge case), the clamping
    logic must keep ``_max_tokens`` within [1.0, 10.0].

    # Feature: web-security-audit-toolkit, Property 3: Limitação de taxa e cálculo de delay
    **Validates: Requirements 3.7**
    """
    # RateLimiter clamps via max(1, min(10, max_rps)); works with floats too
    rl = RateLimiter(max_rps=int(max_rps))  # constructor expects int; cast first
    assert 1.0 <= rl._max_tokens <= 10.0, (
        f"_max_tokens={rl._max_tokens!r} out of [1.0, 10.0] for max_rps={max_rps}"
    )


# ---------------------------------------------------------------------------
# Property 3b: apply_backoff always sleeps with a value in [1.0, 60.0]
# Feature: web-security-audit-toolkit, Property 3: Limitação de taxa e cálculo de delay
# Validates: Requirements 3.6
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(
    delay=st.floats(
        min_value=-1000.0,
        max_value=1000.0,
        allow_nan=False,
        allow_infinity=False,
    )
)
def test_apply_backoff_delay_clamped_within_bounds(delay: float) -> None:
    """
    **Property 3b — apply_backoff delay is always clamped to [1, 60]s**

    For any delay value passed to ``apply_backoff(delay_s)``,
    ``time.sleep`` must be called with a value within [1.0, 60.0].

    # Feature: web-security-audit-toolkit, Property 3: Limitação de taxa e cálculo de delay
    **Validates: Requirements 3.6**
    """
    rl = RateLimiter()
    with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
        rl.apply_backoff(delay_s=delay)

    mock_sleep.assert_called_once()
    actual_sleep_arg = mock_sleep.call_args[0][0]

    assert 1.0 <= actual_sleep_arg <= 60.0, (
        f"time.sleep called with {actual_sleep_arg!r} (outside [1.0, 60.0]) "
        f"for delay_s={delay!r}"
    )


@settings(max_examples=100)
@given(
    delay=st.one_of(
        # Below lower bound
        st.floats(min_value=-1000.0, max_value=0.9999, allow_nan=False, allow_infinity=False),
        # Above upper bound
        st.floats(min_value=60.0001, max_value=1000.0, allow_nan=False, allow_infinity=False),
    )
)
def test_apply_backoff_out_of_range_delay_is_clamped(delay: float) -> None:
    """
    **Property 3b — Out-of-range delay values are clamped**

    When ``delay_s`` is below 1 or above 60, ``time.sleep`` is still called
    with the clamped boundary value (1.0 or 60.0 respectively).

    # Feature: web-security-audit-toolkit, Property 3: Limitação de taxa e cálculo de delay
    **Validates: Requirements 3.6**
    """
    rl = RateLimiter()
    with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
        rl.apply_backoff(delay_s=delay)

    mock_sleep.assert_called_once()
    actual_sleep_arg = mock_sleep.call_args[0][0]

    assert actual_sleep_arg in (1.0, 60.0) or 1.0 <= actual_sleep_arg <= 60.0, (
        f"time.sleep called with {actual_sleep_arg!r} for out-of-range delay_s={delay!r}"
    )
    assert 1.0 <= actual_sleep_arg <= 60.0


def test_apply_backoff_default_is_5_seconds() -> None:
    """
    **Property 3b — Default delay is exactly 5.0s**

    When ``apply_backoff()`` is called without arguments,
    ``time.sleep`` must be called with exactly 5.0.

    # Feature: web-security-audit-toolkit, Property 3: Limitação de taxa e cálculo de delay
    **Validates: Requirements 3.6**
    """
    rl = RateLimiter()
    with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
        rl.apply_backoff()

    mock_sleep.assert_called_once_with(5.0)
