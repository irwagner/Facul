"""
Property-based tests for ``RateLimiter`` (task 3.2, Req. 3.6, 3.7).

# Feature: web-security-audit-toolkit, Property 3: Limitação de taxa e cálculo de delay

**Validates: Requirements 3.6, 3.7**

Properties
----------
1. For any ``max_rps`` value (positive, zero, negative, above 10),
   ``RateLimiter(max_rps)._max_tokens`` is always within [1.0, 10.0].

2. For any delay value passed to ``apply_backoff(delay_s)``,
   ``time.sleep`` is called with a value within [1.0, 60.0].
"""

from __future__ import annotations

import unittest.mock as mock

from hypothesis import given, settings
from hypothesis import strategies as st

from toolkit.governance.rate_limiter import RateLimiter


# ---------------------------------------------------------------------------
# Property 1: RateLimiter._max_tokens is always clamped to [1.0, 10.0]
# Validates: Requirements 3.7
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(max_rps=st.integers(min_value=-1000, max_value=1000))
def test_max_tokens_always_within_bounds(max_rps: int) -> None:
    """
    Property 1: For any ``max_rps`` value, ``RateLimiter(max_rps)._max_tokens``
    is always within [1.0, 10.0].

    Validates: Requirements 3.7
    """
    rl = RateLimiter(max_rps=max_rps)
    assert 1.0 <= rl._max_tokens <= 10.0, (
        f"_max_tokens={rl._max_tokens!r} out of [1.0, 10.0] for max_rps={max_rps}"
    )


# ---------------------------------------------------------------------------
# Property 2: apply_backoff always calls time.sleep with a value in [1.0, 60.0]
# Validates: Requirements 3.6
# ---------------------------------------------------------------------------

@settings(max_examples=100)
@given(delay=st.floats(min_value=-1000.0, max_value=1000.0, allow_nan=False, allow_infinity=False))
def test_apply_backoff_sleep_within_bounds(delay: float) -> None:
    """
    Property 2: For any delay value passed to ``apply_backoff(delay_s)``,
    ``time.sleep`` is called with a value within [1.0, 60.0].

    Validates: Requirements 3.6
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
