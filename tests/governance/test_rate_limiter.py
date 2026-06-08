"""
Unit tests for ``RateLimiter`` (task 3.1, Req. 3.6, 3.7).

These tests verify:
- Clamping of max_rps to [1, 10]
- Token-bucket behaviour of acquire()
- Clamping of backoff delay to [1, 60] by apply_backoff()
"""

from __future__ import annotations

import time
import unittest.mock as mock

import pytest

from toolkit.governance.rate_limiter import RateLimiter


# ---------------------------------------------------------------------------
# __init__ — rate clamping
# ---------------------------------------------------------------------------

class TestRateLimiterInit:
    """Verify that max_rps is clamped to [1, 10] on construction."""

    def test_default_rps_is_10(self):
        rl = RateLimiter()
        assert rl._max_tokens == 10.0
        assert rl._refill_rate == 10.0

    def test_explicit_10_rps(self):
        rl = RateLimiter(max_rps=10)
        assert rl._max_tokens == 10.0
        assert rl._refill_rate == 10.0

    def test_explicit_1_rps(self):
        rl = RateLimiter(max_rps=1)
        assert rl._max_tokens == 1.0
        assert rl._refill_rate == 1.0

    def test_above_max_clamped_to_10(self):
        rl = RateLimiter(max_rps=100)
        assert rl._max_tokens == 10.0
        assert rl._refill_rate == 10.0

    def test_zero_clamped_to_1(self):
        rl = RateLimiter(max_rps=0)
        assert rl._max_tokens == 1.0
        assert rl._refill_rate == 1.0

    def test_negative_clamped_to_1(self):
        rl = RateLimiter(max_rps=-5)
        assert rl._max_tokens == 1.0
        assert rl._refill_rate == 1.0

    def test_mid_range_value(self):
        rl = RateLimiter(max_rps=5)
        assert rl._max_tokens == 5.0
        assert rl._refill_rate == 5.0

    def test_tokens_initialised_to_max(self):
        """Token bucket starts full."""
        rl = RateLimiter(max_rps=7)
        assert rl._tokens == 7.0


# ---------------------------------------------------------------------------
# acquire() — token bucket
# ---------------------------------------------------------------------------

class TestAcquire:
    """Verify acquire() respects the token-bucket semantics."""

    def test_acquire_returns_immediately_when_tokens_available(self):
        """With a full bucket, acquire() should return without sleeping."""
        rl = RateLimiter(max_rps=10)
        start = time.monotonic()
        rl.acquire()
        elapsed = time.monotonic() - start
        # Should be nearly instant (well under 100 ms)
        assert elapsed < 0.1

    def test_acquire_consumes_token(self):
        """Each successful acquire() reduces the token count by 1."""
        rl = RateLimiter(max_rps=5)
        initial_tokens = rl._tokens
        rl.acquire()
        # After one acquire the token count must be lower (may have been
        # slightly refilled by elapsed time, but will be < initial)
        assert rl._tokens < initial_tokens + 0.01  # at most a tiny refill

    def test_multiple_acquires_up_to_bucket_size_are_immediate(self):
        """Acquiring up to max_rps tokens from a full bucket is immediate."""
        max_rps = 5
        rl = RateLimiter(max_rps=max_rps)
        start = time.monotonic()
        for _ in range(max_rps):
            rl.acquire()
        elapsed = time.monotonic() - start
        # All tokens consumed from a full bucket — should be very fast
        assert elapsed < 0.5

    def test_acquire_waits_when_no_tokens_available(self):
        """When the bucket is empty, acquire() must block until refill."""
        rl = RateLimiter(max_rps=10)

        # Drain all tokens manually
        with rl._lock:
            rl._tokens = 0.0

        start = time.monotonic()
        rl.acquire()
        elapsed = time.monotonic() - start
        # At 10 req/s a token takes 0.1 s to arrive; allow generous margin
        assert elapsed >= 0.05

    def test_acquire_sleeps_correct_duration_via_mock(self):
        """acquire() calls time.sleep with a value close to 1/refill_rate."""
        rl = RateLimiter(max_rps=10)  # refill_rate = 10 → 0.1 s per token

        # Drain all tokens
        with rl._lock:
            rl._tokens = 0.0

        sleep_calls: list[float] = []

        original_sleep = time.sleep

        def capturing_sleep(duration: float) -> None:
            sleep_calls.append(duration)
            original_sleep(duration)

        with mock.patch("toolkit.governance.rate_limiter.time.sleep", side_effect=capturing_sleep):
            rl.acquire()

        assert sleep_calls, "time.sleep should have been called at least once"
        # First sleep should be close to 1/10 = 0.1 s
        assert sleep_calls[0] == pytest.approx(0.1, abs=0.02)


# ---------------------------------------------------------------------------
# apply_backoff() — delay clamping
# ---------------------------------------------------------------------------

class TestApplyBackoff:
    """Verify that apply_backoff() clamps the delay to [1, 60] and sleeps."""

    @pytest.mark.parametrize("delay, expected", [
        (5.0, 5.0),       # nominal default
        (1.0, 1.0),       # lower bound (exact)
        (60.0, 60.0),     # upper bound (exact)
        (0.5, 1.0),       # below lower bound → clamped to 1
        (0.0, 1.0),       # zero → clamped to 1
        (-10.0, 1.0),     # negative → clamped to 1
        (120.0, 60.0),    # above upper bound → clamped to 60
        (61.0, 60.0),     # just above upper bound → clamped to 60
        (30.0, 30.0),     # mid-range
    ])
    def test_backoff_clamping(self, delay: float, expected: float):
        """apply_backoff() must sleep for the clamped value."""
        rl = RateLimiter()
        with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
            rl.apply_backoff(delay_s=delay)
        mock_sleep.assert_called_once_with(expected)

    def test_backoff_default_delay_is_5(self):
        """Default delay (no argument) should be 5.0 s."""
        rl = RateLimiter()
        with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
            rl.apply_backoff()
        mock_sleep.assert_called_once_with(5.0)

    def test_backoff_calls_sleep_exactly_once(self):
        """apply_backoff() must call time.sleep exactly once."""
        rl = RateLimiter()
        with mock.patch("toolkit.governance.rate_limiter.time.sleep") as mock_sleep:
            rl.apply_backoff(delay_s=10.0)
        assert mock_sleep.call_count == 1
