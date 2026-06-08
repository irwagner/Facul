"""
Rate limiter for the Web Security Audit Toolkit.

Implements a token-bucket algorithm to enforce a configurable request rate
(1–10 req/s) and a backoff helper for HTTP 429 responses (1–60 s, default 5 s).

Requirements: 3.6, 3.7
"""

import threading
import time


class RateLimiter:
    """
    Token-bucket rate limiter with configurable max rate and backoff support.

    Parameters
    ----------
    max_rps:
        Maximum requests per second. Clamped to the range [1, 10] (Req. 3.7).
    """

    def __init__(self, max_rps: int = 10) -> None:
        # Clamp to [1, 10] req/s as required by Req. 3.7
        effective_rps = max(1, min(10, max_rps))

        self._max_tokens: float = float(effective_rps)
        self._refill_rate: float = float(effective_rps)  # tokens per second
        self._tokens: float = float(effective_rps)
        self._last_refill: float = time.monotonic()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def acquire(self) -> None:
        """
        Block until a token is available (Req. 3.7).

        Uses a token-bucket algorithm: tokens are added at `_refill_rate`
        tokens per second up to `_max_tokens`. When no token is available,
        the method sleeps for the fractional time needed for the next token
        to arrive and then retries.
        """
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                # Refill tokens based on elapsed time
                self._tokens = min(
                    self._max_tokens,
                    self._tokens + elapsed * self._refill_rate,
                )
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

                # Calculate how long until the next token arrives
                wait = (1.0 - self._tokens) / self._refill_rate

            # Sleep outside the lock so other threads can also check
            time.sleep(wait)

    def apply_backoff(self, delay_s: float = 5.0) -> None:
        """
        Sleep for *delay_s* seconds (clamped to [1, 60]) to back off after
        receiving an HTTP 429 response (Req. 3.6).

        Parameters
        ----------
        delay_s:
            Requested backoff duration in seconds. Values below 1 are raised
            to 1; values above 60 are lowered to 60. Defaults to 5 s.
        """
        clamped = max(1.0, min(60.0, delay_s))
        time.sleep(clamped)
