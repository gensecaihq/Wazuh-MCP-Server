"""
CircuitBreaker state-machine tests.

Regression focus: a half-open trial that raises an exception outside the monitored
set (or a 429 throttle) must not strand the breaker HALF_OPEN with the single-trial
gate stuck set — that bug returned HTTP 503 for every subsequent call until restart.
"""

import httpx
import pytest

from wazuh_mcp_server.resilience import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState


def _breaker(**overrides):
    cfg = CircuitBreakerConfig(
        failure_threshold=overrides.pop("failure_threshold", 1),
        recovery_timeout=overrides.pop("recovery_timeout", 0),  # 0 → immediately eligible to trial
        expected_exception=overrides.pop("expected_exception", (ConnectionError, httpx.HTTPStatusError)),
        **overrides,
    )
    return CircuitBreaker(cfg)


async def _raise(exc):
    raise exc


async def _ok():
    return "ok"


class TestHalfOpenRecovery:
    @pytest.mark.asyncio
    async def test_unexpected_exception_during_trial_does_not_deadlock(self):
        """The core regression: an unmonitored exception in the half-open trial must
        release the gate and return to OPEN, so recovery can still happen."""
        cb = _breaker()

        # Trip the breaker with a monitored failure.
        with pytest.raises(ConnectionError):
            await cb._call(_raise, ConnectionError("down"))
        assert cb.state == CircuitBreakerState.OPEN

        # Recovery-eligible (recovery_timeout=0): the trial raises an UNEXPECTED type.
        with pytest.raises(ValueError):
            await cb._call(_raise, ValueError("bad json"))

        # Must not be stuck: gate released, back to OPEN.
        assert cb._half_open_trial_in_progress is False
        assert cb.state == CircuitBreakerState.OPEN

        # A subsequent healthy call must be allowed to trial and close the circuit.
        assert await cb._call(_ok) == "ok"
        assert cb.state == CircuitBreakerState.CLOSED

    @pytest.mark.asyncio
    async def test_429_during_trial_returns_to_open_without_counting_failure(self):
        cb = _breaker(failure_threshold=5)

        # Open it with 5 monitored failures.
        for _ in range(5):
            with pytest.raises(ConnectionError):
                await cb._call(_raise, ConnectionError("down"))
        assert cb.state == CircuitBreakerState.OPEN
        assert cb.failure_count == 5

        # Trial hits a 429 throttle: not a monitored failure, but the trial is unproven.
        resp = httpx.Response(429, request=httpx.Request("GET", "http://x"))
        with pytest.raises(httpx.HTTPStatusError):
            await cb._call(_raise, httpx.HTTPStatusError("throttled", request=resp.request, response=resp))

        assert cb._half_open_trial_in_progress is False
        assert cb.state == CircuitBreakerState.OPEN
        # 429 must not have incremented the failure count.
        assert cb.failure_count == 5

        # Recovery still works on the next healthy call.
        assert await cb._call(_ok) == "ok"
        assert cb.state == CircuitBreakerState.CLOSED

    @pytest.mark.asyncio
    async def test_unexpected_exception_in_closed_state_does_not_open(self):
        cb = _breaker(failure_threshold=2)
        with pytest.raises(ValueError):
            await cb._call(_raise, ValueError("user error"))
        # Unexpected exceptions are not monitored failures.
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.failure_count == 0

    @pytest.mark.asyncio
    async def test_expected_failures_open_then_success_closes(self):
        cb = _breaker(failure_threshold=3)
        for _ in range(3):
            with pytest.raises(ConnectionError):
                await cb._call(_raise, ConnectionError("down"))
        assert cb.state == CircuitBreakerState.OPEN
        assert await cb._call(_ok) == "ok"
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.failure_count == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
