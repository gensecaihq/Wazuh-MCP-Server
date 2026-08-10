#!/usr/bin/env python3
"""
Production resilience patterns - Circuit breakers, retries, timeouts
Implements comprehensive error handling and recovery mechanisms
"""

import asyncio
import functools
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Optional, Tuple, Type, Union

import httpx
from fastapi import HTTPException
from tenacity import retry, retry_if_exception, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

# Production Constants
GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS = 30


class CircuitBreakerState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreakerConfig:
    """Circuit breaker configuration."""

    failure_threshold: int = 5
    recovery_timeout: int = 60
    expected_exception: Union[Type[Exception], Tuple[Type[Exception], ...]] = Exception
    fallback_function: Optional[Callable] = None


class CircuitBreaker:
    """Circuit breaker implementation with fallback support."""

    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.next_retry_time: Optional[float] = None
        self._lock = asyncio.Lock()
        self._half_open_trial_in_progress = False  # Only allow one trial request in HALF_OPEN

    def __call__(self, func: Callable) -> Callable:
        """Decorator to apply circuit breaker to function."""

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await self._call(func, *args, **kwargs)

        return wrapper

    async def _call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker logic."""

        # Check if circuit is open (under lock to prevent race conditions)
        async with self._lock:
            if self.state == CircuitBreakerState.OPEN:
                if self._should_attempt_reset():
                    if self._half_open_trial_in_progress:
                        # Another coroutine is already running the trial request — reject this one
                        raise HTTPException(
                            status_code=503,
                            detail="Service temporarily unavailable - circuit breaker half-open trial in progress",
                        )
                    self.state = CircuitBreakerState.HALF_OPEN
                    self._half_open_trial_in_progress = True
                    logger.info(f"Circuit breaker {func.__name__} moved to HALF_OPEN")
                else:
                    if self.config.fallback_function:
                        logger.warning(f"Circuit breaker {func.__name__} OPEN, using fallback")
                        return await self.config.fallback_function(*args, **kwargs)
                    else:
                        raise HTTPException(
                            status_code=503, detail="Service temporarily unavailable - circuit breaker open"
                        )
            elif self.state == CircuitBreakerState.HALF_OPEN and self._half_open_trial_in_progress:
                # HALF_OPEN with a trial already running — reject concurrent requests
                raise HTTPException(
                    status_code=503,
                    detail="Service temporarily unavailable - circuit breaker half-open trial in progress",
                )

        try:
            result = await func(*args, **kwargs)
            await self._on_success(func.__name__)
            return result

        except self.config.expected_exception as e:
            if isinstance(e, httpx.HTTPStatusError):
                status = e.response.status_code
                # A 429 is an upstream rate-limit (transient throttle), not a service outage —
                # counting it would turn a soft throttle into a hard circuit-open. Re-raise
                # for the retry layer without recording a circuit failure, but end any in-flight
                # trial cleanly: leaving it HALF_OPEN with the gate released lets concurrent
                # callers run untracked, and a stray success would prematurely close the circuit.
                if status == 429:
                    await self._end_trial_unproven(func.__name__, "429 throttle")
                    raise
                # A 4xx client error is a *completed* HTTP response: the dependency is alive
                # and correctly rejecting bad input. Treat it as proof of liveness so a user
                # probing an invalid id during the half-open trial doesn't strand the breaker
                # OPEN. Only 5xx (and transport errors below) are genuine service failures.
                if 400 <= status < 500:
                    await self._on_liveness_proven(func.__name__)
                    raise
            await self._on_failure(func.__name__, e)
            raise
        except Exception as e:
            # A domain-layer error raised *after* a completed HTTP response (marked with
            # _service_alive, e.g. a 4xx wrapped as ValueError, or an unparseable body) also
            # proves the dependency is reachable — don't strand the breaker OPEN on it.
            if getattr(e, "_service_alive", False):
                logger.debug(f"Application error in {func.__name__} after a completed response: {e}")
                await self._on_liveness_proven(func.__name__)
                raise
            # Truly unexpected exceptions (no proof of an HTTP round-trip) are not counted as
            # monitored failures, but a trial that raised one has NOT proven recovery. Release
            # the single-trial gate and re-arm — otherwise the breaker stays HALF_OPEN with the
            # gate stuck set and every later call short-circuits to 503 until the process restarts.
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            await self._end_trial_unproven(func.__name__, f"unexpected {type(e).__name__}")
            raise
        except BaseException as e:
            # asyncio.CancelledError (and KeyboardInterrupt/SystemExit) are BaseException, NOT
            # Exception, so they bypass the handlers above. A half-open trial cancelled mid-flight
            # — client disconnect, server shutdown, or cancellation during the up-to-60s 429 sleep
            # in the Wazuh client — would otherwise leave _half_open_trial_in_progress stuck True,
            # stranding the breaker HALF_OPEN and 503-ing every later call until process restart.
            await self._end_trial_unproven(func.__name__, f"cancelled/{type(e).__name__}")
            raise

    async def _end_trial_unproven(self, func_name: str, reason: str) -> None:
        """End a half-open trial that neither succeeded nor counted as a monitored failure.

        Always releases the single-trial gate. If we were mid-trial, return to OPEN and
        re-arm the recovery timer so the breaker neither livelocks with the gate stuck set
        nor floods the still-unhealthy dependency with concurrent probes.
        """
        async with self._lock:
            self._half_open_trial_in_progress = False
            if self.state == CircuitBreakerState.HALF_OPEN:
                self.state = CircuitBreakerState.OPEN
                self.last_failure_time = time.time()
                logger.info(f"Circuit breaker {func_name} half-open trial ended unproven ({reason}); returning to OPEN")

    async def _on_liveness_proven(self, func_name: str) -> None:
        """A completed HTTP response (a 4xx client error) proves the dependency is reachable.

        Close a half-open trial (recovery proven). In CLOSED state a client error is neither a
        success nor a monitored failure, so leave the failure count untouched — a stream of
        client errors must not erase a real 5xx failure streak.
        """
        async with self._lock:
            self._half_open_trial_in_progress = False
            if self.state == CircuitBreakerState.HALF_OPEN:
                self.state = CircuitBreakerState.CLOSED
                self.failure_count = 0
                self.last_failure_time = None
                logger.info(f"Circuit breaker {func_name} reset to CLOSED (liveness proven by HTTP response)")

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        return time.time() - self.last_failure_time >= self.config.recovery_timeout

    async def _on_success(self, func_name: str):
        """Handle successful execution."""
        async with self._lock:
            self._half_open_trial_in_progress = False
            if self.state == CircuitBreakerState.HALF_OPEN:
                self.state = CircuitBreakerState.CLOSED
                logger.info(f"Circuit breaker {func_name} reset to CLOSED")
            self.failure_count = 0
            self.last_failure_time = None

    async def _on_failure(self, func_name: str, exception: Exception):
        """Handle failed execution."""
        async with self._lock:
            self._half_open_trial_in_progress = False
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.config.failure_threshold:
                self.state = CircuitBreakerState.OPEN
                logger.warning(
                    f"Circuit breaker {func_name} opened after {self.failure_count} failures. "
                    f"Last error: {exception}"
                )


def _is_retryable(exception):
    """Only retry on transient errors (5xx, 429 rate-limit, connection, timeout)."""
    if isinstance(exception, httpx.RequestError):
        return True  # Connection/timeout errors
    if isinstance(exception, httpx.HTTPStatusError):
        return exception.response.status_code == 429 or exception.response.status_code >= 500
    return False


class RetryConfig:
    """Retry configuration."""

    WAZUH_API_RETRY = retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception(_is_retryable),
        reraise=True,
    )

    DATABASE_RETRY = retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=0.5, min=0.5, max=5),
        retry=retry_if_exception_type((ConnectionError, TimeoutError)),
        reraise=True,
    )


class GracefulShutdown:
    """Handle graceful shutdown of the application."""

    def __init__(self):
        self.shutdown_event = asyncio.Event()
        self.active_connections: set = set()
        self.cleanup_tasks: list = []

    def add_connection(self, connection_id: str):
        """Add active connection."""
        self.active_connections.add(connection_id)

    def remove_connection(self, connection_id: str):
        """Remove active connection."""
        self.active_connections.discard(connection_id)

    def add_cleanup_task(self, task: Callable):
        """Add cleanup task to run on shutdown."""
        self.cleanup_tasks.append(task)

    async def initiate_shutdown(self):
        """Initiate graceful shutdown."""
        logger.info("Initiating graceful shutdown...")
        self.shutdown_event.set()

        # Wait for active connections to complete (with timeout)
        max_wait = GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS
        start_time = time.time()

        while self.active_connections and (time.time() - start_time) < max_wait:
            logger.info(f"Waiting for {len(self.active_connections)} active connections...")
            await asyncio.sleep(1)

        if self.active_connections:
            logger.warning(f"Forcing shutdown with {len(self.active_connections)} active connections")

        # Run cleanup tasks
        for task in self.cleanup_tasks:
            try:
                await task()
            except Exception as e:
                logger.error(f"Cleanup task failed: {e}")

        logger.info("Graceful shutdown completed")
