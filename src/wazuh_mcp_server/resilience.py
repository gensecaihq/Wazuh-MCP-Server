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
from typing import Any, Callable, Optional, Type

import httpx
from fastapi import HTTPException
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

# Production Constants
GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS = 30
WAZUH_API_MAX_CONCURRENT = 10
SSE_MAX_CONCURRENT_CONNECTIONS = 100
AUTH_MAX_CONCURRENT_REQUESTS = 20
FALLBACK_SEMAPHORE_LIMIT = 5


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
    expected_exception: Type[Exception] = Exception
    fallback_function: Optional[Callable] = None


class CircuitBreaker:
    """Circuit breaker implementation with fallback support."""

    def __init__(self, config: CircuitBreakerConfig):
        self.config = config
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self.next_retry_time: Optional[float] = None

    def __call__(self, func: Callable) -> Callable:
        """Decorator to apply circuit breaker to function."""

        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            return await self._call(func, *args, **kwargs)

        return wrapper

    async def _call(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with circuit breaker logic."""

        # Check if circuit is open
        if self.state == CircuitBreakerState.OPEN:
            if self._should_attempt_reset():
                self.state = CircuitBreakerState.HALF_OPEN
                logger.info(f"Circuit breaker {func.__name__} moved to HALF_OPEN")
            else:
                if self.config.fallback_function:
                    logger.warning(f"Circuit breaker {func.__name__} OPEN, using fallback")
                    return await self.config.fallback_function(*args, **kwargs)
                else:
                    raise HTTPException(
                        status_code=503, detail="Service temporarily unavailable - circuit breaker open"
                    )

        try:
            result = await func(*args, **kwargs)
            await self._on_success(func.__name__)
            return result

        except self.config.expected_exception as e:
            await self._on_failure(func.__name__, e)
            raise
        except Exception as e:
            # Unexpected exceptions don't count as circuit breaker failures
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            raise

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        return time.time() - self.last_failure_time >= self.config.recovery_timeout

    async def _on_success(self, func_name: str):
        """Handle successful execution."""
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.CLOSED
            logger.info(f"Circuit breaker {func_name} reset to CLOSED")

        self.failure_count = 0
        self.last_failure_time = None

    async def _on_failure(self, func_name: str, exception: Exception):
        """Handle failed execution."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.config.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            logger.warning(
                f"Circuit breaker {func_name} opened after {self.failure_count} failures. " f"Last error: {exception}"
            )


class TimeoutManager:
    """Manage timeouts for various operations."""

    DEFAULT_TIMEOUTS = {
        "http_request": 30.0,
        "database_query": 10.0,
        "file_operation": 5.0,
        "sse_response": 60.0,
        "authentication": 5.0,
    }

    @classmethod
    def get_timeout(cls, operation: str) -> float:
        """Get timeout for operation type."""
        return cls.DEFAULT_TIMEOUTS.get(operation, 30.0)

    @classmethod
    def with_timeout(cls, operation: str):
        """Decorator to apply timeout to async function."""

        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                timeout = cls.get_timeout(operation)
                try:
                    return await asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
                except asyncio.TimeoutError:
                    logger.error(f"Operation {func.__name__} timed out after {timeout}s")
                    raise HTTPException(status_code=408, detail=f"Operation timed out after {timeout} seconds")

            return wrapper

        return decorator


class RetryConfig:
    """Retry configuration."""

    WAZUH_API_RETRY = retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.RequestError, httpx.HTTPStatusError)),
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


class ErrorRecovery:
    """Error recovery strategies."""

    @staticmethod
    async def recover_wazuh_connection():
        """Recover Wazuh API connection."""
        try:
            from wazuh_mcp_server.server import get_wazuh_client

            client = await get_wazuh_client()

            # Reinitialize connection
            await client.initialize()
            logger.info("Wazuh connection recovered")
            return True

        except Exception as e:
            logger.error(f"Failed to recover Wazuh connection: {e}")
            return False

    @staticmethod
    async def recover_session_storage():
        """Recover session storage."""
        try:
            # Clear corrupted sessions and reinitialize
            from wazuh_mcp_server.server import sessions

            await sessions.clear()
            logger.info("Session storage recovered")
            return True

        except Exception as e:
            logger.error(f"Failed to recover session storage: {e}")
            return False


class BulkheadIsolation:
    """Isolate different components to prevent cascade failures."""

    def __init__(self):
        self.resource_pools = {
            "wazuh_api": asyncio.Semaphore(WAZUH_API_MAX_CONCURRENT),
            "sse_connections": asyncio.Semaphore(SSE_MAX_CONCURRENT_CONNECTIONS),
            "authentication": asyncio.Semaphore(AUTH_MAX_CONCURRENT_REQUESTS),
        }

    def get_semaphore(self, resource_type: str) -> asyncio.Semaphore:
        """Get semaphore for resource type (synchronous, returns semaphore for use in async with)."""
        if resource_type in self.resource_pools:
            return self.resource_pools[resource_type]
        else:
            # Create and cache fallback semaphore to avoid creating new ones each time
            if resource_type not in self.resource_pools:
                self.resource_pools[resource_type] = asyncio.Semaphore(FALLBACK_SEMAPHORE_LIMIT)
            return self.resource_pools[resource_type]


class HealthRecovery:
    """Automatic health recovery mechanisms."""

    def __init__(self):
        self.recovery_strategies = {
            "memory_pressure": self._recover_memory_pressure,
            "connection_pool_exhaustion": self._recover_connection_pool,
            "wazuh_api_failure": self._recover_wazuh_api,
        }

    async def attempt_recovery(self, issue: str) -> bool:
        """Attempt to recover from specific issue."""
        if issue in self.recovery_strategies:
            try:
                return await self.recovery_strategies[issue]()
            except Exception as e:
                logger.error(f"Recovery strategy for {issue} failed: {e}")
                return False
        return False

    async def _recover_memory_pressure(self) -> bool:
        """Recover from memory pressure."""
        try:
            # Clear caches and force garbage collection
            import gc

            gc.collect()

            # Clear expired sessions
            from wazuh_mcp_server.server import sessions

            expired_count = await sessions.cleanup_expired(timeout_minutes=15)

            # Clear Wazuh client cache if available
            try:
                from wazuh_mcp_server.server import get_wazuh_client

                client = await get_wazuh_client()
                if hasattr(client, "_cache"):
                    client._cache.clear()
            except (ImportError, RuntimeError):
                pass  # Client may not be initialized yet

            logger.info(f"Memory recovery: cleared {expired_count} expired sessions")
            return True

        except Exception as e:
            logger.error(f"Memory recovery failed: {e}")
            return False

    async def _recover_connection_pool(self) -> bool:
        """Recover from connection pool exhaustion."""
        try:
            from wazuh_mcp_server.security import connection_pool_manager

            await connection_pool_manager.close_all()
            logger.info("Connection pool recovery: closed all connections")
            return True

        except Exception as e:
            logger.error(f"Connection pool recovery failed: {e}")
            return False

    async def _recover_wazuh_api(self) -> bool:
        """Recover from Wazuh API failure."""
        return await ErrorRecovery.recover_wazuh_connection()


# Global instances
graceful_shutdown = GracefulShutdown()
bulkhead_isolation = BulkheadIsolation()
health_recovery = HealthRecovery()

# Common circuit breakers
wazuh_api_circuit_breaker = CircuitBreaker(
    CircuitBreakerConfig(failure_threshold=3, recovery_timeout=30, expected_exception=httpx.RequestError)
)

authentication_circuit_breaker = CircuitBreaker(
    CircuitBreakerConfig(failure_threshold=5, recovery_timeout=60, expected_exception=HTTPException)
)


# Decorators for common patterns
def with_wazuh_resilience(func: Callable) -> Callable:
    """Apply resilience patterns for Wazuh API calls."""

    @RetryConfig.WAZUH_API_RETRY
    @wazuh_api_circuit_breaker
    @TimeoutManager.with_timeout("http_request")
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        async with bulkhead_isolation.get_semaphore("wazuh_api"):
            return await func(*args, **kwargs)

    return wrapper


def with_auth_resilience(func: Callable) -> Callable:
    """Apply resilience patterns for authentication."""

    @authentication_circuit_breaker
    @TimeoutManager.with_timeout("authentication")
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        async with bulkhead_isolation.get_semaphore("authentication"):
            return await func(*args, **kwargs)

    return wrapper
