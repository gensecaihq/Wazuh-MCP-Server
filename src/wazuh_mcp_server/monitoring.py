#!/usr/bin/env python3
"""
Production monitoring, metrics, and observability for Wazuh MCP Server
Implements comprehensive monitoring with Prometheus metrics and health checks
"""

import asyncio
import contextvars
import logging
import os
import sys
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import psutil
from fastapi import Request
from fastapi.responses import PlainTextResponse
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Info, generate_latest

from wazuh_mcp_server import __version__

logger = logging.getLogger(__name__)

# Context variable for request correlation ID
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("correlation_id", default="")


def get_correlation_id() -> str:
    """Get the current correlation ID from context."""
    return correlation_id_var.get() or str(uuid.uuid4())[:8]


def set_correlation_id(correlation_id: Optional[str] = None) -> str:
    """Set correlation ID in context. Generates one if not provided."""
    cid = correlation_id or str(uuid.uuid4())[:8]
    correlation_id_var.set(cid)
    return cid


class StructuredLogger:
    """Structured logging helper for consistent log format."""

    def __init__(self, name: str):
        self._logger = logging.getLogger(name)

    def _format_extra(self, extra: Dict[str, Any]) -> Dict[str, Any]:
        """Add correlation ID and timestamp to log extra."""
        return {"correlation_id": get_correlation_id(), "timestamp": datetime.now(timezone.utc).isoformat(), **extra}

    def info(self, message: str, **extra: Any) -> None:
        """Log info with structured data."""
        self._logger.info(message, extra=self._format_extra(extra))

    def warning(self, message: str, **extra: Any) -> None:
        """Log warning with structured data."""
        self._logger.warning(message, extra=self._format_extra(extra))

    def error(self, message: str, exc_info: bool = False, **extra: Any) -> None:
        """Log error with structured data."""
        self._logger.error(message, exc_info=exc_info, extra=self._format_extra(extra))

    def debug(self, message: str, **extra: Any) -> None:
        """Log debug with structured data."""
        self._logger.debug(message, extra=self._format_extra(extra))


# Structured logger instance
structured_logger = StructuredLogger(__name__)

# Prometheus metrics registry
REGISTRY = CollectorRegistry()

# Core metrics
REQUEST_COUNT = Counter(
    "wazuh_mcp_requests_total", "Total number of requests", ["method", "endpoint", "status_code"], registry=REGISTRY
)

REQUEST_DURATION = Histogram(
    "wazuh_mcp_request_duration_seconds", "Request duration in seconds", ["method", "endpoint"], registry=REGISTRY
)

ACTIVE_CONNECTIONS = Gauge("wazuh_mcp_active_connections", "Number of active SSE connections", registry=REGISTRY)

SSE_EVENTS_SENT = Counter("wazuh_mcp_sse_events_total", "Total SSE events sent", ["event_type"], registry=REGISTRY)

AUTHENTICATION_ATTEMPTS = Counter(
    "wazuh_mcp_auth_attempts_total", "Authentication attempts", ["result"], registry=REGISTRY
)

WAZUH_API_CALLS = Counter(
    "wazuh_mcp_wazuh_api_calls_total", "Wazuh API calls", ["endpoint", "status"], registry=REGISTRY
)

SYSTEM_MEMORY_USAGE = Gauge("wazuh_mcp_memory_usage_bytes", "Memory usage in bytes", registry=REGISTRY)

SYSTEM_CPU_USAGE = Gauge("wazuh_mcp_cpu_usage_percent", "CPU usage percentage", registry=REGISTRY)

ERROR_RATE = Counter("wazuh_mcp_errors_total", "Total errors", ["error_type", "component"], registry=REGISTRY)

CIRCUIT_BREAKER_STATE = Gauge(
    "wazuh_mcp_circuit_breaker_state",
    "Circuit breaker state (0=closed, 1=open, 2=half-open)",
    ["service"],
    registry=REGISTRY,
)

SERVER_INFO = Info("wazuh_mcp_server_info", "Server information", registry=REGISTRY)

# Session metrics for improved observability
SESSION_ACTIVE = Gauge("wazuh_mcp_sessions_active", "Number of active sessions", registry=REGISTRY)

SESSION_CREATED = Counter("wazuh_mcp_sessions_created_total", "Total sessions created", registry=REGISTRY)

SESSION_EXPIRED = Counter("wazuh_mcp_sessions_expired_total", "Total sessions expired", registry=REGISTRY)

# Cache metrics for performance monitoring
CACHE_HITS = Counter("wazuh_mcp_cache_hits_total", "Cache hits", ["cache_type"], registry=REGISTRY)

CACHE_MISSES = Counter("wazuh_mcp_cache_misses_total", "Cache misses", ["cache_type"], registry=REGISTRY)

# Rate limiter metrics
RATE_LIMIT_HITS = Counter(
    "wazuh_mcp_rate_limit_hits_total", "Rate limit enforcement count", ["endpoint"], registry=REGISTRY
)

# MCP tool execution metrics
TOOL_EXECUTION_COUNT = Counter(
    "wazuh_mcp_tool_executions_total", "Total tool executions", ["tool_name", "status"], registry=REGISTRY
)

TOOL_EXECUTION_DURATION = Histogram(
    "wazuh_mcp_tool_duration_seconds",
    "Tool execution duration in seconds",
    ["tool_name"],
    buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
    registry=REGISTRY,
)


@dataclass
class HealthCheckResult:
    """Health check result."""

    name: str
    status: str  # "healthy", "degraded", "unhealthy"
    message: str
    duration_ms: float
    timestamp: datetime
    details: Dict[str, Any] = field(default_factory=dict)


class HealthChecker:
    """Comprehensive health checking system."""

    def __init__(self):
        self.checks: Dict[str, callable] = {}
        self.last_results: Dict[str, HealthCheckResult] = {}
        self.check_timeout = 5.0  # seconds

    def register_check(self, name: str, check_func: callable):
        """Register a health check function."""
        self.checks[name] = check_func

    async def run_check(self, name: str) -> HealthCheckResult:
        """Run a single health check."""
        if name not in self.checks:
            return HealthCheckResult(
                name=name,
                status="unhealthy",
                message=f"Check '{name}' not found",
                duration_ms=0,
                timestamp=datetime.now(timezone.utc),
            )

        start_time = time.time()
        try:
            result = await asyncio.wait_for(self.checks[name](), timeout=self.check_timeout)

            duration_ms = (time.time() - start_time) * 1000

            if isinstance(result, dict):
                status = result.get("status", "healthy")
                message = result.get("message", "OK")
                details = result.get("details", {})
            else:
                status = "healthy" if result else "unhealthy"
                message = "OK" if result else "Check failed"
                details = {}

            return HealthCheckResult(
                name=name,
                status=status,
                message=message,
                duration_ms=duration_ms,
                timestamp=datetime.now(timezone.utc),
                details=details,
            )

        except asyncio.TimeoutError:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=name,
                status="unhealthy",
                message=f"Check timed out after {self.check_timeout}s",
                duration_ms=duration_ms,
                timestamp=datetime.now(timezone.utc),
            )
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            return HealthCheckResult(
                name=name,
                status="unhealthy",
                message=f"Check failed: {str(e)}",
                duration_ms=duration_ms,
                timestamp=datetime.now(timezone.utc),
            )

    async def run_all_checks(self) -> Dict[str, HealthCheckResult]:
        """Run all registered health checks."""
        tasks = [self.run_check(name) for name in self.checks.keys()]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        health_results = {}
        for i, (name, result) in enumerate(zip(self.checks.keys(), results)):
            if isinstance(result, Exception):
                health_results[name] = HealthCheckResult(
                    name=name,
                    status="unhealthy",
                    message=f"Check execution failed: {str(result)}",
                    duration_ms=0,
                    timestamp=datetime.now(timezone.utc),
                )
            else:
                health_results[name] = result

        self.last_results = health_results
        return health_results


class MetricsCollector:
    """Collect and export system metrics."""

    def __init__(self):
        self.collection_interval = 30  # seconds
        self.last_collection = 0
        self._collection_task = None

    async def start_collection(self):
        """Start metrics collection task."""
        if self._collection_task is None:
            self._collection_task = asyncio.create_task(self._collection_loop())

    async def stop_collection(self):
        """Stop metrics collection task."""
        if self._collection_task:
            self._collection_task.cancel()
            try:
                await self._collection_task
            except asyncio.CancelledError:
                pass
            self._collection_task = None

    async def _collection_loop(self):
        """Main metrics collection loop."""
        while True:
            try:
                await self._collect_system_metrics()
                await asyncio.sleep(self.collection_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(5)  # Short retry delay

    async def _collect_system_metrics(self):
        """Collect system-level metrics."""
        try:
            # Memory usage
            process = psutil.Process()
            memory_info = process.memory_info()
            SYSTEM_MEMORY_USAGE.set(memory_info.rss)

            # CPU usage
            cpu_percent = process.cpu_percent()
            SYSTEM_CPU_USAGE.set(cpu_percent)

        except Exception as e:
            logger.error(f"System metrics collection failed: {e}")


class AlertManager:
    """Manage alerts and notifications."""

    def __init__(self):
        self.alert_rules: List[Dict[str, Any]] = []
        self.active_alerts: Dict[str, Dict[str, Any]] = {}
        self.alert_history: deque = deque(maxlen=1000)

    def add_rule(self, name: str, condition: callable, severity: str = "warning"):
        """Add an alert rule."""
        self.alert_rules.append({"name": name, "condition": condition, "severity": severity, "last_triggered": None})

    async def evaluate_rules(self):
        """Evaluate all alert rules."""
        for rule in self.alert_rules:
            try:
                if await rule["condition"]():
                    await self._trigger_alert(rule)
                else:
                    await self._resolve_alert(rule["name"])
            except Exception as e:
                logger.error(f"Alert rule evaluation failed for {rule['name']}: {e}")

    async def _trigger_alert(self, rule: Dict[str, Any]):
        """Trigger an alert."""
        alert_id = rule["name"]
        now = datetime.now(timezone.utc)

        if alert_id not in self.active_alerts:
            alert = {
                "id": alert_id,
                "name": rule["name"],
                "severity": rule["severity"],
                "triggered_at": now,
                "count": 1,
                "last_seen": now,
            }

            self.active_alerts[alert_id] = alert
            self.alert_history.append(alert.copy())

            logger.warning(f"Alert triggered: {rule['name']} (severity: {rule['severity']})")
        else:
            # Update existing alert
            self.active_alerts[alert_id]["count"] += 1
            self.active_alerts[alert_id]["last_seen"] = now

        rule["last_triggered"] = now

    async def _resolve_alert(self, alert_id: str):
        """Resolve an alert."""
        if alert_id in self.active_alerts:
            resolved_alert = self.active_alerts.pop(alert_id)
            resolved_alert["resolved_at"] = datetime.now(timezone.utc)
            self.alert_history.append(resolved_alert)

            logger.info(f"Alert resolved: {alert_id}")


class PerformanceProfiler:
    """Profile performance and detect bottlenecks."""

    def __init__(self):
        self.slow_requests: deque = deque(maxlen=100)
        self.slow_threshold = 1.0  # seconds

    def record_request(self, method: str, path: str, duration: float, status_code: int):
        """Record request performance."""
        if duration > self.slow_threshold:
            self.slow_requests.append(
                {
                    "method": method,
                    "path": path,
                    "duration": duration,
                    "status_code": status_code,
                    "timestamp": datetime.now(timezone.utc),
                }
            )

    def get_slow_requests(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent slow requests."""
        return list(self.slow_requests)[-limit:]


# Global instances
health_checker = HealthChecker()
metrics_collector = MetricsCollector()
alert_manager = AlertManager()
performance_profiler = PerformanceProfiler()


# Register default health checks
async def check_memory_usage():
    """Check memory usage."""
    try:
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        max_memory_mb = max(1, int(os.getenv("MAX_MEMORY_MB", "512")))  # Prevent division by zero

        usage_percent = (memory_mb / max_memory_mb) * 100

        if usage_percent > 90:
            return {
                "status": "unhealthy",
                "message": f"Memory usage critical: {usage_percent:.1f}%",
                "details": {"memory_mb": memory_mb, "max_memory_mb": max_memory_mb},
            }
        elif usage_percent > 80:
            return {
                "status": "degraded",
                "message": f"Memory usage high: {usage_percent:.1f}%",
                "details": {"memory_mb": memory_mb, "max_memory_mb": max_memory_mb},
            }
        else:
            return {
                "status": "healthy",
                "message": f"Memory usage normal: {usage_percent:.1f}%",
                "details": {"memory_mb": memory_mb, "max_memory_mb": max_memory_mb},
            }
    except Exception as e:
        return {"status": "unhealthy", "message": f"Memory check failed: {str(e)}"}


async def check_wazuh_connectivity():
    """Check Wazuh API connectivity."""
    try:
        from wazuh_mcp_server.server import get_wazuh_client

        client = await get_wazuh_client()

        # Simple health check call
        start_time = time.time()
        response = await client.get_manager_info()
        duration_ms = (time.time() - start_time) * 1000

        if response and "data" in response:
            return {
                "status": "healthy",
                "message": f"Wazuh API responding ({duration_ms:.1f}ms)",
                "details": {"response_time_ms": duration_ms},
            }
        else:
            return {"status": "unhealthy", "message": "Wazuh API returned invalid response"}
    except Exception as e:
        return {"status": "unhealthy", "message": f"Wazuh API unreachable: {str(e)}"}


async def check_session_store() -> Dict[str, Any]:
    """Check session store health."""
    try:
        from wazuh_mcp_server.server import sessions

        # Use get_all() to get all sessions count
        all_sessions = await sessions.get_all()
        active_count = len(all_sessions)
        SESSION_ACTIVE.set(active_count)

        return {
            "status": "healthy",
            "message": f"Session store operational ({active_count} active sessions)",
            "details": {"active_sessions": active_count},
        }
    except Exception as e:
        return {"status": "unhealthy", "message": f"Session store check failed: {str(e)}"}


async def check_rate_limiter() -> Dict[str, Any]:
    """Check rate limiter health."""
    try:
        from wazuh_mcp_server.server import get_wazuh_client

        client = await get_wazuh_client()
        if hasattr(client, "_request_times"):
            current_requests = len(client._request_times)
            max_requests = client._max_requests_per_minute

            usage_percent = (current_requests / max_requests) * 100 if max_requests > 0 else 0

            if usage_percent > 90:
                return {
                    "status": "degraded",
                    "message": f"Rate limiter near capacity: {usage_percent:.1f}%",
                    "details": {"current": current_requests, "max": max_requests},
                }
            return {
                "status": "healthy",
                "message": f"Rate limiter OK: {usage_percent:.1f}% capacity",
                "details": {"current": current_requests, "max": max_requests},
            }
        return {"status": "healthy", "message": "Rate limiter not configured"}
    except Exception as e:
        return {"status": "unhealthy", "message": f"Rate limiter check failed: {str(e)}"}


async def check_circuit_breaker() -> Dict[str, Any]:
    """Check circuit breaker health."""
    try:
        from wazuh_mcp_server.server import get_wazuh_client

        client = await get_wazuh_client()
        if hasattr(client, "_circuit_breaker"):
            cb = client._circuit_breaker
            state = cb._state if hasattr(cb, "_state") else "unknown"
            failure_count = cb.failure_count if hasattr(cb, "failure_count") else 0

            # Update Prometheus metric
            state_value = {"closed": 0, "open": 1, "half_open": 2}.get(state, -1)
            CIRCUIT_BREAKER_STATE.labels(service="wazuh_api").set(state_value)

            if state == "open":
                return {
                    "status": "unhealthy",
                    "message": f"Circuit breaker OPEN (failures: {failure_count})",
                    "details": {"state": state, "failure_count": failure_count},
                }
            elif state == "half_open":
                return {
                    "status": "degraded",
                    "message": "Circuit breaker HALF-OPEN (recovering)",
                    "details": {"state": state, "failure_count": failure_count},
                }
            return {
                "status": "healthy",
                "message": "Circuit breaker CLOSED",
                "details": {"state": state, "failure_count": failure_count},
            }
        return {"status": "healthy", "message": "Circuit breaker not configured"}
    except Exception as e:
        return {"status": "unhealthy", "message": f"Circuit breaker check failed: {str(e)}"}


# Register health checks
health_checker.register_check("memory", check_memory_usage)
health_checker.register_check("wazuh_api", check_wazuh_connectivity)
health_checker.register_check("session_store", check_session_store)
health_checker.register_check("rate_limiter", check_rate_limiter)
health_checker.register_check("circuit_breaker", check_circuit_breaker)

# Set up server info metric
SERVER_INFO.info(
    {
        "version": __version__,
        "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        "start_time": datetime.now(timezone.utc).isoformat(),
    }
)


async def metrics_endpoint() -> PlainTextResponse:
    """Prometheus metrics endpoint."""
    return PlainTextResponse(generate_latest(REGISTRY), media_type="text/plain; version=0.0.4; charset=utf-8")


async def health_endpoint() -> Dict[str, Any]:
    """Comprehensive health check endpoint."""
    results = await health_checker.run_all_checks()

    overall_status = "healthy"
    if any(r.status == "unhealthy" for r in results.values()):
        overall_status = "unhealthy"
    elif any(r.status == "degraded" for r in results.values()):
        overall_status = "degraded"

    return {
        "status": overall_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks": {
            name: {
                "status": result.status,
                "message": result.message,
                "duration_ms": result.duration_ms,
                "details": result.details,
            }
            for name, result in results.items()
        },
    }


def setup_monitoring_middleware():
    """Set up monitoring middleware for FastAPI."""

    async def monitoring_middleware(request: Request, call_next):
        """Monitoring middleware with correlation ID tracking."""
        # Extract or generate correlation ID
        correlation_id = request.headers.get("X-Correlation-ID") or request.headers.get("X-Request-ID")
        correlation_id = set_correlation_id(correlation_id)

        # Record request start
        start_time = time.time()
        method = request.method
        path = request.url.path

        # Process request
        try:
            response = await call_next(request)
            status_code = response.status_code

            # Add correlation ID to response headers
            response.headers["X-Correlation-ID"] = correlation_id

        except Exception as e:
            status_code = 500
            ERROR_RATE.labels(error_type=type(e).__name__, component="request_processing").inc()
            structured_logger.error(
                f"Request failed: {method} {path}",
                error_type=type(e).__name__,
                error_message=str(e),
                method=method,
                path=path,
            )
            raise
        finally:
            # Record metrics
            duration = time.time() - start_time

            REQUEST_COUNT.labels(method=method, endpoint=path, status_code=status_code).inc()
            REQUEST_DURATION.labels(method=method, endpoint=path).observe(duration)

            # Record slow requests with correlation ID
            if duration > performance_profiler.slow_threshold:
                structured_logger.warning(
                    f"Slow request detected: {method} {path}",
                    duration_seconds=duration,
                    status_code=status_code,
                    method=method,
                    path=path,
                )

            performance_profiler.record_request(method, path, duration, status_code)

        return response

    return monitoring_middleware


def record_tool_execution(tool_name: str, duration: float, success: bool) -> None:
    """Record tool execution metrics."""
    status = "success" if success else "error"
    TOOL_EXECUTION_COUNT.labels(tool_name=tool_name, status=status).inc()
    TOOL_EXECUTION_DURATION.labels(tool_name=tool_name).observe(duration)


def record_cache_access(cache_type: str, hit: bool) -> None:
    """Record cache access metrics."""
    if hit:
        CACHE_HITS.labels(cache_type=cache_type).inc()
    else:
        CACHE_MISSES.labels(cache_type=cache_type).inc()


def record_session_event(event: str) -> None:
    """Record session lifecycle events."""
    if event == "created":
        SESSION_CREATED.inc()
    elif event == "expired":
        SESSION_EXPIRED.inc()
