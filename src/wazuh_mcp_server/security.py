#!/usr/bin/env python3
"""
Production security hardening and edge case handling for Wazuh MCP Server
Implements comprehensive security measures and error handling
"""

import logging
import os
import re
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

import httpx
from fastapi import HTTPException, Request

logger = logging.getLogger(__name__)


# =============================================================================
# TOOL PARAMETER VALIDATION
# =============================================================================


class ToolValidationError(ValueError):
    """Raised when tool parameter validation fails."""

    def __init__(self, param_name: str, message: str, suggestion: str = None):
        self.param_name = param_name
        self.suggestion = suggestion
        full_message = f"Invalid parameter '{param_name}': {message}"
        if suggestion:
            full_message += f". {suggestion}"
        super().__init__(full_message)


# Valid enum values for tool parameters
VALID_TIME_RANGES = {"1h", "6h", "24h", "7d", "1d", "30d"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_AGENT_STATUSES = {"active", "disconnected", "never_connected", "pending"}
VALID_INDICATOR_TYPES = {"ip", "hash", "domain", "url"}
VALID_REPORT_TYPES = {"daily", "weekly", "monthly", "incident"}
VALID_COMPLIANCE_FRAMEWORKS = {"PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST"}

# Regex patterns for parameter validation
AGENT_ID_PATTERN = re.compile(r"^[0-9]{3,5}$")  # Wazuh agent IDs are numeric
RULE_ID_PATTERN = re.compile(r"^[0-9]{1,6}$")  # Rule IDs are numeric
ISO_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$")
IP_ADDRESS_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32,128}$")  # MD5 to SHA-512
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")


def validate_limit(value: Any, min_val: int = 1, max_val: int = 1000, param_name: str = "limit") -> int:
    """Validate and convert limit parameter."""
    if value is None:
        return 100  # Default

    try:
        limit = int(value)
    except (ValueError, TypeError):
        raise ToolValidationError(
            param_name,
            f"must be an integer, got {type(value).__name__}",
            f"Use a number between {min_val} and {max_val}",
        )

    if limit < min_val or limit > max_val:
        raise ToolValidationError(
            param_name,
            f"must be between {min_val} and {max_val}, got {limit}",
            f"Use a value in range [{min_val}, {max_val}]",
        )

    return limit


def validate_agent_id(value: Any, required: bool = False, param_name: str = "agent_id") -> Optional[str]:
    """Validate Wazuh agent ID format."""
    if value is None:
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a valid agent ID (e.g., '001')")
        return None

    agent_id = str(value).strip()

    if not agent_id:
        if required:
            raise ToolValidationError(param_name, "cannot be empty", "Provide a valid agent ID (e.g., '001')")
        return None

    # Agent ID should be numeric (Wazuh format)
    if not AGENT_ID_PATTERN.match(agent_id):
        raise ToolValidationError(
            param_name, f"invalid format '{agent_id}'", "Agent ID should be a 3-5 digit number (e.g., '001', '1234')"
        )

    return agent_id


def validate_rule_id(value: Any, required: bool = False, param_name: str = "rule_id") -> Optional[str]:
    """Validate Wazuh rule ID format."""
    if value is None:
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a valid rule ID (e.g., '5402')")
        return None

    rule_id = str(value).strip()

    if not rule_id:
        if required:
            raise ToolValidationError(param_name, "cannot be empty")
        return None

    if not RULE_ID_PATTERN.match(rule_id):
        raise ToolValidationError(
            param_name, f"invalid format '{rule_id}'", "Rule ID should be a 1-6 digit number (e.g., '5402', '100002')"
        )

    return rule_id


def validate_time_range(value: Any, param_name: str = "time_range") -> str:
    """Validate time range enum value."""
    if value is None:
        return "24h"  # Default

    time_range = str(value).strip().lower()

    if time_range not in VALID_TIME_RANGES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_TIME_RANGES))}"
        )

    return time_range


def validate_severity(value: Any, required: bool = False, param_name: str = "severity") -> Optional[str]:
    """Validate severity enum value."""
    if value is None:
        if required:
            raise ToolValidationError(param_name, "is required")
        return None

    severity = str(value).strip().lower()

    if severity not in VALID_SEVERITIES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )

    return severity


def validate_agent_status(value: Any, param_name: str = "status") -> Optional[str]:
    """Validate agent status enum value."""
    if value is None:
        return None

    status = str(value).strip().lower()

    if status not in VALID_AGENT_STATUSES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_AGENT_STATUSES))}"
        )

    return status


def validate_timestamp(value: Any, required: bool = False, param_name: str = "timestamp") -> Optional[str]:
    """Validate ISO 8601 timestamp format."""
    if value is None:
        if required:
            raise ToolValidationError(param_name, "is required")
        return None

    timestamp = str(value).strip()

    if not timestamp:
        if required:
            raise ToolValidationError(param_name, "cannot be empty")
        return None

    if not ISO_TIMESTAMP_PATTERN.match(timestamp):
        raise ToolValidationError(
            param_name, f"invalid ISO 8601 format '{timestamp}'", "Use format: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ"
        )

    return timestamp


def validate_indicator(value: Any, indicator_type: str, param_name: str = "indicator") -> str:
    """Validate threat indicator based on type."""
    if value is None or str(value).strip() == "":
        raise ToolValidationError(param_name, "is required", "Provide a valid indicator value")

    indicator = str(value).strip()

    if indicator_type == "ip":
        if not IP_ADDRESS_PATTERN.match(indicator):
            raise ToolValidationError(
                param_name, f"invalid IP address '{indicator}'", "Use valid IPv4 (e.g., '192.168.1.1') or IPv6 address"
            )
    elif indicator_type == "hash":
        if not HASH_PATTERN.match(indicator):
            raise ToolValidationError(
                param_name, f"invalid hash '{indicator}'", "Use valid MD5, SHA-1, SHA-256, or SHA-512 hash"
            )
    elif indicator_type == "domain":
        if not DOMAIN_PATTERN.match(indicator):
            raise ToolValidationError(
                param_name, f"invalid domain '{indicator}'", "Use valid domain format (e.g., 'example.com')"
            )
    elif indicator_type == "url":
        if not indicator.startswith(("http://", "https://")):
            raise ToolValidationError(
                param_name, f"invalid URL '{indicator}'", "URL must start with http:// or https://"
            )

    return indicator


def validate_indicator_type(value: Any, param_name: str = "indicator_type") -> str:
    """Validate indicator type enum."""
    if value is None:
        return "ip"  # Default

    ind_type = str(value).strip().lower()

    if ind_type not in VALID_INDICATOR_TYPES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_INDICATOR_TYPES))}"
        )

    return ind_type


def validate_report_type(value: Any, param_name: str = "report_type") -> str:
    """Validate report type enum."""
    if value is None:
        return "daily"  # Default

    report_type = str(value).strip().lower()

    if report_type not in VALID_REPORT_TYPES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_REPORT_TYPES))}"
        )

    return report_type


def validate_compliance_framework(value: Any, param_name: str = "framework") -> str:
    """Validate compliance framework enum."""
    if value is None:
        return "PCI-DSS"  # Default

    framework = str(value).strip().upper()

    # Normalize common variations
    if framework == "PCI" or framework == "PCIDSS":
        framework = "PCI-DSS"

    if framework not in VALID_COMPLIANCE_FRAMEWORKS:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_COMPLIANCE_FRAMEWORKS))}"
        )

    return framework


def validate_query(value: Any, required: bool = True, param_name: str = "query") -> str:
    """Validate search query parameter."""
    if value is None or str(value).strip() == "":
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a search query string")
        return ""

    query = str(value).strip()

    # Check for dangerous patterns
    dangerous = ["<script", "javascript:", "; drop", "; delete", "--"]
    query_lower = query.lower()
    for pattern in dangerous:
        if pattern in query_lower:
            raise ToolValidationError(
                param_name, "contains disallowed pattern", "Remove special characters and try again"
            )

    if len(query) > 500:
        raise ToolValidationError(param_name, f"too long ({len(query)} chars)", "Query must be 500 characters or less")

    return query


def validate_boolean(value: Any, default: bool = True, param_name: str = "flag") -> bool:
    """Validate boolean parameter."""
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes", "on"):
            return True
        if value.lower() in ("false", "0", "no", "off"):
            return False

    raise ToolValidationError(param_name, f"must be a boolean, got '{value}'", "Use true/false")


def validate_input(value: str, max_length: int = 1000, allowed_chars: Optional[str] = None) -> bool:
    """
    Validate user input for security.

    Args:
        value: Input string to validate
        max_length: Maximum allowed length
        allowed_chars: Optional regex pattern for allowed characters

    Returns:
        True if valid

    Raises:
        ValueError: If validation fails
    """
    if not value:
        raise ValueError("Input cannot be empty")

    if len(value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")

    # Check for common injection patterns
    dangerous_patterns = ["<script", "javascript:", "onerror=", "onclick=", "../", "..\\\\"]
    value_lower = value.lower()
    for pattern in dangerous_patterns:
        if pattern in value_lower:
            raise ValueError(f"Input contains disallowed pattern: {pattern}")

    return True


def validate_batch_items(items: List[Any], max_batch_size: int = 100) -> List[Dict[str, Any]]:
    """
    Validate batch request items for security.

    Args:
        items: List of batch request items
        max_batch_size: Maximum allowed batch size

    Returns:
        List of validated items

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(items, list):
        raise ValueError("Batch items must be a list")

    if len(items) > max_batch_size:
        raise ValueError(f"Batch size {len(items)} exceeds maximum of {max_batch_size}")

    validated = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"Batch item at index {idx} must be a dictionary")

        # Validate required fields
        if "jsonrpc" not in item:
            raise ValueError(f"Batch item at index {idx} missing 'jsonrpc' field")

        if "method" not in item:
            raise ValueError(f"Batch item at index {idx} missing 'method' field")

        # Validate method name
        method = item.get("method", "")
        if not isinstance(method, str) or len(method) > 256:
            raise ValueError(f"Invalid method name at index {idx}")

        # Check for suspicious patterns in method
        if any(p in method.lower() for p in ["<", ">", '"', "'", ";", "|", "&"]):
            raise ValueError(f"Invalid characters in method name at index {idx}")

        validated.append(item)

    return validated


# Sensitive data patterns for log sanitization
SENSITIVE_PATTERNS = [
    (r'(password["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r'(token["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r'(api[_-]?key["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r'(secret["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r'(authorization["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r"(bearer\s+)[a-zA-Z0-9._-]+", r"\1[REDACTED]"),
    (r"wst_[a-zA-Z0-9_-]+", "wst_[REDACTED]"),
    (r"wazuh_[a-zA-Z0-9_-]{40,}", "wazuh_[REDACTED]"),
]


def sanitize_log_message(message: str) -> str:
    """
    Sanitize log messages to remove sensitive data.

    Args:
        message: The log message to sanitize

    Returns:
        Sanitized message with sensitive data redacted
    """
    import re

    result = message
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


class SanitizingLogFilter(logging.Filter):
    """Log filter that sanitizes sensitive data."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and sanitize log record."""
        if hasattr(record, "msg") and isinstance(record.msg, str):
            record.msg = sanitize_log_message(record.msg)
        if hasattr(record, "args") and record.args:
            sanitized_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    sanitized_args.append(sanitize_log_message(arg))
                else:
                    sanitized_args.append(arg)
            record.args = tuple(sanitized_args)
        return True


@dataclass
class SecurityMetrics:
    """Track security-related metrics."""

    failed_authentications: int = 0
    rate_limit_violations: int = 0
    suspicious_requests: int = 0
    blocked_ips: Set[str] = None
    last_reset: datetime = None

    def __post_init__(self):
        if self.blocked_ips is None:
            self.blocked_ips = set()
        if self.last_reset is None:
            self.last_reset = datetime.now(timezone.utc)


class RateLimiter:
    """Advanced rate limiting with sliding window."""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.blocked_until: Dict[str, datetime] = {}

    def is_allowed(self, identifier: str) -> tuple[bool, Optional[int]]:
        """Check if request is allowed. Returns (allowed, retry_after_seconds)."""
        now = time.time()

        # Check if currently blocked
        if identifier in self.blocked_until:
            if datetime.now(timezone.utc) < self.blocked_until[identifier]:
                retry_after = int((self.blocked_until[identifier] - datetime.now(timezone.utc)).total_seconds())
                return False, retry_after
            else:
                del self.blocked_until[identifier]

        # Clean old requests
        window_start = now - self.window_seconds
        request_times = self.requests[identifier]
        while request_times and request_times[0] < window_start:
            request_times.popleft()

        # Check rate limit
        if len(request_times) >= self.max_requests:
            # Block for escalating time periods
            block_duration = min(300, len(request_times) * 10)  # Max 5 minutes
            self.blocked_until[identifier] = datetime.now(timezone.utc) + timedelta(seconds=block_duration)
            return False, block_duration

        # Allow request
        request_times.append(now)
        return True, None


class SecurityValidator:
    """Validate requests for security threats."""

    # Pre-compiled regex patterns for performance (class-level constants)
    MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB

    def __init__(self):
        import re

        # Pre-compile patterns at initialization for O(1) matching per pattern
        # Patterns require SQL/command context to avoid false positives on
        # legitimate MCP tool names and JSON-RPC content
        self._compiled_patterns = [
            # SQL Injection patterns (require SQL context around keywords)
            re.compile(
                r"(?i)\b(union\s+select|insert\s+into|delete\s+from|drop\s+(table|database)"
                r"|alter\s+table|exec\s*\(|execute\s+|;\s*select\s+|;\s*drop\s+)"
            ),
            # XSS patterns
            re.compile(r"(?i)(<script|javascript:|onload=|onerror=)"),
            # Path traversal
            re.compile(r"(\.\./|\.\.\\|%2e%2e)"),
            # Command injection (require shell context, not bare chars)
            re.compile(r"(;\s*\w+\s|`[^`]+`|\$\([^)]+\)|\$\{[^}]+\})"),
        ]
        self.max_payload_size = self.MAX_PAYLOAD_SIZE

    def validate_request(self, request: Request, body: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """Validate request for security threats. Returns (is_safe, reason)."""

        # Check payload size
        if body and len(body) > self.max_payload_size:
            return False, "Payload too large"

        # Check for suspicious patterns in headers
        for header_name, header_value in request.headers.items():
            if self._contains_suspicious_pattern(header_value):
                return False, f"Suspicious pattern in header {header_name}"

        # Check query parameters
        for key, value in request.query_params.items():
            if self._contains_suspicious_pattern(value):
                return False, f"Suspicious pattern in query parameter {key}"

        # Check body content
        if body and self._contains_suspicious_pattern(body):
            return False, "Suspicious pattern in request body"

        return True, None

    def _contains_suspicious_pattern(self, text: str) -> bool:
        """Check if text contains suspicious patterns using pre-compiled regex."""
        for pattern in self._compiled_patterns:
            if pattern.search(text):
                return True
        return False


class CircuitBreaker:
    """Circuit breaker for external dependencies."""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = None
        self.state = "CLOSED"  # CLOSED, OPEN, HALF_OPEN

    @asynccontextmanager
    async def call(self):
        """Context manager for circuit breaker calls."""
        if self.state == "OPEN":
            if self._should_attempt_reset():
                self.state = "HALF_OPEN"
            else:
                raise HTTPException(status_code=503, detail="Service temporarily unavailable")

        try:
            yield
            self._on_success()
        except Exception:
            self._on_failure()
            raise

    def _should_attempt_reset(self) -> bool:
        """Check if enough time has passed to attempt reset."""
        if self.last_failure_time is None:
            return True
        return time.time() - self.last_failure_time > self.recovery_timeout

    def _on_success(self):
        """Handle successful call."""
        self.failure_count = 0
        self.state = "CLOSED"

    def _on_failure(self):
        """Handle failed call."""
        self.failure_count += 1
        self.last_failure_time = time.time()

        if self.failure_count >= self.failure_threshold:
            self.state = "OPEN"


class SecurityManager:
    """Centralized security management."""

    def __init__(self):
        self.metrics = SecurityMetrics()
        self.rate_limiter = RateLimiter(
            max_requests=int(os.getenv("RATE_LIMIT_REQUESTS", "100")),
            window_seconds=int(os.getenv("RATE_LIMIT_WINDOW", "60")),
        )
        self.validator = SecurityValidator()
        self.circuit_breaker = CircuitBreaker()
        self.trusted_proxies = set(os.getenv("TRUSTED_PROXIES", "").split(","))

    def get_client_ip(self, request: Request) -> str:
        """Get real client IP accounting for proxies."""
        # Check X-Forwarded-For header from trusted proxies
        if "x-forwarded-for" in request.headers:
            forwarded_ips = request.headers["x-forwarded-for"].split(",")
            for ip in forwarded_ips:
                ip = ip.strip()
                if self._is_trusted_proxy(request.client.host):
                    return ip

        # Check X-Real-IP header
        if "x-real-ip" in request.headers:
            if self._is_trusted_proxy(request.client.host):
                return request.headers["x-real-ip"]

        # Fall back to direct connection
        return request.client.host

    def _is_trusted_proxy(self, ip: str) -> bool:
        """Check if IP is a trusted proxy."""
        return ip in self.trusted_proxies or ip in ["127.0.0.1", "::1"]

    async def validate_request(self, request: Request) -> None:
        """Comprehensive request validation."""
        client_ip = self.get_client_ip(request)

        # Check rate limiting
        allowed, retry_after = self.rate_limiter.is_allowed(client_ip)
        if not allowed:
            self.metrics.rate_limit_violations += 1
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded",
                headers={"Retry-After": str(retry_after)} if retry_after else {},
            )

        # Read request body for validation
        body = None
        if request.method == "POST":
            try:
                body = await request.body()
                body = body.decode("utf-8") if body else None
            except (UnicodeDecodeError, RuntimeError) as e:
                logger.debug(f"Failed to read request body: {e}")
                body = None

        # Validate for security threats
        is_safe, reason = self.validator.validate_request(request, body)
        if not is_safe:
            self.metrics.suspicious_requests += 1
            logger.warning(f"Suspicious request from {client_ip}: {reason}")
            raise HTTPException(status_code=400, detail="Invalid request")


class ConnectionPoolManager:
    """Manage HTTP connection pools for external services."""

    def __init__(self):
        self.pools: Dict[str, httpx.AsyncClient] = {}
        self.pool_configs = {
            "wazuh": {
                "timeout": httpx.Timeout(10.0, connect=5.0),
                "limits": httpx.Limits(max_connections=20, max_keepalive_connections=5),
                "retries": 3,
            }
        }

    async def get_client(self, service: str) -> httpx.AsyncClient:
        """Get or create HTTP client for service."""
        if service not in self.pools:
            config = self.pool_configs.get(service, self.pool_configs["wazuh"])
            self.pools[service] = httpx.AsyncClient(timeout=config["timeout"], limits=config["limits"])
        return self.pools[service]

    async def close_all(self):
        """Close all connection pools."""
        for client in self.pools.values():
            await client.aclose()
        self.pools.clear()


class MemoryManager:
    """Monitor and manage memory usage."""

    def __init__(self, max_memory_mb: int = 512):
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.last_check = time.time()
        self.check_interval = 30  # seconds

    def check_memory_usage(self) -> bool:
        """Check if memory usage is within limits."""
        now = time.time()
        if now - self.last_check < self.check_interval:
            return True

        try:
            import psutil

            process = psutil.Process()
            memory_usage = process.memory_info().rss

            if memory_usage > self.max_memory_bytes:
                logger.warning(f"Memory usage {memory_usage / 1024 / 1024:.1f}MB exceeds limit")
                return False

            self.last_check = now
            return True
        except ImportError:
            # psutil not available, skip check
            return True
        except Exception as e:
            logger.error(f"Memory check failed: {e}")
            return True


# Global security manager instance
security_manager = SecurityManager()
connection_pool_manager = ConnectionPoolManager()
memory_manager = MemoryManager()


async def security_middleware(request: Request, call_next):
    """Security middleware for FastAPI."""
    try:
        # Memory check
        if not memory_manager.check_memory_usage():
            raise HTTPException(status_code=503, detail="Server overloaded")

        # Security validation
        await security_manager.validate_request(request)

        # Process request
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        return response

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Security middleware error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
