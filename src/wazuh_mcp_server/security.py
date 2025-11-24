#!/usr/bin/env python3
"""
Production security hardening and edge case handling for Wazuh MCP Server
Implements comprehensive security measures and error handling
"""

import os
import time
import hashlib
import secrets
import logging
from typing import Dict, Any, Optional, Set, List
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
from collections import defaultdict, deque
import asyncio
from contextlib import asynccontextmanager

from fastapi import HTTPException, Request
from pydantic import BaseModel
import httpx

logger = logging.getLogger(__name__)

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
    dangerous_patterns = ['<script', 'javascript:', 'onerror=', 'onclick=', '../', '..\\\\']
    value_lower = value.lower()
    for pattern in dangerous_patterns:
        if pattern in value_lower:
            raise ValueError(f"Input contains disallowed pattern: {pattern}")

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
    
    def __init__(self):
        self.suspicious_patterns = [
            # SQL Injection patterns
            r"(?i)(union|select|insert|delete|drop|create|alter|exec|execute)",
            # XSS patterns
            r"(?i)(<script|javascript:|onload=|onerror=)",
            # Path traversal
            r"(\.\./|\.\.\\|%2e%2e)",
            # Command injection
            r"(;|\||&|`|\$\(|\$\{)",
        ]
        self.max_payload_size = 1024 * 1024  # 1MB
        
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
        """Check if text contains suspicious patterns."""
        import re
        for pattern in self.suspicious_patterns:
            if re.search(pattern, text):
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
        except Exception as e:
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
            window_seconds=int(os.getenv("RATE_LIMIT_WINDOW", "60"))
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
                headers={"Retry-After": str(retry_after)} if retry_after else {}
            )
        
        # Read request body for validation
        body = None
        if request.method == "POST":
            try:
                body = await request.body()
                body = body.decode('utf-8') if body else None
            except Exception:
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
                "retries": 3
            }
        }
        
    async def get_client(self, service: str) -> httpx.AsyncClient:
        """Get or create HTTP client for service."""
        if service not in self.pools:
            config = self.pool_configs.get(service, self.pool_configs["wazuh"])
            self.pools[service] = httpx.AsyncClient(
                timeout=config["timeout"],
                limits=config["limits"]
            )
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