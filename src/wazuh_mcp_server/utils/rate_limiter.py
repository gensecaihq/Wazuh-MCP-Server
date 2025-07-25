"""Rate limiting utilities for API protection."""

import time
import asyncio
from typing import Dict, Optional
from collections import defaultdict, deque
from dataclasses import dataclass
from .exceptions import RateLimitError


@dataclass
class RateLimitConfig:
    """Rate limit configuration."""
    max_requests: int
    time_window: int  # seconds
    burst_limit: Optional[int] = None  # Allow short bursts


class TokenBucket:
    """Token bucket rate limiter implementation."""
    
    def __init__(self, max_tokens: int, refill_rate: float, burst_limit: Optional[int] = None):
        self.max_tokens = max_tokens
        self.refill_rate = refill_rate  # tokens per second
        self.burst_limit = burst_limit or max_tokens
        self.tokens = max_tokens
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens from the bucket."""
        async with self._lock:
            now = time.time()
            
            # Refill tokens based on time elapsed
            time_passed = now - self.last_refill
            new_tokens = time_passed * self.refill_rate
            self.tokens = min(self.max_tokens, self.tokens + new_tokens)
            self.last_refill = now
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    async def wait_for_tokens(self, tokens: int = 1, timeout: Optional[float] = None) -> bool:
        """Wait until tokens are available."""
        start_time = time.time()
        
        while True:
            if await self.consume(tokens):
                return True
            
            if timeout and (time.time() - start_time) >= timeout:
                return False
            
            # Calculate wait time until next token is available
            wait_time = tokens / self.refill_rate
            await asyncio.sleep(min(wait_time, 0.1))  # Cap wait time


class SlidingWindowRateLimiter:
    """Sliding window rate limiter."""
    
    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.requests: Dict[str, deque] = defaultdict(deque)
        self._lock = asyncio.Lock()
    
    async def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed."""
        async with self._lock:
            now = time.time()
            window_start = now - self.config.time_window
            
            # Clean old requests
            request_times = self.requests[identifier]
            while request_times and request_times[0] < window_start:
                request_times.popleft()
            
            # Check if under limit
            if len(request_times) < self.config.max_requests:
                request_times.append(now)
                return True
            
            return False
    
    async def time_until_reset(self, identifier: str) -> float:
        """Get time until rate limit resets."""
        async with self._lock:
            request_times = self.requests[identifier]
            if not request_times:
                return 0.0
            
            oldest_request = request_times[0]
            reset_time = oldest_request + self.config.time_window
            return max(0.0, reset_time - time.time())


class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on system load."""
    
    def __init__(self, base_config: RateLimitConfig, adaptation_factor: float = 0.8):
        self.base_config = base_config
        self.adaptation_factor = adaptation_factor
        self.current_limit = base_config.max_requests
        self.limiter = SlidingWindowRateLimiter(base_config)
        self.error_count = 0
        self.success_count = 0
        self.last_adaptation = time.time()
        self._lock = asyncio.Lock()
    
    async def is_allowed(self, identifier: str) -> bool:
        """Check if request is allowed with adaptive limits."""
        # Update current limit based on recent performance
        await self._adapt_limit()
        
        # Temporarily update the limiter's config
        original_limit = self.limiter.config.max_requests
        self.limiter.config.max_requests = self.current_limit
        
        try:
            return await self.limiter.is_allowed(identifier)
        finally:
            self.limiter.config.max_requests = original_limit
    
    async def record_success(self):
        """Record a successful request."""
        async with self._lock:
            self.success_count += 1
    
    async def record_error(self):
        """Record a failed request."""
        async with self._lock:
            self.error_count += 1
    
    async def _adapt_limit(self):
        """Adapt rate limit based on error rate."""
        async with self._lock:
            now = time.time()
            if now - self.last_adaptation < 60:  # Adapt every minute
                return
            
            total_requests = self.success_count + self.error_count
            if total_requests == 0:
                return
            
            error_rate = self.error_count / total_requests
            
            if error_rate > 0.1:  # > 10% error rate, reduce limit
                self.current_limit = max(
                    1, 
                    int(self.current_limit * self.adaptation_factor)
                )
            elif error_rate < 0.05:  # < 5% error rate, increase limit
                self.current_limit = min(
                    self.base_config.max_requests,
                    int(self.current_limit / self.adaptation_factor)
                )
            
            # Reset counters
            self.success_count = 0
            self.error_count = 0
            self.last_adaptation = now


class GlobalRateLimiter:
    """Global rate limiter for the entire application."""
    
    def __init__(self):
        self.limiters: Dict[str, SlidingWindowRateLimiter] = {}
        self.token_buckets: Dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()
    
    def configure_endpoint(self, endpoint: str, config: RateLimitConfig):
        """Configure rate limiting for a specific endpoint."""
        self.limiters[endpoint] = SlidingWindowRateLimiter(config)
    
    def configure_token_bucket(self, identifier: str, max_tokens: int, refill_rate: float):
        """Configure token bucket for a specific identifier."""
        self.token_buckets[identifier] = TokenBucket(max_tokens, refill_rate)
    
    async def check_rate_limit(self, endpoint: str, identifier: str = "global") -> bool:
        """Check if request is within rate limits."""
        limiter = self.limiters.get(endpoint)
        if not limiter:
            return True  # No rate limit configured
        
        return await limiter.is_allowed(identifier)
    
    async def consume_tokens(self, identifier: str, tokens: int = 1) -> bool:
        """Consume tokens from a token bucket."""
        bucket = self.token_buckets.get(identifier)
        if not bucket:
            return True  # No token bucket configured
        
        return await bucket.consume(tokens)
    
    async def enforce_rate_limit(self, endpoint: str, identifier: str = "global"):
        """Enforce rate limit, raising exception if exceeded."""
        if not await self.check_rate_limit(endpoint, identifier):
            limiter = self.limiters.get(endpoint)
            if limiter:
                retry_after = await limiter.time_until_reset(identifier)
                raise RateLimitError(
                    f"Rate limit exceeded for {endpoint}", 
                    retry_after=int(retry_after) + 1
                )


# Global rate limiter instance
global_rate_limiter = GlobalRateLimiter()


class RateLimiter:
    """Simple rate limiter for backward compatibility."""
    
    def __init__(self, max_requests: int = 100, time_window: int = 60):
        self.config = RateLimitConfig(max_requests, time_window)
        self.limiter = SlidingWindowRateLimiter(self.config)
    
    async def acquire(self, identifier: str = "global") -> bool:
        """Acquire a rate limit slot."""
        return await self.limiter.is_allowed(identifier)
    
    async def time_until_reset(self, identifier: str = "global") -> float:
        """Get time until rate limit resets."""
        return await self.limiter.time_until_reset(identifier)


def rate_limit(endpoint: str, identifier_func=None):
    """Decorator for rate limiting functions."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            identifier = "global"
            if identifier_func:
                identifier = identifier_func(*args, **kwargs)
            
            await global_rate_limiter.enforce_rate_limit(endpoint, identifier)
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator