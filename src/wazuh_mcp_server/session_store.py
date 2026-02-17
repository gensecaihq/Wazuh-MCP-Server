#!/usr/bin/env python3
"""
Session storage backends for serverless-ready architecture
Provides pluggable session storage with in-memory and Redis implementations
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class SessionStore(ABC):
    """Abstract base class for session storage backends."""

    @abstractmethod
    async def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID."""
        pass

    @abstractmethod
    async def set(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        """Store session data."""
        pass

    @abstractmethod
    async def delete(self, session_id: str) -> bool:
        """Delete session by ID."""
        pass

    @abstractmethod
    async def exists(self, session_id: str) -> bool:
        """Check if session exists."""
        pass

    @abstractmethod
    async def get_all(self) -> Dict[str, Dict[str, Any]]:
        """Get all sessions."""
        pass

    @abstractmethod
    async def clear(self) -> bool:
        """Clear all sessions."""
        pass

    @abstractmethod
    async def cleanup_expired(self, timeout_minutes: int = 30) -> int:
        """Remove expired sessions and return count."""
        pass


class InMemorySessionStore(SessionStore):
    """
    In-memory session storage (default, current behavior).
    Thread-safe for single-instance deployments.
    NOT suitable for serverless/multi-instance deployments.
    """

    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        logger.info("Initialized InMemorySessionStore (single-instance mode)")

    async def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID."""
        return self._sessions.get(session_id)

    async def set(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        """Store session data."""
        try:
            self._sessions[session_id] = session_data
            return True
        except Exception as e:
            logger.error(f"Failed to store session {session_id}: {e}")
            return False

    async def delete(self, session_id: str) -> bool:
        """Delete session by ID."""
        try:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False
        except Exception as e:
            logger.error(f"Failed to delete session {session_id}: {e}")
            return False

    async def exists(self, session_id: str) -> bool:
        """Check if session exists."""
        return session_id in self._sessions

    async def get_all(self) -> Dict[str, Dict[str, Any]]:
        """Get all sessions."""
        return dict(self._sessions)

    async def clear(self) -> bool:
        """Clear all sessions."""
        try:
            self._sessions.clear()
            return True
        except Exception as e:
            logger.error(f"Failed to clear sessions: {e}")
            return False

    async def cleanup_expired(self, timeout_minutes: int = 30) -> int:
        """Remove expired sessions and return count."""
        from datetime import timedelta

        expired_count = 0
        now = datetime.now(timezone.utc)

        expired_ids = []
        for session_id, session_data in self._sessions.items():
            last_activity_str = session_data.get("last_activity")
            if last_activity_str:
                try:
                    last_activity = datetime.fromisoformat(last_activity_str.replace("Z", "+00:00"))
                    if now - last_activity > timedelta(minutes=timeout_minutes):
                        expired_ids.append(session_id)
                except Exception as e:
                    logger.error(f"Error parsing last_activity for session {session_id}: {e}")

        for session_id in expired_ids:
            if await self.delete(session_id):
                expired_count += 1

        if expired_count > 0:
            logger.info(f"Cleaned up {expired_count} expired sessions")

        return expired_count


class RedisSessionStore(SessionStore):
    """
    Redis-based session storage for serverless/multi-instance deployments.
    Enables horizontal scaling and serverless compatibility.
    """

    def __init__(self, redis_url: str, ttl_seconds: int = 1800):
        """
        Initialize Redis session store.

        Args:
            redis_url: Redis connection URL (e.g., redis://localhost:6379/0)
            ttl_seconds: Session TTL in seconds (default: 1800 = 30 minutes)
        """
        self.redis_url = redis_url
        self.ttl_seconds = ttl_seconds
        self._redis = None
        self._initialized = False

        logger.info(f"RedisSessionStore configured with TTL={ttl_seconds}s")

    async def _ensure_initialized(self):
        """Lazy initialization of Redis connection."""
        if self._initialized:
            return

        try:
            import redis.asyncio as aioredis

            self._redis = await aioredis.from_url(self.redis_url, encoding="utf-8", decode_responses=True)

            # Test connection
            await self._redis.ping()
            self._initialized = True
            logger.info(f"✅ Redis connection established: {self.redis_url}")

        except ImportError:
            logger.error("redis package not installed. Install with: pip install redis[async]")
            raise ImportError("redis package required for RedisSessionStore")
        except Exception as e:
            logger.error(f"Failed to connect to Redis at {self.redis_url}: {e}")
            raise ConnectionError(f"Redis connection failed: {e}")

    def _session_key(self, session_id: str) -> str:
        """Generate Redis key for session."""
        return f"mcp:session:{session_id}"

    async def get(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data by ID."""
        await self._ensure_initialized()

        try:
            data = await self._redis.get(self._session_key(session_id))
            if data:
                return json.loads(data)
            return None
        except Exception as e:
            logger.error(f"Failed to get session {session_id} from Redis: {e}")
            return None

    async def set(self, session_id: str, session_data: Dict[str, Any]) -> bool:
        """Store session data with TTL."""
        await self._ensure_initialized()

        try:
            key = self._session_key(session_id)
            data = json.dumps(session_data, default=str)
            await self._redis.setex(key, self.ttl_seconds, data)
            return True
        except Exception as e:
            logger.error(f"Failed to store session {session_id} in Redis: {e}")
            return False

    async def delete(self, session_id: str) -> bool:
        """Delete session by ID."""
        await self._ensure_initialized()

        try:
            result = await self._redis.delete(self._session_key(session_id))
            return result > 0
        except Exception as e:
            logger.error(f"Failed to delete session {session_id} from Redis: {e}")
            return False

    async def exists(self, session_id: str) -> bool:
        """Check if session exists."""
        await self._ensure_initialized()

        try:
            result = await self._redis.exists(self._session_key(session_id))
            return result > 0
        except Exception as e:
            logger.error(f"Failed to check session {session_id} existence in Redis: {e}")
            return False

    async def get_all(self) -> Dict[str, Dict[str, Any]]:
        """Get all sessions."""
        await self._ensure_initialized()

        try:
            pattern = self._session_key("*")
            keys = await self._redis.keys(pattern)

            sessions = {}
            for key in keys:
                session_id = key.split(":")[-1]
                data = await self._redis.get(key)
                if data:
                    sessions[session_id] = json.loads(data)

            return sessions
        except Exception as e:
            logger.error(f"Failed to get all sessions from Redis: {e}")
            return {}

    async def clear(self) -> bool:
        """Clear all sessions."""
        await self._ensure_initialized()

        try:
            pattern = self._session_key("*")
            keys = await self._redis.keys(pattern)

            if keys:
                await self._redis.delete(*keys)
                logger.info(f"Cleared {len(keys)} sessions from Redis")

            return True
        except Exception as e:
            logger.error(f"Failed to clear sessions from Redis: {e}")
            return False

    async def cleanup_expired(self, timeout_minutes: int = 30) -> int:
        """
        Redis handles expiration automatically via TTL.
        This is a no-op that returns 0.
        """
        # Redis automatically removes expired keys
        return 0

    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            logger.info("Redis connection closed")


def create_session_store() -> SessionStore:
    """
    Factory function to create appropriate session store based on configuration.

    Returns:
        SessionStore: InMemorySessionStore or RedisSessionStore based on REDIS_URL env var
    """
    redis_url = os.getenv("REDIS_URL")

    if redis_url:
        try:
            ttl_seconds = int(os.getenv("SESSION_TTL_SECONDS", "1800"))
            logger.info(f"Creating RedisSessionStore with URL: {redis_url}")
            return RedisSessionStore(redis_url, ttl_seconds)
        except Exception as e:
            logger.warning(f"Failed to create RedisSessionStore: {e}. Falling back to InMemorySessionStore")
            return InMemorySessionStore()
    else:
        logger.info("REDIS_URL not configured. Using InMemorySessionStore (not serverless-ready)")
        return InMemorySessionStore()
