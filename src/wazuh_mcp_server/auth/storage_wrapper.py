"""
OAuth2 Storage Wrapper - Backward compatible persistent storage layer
Provides persistence while maintaining in-memory interface compatibility
"""

import asyncio
import logging
from typing import Dict, Any, Optional
from .storage import OAuth2Storage, FallbackInMemoryStorage
from .models import User, Client, AuthorizationCode, Token

logger = logging.getLogger(__name__)


class PersistentDict:
    """Dictionary-like interface that persists data to storage backend."""
    
    def __init__(self, storage_backend, prefix: str, ttl_seconds: Optional[int] = None):
        self.storage = storage_backend
        self.prefix = prefix
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Any] = {}
        self._loaded = False
    
    async def _ensure_loaded(self):
        """Ensure data is loaded from storage."""
        if not self._loaded and self.storage:
            try:
                if self.prefix == 'user':
                    data = await self.storage.get_all_users()
                elif self.prefix == 'client':
                    data = await self.storage.get_all_clients()
                else:
                    data = {}
                
                self._cache.update(data)
                self._loaded = True
            except Exception as e:
                logger.error(f"Failed to load {self.prefix} data from storage: {e}")
    
    def __getitem__(self, key):
        return self._cache[key]
    
    def __setitem__(self, key, value):
        self._cache[key] = value
        # Persist to storage asynchronously
        if self.storage:
            asyncio.create_task(self._persist_item(key, value))
    
    def __delitem__(self, key):
        del self._cache[key]
        # Remove from storage asynchronously
        if self.storage:
            asyncio.create_task(self._delete_item(key))
    
    def __contains__(self, key):
        return key in self._cache
    
    def __iter__(self):
        return iter(self._cache)
    
    def __len__(self):
        return len(self._cache)
    
    def get(self, key, default=None):
        return self._cache.get(key, default)
    
    def keys(self):
        return self._cache.keys()
    
    def values(self):
        return self._cache.values()
    
    def items(self):
        return self._cache.items()
    
    def pop(self, key, default=None):
        value = self._cache.pop(key, default)
        if self.storage and key in self._cache:
            asyncio.create_task(self._delete_item(key))
        return value
    
    async def _persist_item(self, key, value):
        """Persist item to storage backend."""
        try:
            if self.prefix == 'user' and isinstance(value, User):
                await self.storage.store_user(value)
            elif self.prefix == 'client' and isinstance(value, Client):
                await self.storage.store_client(value)
            elif self.prefix == 'auth_code' and isinstance(value, AuthorizationCode):
                await self.storage.store_auth_code(value, self.ttl_seconds or 600)
            elif self.prefix == 'token' and isinstance(value, Token):
                await self.storage.store_token(value, self.ttl_seconds)
        except Exception as e:
            logger.error(f"Failed to persist {self.prefix} item {key}: {e}")
    
    async def _delete_item(self, key):
        """Delete item from storage backend."""
        try:
            if self.prefix == 'user':
                await self.storage.delete_user(key)
            elif self.prefix == 'auth_code':
                await self.storage.delete_auth_code(key)
            elif self.prefix == 'token':
                await self.storage.delete_token(key)
        except Exception as e:
            logger.error(f"Failed to delete {self.prefix} item {key}: {e}")


class OAuth2StorageManager:
    """Manager for OAuth2 persistent storage with backward compatibility."""
    
    def __init__(self, redis_url: Optional[str] = None, enable_persistence: bool = True):
        self.redis_url = redis_url
        self.enable_persistence = enable_persistence
        self.storage: Optional[OAuth2Storage] = None
        self.fallback_storage: Optional[FallbackInMemoryStorage] = None
        self._initialized = False
        
        # Create persistent dictionaries that act like regular dicts
        self.users = PersistentDict(None, 'user')
        self.clients = PersistentDict(None, 'client')
        self.authorization_codes = PersistentDict(None, 'auth_code', ttl_seconds=600)
        self.active_tokens = PersistentDict(None, 'token', ttl_seconds=3600)
    
    async def initialize(self) -> bool:
        """Initialize storage backend."""
        if self._initialized:
            return True
        
        if not self.enable_persistence:
            logger.info("Persistent storage disabled, using in-memory only")
            self._initialized = True
            return True
        
        try:
            # Try to connect to Redis
            self.storage = OAuth2Storage(self.redis_url or "redis://localhost:6379")
            connected = await self.storage.connect()
            
            if connected:
                logger.info("Successfully connected to persistent OAuth2 storage")
                # Update persistent dicts to use the storage
                self.users.storage = self.storage
                self.clients.storage = self.storage
                self.authorization_codes.storage = self.storage
                self.active_tokens.storage = self.storage
                
                # Load existing data
                await self.users._ensure_loaded()
                await self.clients._ensure_loaded()
                
                self._initialized = True
                return True
            else:
                logger.warning("Failed to connect to Redis, using in-memory storage")
                return await self._initialize_fallback()
                
        except Exception as e:
            logger.error(f"Failed to initialize persistent storage: {e}")
            return await self._initialize_fallback()
    
    async def _initialize_fallback(self) -> bool:
        """Initialize fallback in-memory storage."""
        try:
            self.fallback_storage = FallbackInMemoryStorage()
            await self.fallback_storage.connect()
            logger.warning("Using fallback in-memory storage - data will not persist")
            self._initialized = True
            return True
        except Exception as e:
            logger.error(f"Failed to initialize fallback storage: {e}")
            return False
    
    async def health_check(self) -> bool:
        """Check if storage is healthy."""
        if self.storage:
            return await self.storage.health_check()
        return True
    
    async def cleanup(self):
        """Cleanup storage connections."""
        if self.storage:
            await self.storage.disconnect()
        if self.fallback_storage:
            await self.fallback_storage.disconnect()
    
    def get_stats(self) -> dict:
        """Get storage statistics."""
        return {
            "users_count": len(self.users),
            "clients_count": len(self.clients),
            "active_codes": len(self.authorization_codes),
            "active_tokens": len(self.active_tokens),
            "persistent_storage": self.storage is not None,
            "storage_type": "redis" if self.storage else "memory"
        }