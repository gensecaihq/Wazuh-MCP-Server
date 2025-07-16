"""
OAuth2 Persistent Storage Layer
Provides persistent storage for OAuth2 data using Redis backend
"""

import json
import logging
import asyncio
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
import redis.asyncio as redis
from dataclasses import asdict, is_dataclass

from .models import User, Client, AuthorizationCode, Token

logger = logging.getLogger(__name__)


class OAuth2Storage:
    """Persistent storage layer for OAuth2 data using Redis."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379", db_index: int = 1):
        """Initialize storage with Redis connection."""
        self.redis_url = redis_url
        self.db_index = db_index
        self.redis_client: Optional[redis.Redis] = None
        
        # Key prefixes for different data types
        self.prefixes = {
            'user': 'oauth2:user:',
            'client': 'oauth2:client:',
            'auth_code': 'oauth2:auth_code:',
            'token': 'oauth2:token:',
            'blacklist': 'oauth2:blacklist:',
            'session': 'oauth2:session:'
        }
        
    async def connect(self) -> bool:
        """Connect to Redis backend."""
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                db=self.db_index,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            # Test connection
            await self.redis_client.ping()
            logger.info("Successfully connected to OAuth2 storage backend")
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to OAuth2 storage: {e}")
            self.redis_client = None
            return False
    
    async def disconnect(self):
        """Disconnect from Redis backend."""
        if self.redis_client:
            await self.redis_client.close()
            self.redis_client = None
    
    def _serialize(self, obj: Any) -> str:
        """Serialize object to JSON string."""
        if is_dataclass(obj):
            data = asdict(obj)
            # Convert datetime objects to ISO strings
            for key, value in data.items():
                if isinstance(value, datetime):
                    data[key] = value.isoformat()
            return json.dumps(data)
        return json.dumps(obj)
    
    def _deserialize(self, data: str, obj_type: type) -> Any:
        """Deserialize JSON string to object."""
        if not data:
            return None
            
        json_data = json.loads(data)
        
        # Convert ISO strings back to datetime objects
        for key, value in json_data.items():
            if isinstance(value, str) and 'T' in value:
                try:
                    json_data[key] = datetime.fromisoformat(value)
                except ValueError:
                    pass  # Not a datetime string
        
        return obj_type(**json_data)
    
    # User Management
    async def store_user(self, user: User) -> bool:
        """Store user in persistent storage."""
        try:
            if not self.redis_client:
                return False
                
            key = f"{self.prefixes['user']}{user.username}"
            await self.redis_client.set(key, self._serialize(user))
            logger.debug(f"Stored user: {user.username}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store user {user.username}: {e}")
            return False
    
    async def get_user(self, username: str) -> Optional[User]:
        """Retrieve user from persistent storage."""
        try:
            if not self.redis_client:
                return None
                
            key = f"{self.prefixes['user']}{username}"
            data = await self.redis_client.get(key)
            
            if data:
                return self._deserialize(data, User)
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve user {username}: {e}")
            return None
    
    async def get_all_users(self) -> Dict[str, User]:
        """Retrieve all users from persistent storage."""
        try:
            if not self.redis_client:
                return {}
                
            pattern = f"{self.prefixes['user']}*"
            keys = await self.redis_client.keys(pattern)
            
            users = {}
            for key in keys:
                data = await self.redis_client.get(key)
                if data:
                    user = self._deserialize(data, User)
                    users[user.username] = user
            
            return users
            
        except Exception as e:
            logger.error(f"Failed to retrieve all users: {e}")
            return {}
    
    async def delete_user(self, username: str) -> bool:
        """Delete user from persistent storage."""
        try:
            if not self.redis_client:
                return False
                
            key = f"{self.prefixes['user']}{username}"
            result = await self.redis_client.delete(key)
            return result > 0
            
        except Exception as e:
            logger.error(f"Failed to delete user {username}: {e}")
            return False
    
    # Client Management
    async def store_client(self, client: Client) -> bool:
        """Store OAuth2 client in persistent storage."""
        try:
            if not self.redis_client:
                return False
                
            key = f"{self.prefixes['client']}{client.client_id}"
            await self.redis_client.set(key, self._serialize(client))
            logger.debug(f"Stored client: {client.client_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store client {client.client_id}: {e}")
            return False
    
    async def get_client(self, client_id: str) -> Optional[Client]:
        """Retrieve OAuth2 client from persistent storage."""
        try:
            if not self.redis_client:
                return None
                
            key = f"{self.prefixes['client']}{client_id}"
            data = await self.redis_client.get(key)
            
            if data:
                return self._deserialize(data, Client)
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve client {client_id}: {e}")
            return None
    
    async def get_all_clients(self) -> Dict[str, Client]:
        """Retrieve all OAuth2 clients from persistent storage."""
        try:
            if not self.redis_client:
                return {}
                
            pattern = f"{self.prefixes['client']}*"
            keys = await self.redis_client.keys(pattern)
            
            clients = {}
            for key in keys:
                data = await self.redis_client.get(key)
                if data:
                    client = self._deserialize(data, Client)
                    clients[client.client_id] = client
            
            return clients
            
        except Exception as e:
            logger.error(f"Failed to retrieve all clients: {e}")
            return {}
    
    # Authorization Code Management
    async def store_auth_code(self, code: AuthorizationCode, ttl_seconds: int = 600) -> bool:
        """Store authorization code with TTL."""
        try:
            if not self.redis_client:
                return False
                
            key = f"{self.prefixes['auth_code']}{code.code}"
            await self.redis_client.setex(key, ttl_seconds, self._serialize(code))
            logger.debug(f"Stored auth code with {ttl_seconds}s TTL")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store auth code: {e}")
            return False
    
    async def get_auth_code(self, code: str) -> Optional[AuthorizationCode]:
        """Retrieve authorization code."""
        try:
            if not self.redis_client:
                return None
                
            key = f"{self.prefixes['auth_code']}{code}"
            data = await self.redis_client.get(key)
            
            if data:
                return self._deserialize(data, AuthorizationCode)
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve auth code: {e}")
            return None
    
    async def delete_auth_code(self, code: str) -> bool:
        """Delete authorization code."""
        try:
            if not self.redis_client:
                return False
                
            key = f"{self.prefixes['auth_code']}{code}"
            result = await self.redis_client.delete(key)
            return result > 0
            
        except Exception as e:
            logger.error(f"Failed to delete auth code: {e}")
            return False
    
    # Token Management
    async def store_token(self, token: Token, ttl_seconds: Optional[int] = None) -> bool:
        """Store access token with optional TTL."""
        try:
            if not self.redis_client:
                return False
                
            key = f"{self.prefixes['token']}{token.access_token}"
            
            if ttl_seconds:
                await self.redis_client.setex(key, ttl_seconds, self._serialize(token))
            else:
                await self.redis_client.set(key, self._serialize(token))
            
            logger.debug(f"Stored token with {ttl_seconds or 'no'} TTL")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store token: {e}")
            return False
    
    async def get_token(self, access_token: str) -> Optional[Token]:
        """Retrieve access token."""
        try:
            if not self.redis_client:
                return None
                
            key = f"{self.prefixes['token']}{access_token}"
            data = await self.redis_client.get(key)
            
            if data:
                return self._deserialize(data, Token)
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve token: {e}")
            return None
    
    async def delete_token(self, access_token: str) -> bool:
        """Delete access token."""
        try:
            if not self.redis_client:
                return False
                
            key = f"{self.prefixes['token']}{access_token}"
            result = await self.redis_client.delete(key)
            return result > 0
            
        except Exception as e:
            logger.error(f"Failed to delete token: {e}")
            return False
    
    async def get_tokens_by_user(self, username: str) -> List[Token]:
        """Get all tokens for a specific user."""
        try:
            if not self.redis_client:
                return []
                
            pattern = f"{self.prefixes['token']}*"
            keys = await self.redis_client.keys(pattern)
            
            tokens = []
            for key in keys:
                data = await self.redis_client.get(key)
                if data:
                    token = self._deserialize(data, Token)
                    if token.username == username:
                        tokens.append(token)
            
            return tokens
            
        except Exception as e:
            logger.error(f"Failed to retrieve tokens for user {username}: {e}")
            return []
    
    # Token Blacklist Management
    async def blacklist_token(self, jti: str, ttl_seconds: int) -> bool:
        """Add token to blacklist with TTL."""
        try:
            if not self.redis_client:
                return False
                
            key = f"{self.prefixes['blacklist']}{jti}"
            await self.redis_client.setex(key, ttl_seconds, "blacklisted")
            logger.debug(f"Blacklisted token {jti} for {ttl_seconds}s")
            return True
            
        except Exception as e:
            logger.error(f"Failed to blacklist token {jti}: {e}")
            return False
    
    async def is_token_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted."""
        try:
            if not self.redis_client:
                return False
                
            key = f"{self.prefixes['blacklist']}{jti}"
            result = await self.redis_client.exists(key)
            return result > 0
            
        except Exception as e:
            logger.error(f"Failed to check blacklist for token {jti}: {e}")
            return False
    
    # Health Check
    async def health_check(self) -> bool:
        """Check if storage backend is healthy."""
        try:
            if not self.redis_client:
                return False
            await self.redis_client.ping()
            return True
        except Exception:
            return False
    
    # Cleanup Operations
    async def cleanup_expired_data(self) -> dict:
        """Clean up expired tokens and codes (Redis handles TTL automatically)."""
        cleanup_stats = {
            "expired_tokens": 0,
            "expired_codes": 0,
            "expired_blacklist": 0
        }
        
        try:
            if not self.redis_client:
                return cleanup_stats
            
            # Redis automatically handles TTL cleanup, but we can return stats
            # Count current active items for reporting
            token_keys = await self.redis_client.keys(f"{self.prefixes['token']}*")
            code_keys = await self.redis_client.keys(f"{self.prefixes['auth_code']}*")
            blacklist_keys = await self.redis_client.keys(f"{self.prefixes['blacklist']}*")
            
            cleanup_stats.update({
                "active_tokens": len(token_keys),
                "active_codes": len(code_keys),
                "blacklisted_tokens": len(blacklist_keys)
            })
            
            logger.debug(f"Storage cleanup stats: {cleanup_stats}")
            
        except Exception as e:
            logger.error(f"Failed to get cleanup stats: {e}")
        
        return cleanup_stats


class FallbackInMemoryStorage:
    """Fallback in-memory storage when Redis is unavailable."""
    
    def __init__(self):
        self.users: Dict[str, User] = {}
        self.clients: Dict[str, Client] = {}
        self.auth_codes: Dict[str, AuthorizationCode] = {}
        self.tokens: Dict[str, Token] = {}
        self.blacklist: Dict[str, datetime] = {}
        logger.warning("Using fallback in-memory storage - data will not persist")
    
    async def connect(self) -> bool:
        return True
    
    async def disconnect(self):
        pass
    
    async def store_user(self, user: User) -> bool:
        self.users[user.username] = user
        return True
    
    async def get_user(self, username: str) -> Optional[User]:
        return self.users.get(username)
    
    async def get_all_users(self) -> Dict[str, User]:
        return self.users.copy()
    
    async def delete_user(self, username: str) -> bool:
        return self.users.pop(username, None) is not None
    
    async def store_client(self, client: Client) -> bool:
        self.clients[client.client_id] = client
        return True
    
    async def get_client(self, client_id: str) -> Optional[Client]:
        return self.clients.get(client_id)
    
    async def get_all_clients(self) -> Dict[str, Client]:
        return self.clients.copy()
    
    async def store_auth_code(self, code: AuthorizationCode, ttl_seconds: int = 600) -> bool:
        self.auth_codes[code.code] = code
        # Schedule cleanup after TTL (simplified)
        asyncio.get_event_loop().call_later(
            ttl_seconds, 
            lambda: self.auth_codes.pop(code.code, None)
        )
        return True
    
    async def get_auth_code(self, code: str) -> Optional[AuthorizationCode]:
        return self.auth_codes.get(code)
    
    async def delete_auth_code(self, code: str) -> bool:
        return self.auth_codes.pop(code, None) is not None
    
    async def store_token(self, token: Token, ttl_seconds: Optional[int] = None) -> bool:
        self.tokens[token.access_token] = token
        if ttl_seconds:
            asyncio.get_event_loop().call_later(
                ttl_seconds,
                lambda: self.tokens.pop(token.access_token, None)
            )
        return True
    
    async def get_token(self, access_token: str) -> Optional[Token]:
        return self.tokens.get(access_token)
    
    async def delete_token(self, access_token: str) -> bool:
        return self.tokens.pop(access_token, None) is not None
    
    async def get_tokens_by_user(self, username: str) -> List[Token]:
        return [t for t in self.tokens.values() if t.username == username]
    
    async def blacklist_token(self, jti: str, ttl_seconds: int) -> bool:
        expiry = datetime.now() + timedelta(seconds=ttl_seconds)
        self.blacklist[jti] = expiry
        return True
    
    async def is_token_blacklisted(self, jti: str) -> bool:
        expiry = self.blacklist.get(jti)
        if expiry and datetime.now() > expiry:
            self.blacklist.pop(jti, None)
            return False
        return jti in self.blacklist
    
    async def health_check(self) -> bool:
        return True
    
    async def cleanup_expired_data(self) -> dict:
        now = datetime.now()
        expired_blacklist = [jti for jti, expiry in self.blacklist.items() if now > expiry]
        for jti in expired_blacklist:
            self.blacklist.pop(jti, None)
        
        return {
            "active_tokens": len(self.tokens),
            "active_codes": len(self.auth_codes),
            "blacklisted_tokens": len(self.blacklist),
            "expired_blacklist": len(expired_blacklist)
        }