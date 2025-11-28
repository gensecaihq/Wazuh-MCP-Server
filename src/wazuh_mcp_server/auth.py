#!/usr/bin/env python3
"""
Authentication module for MCP SSE Server
Implements token-based authentication with API key support
"""

import os
import secrets
import hashlib
import hmac
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
import json
import base64
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError

from pydantic import BaseModel, Field
import httpx
from fastapi import HTTPException, Header

@dataclass
class AuthToken:
    """Authentication token data."""
    token: str
    api_key_id: str
    created_at: datetime
    expires_at: Optional[datetime] = None
    scopes: List[str] = None
    metadata: Dict[str, Any] = None
    
    def is_valid(self) -> bool:
        """Check if token is still valid."""
        if self.expires_at:
            return datetime.now(timezone.utc) < self.expires_at
        return True
    
    def has_scope(self, scope: str) -> bool:
        """Check if token has specific scope."""
        if not self.scopes:
            return True  # No scopes means full access
        return scope in self.scopes

class APIKey(BaseModel):
    """API Key model."""
    id: str = Field(description="Unique key identifier")
    name: str = Field(description="Human-readable name")
    key_hash: str = Field(description="Hashed API key")
    created_at: datetime = Field(description="Creation timestamp")
    expires_at: Optional[datetime] = Field(default=None, description="Expiration timestamp")
    scopes: List[str] = Field(default_factory=list, description="Allowed scopes")
    active: bool = Field(default=True, description="Whether key is active")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")

class AuthManager:
    """Manage authentication for MCP server."""
    
    def __init__(self):
        self.secret_key = os.getenv("AUTH_SECRET_KEY", secrets.token_urlsafe(32))
        self.token_lifetime = int(os.getenv("TOKEN_LIFETIME_HOURS", "24"))
        self.api_keys: Dict[str, APIKey] = {}
        self.tokens: Dict[str, AuthToken] = {}
        
        # Load API keys from environment or config
        self._load_api_keys()
    
    def _load_api_keys(self):
        """Load API keys from configuration."""
        # Load from environment variable (JSON format)
        api_keys_json = os.getenv("API_KEYS")
        if api_keys_json:
            try:
                keys_data = json.loads(api_keys_json)
                for key_data in keys_data:
                    api_key = APIKey(**key_data)
                    self.api_keys[api_key.id] = api_key
            except Exception as e:
                print(f"Error loading API keys: {e}")
        
        # Create default API key if none exist
        if not self.api_keys:
            default_key = self.create_api_key(
                name="Default API Key",
                scopes=["wazuh:read", "wazuh:write"]
            )
            # Only log that a key was created, not the actual key value
            print("Created default API key - save this securely for client authentication")
    
    def hash_api_key(self, api_key: str) -> str:
        """Hash an API key using HMAC-SHA256."""
        return hmac.new(
            self.secret_key.encode(),
            api_key.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def create_api_key(
        self,
        name: str,
        scopes: Optional[List[str]] = None,
        expires_at: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Create new API key."""
        # Generate secure random key
        api_key = f"wazuh_{secrets.token_urlsafe(32)}"
        key_id = secrets.token_urlsafe(16)
        
        # Create key object
        key_obj = APIKey(
            id=key_id,
            name=name,
            key_hash=self.hash_api_key(api_key),
            created_at=datetime.now(timezone.utc),
            expires_at=expires_at,
            scopes=scopes or [],
            metadata=metadata or {}
        )
        
        self.api_keys[key_id] = key_obj
        return api_key
    
    def validate_api_key(self, api_key: str) -> Optional[APIKey]:
        """Validate API key and return key object if valid with proper cryptographic verification."""
        # Input validation
        if not api_key or not isinstance(api_key, str):
            return None
            
        # Format validation - must start with wazuh_ and have proper length
        # secrets.token_urlsafe(32) generates 43 chars, so total = 6 + 43 = 49
        if not api_key.startswith("wazuh_") or len(api_key) != 49:
            return None
            
        # Sanitize input to prevent injection attacks
        if not api_key.replace("_", "").replace("-", "").isalnum():
            return None
            
        # Use constant-time comparison to prevent timing attacks
        key_hash = self.hash_api_key(api_key)
        
        for key_obj in self.api_keys.values():
            # Use hmac.compare_digest for constant-time comparison
            if hmac.compare_digest(key_obj.key_hash, key_hash) and key_obj.active:
                # Check expiration with timezone awareness
                if key_obj.expires_at and datetime.now(timezone.utc) > key_obj.expires_at:
                    # Log expiration attempt (without exposing key)
                    print(f"Attempted use of expired API key (ID: {key_obj.id[:8]}...)")
                    return None
                return key_obj
                
        return None
    
    def create_token(self, api_key: str) -> Optional[str]:
        """Create authentication token from API key."""
        key_obj = self.validate_api_key(api_key)
        if not key_obj:
            return None
            
        # Generate token
        token = f"wst_{secrets.token_urlsafe(48)}"  # wst = Wazuh Session Token
        
        # Create token object
        token_obj = AuthToken(
            token=token,
            api_key_id=key_obj.id,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(hours=self.token_lifetime),
            scopes=key_obj.scopes,
            metadata={
                "api_key_name": key_obj.name,
                **key_obj.metadata
            }
        )
        
        self.tokens[token] = token_obj
        return token
    
    def validate_token(self, token: str) -> Optional[AuthToken]:
        """Validate token and return token object if valid."""
        if not token.startswith("wst_"):
            return None
            
        token_obj = self.tokens.get(token)
        if token_obj and token_obj.is_valid():
            return token_obj
            
        # Clean up expired token
        if token_obj:
            del self.tokens[token]
            
        return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        if token in self.tokens:
            del self.tokens[token]
            return True
        return False
    
    def revoke_api_key(self, key_id: str) -> bool:
        """Revoke an API key and all associated tokens."""
        if key_id in self.api_keys:
            self.api_keys[key_id].active = False
            
            # Revoke all tokens for this key
            tokens_to_revoke = [
                token for token, token_obj in self.tokens.items()
                if token_obj.api_key_id == key_id
            ]
            
            for token in tokens_to_revoke:
                del self.tokens[token]
                
            return True
        return False
    
    def cleanup_expired(self):
        """Clean up expired tokens."""
        expired_tokens = [
            token for token, token_obj in self.tokens.items()
            if not token_obj.is_valid()
        ]
        
        for token in expired_tokens:
            del self.tokens[token]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get authentication statistics."""
        self.cleanup_expired()
        
        return {
            "api_keys": {
                "total": len(self.api_keys),
                "active": sum(1 for k in self.api_keys.values() if k.active)
            },
            "tokens": {
                "total": len(self.tokens),
                "active": sum(1 for t in self.tokens.values() if t.is_valid())
            }
        }

# Global auth manager instance
auth_manager = AuthManager()

class TokenRequest(BaseModel):
    """Token request model."""
    api_key: str = Field(description="API key to exchange for token")

class TokenResponse(BaseModel):
    """Token response model."""
    token: str = Field(description="Authentication token")
    expires_in: int = Field(description="Token lifetime in seconds")
    token_type: str = Field(default="Bearer")

async def verify_bearer_token(authorization: str) -> AuthToken:
    """Verify bearer token from Authorization header."""
    if not authorization.startswith("Bearer "):
        raise ValueError("Invalid authorization header format")
        
    token = authorization[7:]  # Remove "Bearer " prefix
    token_obj = auth_manager.validate_token(token)
    
    if not token_obj:
        raise ValueError("Invalid or expired token")
        
    return token_obj

def create_access_token(data: Dict[str, Any], secret_key: str, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=24)
    
    to_encode.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    
    try:
        encoded_jwt = jwt.encode(to_encode, secret_key, algorithm="HS256")
        return encoded_jwt
    except Exception as e:
        raise ValueError(f"Failed to create access token: {str(e)}")


def verify_token(token: str, secret_key: str) -> Dict[str, Any]:
    """Verify and decode JWT token."""
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
        return payload
    except ExpiredSignatureError:
        raise ValueError("Token has expired")
    except JWTError:
        raise ValueError("Invalid token")


async def create_auth_endpoints(app):
    """Add authentication endpoints to FastAPI app."""
    
    @app.post("/auth/token", response_model=TokenResponse)
    async def create_token(request: TokenRequest):
        """Exchange API key for authentication token."""
        token = auth_manager.create_token(request.api_key)
        if not token:
            raise HTTPException(status_code=401, detail="Invalid API key")
            
        token_obj = auth_manager.tokens[token]
        expires_in = int((token_obj.expires_at - datetime.now(timezone.utc)).total_seconds())
        
        return TokenResponse(
            token=token,
            expires_in=expires_in
        )
    
    @app.get("/auth/validate")
    async def validate_token(
        authorization: str = Header(description="Bearer token")
    ):
        """Validate authentication token."""
        try:
            token_obj = await verify_bearer_token(authorization)
            return {
                "valid": True,
                "api_key_id": token_obj.api_key_id,
                "scopes": token_obj.scopes,
                "expires_at": token_obj.expires_at.isoformat() if token_obj.expires_at else None
            }
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e))
    
    @app.post("/auth/revoke")
    async def revoke_token(
        authorization: str = Header(description="Bearer token")
    ):
        """Revoke authentication token."""
        if not authorization.startswith("Bearer "):
            raise HTTPException(status_code=400, detail="Invalid authorization header")
            
        token = authorization[7:]
        if auth_manager.revoke_token(token):
            return {"revoked": True}
        else:
            raise HTTPException(status_code=404, detail="Token not found")
    
    @app.get("/auth/stats")
    async def auth_stats(
        authorization: str = Header(description="Bearer token")
    ):
        """Get authentication statistics (requires admin scope)."""
        try:
            token_obj = await verify_bearer_token(authorization)
            if not token_obj.has_scope("admin"):
                raise HTTPException(status_code=403, detail="Admin scope required")
                
            return auth_manager.get_stats()
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e))