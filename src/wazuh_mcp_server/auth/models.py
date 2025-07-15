"""Authentication models for OAuth 2.0 implementation."""

import time
import uuid
import re
from enum import Enum
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from ..utils.pydantic_compat import BaseModel, Field


class AuthScope(Enum):
    """OAuth 2.0 scopes for Wazuh MCP Server."""
    READ_ALERTS = "read:alerts"
    READ_AGENTS = "read:agents"
    READ_VULNERABILITIES = "read:vulnerabilities"
    READ_STATS = "read:stats"
    READ_LOGS = "read:logs"
    WRITE_AGENTS = "write:agents"
    WRITE_CONFIG = "write:config"
    ADMIN_CLUSTER = "admin:cluster"
    ADMIN_CONFIG = "admin:config"
    ADMIN_USERS = "admin:users"


class GrantType(Enum):
    """OAuth 2.0 grant types."""
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    REFRESH_TOKEN = "refresh_token"


class TokenType(Enum):
    """Token types."""
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    AUTHORIZATION_CODE = "authorization_code"


@dataclass
class User:
    """User model for authentication."""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    username: str = ""
    email: str = ""
    is_active: bool = True
    is_admin: bool = False
    created_at: float = field(default_factory=time.time)
    last_login: Optional[float] = None
    scopes: List[AuthScope] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    password_change_required: bool = False
    failed_login_attempts: int = 0
    account_locked_until: Optional[float] = None
    
    def has_scope(self, scope: AuthScope) -> bool:
        """Check if user has a specific scope."""
        return scope in self.scopes or self.is_admin
    
    def has_any_scope(self, scopes: List[AuthScope]) -> bool:
        """Check if user has any of the specified scopes."""
        if self.is_admin:
            return True
        return any(scope in self.scopes for scope in scopes)
    
    @property
    def is_account_locked(self) -> bool:
        """Check if account is locked due to failed login attempts."""
        if self.account_locked_until is None:
            return False
        return time.time() < self.account_locked_until
    
    def lock_account(self, duration: int = 1800) -> None:
        """Lock account for specified duration (default 30 minutes)."""
        self.account_locked_until = time.time() + duration
    
    def unlock_account(self) -> None:
        """Unlock account and reset failed login attempts."""
        self.account_locked_until = None
        self.failed_login_attempts = 0
    
    def record_failed_login(self) -> None:
        """Record a failed login attempt."""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            self.lock_account()
    
    def record_successful_login(self) -> None:
        """Record a successful login."""
        self.last_login = time.time()
        self.failed_login_attempts = 0
        self.account_locked_until = None


@dataclass
class Client:
    """OAuth 2.0 client model."""
    client_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_secret: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    redirect_uris: List[str] = field(default_factory=list)
    grant_types: List[GrantType] = field(default_factory=lambda: [GrantType.AUTHORIZATION_CODE])
    scopes: List[AuthScope] = field(default_factory=list)
    is_active: bool = True
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def validate_redirect_uri(self, uri: str) -> bool:
        """Validate a redirect URI."""
        return uri in self.redirect_uris
    
    def supports_grant_type(self, grant_type: GrantType) -> bool:
        """Check if client supports a grant type."""
        return grant_type in self.grant_types
    
    def has_scope(self, scope: AuthScope) -> bool:
        """Check if client has a specific scope."""
        return scope in self.scopes


@dataclass
class Token:
    """OAuth 2.0 token model."""
    token: str = field(default_factory=lambda: str(uuid.uuid4()))
    token_type: TokenType = TokenType.ACCESS_TOKEN
    client_id: str = ""
    user_id: Optional[str] = None
    scopes: List[AuthScope] = field(default_factory=list)
    expires_at: float = field(default_factory=lambda: time.time() + 3600)  # 1 hour default
    created_at: float = field(default_factory=time.time)
    revoked: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return time.time() > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if token is valid (not expired and not revoked)."""
        return not self.is_expired and not self.revoked
    
    def revoke(self) -> None:
        """Revoke the token."""
        self.revoked = True


@dataclass
class AuthorizationCode:
    """OAuth 2.0 authorization code model."""
    code: str = field(default_factory=lambda: str(uuid.uuid4()))
    client_id: str = ""
    user_id: str = ""
    redirect_uri: str = ""
    scopes: List[AuthScope] = field(default_factory=list)
    expires_at: float = field(default_factory=lambda: time.time() + 600)  # 10 minutes
    created_at: float = field(default_factory=time.time)
    used: bool = False
    
    @property
    def is_expired(self) -> bool:
        """Check if authorization code is expired."""
        return time.time() > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if authorization code is valid."""
        return not self.is_expired and not self.used
    
    def use(self) -> None:
        """Mark authorization code as used."""
        self.used = True


# Pydantic models for API requests/responses
class TokenRequest(BaseModel):
    """Token request model."""
    grant_type: str
    client_id: str
    client_secret: Optional[str] = None
    code: Optional[str] = None
    redirect_uri: Optional[str] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


class TokenResponse(BaseModel):
    """Token response model."""
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: Optional[str] = None
    scope: Optional[str] = None


class AuthorizeRequest(BaseModel):
    """Authorization request model."""
    response_type: str
    client_id: str
    redirect_uri: str
    scope: Optional[str] = None
    state: Optional[str] = None


class ErrorResponse(BaseModel):
    """OAuth 2.0 error response model."""
    error: str
    error_description: Optional[str] = None
    error_uri: Optional[str] = None


class UserInfo(BaseModel):
    """User info response model."""
    sub: str  # User ID
    username: str
    email: Optional[str] = None
    is_admin: bool = False
    scopes: List[str] = Field(default_factory=list)
    password_change_required: bool = False
    account_locked: bool = False


class ClientInfo(BaseModel):
    """Client info response model."""
    client_id: str
    name: str
    description: Optional[str] = None
    scopes: List[str] = Field(default_factory=list)
    grant_types: List[str] = Field(default_factory=list)


class PasswordPolicy:
    """Password policy validation."""
    
    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        """Validate password against security policy."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        # Check for common weak passwords
        weak_passwords = [
            'password', 'admin', '123456', 'qwerty', 'letmein',
            'welcome', 'monkey', 'dragon', 'password123', 'admin123'
        ]
        
        if password.lower() in weak_passwords:
            return False, "Password is too common and easily guessable"
        
        return True, "Password meets security requirements"


class PasswordChangeRequest(BaseModel):
    """Password change request model."""
    current_password: str
    new_password: str
    confirm_password: str
    
    def validate(self) -> tuple[bool, str]:
        """Validate password change request."""
        if self.new_password != self.confirm_password:
            return False, "New passwords do not match"
        
        if self.current_password == self.new_password:
            return False, "New password must be different from current password"
        
        return PasswordPolicy.validate_password(self.new_password)