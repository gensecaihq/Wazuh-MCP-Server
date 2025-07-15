"""Production-grade OAuth 2.0 server implementation for Wazuh MCP Server."""

import asyncio
import time
import secrets
import hashlib
import hmac
import logging
import os
import redis
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlencode, parse_qs
from datetime import datetime, timedelta

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from passlib.context import CryptContext

from .models import (
    User, Client, Token, AuthorizationCode, AuthScope, GrantType, TokenType,
    TokenRequest, TokenResponse, AuthorizeRequest, ErrorResponse, UserInfo,
    PasswordPolicy, PasswordChangeRequest
)
from ..utils.exceptions import (
    AuthenticationError, AuthorizationError, ValidationError, ConfigurationError
)
from ..utils.logging import get_logger
from ..utils.security_audit import (
    audit_authentication_success, audit_authentication_failure,
    audit_authorization_failure, audit_admin_action, audit_suspicious_activity,
    get_auditor
)

logger = get_logger(__name__)


class TokenManager:
    """Secure token management with JWT and proper encryption."""
    
    def __init__(self, secret_key: Optional[str] = None, key_rotation_interval: int = 86400):
        self.secret_key = self._validate_and_generate_key(secret_key)
        self.key_rotation_interval = key_rotation_interval
        self.algorithm = "HS256"
        self._key_created_at = time.time()
        self._key_version = 1
        
        # Redis for token blacklist
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        try:
            self._redis = redis.from_url(redis_url, decode_responses=True)
            self._redis.ping()
            logger.info("Connected to Redis for token blacklist")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Token blacklisting disabled.")
            self._redis = None
        
        # Generate RSA key pair for advanced scenarios
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self._public_key = self._private_key.public_key()
        
        logger.info(f"TokenManager initialized with secure key management (version {self._key_version})")
    
    def _validate_and_generate_key(self, secret_key: Optional[str]) -> str:
        """Validate key strength and generate secure key if needed."""
        if secret_key:
            # Validate key strength
            if len(secret_key) < 32:
                raise ValueError("JWT secret key must be at least 32 characters long")
            if secret_key.lower() in ['admin', 'password', 'secret', 'key', 'test']:
                raise ValueError("JWT secret key is too weak")
            return secret_key
        
        # Generate cryptographically secure key
        return secrets.token_urlsafe(64)
    
    def _should_rotate_key(self) -> bool:
        """Check if key should be rotated."""
        return (time.time() - self._key_created_at) > self.key_rotation_interval
    
    def rotate_key(self) -> None:
        """Rotate the JWT signing key."""
        old_version = self._key_version
        self.secret_key = secrets.token_urlsafe(64)
        self._key_created_at = time.time()
        self._key_version += 1
        
        logger.info(f"JWT key rotated from version {old_version} to {self._key_version}")
        
        # In production, you would store old keys for token validation during transition
        # For now, we'll just log the rotation
    
    def _is_token_blacklisted(self, jti: str) -> bool:
        """Check if token is blacklisted."""
        if not self._redis:
            return False
        
        try:
            return self._redis.exists(f"blacklist:{jti}")
        except Exception as e:
            logger.error(f"Failed to check token blacklist: {e}")
            return False
    
    def _blacklist_token(self, jti: str, exp: int) -> None:
        """Add token to blacklist."""
        if not self._redis:
            return
        
        try:
            ttl = max(0, exp - int(time.time()))
            if ttl > 0:
                self._redis.setex(f"blacklist:{jti}", ttl, "revoked")
        except Exception as e:
            logger.error(f"Failed to blacklist token: {e}")
    
    def create_access_token(self, user_id: str, client_id: str, scopes: List[AuthScope], 
                          expires_in: int = 3600) -> str:
        """Create a secure JWT access token."""
        try:
            # Check if key should be rotated
            if self._should_rotate_key():
                self.rotate_key()
            
            now = time.time()
            payload = {
                "sub": user_id,
                "client_id": client_id,
                "scopes": [scope.value for scope in scopes],
                "iat": now,
                "exp": now + expires_in,
                "jti": secrets.token_urlsafe(16),
                "token_type": "access_token",
                "key_version": self._key_version
            }
            
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            logger.debug(f"Created access token for user {user_id}, client {client_id}")
            return token
            
        except Exception as e:
            logger.error(f"Failed to create access token: {e}")
            raise AuthenticationError("Failed to create access token")
    
    def create_refresh_token(self, user_id: str, client_id: str) -> str:
        """Create a secure refresh token."""
        try:
            now = time.time()
            payload = {
                "sub": user_id,
                "client_id": client_id,
                "iat": now,
                "exp": now + (30 * 24 * 3600),  # 30 days
                "jti": secrets.token_urlsafe(16),
                "token_type": "refresh_token"
            }
            
            token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
            logger.debug(f"Created refresh token for user {user_id}, client {client_id}")
            return token
            
        except Exception as e:
            logger.error(f"Failed to create refresh token: {e}")
            raise AuthenticationError("Failed to create refresh token")
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode a JWT token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            # Check if token is expired
            if payload.get("exp", 0) < time.time():
                raise AuthenticationError("Token has expired")
            
            # Check if token is blacklisted
            jti = payload.get("jti")
            if jti and self._is_token_blacklisted(jti):
                raise AuthenticationError("Token has been revoked")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            raise AuthenticationError("Invalid token")
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            raise AuthenticationError("Token verification failed")
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token (add to blacklist)."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm], options={"verify_exp": False})
            jti = payload.get("jti")
            exp = payload.get("exp", 0)
            
            if jti:
                self._blacklist_token(jti, exp)
                logger.info(f"Token revoked: {jti}")
                return True
            else:
                logger.warning("Token has no JTI, cannot revoke")
                return False
                
        except Exception as e:
            logger.error(f"Failed to revoke token: {e}")
            return False


class OAuth2Server:
    """Production-grade OAuth 2.0 authorization server."""
    
    def __init__(self, token_manager: TokenManager):
        self.token_manager = token_manager
        self.password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        # In-memory stores (should be replaced with persistent storage in production)
        self.users: Dict[str, User] = {}
        self.clients: Dict[str, Client] = {}
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.active_tokens: Dict[str, Token] = {}
        
        # Security settings
        self.max_auth_code_lifetime = 600  # 10 minutes
        self.max_access_token_lifetime = 3600  # 1 hour
        self.max_refresh_token_lifetime = 30 * 24 * 3600  # 30 days
        
        logger.info("OAuth2Server initialized with secure defaults")
        
        # Initialize default admin user if none exists
        asyncio.create_task(self._initialize_default_admin())
    
    async def _initialize_default_admin(self) -> None:
        """Initialize default admin user if none exists."""
        try:
            # Check if any admin user exists
            admin_users = [u for u in self.users.values() if u.is_admin]
            if admin_users:
                return
            
            # Create default admin with strong password requirement
            admin_password = os.getenv("ADMIN_PASSWORD")
            if not admin_password or admin_password == "admin":
                admin_password = secrets.token_urlsafe(16)
                logger.warning(f"Generated secure admin password: {admin_password}")
                logger.warning("Please change this password immediately after first login")
            
            admin_user = await self.create_user(
                username="admin",
                email="admin@wazuh-mcp.local",
                password=admin_password,
                scopes=list(AuthScope),
                is_admin=True,
                force_password_change=True
            )
            
            logger.info(f"Default admin user created: {admin_user.username}")
            
        except Exception as e:
            logger.error(f"Failed to initialize default admin: {e}")
    
    async def create_user(self, username: str, email: str, password: str, 
                         scopes: List[AuthScope] = None, is_admin: bool = False,
                         force_password_change: bool = False) -> User:
        """Create a new user with secure password hashing."""
        try:
            if username in [u.username for u in self.users.values()]:
                raise ValidationError("Username already exists")
            
            # Validate password strength
            is_valid, message = PasswordPolicy.validate_password(password)
            if not is_valid:
                raise ValidationError(f"Password validation failed: {message}")
            
            user = User(
                username=username,
                email=email,
                scopes=scopes or [],
                is_admin=is_admin,
                password_change_required=force_password_change
            )
            
            # Hash password securely
            password_hash = self.password_context.hash(password)
            user.metadata["password_hash"] = password_hash
            
            self.users[user.id] = user
            logger.info(f"Created user: {username} ({user.id})")
            return user
            
        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            raise
    
    async def create_client(self, name: str, description: str = "", 
                           redirect_uris: List[str] = None,
                           grant_types: List[GrantType] = None,
                           scopes: List[AuthScope] = None) -> Client:
        """Create a new OAuth 2.0 client."""
        try:
            client = Client(
                name=name,
                description=description,
                redirect_uris=redirect_uris or [],
                grant_types=grant_types or [GrantType.AUTHORIZATION_CODE],
                scopes=scopes or []
            )
            
            self.clients[client.client_id] = client
            logger.info(f"Created OAuth2 client: {name} ({client.client_id})")
            return client
            
        except Exception as e:
            logger.error(f"Failed to create client {name}: {e}")
            raise
    
    async def authenticate_user(self, username: str, password: str, client_ip: str = None, 
                               user_agent: str = None, correlation_id: str = None) -> Optional[User]:
        """Authenticate a user with secure password verification."""
        try:
            user = next((u for u in self.users.values() if u.username == username), None)
            if not user or not user.is_active:
                audit_authentication_failure(username, client_ip, user_agent, "User not found or inactive", correlation_id)
                return None
            
            # Check if account is locked
            if user.is_account_locked:
                logger.warning(f"Login attempt on locked account: {username}")
                audit_authentication_failure(username, client_ip, user_agent, "Account locked", correlation_id)
                return None
            
            password_hash = user.metadata.get("password_hash")
            if not password_hash:
                audit_authentication_failure(username, client_ip, user_agent, "No password hash found", correlation_id)
                return None
            
            if self.password_context.verify(password, password_hash):
                user.record_successful_login()
                logger.info(f"User authenticated: {username}")
                audit_authentication_success(user.id, username, client_ip, user_agent, correlation_id)
                
                # Log token creation
                get_auditor().log_token_created(user.id, username, "authentication", "session", 3600, correlation_id)
                
                return user
            else:
                user.record_failed_login()
                logger.warning(f"Failed login attempt for user: {username} ({user.failed_login_attempts} attempts)")
                audit_authentication_failure(username, client_ip, user_agent, "Invalid password", correlation_id)
                
                # Log account lockout if threshold reached
                if user.failed_login_attempts >= 5:
                    get_auditor().log_account_locked(user.id, username, client_ip, "Too many failed attempts", correlation_id)
                
                return None
            
        except Exception as e:
            logger.error(f"Authentication failed for {username}: {e}")
            audit_authentication_failure(username, client_ip, user_agent, f"System error: {str(e)}", correlation_id)
            return None
    
    async def validate_client(self, client_id: str, client_secret: str = None) -> Optional[Client]:
        """Validate OAuth 2.0 client credentials."""
        try:
            client = self.clients.get(client_id)
            if not client or not client.is_active:
                return None
            
            if client_secret and client.client_secret != client_secret:
                return None
            
            return client
            
        except Exception as e:
            logger.error(f"Client validation failed for {client_id}: {e}")
            return None
    
    async def create_authorization_code(self, client_id: str, user_id: str, 
                                      redirect_uri: str, scopes: List[AuthScope]) -> str:
        """Create an authorization code for OAuth 2.0 flow."""
        try:
            code = secrets.token_urlsafe(32)
            auth_code = AuthorizationCode(
                code=code,
                client_id=client_id,
                user_id=user_id,
                redirect_uri=redirect_uri,
                scopes=scopes
            )
            
            self.authorization_codes[code] = auth_code
            logger.debug(f"Created authorization code for client {client_id}, user {user_id}")
            return code
            
        except Exception as e:
            logger.error(f"Failed to create authorization code: {e}")
            raise AuthenticationError("Failed to create authorization code")
    
    async def exchange_code_for_tokens(self, code: str, client_id: str, 
                                     redirect_uri: str) -> Tuple[str, str]:
        """Exchange authorization code for access and refresh tokens."""
        try:
            auth_code = self.authorization_codes.get(code)
            if not auth_code or not auth_code.is_valid:
                raise AuthenticationError("Invalid or expired authorization code")
            
            if auth_code.client_id != client_id:
                raise AuthenticationError("Client ID mismatch")
            
            if auth_code.redirect_uri != redirect_uri:
                raise AuthenticationError("Redirect URI mismatch")
            
            # Mark code as used
            auth_code.use()
            
            # Create tokens
            access_token = self.token_manager.create_access_token(
                auth_code.user_id, client_id, auth_code.scopes
            )
            refresh_token = self.token_manager.create_refresh_token(
                auth_code.user_id, client_id
            )
            
            logger.info(f"Exchanged authorization code for tokens: {client_id}")
            return access_token, refresh_token
            
        except Exception as e:
            logger.error(f"Token exchange failed: {e}")
            raise
    
    async def refresh_access_token(self, refresh_token: str, client_id: str) -> str:
        """Refresh an access token using a refresh token."""
        try:
            payload = self.token_manager.verify_token(refresh_token)
            
            if payload.get("token_type") != "refresh_token":
                raise AuthenticationError("Invalid token type")
            
            if payload.get("client_id") != client_id:
                raise AuthenticationError("Client ID mismatch")
            
            user_id = payload.get("sub")
            user = self.users.get(user_id)
            if not user or not user.is_active:
                raise AuthenticationError("User not found or inactive")
            
            # Create new access token
            access_token = self.token_manager.create_access_token(
                user_id, client_id, user.scopes
            )
            
            logger.info(f"Refreshed access token for user {user_id}")
            return access_token
            
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise
    
    async def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate an access token and return payload."""
        try:
            payload = self.token_manager.verify_token(token)
            
            if payload.get("token_type") != "access_token":
                return None
            
            # Verify user is still active
            user_id = payload.get("sub")
            user = self.users.get(user_id)
            if not user or not user.is_active:
                return None
            
            return payload
            
        except Exception as e:
            logger.debug(f"Token validation failed: {e}")
            return None
    
    async def change_password(self, user_id: str, current_password: str, new_password: str, 
                            client_ip: str = None, correlation_id: str = None) -> bool:
        """Change user password with validation."""
        try:
            user = self.users.get(user_id)
            if not user:
                audit_suspicious_activity(f"Password change attempt for non-existent user: {user_id}", client_ip, correlation_id=correlation_id)
                return False
            
            # Verify current password
            current_hash = user.metadata.get("password_hash")
            if not current_hash or not self.password_context.verify(current_password, current_hash):
                audit_authentication_failure(user.username, client_ip, reason="Invalid current password during password change", correlation_id=correlation_id)
                return False
            
            # Validate new password
            is_valid, message = PasswordPolicy.validate_password(new_password)
            if not is_valid:
                logger.warning(f"Password validation failed for user {user.username}: {message}")
                raise ValidationError(f"Password validation failed: {message}")
            
            # Check if new password is different from current
            if self.password_context.verify(new_password, current_hash):
                raise ValidationError("New password must be different from current password")
            
            # Hash and store new password
            new_hash = self.password_context.hash(new_password)
            user.metadata["password_hash"] = new_hash
            forced = user.password_change_required
            user.password_change_required = False
            
            logger.info(f"Password changed for user: {user.username}")
            get_auditor().log_password_changed(user.id, user.username, client_ip, forced, correlation_id)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to change password for user {user_id}: {e}")
            get_auditor().log_system_error("password_change_error", str(e), user_id, client_ip, correlation_id)
            return False
    
    async def cleanup_expired_codes(self) -> None:
        """Clean up expired authorization codes."""
        try:
            expired_codes = [
                code for code, auth_code in self.authorization_codes.items()
                if not auth_code.is_valid
            ]
            
            for code in expired_codes:
                del self.authorization_codes[code]
            
            if expired_codes:
                logger.info(f"Cleaned up {len(expired_codes)} expired authorization codes")
                
        except Exception as e:
            logger.error(f"Failed to cleanup expired codes: {e}")


class OAuth2Client:
    """OAuth 2.0 client for connecting to remote servers."""
    
    def __init__(self, client_id: str, client_secret: str, server_url: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self.server_url = server_url.rstrip('/')
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[float] = None
        
        logger.info(f"OAuth2Client initialized for server: {server_url}")
    
    def get_authorization_url(self, redirect_uri: str, scopes: List[str] = None,
                            state: str = None) -> str:
        """Generate authorization URL for OAuth 2.0 flow."""
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri
        }
        
        if scopes:
            params["scope"] = " ".join(scopes)
        
        if state:
            params["state"] = state
        
        return f"{self.server_url}/oauth/authorize?{urlencode(params)}"
    
    async def exchange_code(self, code: str, redirect_uri: str) -> bool:
        """Exchange authorization code for tokens."""
        # Implementation would use aiohttp to make request to token endpoint
        # For now, returning True as placeholder
        return True
    
    def is_token_valid(self) -> bool:
        """Check if current access token is valid."""
        if not self.access_token or not self.token_expires_at:
            return False
        return time.time() < self.token_expires_at - 60  # 1 minute buffer
    
    async def ensure_valid_token(self) -> str:
        """Ensure we have a valid access token, refreshing if necessary."""
        if self.is_token_valid():
            return self.access_token
        
        if self.refresh_token:
            # Attempt to refresh token
            # Implementation would make HTTP request
            pass
        
        raise AuthenticationError("No valid access token available")