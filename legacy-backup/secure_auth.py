"""Enhanced authentication module with JWT support and security best practices."""

import os
import jwt
import hashlib
import secrets
import time
from typing import Optional, Dict, Any, Tuple, List
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import asyncio
from ..utils.exceptions import AuthenticationError, AuthorizationError
from ..utils.logging import get_logger

logger = get_logger(__name__)

# Security constants
TOKEN_EXPIRY_MINUTES = 30
REFRESH_TOKEN_EXPIRY_DAYS = 7
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
MIN_PASSWORD_LENGTH = 12
PBKDF2_ITERATIONS = 100000


@dataclass
class AuthToken:
    """Authentication token with metadata."""
    token: str
    expires_at: datetime
    token_type: str = "Bearer"
    refresh_token: Optional[str] = None
    user_id: Optional[str] = None
    permissions: Optional[List[str]] = None


class SecureAuthManager:
    """Enhanced authentication manager with security features."""
    
    def __init__(self, secret_key: Optional[str] = None):
        """Initialize with secure secret key."""
        self.secret_key = secret_key or os.environ.get('JWT_SECRET_KEY')
        if not self.secret_key:
            # Generate a secure random key if not provided
            self.secret_key = secrets.token_urlsafe(32)
            logger.warning("No JWT secret key provided, generated random key (not suitable for production)")
        
        # Track login attempts for rate limiting
        self._login_attempts: Dict[str, List[float]] = {}
        self._locked_accounts: Dict[str, float] = {}
        self._active_tokens: Dict[str, Dict[str, Any]] = {}
        self._revoked_tokens: set = set()
        
    async def authenticate_user(self, username: str, password: str, ip_address: Optional[str] = None) -> AuthToken:
        """Authenticate user with enhanced security checks."""
        # Check if account is locked
        if await self._is_account_locked(username):
            raise AuthenticationError("Account temporarily locked due to multiple failed attempts")
        
        # Validate credentials (this should connect to your actual auth backend)
        if not await self._validate_credentials(username, password):
            await self._record_failed_attempt(username, ip_address)
            raise AuthenticationError("Invalid username or password")
        
        # Clear failed attempts on successful login
        await self._clear_failed_attempts(username)
        
        # Generate tokens
        access_token = await self._generate_access_token(username)
        refresh_token = await self._generate_refresh_token(username)
        
        # Store active token
        self._active_tokens[access_token['jti']] = {
            'user': username,
            'ip': ip_address,
            'created_at': time.time()
        }
        
        return AuthToken(
            token=access_token['token'],
            expires_at=access_token['expires_at'],
            refresh_token=refresh_token['token'],
            user_id=username,
            permissions=await self._get_user_permissions(username)
        )
    
    async def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify JWT token with security checks."""
        try:
            # Check if token is revoked
            if token in self._revoked_tokens:
                raise AuthenticationError("Token has been revoked")
            
            # Decode and verify token
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=['HS256'],
                options={"verify_exp": True}
            )
            
            # Check if token is in active tokens
            jti = payload.get('jti')
            if jti and jti not in self._active_tokens:
                raise AuthenticationError("Token not found in active tokens")
            
            # Additional security checks
            if 'user' not in payload:
                raise AuthenticationError("Invalid token payload")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")
    
    async def refresh_access_token(self, refresh_token: str) -> AuthToken:
        """Refresh access token using refresh token."""
        try:
            # Verify refresh token
            payload = jwt.decode(
                refresh_token,
                self.secret_key,
                algorithms=['HS256'],
                options={"verify_exp": True}
            )
            
            if payload.get('type') != 'refresh':
                raise AuthenticationError("Invalid refresh token")
            
            username = payload.get('user')
            if not username:
                raise AuthenticationError("Invalid refresh token payload")
            
            # Generate new access token
            access_token = await self._generate_access_token(username)
            
            return AuthToken(
                token=access_token['token'],
                expires_at=access_token['expires_at'],
                user_id=username,
                permissions=await self._get_user_permissions(username)
            )
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Refresh token has expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid refresh token: {str(e)}")
    
    async def revoke_token(self, token: str):
        """Revoke a token."""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'], options={"verify_exp": False})
            jti = payload.get('jti')
            
            if jti:
                self._revoked_tokens.add(token)
                self._active_tokens.pop(jti, None)
                logger.info(f"Token revoked for user: {payload.get('user')}")
                
        except jwt.InvalidTokenError:
            logger.warning("Attempted to revoke invalid token")
    
    async def hash_password(self, password: str) -> str:
        """Hash password using PBKDF2 with salt."""
        salt = secrets.token_bytes(32)
        pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
        return salt.hex() + pwdhash.hex()
    
    async def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash."""
        try:
            salt = bytes.fromhex(password_hash[:64])
            stored_hash = password_hash[64:]
            pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
            return pwdhash.hex() == stored_hash
        except Exception:
            return False
    
    async def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password meets security requirements."""
        if len(password) < MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {MIN_PASSWORD_LENGTH} characters"
        
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            return False, "Password must contain at least one special character"
        
        # Check against common passwords
        common_passwords = {'password', 'admin', '123456', 'wazuh', 'security'}
        if password.lower() in common_passwords:
            return False, "Password is too common"
        
        return True, "Password meets requirements"
    
    async def _generate_access_token(self, username: str) -> Dict[str, Any]:
        """Generate JWT access token."""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=TOKEN_EXPIRY_MINUTES)
        jti = secrets.token_urlsafe(16)
        
        payload = {
            'user': username,
            'exp': expires_at,
            'iat': now,
            'jti': jti,
            'type': 'access'
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        
        return {
            'token': token,
            'expires_at': expires_at,
            'jti': jti
        }
    
    async def _generate_refresh_token(self, username: str) -> Dict[str, Any]:
        """Generate JWT refresh token."""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(days=REFRESH_TOKEN_EXPIRY_DAYS)
        
        payload = {
            'user': username,
            'exp': expires_at,
            'iat': now,
            'type': 'refresh'
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        
        return {
            'token': token,
            'expires_at': expires_at
        }
    
    async def _validate_credentials(self, username: str, password: str) -> bool:
        """Validate user credentials against backend."""
        # This should be replaced with actual credential validation
        # For now, we'll use environment variables as a simple example
        env_username = os.environ.get('WAZUH_USER')
        env_password = os.environ.get('WAZUH_PASS')
        
        if not env_username or not env_password:
            logger.error("No credentials configured in environment")
            return False
        
        # In production, this would check against a database with hashed passwords
        return username == env_username and password == env_password
    
    async def _get_user_permissions(self, username: str) -> List[str]:
        """Get user permissions."""
        # This should be replaced with actual permission lookup
        # For now, return default permissions
        return ['read', 'write', 'execute']
    
    async def _is_account_locked(self, username: str) -> bool:
        """Check if account is locked due to failed attempts."""
        if username in self._locked_accounts:
            lock_time = self._locked_accounts[username]
            if time.time() < lock_time:
                return True
            else:
                # Unlock expired lock
                del self._locked_accounts[username]
        return False
    
    async def _record_failed_attempt(self, username: str, ip_address: Optional[str] = None):
        """Record failed login attempt."""
        current_time = time.time()
        
        # Initialize or get attempts list
        if username not in self._login_attempts:
            self._login_attempts[username] = []
        
        # Add current attempt
        self._login_attempts[username].append(current_time)
        
        # Remove old attempts (outside lockout window)
        cutoff_time = current_time - (LOCKOUT_DURATION_MINUTES * 60)
        self._login_attempts[username] = [
            t for t in self._login_attempts[username] if t > cutoff_time
        ]
        
        # Check if we should lock the account
        if len(self._login_attempts[username]) >= MAX_LOGIN_ATTEMPTS:
            lock_until = current_time + (LOCKOUT_DURATION_MINUTES * 60)
            self._locked_accounts[username] = lock_until
            logger.warning(f"Account locked for {username} due to {MAX_LOGIN_ATTEMPTS} failed attempts")
            if ip_address:
                logger.warning(f"Failed attempts from IP: {ip_address}")
    
    async def _clear_failed_attempts(self, username: str):
        """Clear failed login attempts on successful login."""
        self._login_attempts.pop(username, None)
        self._locked_accounts.pop(username, None)
    
    async def cleanup_expired_tokens(self):
        """Clean up expired tokens from memory."""
        current_time = time.time()
        
        # Clean up active tokens older than token expiry
        expired_tokens = []
        for jti, token_info in self._active_tokens.items():
            if current_time - token_info['created_at'] > (TOKEN_EXPIRY_MINUTES * 60):
                expired_tokens.append(jti)
        
        for jti in expired_tokens:
            del self._active_tokens[jti]
        
        if expired_tokens:
            logger.info(f"Cleaned up {len(expired_tokens)} expired tokens")


# Global auth manager instance
_auth_manager: Optional[SecureAuthManager] = None


def get_auth_manager() -> SecureAuthManager:
    """Get or create auth manager instance."""
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = SecureAuthManager()
    return _auth_manager