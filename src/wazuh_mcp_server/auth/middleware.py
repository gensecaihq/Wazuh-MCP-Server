"""Authentication middleware for HTTP/SSE transport."""

import asyncio
import time
from typing import Callable, Dict, Any, Optional, List
from functools import wraps
import logging

from aiohttp import web
from aiohttp.web_request import Request
from aiohttp.web_response import Response

from .oauth2 import OAuth2Server, TokenManager
from .models import AuthScope, ErrorResponse
from ..utils.exceptions import AuthenticationError, AuthorizationError
from ..utils.logging import get_logger

logger = get_logger(__name__)


class AuthContext:
    """Authentication context for requests."""
    
    def __init__(self, user_id: str, client_id: str, scopes: List[AuthScope], 
                 token_payload: Dict[str, Any]):
        self.user_id = user_id
        self.client_id = client_id
        self.scopes = scopes
        self.token_payload = token_payload
        self.authenticated_at = time.time()
    
    def has_scope(self, scope: AuthScope) -> bool:
        """Check if context has a specific scope."""
        return scope in self.scopes
    
    def has_any_scope(self, scopes: List[AuthScope]) -> bool:
        """Check if context has any of the specified scopes."""
        return any(scope in self.scopes for scope in scopes)
    
    def has_all_scopes(self, scopes: List[AuthScope]) -> bool:
        """Check if context has all of the specified scopes."""
        return all(scope in self.scopes for scope in scopes)


class AuthMiddleware:
    """Production-grade authentication middleware."""
    
    def __init__(self, oauth2_server: OAuth2Server, 
                 exclude_paths: List[str] = None,
                 rate_limit_requests: int = 100,
                 rate_limit_window: int = 3600):
        self.oauth2_server = oauth2_server
        self.exclude_paths = exclude_paths or [
            "/health", "/metrics", "/oauth/authorize", "/oauth/token"
        ]
        
        # Rate limiting
        self.rate_limit_requests = rate_limit_requests
        self.rate_limit_window = rate_limit_window
        self.request_counts: Dict[str, List[float]] = {}
        
        logger.info("AuthMiddleware initialized with secure defaults")
    
    async def __call__(self, request: Request, handler: Callable) -> Response:
        """Main middleware handler."""
        try:
            # Skip authentication for excluded paths
            if self._should_skip_auth(request):
                return await handler(request)
            
            # Extract and validate token
            auth_context = await self._authenticate_request(request)
            if not auth_context:
                return self._unauthorized_response()
            
            # Check rate limits
            if not await self._check_rate_limit(request, auth_context):
                return self._rate_limit_response()
            
            # Add auth context to request
            request['auth'] = auth_context
            
            # Log authenticated request
            logger.debug(f"Authenticated request: {auth_context.user_id} -> {request.path}")
            
            return await handler(request)
            
        except AuthenticationError as e:
            logger.warning(f"Authentication failed: {e}")
            return self._unauthorized_response(str(e))
        except AuthorizationError as e:
            logger.warning(f"Authorization failed: {e}")
            return self._forbidden_response(str(e))
        except Exception as e:
            logger.error(f"Auth middleware error: {e}")
            return self._internal_error_response()
    
    def _should_skip_auth(self, request: Request) -> bool:
        """Check if authentication should be skipped for this request."""
        path = request.path.rstrip('/')
        return any(path.startswith(exclude_path) for exclude_path in self.exclude_paths)
    
    async def _authenticate_request(self, request: Request) -> Optional[AuthContext]:
        """Extract and validate authentication from request."""
        try:
            # Extract Authorization header
            auth_header = request.headers.get('Authorization')
            if not auth_header:
                return None
            
            # Parse Bearer token
            if not auth_header.startswith('Bearer '):
                return None
            
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Validate token
            token_payload = await self.oauth2_server.validate_token(token)
            if not token_payload:
                return None
            
            # Extract information from token
            user_id = token_payload.get('sub')
            client_id = token_payload.get('client_id')
            scope_strings = token_payload.get('scopes', [])
            
            # Convert scope strings to AuthScope objects
            scopes = []
            for scope_str in scope_strings:
                try:
                    scopes.append(AuthScope(scope_str))
                except ValueError:
                    logger.warning(f"Unknown scope in token: {scope_str}")
            
            return AuthContext(user_id, client_id, scopes, token_payload)
            
        except Exception as e:
            logger.debug(f"Authentication extraction failed: {e}")
            return None
    
    async def _check_rate_limit(self, request: Request, auth_context: AuthContext) -> bool:
        """Check rate limits for authenticated user."""
        try:
            user_id = auth_context.user_id
            current_time = time.time()
            window_start = current_time - self.rate_limit_window
            
            # Get or create request list for user
            if user_id not in self.request_counts:
                self.request_counts[user_id] = []
            
            # Clean old requests outside window
            self.request_counts[user_id] = [
                req_time for req_time in self.request_counts[user_id]
                if req_time > window_start
            ]
            
            # Check if user has exceeded limit
            if len(self.request_counts[user_id]) >= self.rate_limit_requests:
                logger.warning(f"Rate limit exceeded for user: {user_id}")
                return False
            
            # Add current request
            self.request_counts[user_id].append(current_time)
            return True
            
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return True  # Allow request on error
    
    def _unauthorized_response(self, message: str = "Unauthorized") -> Response:
        """Return 401 Unauthorized response."""
        error = ErrorResponse(
            error="unauthorized",
            error_description=message
        )
        return web.json_response(
            error.dict(),
            status=401,
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    def _forbidden_response(self, message: str = "Forbidden") -> Response:
        """Return 403 Forbidden response."""
        error = ErrorResponse(
            error="forbidden",
            error_description=message
        )
        return web.json_response(error.dict(), status=403)
    
    def _rate_limit_response(self) -> Response:
        """Return 429 Too Many Requests response."""
        error = ErrorResponse(
            error="rate_limit_exceeded",
            error_description="Too many requests"
        )
        return web.json_response(
            error.dict(),
            status=429,
            headers={"Retry-After": str(self.rate_limit_window)}
        )
    
    def _internal_error_response(self) -> Response:
        """Return 500 Internal Server Error response."""
        error = ErrorResponse(
            error="internal_error",
            error_description="Internal server error"
        )
        return web.json_response(error.dict(), status=500)


def require_auth(scopes: List[AuthScope] = None):
    """Decorator to require authentication with optional scope checking."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            # Check if request is authenticated
            auth_context = request.get('auth')
            if not auth_context:
                raise AuthenticationError("Authentication required")
            
            # Check required scopes
            if scopes and not auth_context.has_any_scope(scopes):
                required_scopes = [scope.value for scope in scopes]
                raise AuthorizationError(f"Required scopes: {required_scopes}")
            
            return await func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def require_scopes(*scopes: AuthScope):
    """Decorator to require specific scopes."""
    return require_auth(list(scopes))


def require_admin():
    """Decorator to require admin privileges."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            auth_context = request.get('auth')
            if not auth_context:
                raise AuthenticationError("Authentication required")
            
            # Check if user has admin scope
            if not auth_context.has_scope(AuthScope.ADMIN_CONFIG):
                raise AuthorizationError("Admin privileges required")
            
            return await func(request, *args, **kwargs)
        
        return wrapper
    return decorator


async def get_auth_context(request: Request) -> Optional[AuthContext]:
    """Helper function to get authentication context from request."""
    return request.get('auth')


class SecurityHeaders:
    """Security headers middleware."""
    
    def __init__(self):
        self.security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'",
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }
    
    async def __call__(self, request: Request, handler: Callable) -> Response:
        """Add security headers to response."""
        response = await handler(request)
        
        for header, value in self.security_headers.items():
            response.headers[header] = value
        
        return response