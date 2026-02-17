#!/usr/bin/env python3
"""
OAuth 2.0 implementation with Dynamic Client Registration (DCR) support.
Implements MCP 2025-11-25 authentication specification for Claude Desktop integration.
"""

import hashlib
import logging
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from jose import jwt
from jose.exceptions import JWTError

logger = logging.getLogger(__name__)

# OAuth 2.0 Error Codes (RFC 6749)
OAUTH_ERRORS = {
    "invalid_request": "The request is missing a required parameter or is malformed",
    "unauthorized_client": "The client is not authorized to use this method",
    "access_denied": "The resource owner denied the request",
    "unsupported_response_type": "The response type is not supported",
    "invalid_scope": "The requested scope is invalid or unknown",
    "server_error": "The server encountered an unexpected error",
    "temporarily_unavailable": "The server is temporarily unavailable",
    "invalid_client": "Client authentication failed",
    "invalid_grant": "The authorization grant is invalid or expired",
    "unsupported_grant_type": "The grant type is not supported",
}


@dataclass
class OAuthClient:
    """Registered OAuth client."""

    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str] = field(default_factory=lambda: ["authorization_code", "refresh_token"])
    response_types: List[str] = field(default_factory=lambda: ["code"])
    scope: str = "wazuh:read wazuh:write"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    token_endpoint_auth_method: str = "client_secret_post"

    def to_registration_response(self) -> Dict[str, Any]:
        """Convert to DCR registration response."""
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "client_name": self.client_name,
            "redirect_uris": self.redirect_uris,
            "grant_types": self.grant_types,
            "response_types": self.response_types,
            "scope": self.scope,
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
            "client_id_issued_at": int(self.created_at.timestamp()),
        }


@dataclass
class AuthorizationCode:
    """OAuth authorization code."""

    code: str
    client_id: str
    redirect_uri: str
    scope: str
    created_at: datetime
    expires_at: datetime
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class OAuthToken:
    """OAuth access/refresh token."""

    token: str
    token_type: str  # "access" or "refresh"
    client_id: str
    scope: str
    created_at: datetime
    expires_at: datetime

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


class OAuthManager:
    """Manage OAuth 2.0 authentication with DCR support."""

    def __init__(self, config):
        self.config = config
        self.secret_key = config.AUTH_SECRET_KEY
        self.clients: Dict[str, OAuthClient] = {}
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.access_tokens: Dict[str, OAuthToken] = {}
        self.refresh_tokens: Dict[str, OAuthToken] = {}

        # Pre-register Claude as a known client
        self._register_claude_client()

    def _register_claude_client(self):
        """Pre-register Claude Desktop as a known OAuth client."""
        claude_client = OAuthClient(
            client_id="claude-desktop",
            client_secret=secrets.token_urlsafe(32),
            client_name="Claude",
            redirect_uris=[
                "https://claude.ai/api/mcp/auth_callback",
                "https://claude.com/api/mcp/auth_callback",
            ],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="wazuh:read wazuh:write",
        )
        self.clients[claude_client.client_id] = claude_client
        logger.info("Pre-registered Claude Desktop OAuth client")

    def get_issuer_url(self, request: Request) -> str:
        """Get the OAuth issuer URL."""
        if self.config.OAUTH_ISSUER_URL:
            return self.config.OAUTH_ISSUER_URL
        # Derive from request
        scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
        host = request.headers.get("x-forwarded-host", request.url.netloc)
        return f"{scheme}://{host}"

    def get_metadata(self, request: Request) -> Dict[str, Any]:
        """Get OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
        issuer = self.get_issuer_url(request)

        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "registration_endpoint": f"{issuer}/oauth/register" if self.config.OAUTH_ENABLE_DCR else None,
            "revocation_endpoint": f"{issuer}/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "scopes_supported": ["wazuh:read", "wazuh:write"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "service_documentation": f"{issuer}/docs",
        }

    def register_client(self, request_data: Dict[str, Any]) -> OAuthClient:
        """Dynamic Client Registration (RFC 7591)."""
        if not self.config.OAUTH_ENABLE_DCR:
            raise ValueError("Dynamic client registration is disabled")

        client_name = request_data.get("client_name", "Unknown Client")
        redirect_uris = request_data.get("redirect_uris", [])

        if not redirect_uris:
            raise ValueError("redirect_uris is required")

        # Generate client credentials
        client_id = f"client_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)

        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            client_name=client_name,
            redirect_uris=redirect_uris,
            grant_types=request_data.get("grant_types", ["authorization_code", "refresh_token"]),
            response_types=request_data.get("response_types", ["code"]),
            scope=request_data.get("scope", "wazuh:read wazuh:write"),
            token_endpoint_auth_method=request_data.get("token_endpoint_auth_method", "client_secret_post"),
        )

        self.clients[client_id] = client
        logger.info(f"Registered new OAuth client: {client_name} ({client_id})")

        return client

    def validate_client(self, client_id: str, client_secret: Optional[str] = None) -> Optional[OAuthClient]:
        """Validate client credentials."""
        client = self.clients.get(client_id)
        if not client:
            return None

        if client_secret and not secrets.compare_digest(client.client_secret, client_secret):
            return None

        return client

    def create_authorization_code(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
    ) -> str:
        """Create authorization code for OAuth flow."""
        code = secrets.token_urlsafe(32)

        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.OAUTH_AUTHORIZATION_CODE_TTL),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        self.authorization_codes[code] = auth_code
        return code

    def exchange_code_for_tokens(
        self, code: str, client_id: str, redirect_uri: str, code_verifier: Optional[str] = None
    ) -> Dict[str, Any]:
        """Exchange authorization code for access/refresh tokens."""
        auth_code = self.authorization_codes.get(code)

        if not auth_code:
            raise ValueError("invalid_grant")

        if auth_code.is_expired():
            del self.authorization_codes[code]
            raise ValueError("invalid_grant")

        if auth_code.client_id != client_id:
            raise ValueError("invalid_grant")

        if auth_code.redirect_uri != redirect_uri:
            raise ValueError("invalid_grant")

        # Verify PKCE if used
        if auth_code.code_challenge:
            if not code_verifier:
                raise ValueError("invalid_grant")

            if auth_code.code_challenge_method == "S256":
                computed = hashlib.sha256(code_verifier.encode()).digest()
                import base64

                computed_challenge = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()
            else:  # plain
                computed_challenge = code_verifier

            if not secrets.compare_digest(auth_code.code_challenge, computed_challenge):
                raise ValueError("invalid_grant")

        # Generate tokens
        access_token = self._create_jwt_token(client_id, auth_code.scope, "access")
        refresh_token = self._create_jwt_token(client_id, auth_code.scope, "refresh")

        # Store tokens
        self.access_tokens[access_token] = OAuthToken(
            token=access_token,
            token_type="access",
            client_id=client_id,
            scope=auth_code.scope,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.OAUTH_ACCESS_TOKEN_TTL),
        )

        self.refresh_tokens[refresh_token] = OAuthToken(
            token=refresh_token,
            token_type="refresh",
            client_id=client_id,
            scope=auth_code.scope,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.OAUTH_REFRESH_TOKEN_TTL),
        )

        # Remove used authorization code
        del self.authorization_codes[code]

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.OAUTH_ACCESS_TOKEN_TTL,
            "refresh_token": refresh_token,
            "scope": auth_code.scope,
        }

    def refresh_access_token(self, refresh_token: str, client_id: str) -> Dict[str, Any]:
        """Refresh access token using refresh token."""
        token_obj = self.refresh_tokens.get(refresh_token)

        if not token_obj:
            raise ValueError("invalid_grant")

        if token_obj.is_expired():
            del self.refresh_tokens[refresh_token]
            raise ValueError("invalid_grant")

        if token_obj.client_id != client_id:
            raise ValueError("invalid_grant")

        # Generate new access token
        access_token = self._create_jwt_token(client_id, token_obj.scope, "access")

        self.access_tokens[access_token] = OAuthToken(
            token=access_token,
            token_type="access",
            client_id=client_id,
            scope=token_obj.scope,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.OAUTH_ACCESS_TOKEN_TTL),
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.OAUTH_ACCESS_TOKEN_TTL,
            "scope": token_obj.scope,
        }

    def validate_access_token(self, token: str) -> Optional[OAuthToken]:
        """Validate access token."""
        # First check in-memory tokens
        token_obj = self.access_tokens.get(token)
        if token_obj and not token_obj.is_expired():
            return token_obj

        # Try to decode as JWT
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            if payload.get("type") == "access":
                return OAuthToken(
                    token=token,
                    token_type="access",
                    client_id=payload.get("client_id", ""),
                    scope=payload.get("scope", ""),
                    created_at=datetime.fromtimestamp(payload.get("iat", 0), timezone.utc),
                    expires_at=datetime.fromtimestamp(payload.get("exp", 0), timezone.utc),
                )
        except JWTError:
            pass

        return None

    def revoke_token(self, token: str) -> bool:
        """Revoke access or refresh token."""
        if token in self.access_tokens:
            del self.access_tokens[token]
            return True
        if token in self.refresh_tokens:
            del self.refresh_tokens[token]
            return True
        return False

    def delete_client(self, client_id: str) -> bool:
        """Delete a registered client and all its tokens."""
        if client_id not in self.clients:
            return False

        # Remove all tokens for this client
        self.access_tokens = {k: v for k, v in self.access_tokens.items() if v.client_id != client_id}
        self.refresh_tokens = {k: v for k, v in self.refresh_tokens.items() if v.client_id != client_id}

        del self.clients[client_id]
        logger.info(f"Deleted OAuth client: {client_id}")
        return True

    def _create_jwt_token(self, client_id: str, scope: str, token_type: str) -> str:
        """Create JWT token."""
        ttl = self.config.OAUTH_ACCESS_TOKEN_TTL if token_type == "access" else self.config.OAUTH_REFRESH_TOKEN_TTL

        payload = {
            "sub": client_id,
            "client_id": client_id,
            "scope": scope,
            "type": token_type,
            "iat": datetime.now(timezone.utc).timestamp(),
            "exp": (datetime.now(timezone.utc) + timedelta(seconds=ttl)).timestamp(),
            "jti": secrets.token_urlsafe(16),
        }

        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def cleanup_expired(self):
        """Clean up expired tokens and codes."""
        self.authorization_codes = {k: v for k, v in self.authorization_codes.items() if not v.is_expired()}
        self.access_tokens = {k: v for k, v in self.access_tokens.items() if not v.is_expired()}
        self.refresh_tokens = {k: v for k, v in self.refresh_tokens.items() if not v.is_expired()}


def create_oauth_router(oauth_manager: OAuthManager) -> APIRouter:
    """Create FastAPI router for OAuth endpoints."""
    router = APIRouter(prefix="/oauth", tags=["OAuth"])

    @router.get("/authorize")
    async def authorize(
        request: Request,
        response_type: str = Query(...),
        client_id: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query(default="wazuh:read wazuh:write"),
        state: Optional[str] = Query(default=None),
        code_challenge: Optional[str] = Query(default=None),
        code_challenge_method: Optional[str] = Query(default=None),
    ):
        """OAuth 2.0 Authorization Endpoint."""
        # Validate client
        client = oauth_manager.validate_client(client_id)
        if not client:
            return JSONResponse({"error": "invalid_client", "error_description": "Unknown client"}, status_code=401)

        # Validate redirect_uri
        if redirect_uri not in client.redirect_uris:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid redirect_uri"}, status_code=400
            )

        # Validate response_type
        if response_type != "code":
            return RedirectResponse(f"{redirect_uri}?error=unsupported_response_type&state={state or ''}")

        # For MCP servers, we auto-approve (the user already chose to connect)
        # In production, you might show a consent screen here

        # Generate authorization code
        code = oauth_manager.create_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )

        # Redirect back with code
        params = {"code": code}
        if state:
            params["state"] = state

        redirect_url = f"{redirect_uri}?{urlencode(params)}"
        return RedirectResponse(redirect_url)

    @router.post("/token")
    async def token(
        request: Request,
        grant_type: str = Form(...),
        code: Optional[str] = Form(default=None),
        redirect_uri: Optional[str] = Form(default=None),
        client_id: Optional[str] = Form(default=None),
        client_secret: Optional[str] = Form(default=None),
        refresh_token: Optional[str] = Form(default=None),
        code_verifier: Optional[str] = Form(default=None),
    ):
        """OAuth 2.0 Token Endpoint."""
        # Extract client credentials from Authorization header if not in body
        if not client_id:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                import base64

                try:
                    decoded = base64.b64decode(auth_header[6:]).decode()
                    client_id, client_secret = decoded.split(":", 1)
                except (ValueError, UnicodeDecodeError) as e:
                    logger.debug(f"Failed to decode Basic auth header: {e}")

        if not client_id:
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Client authentication required"}, status_code=401
            )

        # Validate client
        client = oauth_manager.validate_client(client_id, client_secret)
        if not client:
            # Per MCP spec: Return 401 with invalid_client to signal client deletion
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Client authentication failed"}, status_code=401
            )

        try:
            if grant_type == "authorization_code":
                if not code or not redirect_uri:
                    return JSONResponse(
                        {"error": "invalid_request", "error_description": "code and redirect_uri required"},
                        status_code=400,
                    )

                tokens = oauth_manager.exchange_code_for_tokens(
                    code=code,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier,
                )
                return JSONResponse(tokens)

            elif grant_type == "refresh_token":
                if not refresh_token:
                    return JSONResponse(
                        {"error": "invalid_request", "error_description": "refresh_token required"}, status_code=400
                    )

                tokens = oauth_manager.refresh_access_token(refresh_token, client_id)
                return JSONResponse(tokens)

            else:
                return JSONResponse(
                    {
                        "error": "unsupported_grant_type",
                        "error_description": f"Grant type '{grant_type}' not supported",
                    },
                    status_code=400,
                )

        except ValueError as e:
            error_code = str(e)
            return JSONResponse(
                {"error": error_code, "error_description": OAUTH_ERRORS.get(error_code, str(e))}, status_code=400
            )

    @router.post("/register")
    async def register(request: Request):
        """Dynamic Client Registration Endpoint (RFC 7591)."""
        if not oauth_manager.config.OAUTH_ENABLE_DCR:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Dynamic client registration is disabled"},
                status_code=400,
            )

        try:
            body = await request.json()
            client = oauth_manager.register_client(body)
            return JSONResponse(client.to_registration_response(), status_code=201)
        except ValueError as e:
            return JSONResponse({"error": "invalid_request", "error_description": str(e)}, status_code=400)
        except Exception as e:
            logger.error(f"Client registration error: {e}")
            return JSONResponse({"error": "server_error", "error_description": "Registration failed"}, status_code=500)

    @router.post("/revoke")
    async def revoke(
        token: str = Form(...),
        token_type_hint: Optional[str] = Form(default=None),
        client_id: Optional[str] = Form(default=None),
        client_secret: Optional[str] = Form(default=None),
    ):
        """Token Revocation Endpoint (RFC 7009)."""
        oauth_manager.revoke_token(token)
        # Always return 200 OK per RFC 7009
        return JSONResponse({})

    return router


# Global OAuth manager instance (initialized in server.py)
_oauth_manager: Optional[OAuthManager] = None


def get_oauth_manager() -> Optional[OAuthManager]:
    """Get OAuth manager instance."""
    return _oauth_manager


def init_oauth_manager(config) -> OAuthManager:
    """Initialize OAuth manager."""
    global _oauth_manager
    _oauth_manager = OAuthManager(config)
    return _oauth_manager
