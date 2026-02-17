#!/usr/bin/env python3
"""
Wazuh MCP Server - Complete MCP-Compliant Remote Server
Full compliance with Model Context Protocol 2025-11-25 specification
Production-ready with Streamable HTTP and legacy SSE transport, authentication, and monitoring
"""

import asyncio
import json
import logging
import os
import threading
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, ValidationError

from wazuh_mcp_server import __version__
from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError
from wazuh_mcp_server.auth import create_access_token
from wazuh_mcp_server.config import WazuhConfig, get_config
from wazuh_mcp_server.monitoring import ACTIVE_CONNECTIONS, REQUEST_COUNT
from wazuh_mcp_server.resilience import GracefulShutdown
from wazuh_mcp_server.security import (
    RateLimiter,
    ToolValidationError,
    validate_agent_id,
    validate_agent_status,
    validate_boolean,
    validate_compliance_framework,
    validate_indicator,
    validate_indicator_type,
    validate_input,
    validate_limit,
    validate_query,
    validate_report_type,
    validate_rule_id,
    validate_severity,
    validate_time_range,
    validate_timestamp,
)
from wazuh_mcp_server.session_store import SessionStore, create_session_store

# MCP Protocol Version Support
# Latest: 2025-11-25, also supports backwards compatibility with older versions
MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

# Production Constants
SESSION_TIMEOUT_MINUTES = 30
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW_SECONDS = 60
CORS_MAX_AGE_SECONDS = 600
DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 1000

logger = logging.getLogger(__name__)

# OAuth manager (initialized on startup if needed)
_oauth_manager = None


async def verify_authentication(authorization: Optional[str], config) -> bool:
    """
    Verify authentication based on configured auth mode.

    Returns True if authenticated, raises HTTPException if not.
    Supports: authless (none), bearer token, and OAuth modes.
    """
    # Authless mode - no authentication required
    if config.is_authless:
        return True

    # Authentication required
    if not authorization:
        raise HTTPException(
            status_code=401, detail="Authorization header required", headers={"WWW-Authenticate": "Bearer"}
        )

    # OAuth mode
    if config.is_oauth:
        global _oauth_manager
        if _oauth_manager:
            token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
            token_obj = _oauth_manager.validate_access_token(token)
            if token_obj:
                return True
        raise HTTPException(
            status_code=401, detail="Invalid or expired OAuth token", headers={"WWW-Authenticate": "Bearer"}
        )

    # Bearer token mode (default)
    try:
        from wazuh_mcp_server.auth import verify_bearer_token

        await verify_bearer_token(authorization)
        return True
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e), headers={"WWW-Authenticate": "Bearer"})


# MCP Protocol Models
class MCPRequest(BaseModel):
    """MCP JSON-RPC 2.0 Request."""

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Optional[Union[str, int]] = Field(default=None, description="Request ID")
    method: str = Field(description="Method name")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Method parameters")


class MCPResponse(BaseModel):
    """
    MCP JSON-RPC 2.0 Response.

    Compliant with JSON-RPC 2.0 specification:
    - On success: includes 'result', excludes 'error'
    - On error: includes 'error', excludes 'result'
    """

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Optional[Union[str, int]] = Field(default=None, description="Request ID")
    result: Optional[Any] = Field(default=None, description="Result data")
    error: Optional[Dict[str, Any]] = Field(default=None, description="Error object")

    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Override dict() to comply with JSON-RPC 2.0 specification.

        Per JSON-RPC 2.0 spec:
        - "result" and "error" MUST NOT both exist in the same response
        - On success: include 'result', exclude 'error'
        - On error: include 'error', exclude 'result'
        """
        d = super().dict(*args, **kwargs)

        # Remove error field on success (when result is present and error is None)
        if d.get("result") is not None and d.get("error") is None:
            d.pop("error", None)

        # Remove result field on error (when error is present)
        elif d.get("error") is not None:
            d.pop("result", None)

        return d


class MCPError(BaseModel):
    """MCP JSON-RPC 2.0 Error object."""

    code: int = Field(description="Error code")
    message: str = Field(description="Error message")
    data: Optional[Any] = Field(default=None, description="Additional error data")


class MCPSession:
    """MCP Session Management for Remote MCP Server."""

    def __init__(self, session_id: str, origin: Optional[str] = None):
        self.session_id = session_id
        self.origin = origin
        self.created_at = datetime.now(timezone.utc)
        self.last_activity = self.created_at
        self.capabilities = {}
        self.client_info = {}
        self.authenticated = False

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)

    def is_expired(self, timeout_minutes: int = SESSION_TIMEOUT_MINUTES) -> bool:
        """Check if session is expired."""
        timeout = timedelta(minutes=timeout_minutes)
        return datetime.now(timezone.utc) - self.last_activity > timeout

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "origin": self.origin,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "capabilities": self.capabilities,
            "client_info": self.client_info,
            "authenticated": self.authenticated,
        }


# Session management with pluggable backend (serverless-ready)
class SessionManager:
    """
    Session manager with pluggable storage backend.
    Supports both in-memory (default) and Redis (serverless-ready) backends.
    """

    def __init__(self, store: SessionStore):
        self._store = store
        self._lock = threading.RLock()  # For synchronous operations
        logger.info(f"SessionManager initialized with {type(store).__name__}")

    def _session_from_dict(self, data: Dict[str, Any]) -> MCPSession:
        """Reconstruct MCPSession from dictionary."""
        session = MCPSession(data["session_id"], data.get("origin"))
        session.created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        session.last_activity = datetime.fromisoformat(data["last_activity"].replace("Z", "+00:00"))
        session.capabilities = data.get("capabilities", {})
        session.client_info = data.get("client_info", {})
        session.authenticated = data.get("authenticated", False)
        return session

    async def get(self, session_id: str) -> Optional[MCPSession]:
        """Get session by ID."""
        data = await self._store.get(session_id)
        if data:
            return self._session_from_dict(data)
        return None

    async def set(self, session_id: str, session: MCPSession) -> bool:
        """Store session."""
        return await self._store.set(session_id, session.to_dict())

    def _run_sync(self, coro):
        """Run coroutine synchronously, handling existing event loop safely."""
        try:
            # Check if we're in an async context
            loop = asyncio.get_running_loop()
            # If we get here, there's a running loop - this is not safe
            raise RuntimeError(
                "Synchronous SessionManager methods cannot be called from async context. "
                "Use async methods like 'await sessions.get()' instead."
            )
        except RuntimeError:
            # No running loop - safe to create one
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

    def __getitem__(self, session_id: str) -> MCPSession:
        """Synchronous dict-like access (blocks). Not for use in async context."""
        session = self._run_sync(self.get(session_id))
        if session is None:
            raise KeyError(f"Session {session_id} not found")
        return session

    def __setitem__(self, session_id: str, session: MCPSession) -> None:
        """Synchronous dict-like access (blocks). Not for use in async context."""
        self._run_sync(self.set(session_id, session))

    def __delitem__(self, session_id: str) -> None:
        """Synchronous delete (blocks). Not for use in async context."""
        self._run_sync(self.remove(session_id))

    async def __contains__(self, session_id: str) -> bool:
        """Check if session exists."""
        return await self._store.exists(session_id)

    async def remove(self, session_id: str) -> bool:
        """Remove session by ID."""
        return await self._store.delete(session_id)

    def pop(self, session_id: str, default=None) -> Optional[MCPSession]:
        """Remove and return session (synchronous, blocks). Not for use in async context."""

        async def _pop():
            session = await self.get(session_id)
            if session:
                await self.remove(session_id)
                return session
            return default

        return self._run_sync(_pop())

    async def clear(self) -> bool:
        """Clear all sessions."""
        return await self._store.clear()

    def values(self) -> List[MCPSession]:
        """Get all session values (synchronous, blocks). Not for use in async context."""
        sessions_dict = self._run_sync(self.get_all())
        return list(sessions_dict.values())

    def keys(self) -> List[str]:
        """Get all session keys (synchronous, blocks). Not for use in async context."""
        sessions_dict = self._run_sync(self.get_all())
        return list(sessions_dict.keys())

    async def get_all(self) -> Dict[str, MCPSession]:
        """Get all sessions as dictionary."""
        data_dict = await self._store.get_all()
        return {sid: self._session_from_dict(data) for sid, data in data_dict.items()}

    async def cleanup_expired(self) -> int:
        """Remove expired sessions and return count."""
        return await self._store.cleanup_expired()


# Initialize session manager with pluggable backend
# Will use Redis if REDIS_URL is set, otherwise in-memory
_session_store = create_session_store()
sessions = SessionManager(_session_store)


async def get_or_create_session(session_id: Optional[str], origin: Optional[str]) -> MCPSession:
    """Get existing session or create new one."""
    if session_id:
        existing_session = await sessions.get(session_id)
        if existing_session:
            existing_session.update_activity()
            await sessions.set(session_id, existing_session)
            return existing_session

    # Create new session
    new_session_id = session_id or str(uuid.uuid4())
    session = MCPSession(new_session_id, origin)
    await sessions.set(new_session_id, session)

    # Cleanup expired sessions periodically
    try:
        expired_count = await sessions.cleanup_expired()
        if expired_count > 0:
            logger.debug(f"Cleaned up {expired_count} expired sessions")
            # Sync _initialized_sessions with active sessions
            active = await sessions.get_all()
            stale_keys = [k for k in _initialized_sessions if k not in active]
            for k in stale_keys:
                _initialized_sessions.pop(k, None)
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")

    return session


# Lifespan context manager for startup/shutdown events (modern FastAPI pattern)
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle with proper startup and shutdown handling."""
    global _oauth_manager

    # === STARTUP ===
    # Attach log sanitization filter to prevent credential leakage
    from wazuh_mcp_server.security import SanitizingLogFilter

    logging.getLogger().addFilter(SanitizingLogFilter())

    logger.info(f"Wazuh MCP Server v{__version__} starting up...")
    logger.info(f"📡 MCP Protocol: {MCP_PROTOCOL_VERSION}")
    logger.info(f"🔗 Wazuh Host: {get_config().WAZUH_HOST}")
    logger.info(f"🌐 CORS Origins: {get_config().ALLOWED_ORIGINS}")
    logger.info(f"🔐 Auth Mode: {get_config().AUTH_MODE}")

    # Log Indexer configuration status
    cfg = get_config()
    if cfg.WAZUH_INDEXER_HOST:
        logger.info(f"📊 Wazuh Indexer: {cfg.WAZUH_INDEXER_HOST}:{cfg.WAZUH_INDEXER_PORT}")
    else:
        logger.warning("⚠️  Wazuh Indexer not configured. Vulnerability tools require Wazuh 4.8.0+")
        logger.warning("   Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS to enable.")

    # Initialize OAuth if enabled
    if cfg.is_oauth:
        try:
            from wazuh_mcp_server.oauth import create_oauth_router, init_oauth_manager

            _oauth_manager = init_oauth_manager(cfg)
            oauth_router = create_oauth_router(_oauth_manager)
            app.include_router(oauth_router)
            logger.info("✅ OAuth 2.0 with DCR initialized")
            logger.info("   OAuth endpoints: /oauth/authorize, /oauth/token, /oauth/register")
            logger.info("   Discovery: /.well-known/oauth-authorization-server")
        except Exception as e:
            logger.error(f"❌ OAuth initialization failed: {e}")

    # Log auth mode status
    if cfg.is_authless:
        logger.warning("⚠️  Running in AUTHLESS mode - no authentication required!")
    elif cfg.is_bearer:
        logger.info("🔐 Bearer token authentication enabled")
        # Display auto-generated API key if not configured via environment
        if not os.getenv("MCP_API_KEY"):
            from wazuh_mcp_server.auth import auth_manager

            default_key = auth_manager.get_default_api_key()
            if default_key:
                logger.info("=" * 60)
                logger.info("🔑 AUTO-GENERATED API KEY (save this for client auth):")
                logger.info(f"   {default_key}")
                logger.info("   Set MCP_API_KEY environment variable in production")
                logger.info("=" * 60)

    # Initialize Wazuh client (will be available after yield)
    logger.info("✅ Server startup complete with high availability features enabled")

    yield  # Server is running

    # === SHUTDOWN ===
    logger.info("🛑 Wazuh MCP Server initiating graceful shutdown...")

    try:
        # Initiate graceful shutdown (waits for active connections)
        await shutdown_manager.initiate_shutdown()

        # Clear and cleanup auth manager
        from wazuh_mcp_server.auth import auth_manager

        auth_manager.cleanup_expired()
        auth_manager.tokens.clear()
        logger.info("Authentication tokens cleared")

        # Clear sessions with proper cleanup
        await sessions.clear()
        # Close session store backend (e.g., Redis connection)
        if hasattr(sessions._store, "close"):
            await sessions._store.close()
        logger.info("Sessions cleared")

        # Close Wazuh client to release HTTP connections
        if wazuh_client and hasattr(wazuh_client, "close"):
            await wazuh_client.close()
            logger.info("Wazuh client closed")

        # Cleanup rate limiter
        if hasattr(rate_limiter, "cleanup"):
            rate_limiter.cleanup()

        # Close connection pools
        from wazuh_mcp_server.security import connection_pool_manager

        await connection_pool_manager.close_all()
        logger.info("Connection pools closed")

        # Force garbage collection
        import gc

        gc.collect()
        logger.info("Garbage collection completed")

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
    finally:
        logger.info("✅ Graceful shutdown completed")


# Initialize FastAPI app for MCP compliance
app = FastAPI(
    title="Wazuh MCP Server",
    description="MCP-compliant remote server for Wazuh SIEM integration. Supports Streamable HTTP, SSE, OAuth, and authless modes.",
    version=__version__,
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Get configuration
config = get_config()

# Create Wazuh configuration from server config
wazuh_config = WazuhConfig(
    wazuh_host=config.WAZUH_HOST,
    wazuh_user=config.WAZUH_USER,
    wazuh_pass=config.WAZUH_PASS,
    wazuh_port=config.WAZUH_PORT,
    verify_ssl=config.WAZUH_VERIFY_SSL,
    # Wazuh Indexer settings (required for vulnerability tools in Wazuh 4.8.0+)
    wazuh_indexer_host=config.WAZUH_INDEXER_HOST if config.WAZUH_INDEXER_HOST else None,
    wazuh_indexer_port=config.WAZUH_INDEXER_PORT,
    wazuh_indexer_user=config.WAZUH_INDEXER_USER if config.WAZUH_INDEXER_USER else None,
    wazuh_indexer_pass=config.WAZUH_INDEXER_PASS if config.WAZUH_INDEXER_PASS else None,
)

# Initialize Wazuh client
wazuh_client = WazuhClient(wazuh_config)


async def get_wazuh_client() -> WazuhClient:
    """Get the global Wazuh client instance.

    Used by monitoring health checks to access client state.
    """
    return wazuh_client


# Initialize rate limiter
rate_limiter = RateLimiter(max_requests=RATE_LIMIT_REQUESTS, window_seconds=RATE_LIMIT_WINDOW_SECONDS)

# Initialize graceful shutdown manager
shutdown_manager = GracefulShutdown()
logger.info("Graceful shutdown manager initialized")


# CORS middleware for remote access with security
def validate_cors_origins(origins_config: str) -> List[str]:
    """Validate and parse CORS origins configuration."""
    if not origins_config or origins_config.strip() == "*":
        # Only allow wildcard in development
        if os.getenv("ENVIRONMENT") == "development":
            return ["*"]
        else:
            # In production, default to common Claude origins
            return ["https://claude.ai", "https://claude.anthropic.com"]

    origins = []
    for origin in origins_config.split(","):
        origin = origin.strip()
        # Validate origin format
        if origin.startswith(("http://", "https://")) or origin == "*":
            # Parse and validate URL structure
            if origin != "*":
                try:
                    parsed = urlparse(origin)
                    if parsed.netloc:
                        origins.append(origin)
                except ValueError as e:
                    logger.debug(f"Skipping invalid origin '{origin}': {e}")
                    continue
            else:
                origins.append(origin)

    return origins if origins else ["https://claude.ai"]


def validate_origin_header(origin: Optional[str], allowed_origins_config: str) -> None:
    """
    Validate Origin header per MCP 2025-11-25 spec.

    Per spec: "Servers MUST validate the Origin header on all incoming connections
    to prevent DNS rebinding attacks. If the Origin header is present and invalid,
    servers MUST respond with HTTP 403 Forbidden."

    Note: If Origin header is NOT present, that's acceptable (no 403).
    Only reject if Origin IS present but invalid.

    Args:
        origin: The Origin header value (may be None)
        allowed_origins_config: Comma-separated list of allowed origins

    Raises:
        HTTPException: 403 if Origin is present but not in allowed list
    """
    # Per 2025-11-25 spec: only validate if Origin is present
    if not origin:
        return  # No Origin header = acceptable

    # Parse allowed origins
    allowed_origins_list = allowed_origins_config.split(",") if allowed_origins_config else []

    # Check if origin is allowed
    for allowed in allowed_origins_list:
        allowed = allowed.strip()
        if allowed == "*":
            return  # Wildcard allows everything
        if allowed == origin:
            return  # Exact match
        if allowed.startswith("*") and origin.endswith(allowed[1:]):
            return  # Wildcard suffix match
        if "localhost" in allowed and "localhost" in origin:
            return  # Localhost match (for development)

    # Origin present but not in allowed list - per spec MUST return 403
    raise HTTPException(status_code=403, detail=f"Origin not allowed: {origin}")


allowed_origins = validate_cors_origins(config.ALLOWED_ORIGINS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],  # Added DELETE for session management
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "MCP-Protocol-Version",  # MCP protocol version header
        "MCP-Session-Id",  # Session ID header
        "Last-Event-ID",  # SSE reconnection header
    ],  # Specific headers only, no wildcard
    expose_headers=["MCP-Session-Id", "MCP-Protocol-Version", "Content-Type"],
    max_age=CORS_MAX_AGE_SECONDS,
)

# MCP Protocol Error Codes
MCP_ERRORS = {
    "PARSE_ERROR": -32700,
    "INVALID_REQUEST": -32600,
    "METHOD_NOT_FOUND": -32601,
    "INVALID_PARAMS": -32602,
    "INTERNAL_ERROR": -32603,
    "TIMEOUT": -32001,
    "CANCELLED": -32002,
    "RESOURCE_NOT_FOUND": -32003,
}


def create_error_response(
    request_id: Optional[Union[str, int]], code: int, message: str, data: Any = None
) -> MCPResponse:
    """Create MCP error response with correlation ID for tracing."""
    from wazuh_mcp_server.monitoring import get_correlation_id

    # Include correlation ID in error data for request tracing
    error_data = data if data else {}
    if isinstance(error_data, dict):
        error_data = {**error_data, "correlation_id": get_correlation_id()}
    elif data is None:
        error_data = {"correlation_id": get_correlation_id()}
    error = MCPError(code=code, message=message, data=error_data)
    return MCPResponse(id=request_id, error=error.dict())


def create_success_response(request_id: Optional[Union[str, int]], result: Any) -> MCPResponse:
    """Create MCP success response."""
    return MCPResponse(id=request_id, result=result)


def validate_protocol_version(version: Optional[str], strict: bool = False) -> str:
    """
    Validate and normalize MCP protocol version.

    Per MCP 2025-11-25 spec:
    - If no header provided, assume 2025-03-26 for backwards compatibility
    - If invalid/unsupported version, MUST return 400 Bad Request (when strict=True)

    Args:
        version: The protocol version from MCP-Protocol-Version header
        strict: If True, raise HTTPException for invalid versions (2025-11-25 behavior)

    Returns:
        The validated protocol version string
    """
    if not version:
        # Per spec: assume 2025-03-26 if no header provided (backwards compatibility)
        return "2025-03-26"

    if version in SUPPORTED_PROTOCOL_VERSIONS:
        return version

    # Per 2025-11-25 spec: "If the server receives a request with an invalid or
    # unsupported MCP-Protocol-Version, it MUST respond with 400 Bad Request"
    if strict:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported protocol version: {version}. Supported versions: {', '.join(SUPPORTED_PROTOCOL_VERSIONS)}",
        )

    # For backwards compatibility (non-strict mode), try to handle gracefully
    logger.warning(f"Unsupported protocol version {version}, falling back to 2025-03-26")
    return "2025-03-26"


# Track initialized sessions (for notifications/initialized handling)
_initialized_sessions: Dict[str, bool] = {}

# Current log level for logging/setLevel
_current_log_level: str = "info"


# MCP Protocol Handlers


def _compact_alert(alert: dict) -> dict:
    """Strip a raw Wazuh alert to essential fields for MCP output."""
    compact = {}
    if "timestamp" in alert:
        compact["timestamp"] = alert["timestamp"]
    agent = alert.get("agent", {})
    if agent:
        compact["agent"] = {"id": agent.get("id", ""), "name": agent.get("name", "")}
    rule = alert.get("rule", {})
    if rule:
        compact["rule"] = {
            "id": rule.get("id", ""),
            "level": rule.get("level", 0),
            "description": rule.get("description", ""),
            "groups": rule.get("groups", []),
        }
        if rule.get("mitre"):
            compact["rule"]["mitre"] = rule["mitre"]
    src = alert.get("data", {})
    if src.get("srcip"):
        compact["srcip"] = src["srcip"]
    if src.get("dstip"):
        compact["dstip"] = src["dstip"]
    if alert.get("syscheck"):
        sc = alert["syscheck"]
        compact["syscheck"] = {"path": sc.get("path", ""), "event": sc.get("event", "")}
    if alert.get("full_log"):
        log = alert["full_log"]
        compact["full_log"] = (log[:300] + "...") if len(log) > 300 else log
    return compact


def _compact_alerts_result(result: dict) -> dict:
    """Apply compaction to a standard alerts result dict."""
    data = result.get("data", {})
    items = data.get("affected_items", [])
    data["affected_items"] = [_compact_alert(a) for a in items]
    return result


def _compact_vulnerability(vuln: dict) -> dict:
    """Strip a raw Wazuh vulnerability to essential fields for MCP output."""
    compact = {}
    for key in ("id", "severity"):
        if key in vuln:
            compact[key] = vuln[key]
    if "description" in vuln:
        desc = vuln["description"]
        compact["description"] = (desc[:120] + "...") if len(desc) > 120 else desc
    if "published_at" in vuln:
        compact["published_at"] = vuln["published_at"]
    pkg = vuln.get("package", {})
    if pkg:
        compact["package"] = {"name": pkg.get("name", ""), "version": pkg.get("version", "")}
    agent = vuln.get("agent", {})
    if agent:
        compact["agent"] = {"id": agent.get("id", ""), "name": agent.get("name", "")}
    return compact


def _compact_vulns_result(result: dict) -> dict:
    """Apply compaction to a standard vulnerabilities result dict."""
    data = result.get("data", {})
    items = data.get("affected_items", [])
    if items:
        data["affected_items"] = [_compact_vulnerability(v) for v in items]
    return result


async def handle_initialize(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle MCP initialize method per MCP specification."""
    client_protocol_version = params.get("protocolVersion", "2025-03-26")
    capabilities = params.get("capabilities", {})
    client_info = params.get("clientInfo", {})

    # Store client information
    session.capabilities = capabilities
    session.client_info = client_info

    # Protocol version negotiation per MCP spec
    # Server should respond with a version it supports
    if client_protocol_version in SUPPORTED_PROTOCOL_VERSIONS:
        negotiated_version = client_protocol_version
    else:
        # Default to latest supported version
        negotiated_version = MCP_PROTOCOL_VERSION

    # Server capabilities - only declare what we actually implement
    server_capabilities = {
        "logging": {},
        "prompts": {"listChanged": True},
        "resources": {"subscribe": False, "listChanged": True},  # Not fully implemented yet
        "tools": {"listChanged": True},
    }

    # Server information
    server_info = {
        "name": "Wazuh MCP Server",
        "version": __version__,
        "vendor": "GenSec AI",
        "description": "MCP-compliant remote server for Wazuh SIEM integration",
    }

    # Mark session as awaiting initialized notification
    _initialized_sessions[session.session_id] = False

    return {
        "protocolVersion": negotiated_version,
        "capabilities": server_capabilities,
        "serverInfo": server_info,
        "instructions": "Connected to Wazuh MCP Server. Use available tools for security operations.",
    }


async def handle_initialized_notification(params: Dict[str, Any], session: MCPSession) -> None:
    """Handle notifications/initialized - marks session as fully initialized."""
    _initialized_sessions[session.session_id] = True
    logger.info(f"Session {session.session_id} fully initialized")


async def handle_ping(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle ping method per MCP specification.
    MUST respond immediately with empty result.
    """
    return {}


async def handle_logging_set_level(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle logging/setLevel method per MCP specification.
    Sets the minimum log level for server log notifications.
    """
    global _current_log_level
    level = params.get("level", "info")

    valid_levels = ["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]
    if level.lower() not in valid_levels:
        raise ValueError(f"Invalid log level: {level}. Must be one of: {', '.join(valid_levels)}")

    _current_log_level = level.lower()
    logger.info(f"Log level set to: {_current_log_level}")

    return {}


async def handle_prompts_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle prompts/list method per MCP specification.
    Returns list of available prompts with pagination support.
    """
    _cursor = params.get("cursor")  # Reserved for future pagination

    # Wazuh security prompts
    prompts = [
        {
            "name": "security_investigation",
            "description": "Investigate a security incident using Wazuh data",
            "arguments": [
                {
                    "name": "incident_type",
                    "description": "Type of incident to investigate (e.g., malware, intrusion, data_breach)",
                    "required": True,
                },
                {
                    "name": "time_range",
                    "description": "Time range for investigation (e.g., 1h, 24h, 7d)",
                    "required": False,
                },
            ],
        },
        {
            "name": "threat_hunt",
            "description": "Perform proactive threat hunting across Wazuh agents",
            "arguments": [
                {"name": "hunt_hypothesis", "description": "The threat hypothesis to investigate", "required": True},
                {
                    "name": "agent_scope",
                    "description": "Scope of agents to hunt (all, critical, specific)",
                    "required": False,
                },
            ],
        },
        {
            "name": "compliance_audit",
            "description": "Generate compliance audit report for a specific framework",
            "arguments": [
                {
                    "name": "framework",
                    "description": "Compliance framework (PCI-DSS, HIPAA, SOX, GDPR, NIST)",
                    "required": True,
                },
                {
                    "name": "include_remediation",
                    "description": "Include remediation recommendations",
                    "required": False,
                },
            ],
        },
        {
            "name": "vulnerability_assessment",
            "description": "Assess vulnerabilities across the environment",
            "arguments": [
                {
                    "name": "severity_threshold",
                    "description": "Minimum severity to include (low, medium, high, critical)",
                    "required": False,
                },
                {"name": "agent_id", "description": "Specific agent to assess (optional)", "required": False},
            ],
        },
    ]

    # Simple pagination (no cursor means start from beginning)
    # In production, implement proper cursor-based pagination
    return {"prompts": prompts, "nextCursor": None}  # No more results


async def handle_prompts_get(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle prompts/get method per MCP specification.
    Returns prompt content with substituted arguments.
    """
    name = params.get("name")
    arguments = params.get("arguments", {})

    if not name:
        raise ValueError("Prompt name is required")

    # Prompt templates
    prompt_templates = {
        "security_investigation": {
            "description": "Security incident investigation workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Investigate a {arguments.get('incident_type', 'security')} incident. "
                        f"Time range: {arguments.get('time_range', '24h')}. "
                        f"Steps:\n"
                        f"1. Use get_wazuh_alerts to retrieve relevant alerts\n"
                        f"2. Use analyze_alert_patterns to identify patterns\n"
                        f"3. Use search_security_events to find related events\n"
                        f"4. Use check_agent_health for affected agents\n"
                        f"5. Use perform_risk_assessment to evaluate impact",
                    },
                }
            ],
        },
        "threat_hunt": {
            "description": "Proactive threat hunting workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Hunt for threats based on hypothesis: {arguments.get('hunt_hypothesis', 'suspicious activity')}. "
                        f"Agent scope: {arguments.get('agent_scope', 'all')}. "
                        f"Workflow:\n"
                        f"1. Use get_wazuh_agents to identify target agents\n"
                        f"2. Use search_security_events with relevant patterns\n"
                        f"3. Use analyze_security_threat for any indicators found\n"
                        f"4. Use check_ioc_reputation for suspicious IPs/domains\n"
                        f"5. Use generate_security_report to document findings",
                    },
                }
            ],
        },
        "compliance_audit": {
            "description": "Compliance audit workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Perform {arguments.get('framework', 'PCI-DSS')} compliance audit. "
                        f"Include remediation: {arguments.get('include_remediation', 'true')}. "
                        f"Steps:\n"
                        f"1. Use run_compliance_check with the specified framework\n"
                        f"2. Use get_wazuh_agents to assess agent coverage\n"
                        f"3. Use get_wazuh_vulnerabilities to identify security gaps\n"
                        f"4. Use generate_security_report for compliance documentation",
                    },
                }
            ],
        },
        "vulnerability_assessment": {
            "description": "Vulnerability assessment workflow",
            "messages": [
                {
                    "role": "user",
                    "content": {
                        "type": "text",
                        "text": f"Assess vulnerabilities with severity >= {arguments.get('severity_threshold', 'medium')}. "
                        f"Agent: {arguments.get('agent_id', 'all')}. "
                        f"Workflow:\n"
                        f"1. Use get_wazuh_vulnerabilities to retrieve vulnerability data\n"
                        f"2. Use get_wazuh_critical_vulnerabilities for highest priority items\n"
                        f"3. Use get_wazuh_vulnerability_summary for statistics\n"
                        f"4. Use perform_risk_assessment to evaluate overall risk",
                    },
                }
            ],
        },
    }

    if name not in prompt_templates:
        raise ValueError(f"Unknown prompt: {name}")

    return prompt_templates[name]


async def handle_resources_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/list method per MCP specification.
    Returns list of available resources with pagination support.
    """
    _cursor = params.get("cursor")  # Reserved for future pagination

    # Wazuh resources
    resources = [
        {
            "uri": "wazuh://manager/info",
            "name": "Wazuh Manager Information",
            "description": "Current Wazuh manager status and configuration",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://agents/summary",
            "name": "Agents Summary",
            "description": "Summary of all Wazuh agents and their status",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://alerts/recent",
            "name": "Recent Alerts",
            "description": "Most recent security alerts from Wazuh",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://cluster/status",
            "name": "Cluster Status",
            "description": "Wazuh cluster health and node information",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://rules/summary",
            "name": "Rules Summary",
            "description": "Summary of active Wazuh detection rules",
            "mimeType": "application/json",
        },
        {
            "uri": "wazuh://vulnerabilities/critical",
            "name": "Critical Vulnerabilities",
            "description": "Critical vulnerabilities from Wazuh Indexer (requires 4.8.0+)",
            "mimeType": "application/json",
        },
    ]

    return {"resources": resources, "nextCursor": None}


async def handle_resources_read(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/read method per MCP specification.
    Returns resource content.
    """
    uri = params.get("uri")

    if not uri:
        raise ValueError("Resource URI is required")

    # Parse Wazuh resource URI
    if not uri.startswith("wazuh://"):
        raise ValueError(f"Invalid resource URI scheme: {uri}. Expected wazuh://")

    resource_path = uri[8:]  # Remove "wazuh://"

    try:
        if resource_path == "manager/info":
            data = await wazuh_client.get_manager_info()
        elif resource_path == "agents/summary":
            data = await wazuh_client.get_running_agents()
        elif resource_path == "alerts/recent":
            data = await wazuh_client.get_alerts(limit=50)
        elif resource_path == "cluster/status":
            data = await wazuh_client.get_cluster_health()
        elif resource_path == "rules/summary":
            data = await wazuh_client.get_rules_summary()
        elif resource_path == "vulnerabilities/critical":
            data = await wazuh_client.get_critical_vulnerabilities(limit=50)
        else:
            raise ValueError(f"Resource not found: {uri}")

        return {"contents": [{"uri": uri, "mimeType": "application/json", "text": json.dumps(data, indent=2)}]}

    except Exception as e:
        logger.error(f"Error reading resource {uri}: {e}")
        raise ValueError(f"Failed to read resource: {str(e)}")


async def handle_resources_templates_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle resources/templates/list method per MCP specification.
    Returns list of resource URI templates.
    """
    templates = [
        {
            "uriTemplate": "wazuh://agents/{agent_id}/info",
            "name": "Agent Information",
            "description": "Detailed information for a specific agent",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "wazuh://agents/{agent_id}/alerts",
            "name": "Agent Alerts",
            "description": "Recent alerts for a specific agent",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "wazuh://agents/{agent_id}/vulnerabilities",
            "name": "Agent Vulnerabilities",
            "description": "Vulnerabilities for a specific agent",
            "mimeType": "application/json",
        },
    ]

    return {"resourceTemplates": templates, "nextCursor": None}


async def handle_completion_complete(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """
    Handle completion/complete method per MCP specification.
    Returns argument completion suggestions.
    """
    ref = params.get("ref", {})
    argument = params.get("argument", {})

    ref_type = ref.get("type")
    ref_name = ref.get("name")
    arg_name = argument.get("name", "")
    arg_value = argument.get("value", "")

    completions = []

    # Provide completions based on context
    if ref_type == "ref/prompt":
        if arg_name == "incident_type":
            completions = ["malware", "intrusion", "data_breach", "ransomware", "phishing", "insider_threat"]
        elif arg_name == "time_range":
            completions = ["1h", "6h", "24h", "7d", "30d"]
        elif arg_name == "framework":
            completions = ["PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST"]
        elif arg_name == "severity_threshold":
            completions = ["low", "medium", "high", "critical"]
        elif arg_name == "agent_scope":
            completions = ["all", "critical", "specific"]

    elif ref_type == "ref/resource":
        if "agent" in ref_name.lower():
            # Could fetch actual agent IDs here
            completions = ["001", "002", "003", "004", "005"]

    # Filter by current value
    if arg_value:
        completions = [c for c in completions if c.lower().startswith(arg_value.lower())]

    return {
        "completion": {
            "values": completions[:100],  # Max 100 per spec
            "total": len(completions),
            "hasMore": len(completions) > 100,
        }
    }


async def handle_tools_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/list method - All 29 Wazuh Security Tools with pagination."""
    _cursor = params.get("cursor")  # Reserved for future pagination
    tools = [
        # Alert Management Tools (4 tools)
        {
            "name": "get_wazuh_alerts",
            "description": "Retrieve Wazuh security alerts with optional filtering",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                    "rule_id": {"type": "string", "description": "Filter by specific rule ID"},
                    "level": {"type": "string", "description": "Filter by alert level (e.g., '12', '10+')"},
                    "agent_id": {"type": "string", "description": "Filter by agent ID"},
                    "timestamp_start": {"type": "string", "description": "Start timestamp (ISO format)"},
                    "timestamp_end": {"type": "string", "description": "End timestamp (ISO format)"},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact alerts with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_alert_summary",
            "description": "Get a summary of Wazuh alerts grouped by specified field",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "24h", "7d"], "default": "24h"},
                    "group_by": {"type": "string", "default": "rule.level"},
                },
                "required": [],
            },
        },
        {
            "name": "analyze_alert_patterns",
            "description": "Analyze alert patterns to identify trends and anomalies",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "24h", "7d"], "default": "24h"},
                    "min_frequency": {"type": "integer", "minimum": 1, "default": 5},
                },
                "required": [],
            },
        },
        {
            "name": "search_security_events",
            "description": "Search for specific security events across all Wazuh data",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query or pattern"},
                    "time_range": {"type": "string", "enum": ["1h", "6h", "24h", "7d"], "default": "24h"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact events with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": ["query"],
            },
        },
        # Agent Management Tools (6 tools)
        {
            "name": "get_wazuh_agents",
            "description": "Retrieve information about Wazuh agents",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Specific agent ID to query"},
                    "status": {
                        "type": "string",
                        "enum": ["active", "disconnected", "never_connected"],
                        "description": "Filter by agent status",
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_running_agents",
            "description": "Get list of currently running/active Wazuh agents",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "check_agent_health",
            "description": "Check the health status of a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent to check"}},
                "required": ["agent_id"],
            },
        },
        {
            "name": "get_agent_processes",
            "description": "Get running processes from a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": ["agent_id"],
            },
        },
        {
            "name": "get_agent_ports",
            "description": "Get open ports from a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": ["agent_id"],
            },
        },
        {
            "name": "get_agent_configuration",
            "description": "Get configuration details for a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {"agent_id": {"type": "string", "description": "ID of the agent"}},
                "required": ["agent_id"],
            },
        },
        # Vulnerability Management Tools (3 tools) - Requires Wazuh Indexer (4.8.0+)
        {
            "name": "get_wazuh_vulnerabilities",
            "description": "Retrieve vulnerability information from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Filter by specific agent ID"},
                    "severity": {
                        "type": "string",
                        "enum": ["low", "medium", "high", "critical"],
                        "description": "Filter by severity level",
                    },
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact vulnerabilities with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_critical_vulnerabilities",
            "description": "Get critical vulnerabilities from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                    "compact": {
                        "type": "boolean",
                        "default": True,
                        "description": "Return compact vulnerabilities with essential fields only (recommended to avoid token limits)",
                    },
                },
                "required": [],
            },
        },
        {
            "name": "get_wazuh_vulnerability_summary",
            "description": "Get vulnerability summary statistics from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {"time_range": {"type": "string", "enum": ["1d", "7d", "30d"], "default": "7d"}},
                "required": [],
            },
        },
        # Security Analysis Tools (6 tools)
        {
            "name": "analyze_security_threat",
            "description": "Analyze a security threat indicator using AI-powered analysis",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "indicator": {
                        "type": "string",
                        "description": "The threat indicator to analyze (IP, hash, domain)",
                    },
                    "indicator_type": {"type": "string", "enum": ["ip", "hash", "domain", "url"], "default": "ip"},
                },
                "required": ["indicator"],
            },
        },
        {
            "name": "check_ioc_reputation",
            "description": "Check reputation of an Indicator of Compromise (IoC)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "The IoC to check (IP, domain, hash, etc.)"},
                    "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"], "default": "ip"},
                },
                "required": ["indicator"],
            },
        },
        {
            "name": "perform_risk_assessment",
            "description": "Perform comprehensive risk assessment for agents or the entire environment",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {
                        "type": "string",
                        "description": "Specific agent ID to assess (if None, assess entire environment)",
                    }
                },
                "required": [],
            },
        },
        {
            "name": "get_top_security_threats",
            "description": "Get top security threats based on alert frequency and severity",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
                    "time_range": {"type": "string", "enum": ["1h", "6h", "24h", "7d"], "default": "24h"},
                },
                "required": [],
            },
        },
        {
            "name": "generate_security_report",
            "description": "Generate comprehensive security report",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "report_type": {
                        "type": "string",
                        "enum": ["daily", "weekly", "monthly", "incident"],
                        "default": "daily",
                    },
                    "include_recommendations": {"type": "boolean", "default": True},
                },
                "required": [],
            },
        },
        {
            "name": "run_compliance_check",
            "description": "Run compliance check against security frameworks",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST"],
                        "default": "PCI-DSS",
                    },
                    "agent_id": {
                        "type": "string",
                        "description": "Specific agent ID to check (if None, check entire environment)",
                    },
                },
                "required": [],
            },
        },
        # System Monitoring Tools (10 tools)
        {
            "name": "get_wazuh_statistics",
            "description": "Get comprehensive Wazuh statistics and metrics",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_weekly_stats",
            "description": "Get weekly statistics from Wazuh including alerts, agents, and trends",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_cluster_health",
            "description": "Get Wazuh cluster health information",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_cluster_nodes",
            "description": "Get information about Wazuh cluster nodes",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_rules_summary",
            "description": "Get summary of Wazuh rules and their effectiveness",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_remoted_stats",
            "description": "Get Wazuh remoted (agent communication) statistics",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_wazuh_log_collector_stats",
            "description": "Get Wazuh log collector statistics",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "search_wazuh_manager_logs",
            "description": "Search Wazuh manager logs for specific patterns",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query/pattern"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
                },
                "required": ["query"],
            },
        },
        {
            "name": "get_wazuh_manager_error_logs",
            "description": "Get recent error logs from Wazuh manager",
            "inputSchema": {
                "type": "object",
                "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}},
                "required": [],
            },
        },
        {
            "name": "validate_wazuh_connection",
            "description": "Validate connection to Wazuh server and return status",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        },
    ]

    # Pagination support per MCP spec
    return {"tools": tools, "nextCursor": None}  # No more tools


async def handle_tools_call(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/call method - All 29 Wazuh Security Tools with comprehensive validation."""
    tool_name = params.get("name")
    arguments = params.get("arguments", {})

    if not tool_name:
        raise ValueError("Tool name is required")

    # Validate tool name
    validate_input(tool_name, max_length=100)

    # Track tool execution for metrics
    import time as _time

    from wazuh_mcp_server.monitoring import record_tool_execution

    _start_time = _time.time()
    _success = False

    try:
        # Alert Management Tools
        if tool_name == "get_wazuh_alerts":
            # Validate all parameters
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            rule_id = validate_rule_id(arguments.get("rule_id"))
            level = arguments.get("level")  # Free-form (e.g., "12", "10+")
            agent_id = validate_agent_id(arguments.get("agent_id"))
            timestamp_start = validate_timestamp(arguments.get("timestamp_start"), param_name="timestamp_start")
            timestamp_end = validate_timestamp(arguments.get("timestamp_end"), param_name="timestamp_end")
            compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")

            result = await wazuh_client.get_alerts(
                limit=limit,
                rule_id=rule_id,
                level=level,
                agent_id=agent_id,
                timestamp_start=timestamp_start,
                timestamp_end=timestamp_end,
            )
            if compact:
                result = _compact_alerts_result(result)
            _success = True
            return {
                "content": [
                    {"type": "text", "text": f"Wazuh Alerts:\n{json.dumps(result, indent=2 if not compact else None)}"}
                ]
            }

        elif tool_name == "get_wazuh_alert_summary":
            time_range = validate_time_range(arguments.get("time_range"))
            group_by = arguments.get("group_by", "rule.level")
            result = await wazuh_client.get_alert_summary(time_range, group_by)
            _success = True
            return {"content": [{"type": "text", "text": f"Alert Summary:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "analyze_alert_patterns":
            time_range = validate_time_range(arguments.get("time_range"))
            min_frequency = validate_limit(
                arguments.get("min_frequency"), min_val=1, max_val=1000, param_name="min_frequency"
            )
            result = await wazuh_client.analyze_alert_patterns(time_range, min_frequency)
            _success = True
            return {"content": [{"type": "text", "text": f"Alert Patterns:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "search_security_events":
            query = validate_query(arguments.get("query"), required=True)
            time_range = validate_time_range(arguments.get("time_range"))
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")

            result = await wazuh_client.search_security_events(query, time_range, limit)
            if compact:
                result = _compact_alerts_result(result)
            _success = True
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Security Events:\n{json.dumps(result, indent=2 if not compact else None)}",
                    }
                ]
            }

        # Agent Management Tools
        elif tool_name == "get_wazuh_agents":
            agent_id = validate_agent_id(arguments.get("agent_id"))
            status = validate_agent_status(arguments.get("status"))
            limit = validate_limit(arguments.get("limit"), max_val=1000)

            result = await wazuh_client.get_agents(agent_id=agent_id, status=status, limit=limit)
            _success = True
            return {"content": [{"type": "text", "text": f"Wazuh Agents:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_wazuh_running_agents":
            result = await wazuh_client.get_running_agents()
            _success = True
            return {"content": [{"type": "text", "text": f"Running Agents:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "check_agent_health":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            result = await wazuh_client.check_agent_health(agent_id)
            _success = True
            return {"content": [{"type": "text", "text": f"Agent Health:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_agent_processes":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            result = await wazuh_client.get_agent_processes(agent_id, limit)
            _success = True
            return {"content": [{"type": "text", "text": f"Agent Processes:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_agent_ports":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            result = await wazuh_client.get_agent_ports(agent_id, limit)
            _success = True
            return {"content": [{"type": "text", "text": f"Agent Ports:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_agent_configuration":
            agent_id = validate_agent_id(arguments.get("agent_id"), required=True)
            result = await wazuh_client.get_agent_configuration(agent_id)
            _success = True
            return {"content": [{"type": "text", "text": f"Agent Configuration:\n{json.dumps(result, indent=2)}"}]}

        # Vulnerability Management Tools
        elif tool_name == "get_wazuh_vulnerabilities":
            agent_id = validate_agent_id(arguments.get("agent_id"))
            severity = validate_severity(arguments.get("severity"))
            limit = validate_limit(arguments.get("limit"), max_val=500)
            compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")

            result = await wazuh_client.get_vulnerabilities(agent_id=agent_id, severity=severity, limit=limit)
            if compact:
                result = _compact_vulns_result(result)
            _success = True
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Vulnerabilities:\n{json.dumps(result, indent=2 if not compact else None)}",
                    }
                ]
            }

        elif tool_name == "get_wazuh_critical_vulnerabilities":
            limit = validate_limit(arguments.get("limit"), max_val=500, param_name="limit")
            compact = validate_boolean(arguments.get("compact"), default=True, param_name="compact")

            result = await wazuh_client.get_critical_vulnerabilities(limit)
            if compact:
                result = _compact_vulns_result(result)
            _success = True
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Critical Vulnerabilities:\n{json.dumps(result, indent=2 if not compact else None)}",
                    }
                ]
            }

        elif tool_name == "get_wazuh_vulnerability_summary":
            time_range = validate_time_range(arguments.get("time_range"))
            result = await wazuh_client.get_vulnerability_summary(time_range)
            _success = True
            return {"content": [{"type": "text", "text": f"Vulnerability Summary:\n{json.dumps(result, indent=2)}"}]}

        # Security Analysis Tools
        elif tool_name == "analyze_security_threat":
            indicator_type = validate_indicator_type(arguments.get("indicator_type"))
            indicator = validate_indicator(arguments.get("indicator"), indicator_type)

            result = await wazuh_client.analyze_security_threat(indicator, indicator_type)
            _success = True
            return {"content": [{"type": "text", "text": f"Threat Analysis:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "check_ioc_reputation":
            indicator_type = validate_indicator_type(arguments.get("indicator_type"))
            indicator = validate_indicator(arguments.get("indicator"), indicator_type)

            result = await wazuh_client.check_ioc_reputation(indicator, indicator_type)
            _success = True
            return {"content": [{"type": "text", "text": f"IoC Reputation:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "perform_risk_assessment":
            agent_id = validate_agent_id(arguments.get("agent_id"))
            result = await wazuh_client.perform_risk_assessment(agent_id)
            _success = True
            return {"content": [{"type": "text", "text": f"Risk Assessment:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_top_security_threats":
            limit = validate_limit(arguments.get("limit"), min_val=1, max_val=50)
            time_range = validate_time_range(arguments.get("time_range"))

            result = await wazuh_client.get_top_security_threats(limit, time_range)
            _success = True
            return {"content": [{"type": "text", "text": f"Top Security Threats:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "generate_security_report":
            report_type = validate_report_type(arguments.get("report_type"))
            include_recommendations = validate_boolean(
                arguments.get("include_recommendations"), default=True, param_name="include_recommendations"
            )

            result = await wazuh_client.generate_security_report(report_type, include_recommendations)
            _success = True
            return {"content": [{"type": "text", "text": f"Security Report:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "run_compliance_check":
            framework = validate_compliance_framework(arguments.get("framework"))
            agent_id = validate_agent_id(arguments.get("agent_id"))

            result = await wazuh_client.run_compliance_check(framework, agent_id)
            _success = True
            return {"content": [{"type": "text", "text": f"Compliance Check:\n{json.dumps(result, indent=2)}"}]}

        # System Monitoring Tools
        elif tool_name == "get_wazuh_statistics":
            result = await wazuh_client.get_wazuh_statistics()
            _success = True
            return {"content": [{"type": "text", "text": f"Wazuh Statistics:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_wazuh_weekly_stats":
            result = await wazuh_client.get_weekly_stats()
            _success = True
            return {"content": [{"type": "text", "text": f"Weekly Statistics:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_wazuh_cluster_health":
            result = await wazuh_client.get_cluster_health()
            _success = True
            return {"content": [{"type": "text", "text": f"Cluster Health:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_wazuh_cluster_nodes":
            result = await wazuh_client.get_cluster_nodes()
            _success = True
            return {"content": [{"type": "text", "text": f"Cluster Nodes:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_wazuh_rules_summary":
            result = await wazuh_client.get_rules_summary()
            _success = True
            return {"content": [{"type": "text", "text": f"Rules Summary:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_wazuh_remoted_stats":
            result = await wazuh_client.get_remoted_stats()
            _success = True
            return {"content": [{"type": "text", "text": f"Remoted Statistics:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_wazuh_log_collector_stats":
            result = await wazuh_client.get_log_collector_stats()
            _success = True
            return {"content": [{"type": "text", "text": f"Log Collector Statistics:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "search_wazuh_manager_logs":
            query = validate_query(arguments.get("query"), required=True)
            limit = validate_limit(arguments.get("limit"), max_val=1000)

            result = await wazuh_client.search_manager_logs(query, limit)
            _success = True
            return {"content": [{"type": "text", "text": f"Manager Logs:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "get_wazuh_manager_error_logs":
            limit = validate_limit(arguments.get("limit"), max_val=1000)
            result = await wazuh_client.get_manager_error_logs(limit)
            _success = True
            return {"content": [{"type": "text", "text": f"Manager Error Logs:\n{json.dumps(result, indent=2)}"}]}

        elif tool_name == "validate_wazuh_connection":
            result = await wazuh_client.validate_connection()
            _success = True
            return {"content": [{"type": "text", "text": f"Connection Validation:\n{json.dumps(result, indent=2)}"}]}

        else:
            raise ValueError(f"Unknown tool: {tool_name}. Use 'tools/list' to see available tools.")

    except ToolValidationError as e:
        # Parameter validation errors - provide actionable guidance
        logger.warning(f"Tool validation error in {tool_name}: {e}")
        raise ValueError(str(e))

    except IndexerNotConfiguredError as e:
        # Provide helpful error for vulnerability tools when indexer is not configured
        logger.warning(f"Indexer not configured for tool {tool_name}: {e}")
        raise ValueError(str(e))

    except ConnectionError as e:
        # Network/connection errors - provide retry guidance
        logger.error(f"Connection error in tool {tool_name}: {e}")
        raise ValueError(f"Connection failed: {str(e)}. Check Wazuh server connectivity and try again.")

    except Exception as e:
        logger.error(f"Tool execution error in {tool_name}: {e}", exc_info=True)
        raise ValueError(f"Tool execution failed: {str(e)}")

    finally:
        # Record tool execution metrics
        _duration = _time.time() - _start_time
        record_tool_execution(tool_name, _duration, _success)


# MCP Method Registry - Full MCP 2025-03-26 Compliance
MCP_METHODS = {
    # Lifecycle methods
    "initialize": handle_initialize,
    "ping": handle_ping,
    # Tools methods
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    # Prompts methods
    "prompts/list": handle_prompts_list,
    "prompts/get": handle_prompts_get,
    # Resources methods
    "resources/list": handle_resources_list,
    "resources/read": handle_resources_read,
    "resources/templates/list": handle_resources_templates_list,
    # Logging methods
    "logging/setLevel": handle_logging_set_level,
    # Completion methods
    "completion/complete": handle_completion_complete,
}


# Notification handlers (don't return responses)
async def handle_cancelled_notification(params: Dict[str, Any], session: MCPSession) -> None:
    """Handle notifications/cancelled - acknowledge cancellation request."""
    request_id = params.get("requestId")
    reason = params.get("reason", "Unknown")
    logger.debug(f"Request {request_id} cancelled: {reason}")


MCP_NOTIFICATIONS = {
    "notifications/initialized": handle_initialized_notification,
    "notifications/cancelled": handle_cancelled_notification,
}


async def process_mcp_notification(method: str, params: Dict[str, Any], session: MCPSession) -> None:
    """
    Process MCP notification (no response expected).
    Per MCP spec, notifications MUST NOT receive responses.
    """
    if method in MCP_NOTIFICATIONS:
        handler = MCP_NOTIFICATIONS[method]
        try:
            await handler(params, session)
        except Exception as e:
            # Log but don't return error - notifications don't get responses
            logger.error(f"Error processing notification {method}: {e}")
    else:
        logger.debug(f"Received unknown notification: {method}")


async def process_mcp_request(request: MCPRequest, session: MCPSession) -> MCPResponse:
    """Process individual MCP request per JSON-RPC 2.0 specification."""
    try:
        # Check if method exists
        if request.method not in MCP_METHODS:
            # Check if it's a notification method being called as request
            if request.method in MCP_NOTIFICATIONS:
                return create_error_response(
                    request.id,
                    MCP_ERRORS["INVALID_REQUEST"],
                    f"'{request.method}' is a notification, not a request method",
                )
            return create_error_response(
                request.id, MCP_ERRORS["METHOD_NOT_FOUND"], f"Method '{request.method}' not found"
            )

        # Execute method handler
        handler = MCP_METHODS[request.method]
        result = await handler(request.params or {}, session)

        return create_success_response(request.id, result)

    except ValueError as e:
        return create_error_response(request.id, MCP_ERRORS["INVALID_PARAMS"], str(e))
    except Exception as e:
        from wazuh_mcp_server.monitoring import structured_logger

        structured_logger.error(
            f"Internal error processing {request.method}",
            exc_info=True,
            method=request.method,
            request_id=str(request.id) if request.id else None,
            error_type=type(e).__name__,
            error_message=str(e),
        )
        return create_error_response(request.id, MCP_ERRORS["INTERNAL_ERROR"], "Internal server error")


async def generate_sse_events(session: MCPSession, event_id_counter: int = 0):
    """
    Generate Server-Sent Events for MCP Streamable HTTP transport.

    Per MCP 2025-11-25 spec:
    - SSE events MUST include an 'id' field for resumability
    - Server SHOULD immediately send a priming event with event ID and empty data
    - Server SHOULD send retry field to indicate reconnection delay
    """
    event_id = event_id_counter

    # Per 2025-11-25 spec: "The server SHOULD immediately send an SSE event
    # consisting of an event ID and an empty data field in order to prime
    # the client to reconnect (using that event ID as Last-Event-ID)"
    event_id += 1
    yield f"id: {event_id}\nretry: 3000\ndata: \n\n"

    # Send session info as a JSON-RPC notification
    event_id += 1
    session_notification = {"jsonrpc": "2.0", "method": "notifications/session", "params": session.to_dict()}
    yield f"id: {event_id}\nevent: message\ndata: {json.dumps(session_notification)}\n\n"

    # Send capabilities notification
    event_id += 1
    capabilities_notification = {
        "jsonrpc": "2.0",
        "method": "notifications/capabilities",
        "params": {"tools": True, "resources": True, "prompts": True, "logging": True},
    }
    yield f"id: {event_id}\nevent: message\ndata: {json.dumps(capabilities_notification)}\n\n"

    # Send periodic keepalive (ping) to maintain connection
    while True:
        event_id += 1
        ping_notification = {
            "jsonrpc": "2.0",
            "method": "notifications/ping",
            "params": {"timestamp": datetime.now(timezone.utc).isoformat()},
        }
        yield f"id: {event_id}\nevent: message\ndata: {json.dumps(ping_notification)}\n\n"
        await asyncio.sleep(30)


def is_json_rpc_notification(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a notification (no 'id' field)."""
    return "method" in message and "id" not in message


def is_json_rpc_response(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a response (has 'result' or 'error', no 'method')."""
    return ("result" in message or "error" in message) and "method" not in message


def is_json_rpc_request(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a request (has 'method' and 'id')."""
    return "method" in message and "id" in message


@app.get("/")
@app.post("/")
async def mcp_endpoint(
    request: Request,
    origin: Optional[str] = Header(None),
    accept: Optional[str] = Header(None),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Main MCP protocol endpoint supporting both GET and POST.
    GET: Returns SSE stream for real-time communication
    POST: Handles JSON-RPC requests
    """
    # Track metrics
    REQUEST_COUNT.labels(method=request.method, endpoint="/", status_code=200).inc()

    ACTIVE_CONNECTIONS.inc()

    try:
        # Origin validation per MCP 2025-11-25 spec
        validate_origin_header(origin, config.ALLOWED_ORIGINS)

        # Rate limiting
        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            headers = {"Retry-After": str(retry_after)} if retry_after else {}
            raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

        # Session validation per MCP Streamable HTTP spec
        if mcp_session_id:
            existing_session = await sessions.get(mcp_session_id)
            if not existing_session:
                raise HTTPException(
                    status_code=404, detail="Session not found. Please start a new session with InitializeRequest."
                )
            session = existing_session
            session.update_activity()
            await sessions.set(mcp_session_id, session)
        else:
            session = await get_or_create_session(None, origin)

        # Handle GET request (SSE)
        if request.method == "GET":
            if accept and "text/event-stream" in accept:
                response = StreamingResponse(
                    generate_sse_events(session),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive",
                        "MCP-Session-Id": session.session_id,
                        "Access-Control-Expose-Headers": "MCP-Session-Id",
                    },
                )
                return response
            else:
                # Return JSON response for non-SSE clients
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "id": None,
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "serverInfo": {"name": "Wazuh MCP Server", "version": __version__},
                            "session": session.to_dict(),
                        },
                    },
                    headers={"MCP-Session-Id": session.session_id, "Access-Control-Expose-Headers": "MCP-Session-Id"},
                )

        # Handle POST request (JSON-RPC)
        elif request.method == "POST":
            try:
                body = await request.json()
            except json.JSONDecodeError:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["PARSE_ERROR"], "Invalid JSON").dict(),
                    status_code=400,
                )

            # Handle batch requests
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], "Empty batch request"
                        ).dict(),
                        status_code=400,
                    )

                # Per MCP Streamable HTTP spec: If the input consists solely of
                # notifications or responses, return HTTP 202 Accepted with no body
                has_requests = any(is_json_rpc_request(item) if isinstance(item, dict) else False for item in body)

                if not has_requests:
                    # Process all notifications before returning 202
                    for item in body:
                        if isinstance(item, dict) and is_json_rpc_notification(item):
                            method = item.get("method", "")
                            params = item.get("params", {})
                            await process_mcp_notification(method, params, session)
                    logger.debug(f"Processed batch of {len(body)} notifications/responses")
                    return Response(
                        status_code=202,
                        headers={
                            "MCP-Session-Id": session.session_id,
                            "Access-Control-Expose-Headers": "MCP-Session-Id",
                        },
                    )

                # Process batch containing requests
                responses = []
                for item in body:
                    # Process notifications but don't add to responses
                    if isinstance(item, dict) and is_json_rpc_notification(item):
                        method = item.get("method", "")
                        params = item.get("params", {})
                        await process_mcp_notification(method, params, session)
                        continue
                    # Skip responses
                    if isinstance(item, dict) and is_json_rpc_response(item):
                        continue
                    try:
                        mcp_request = MCPRequest(**item)
                        response = await process_mcp_request(mcp_request, session)
                        responses.append(response.dict())
                    except ValidationError as e:
                        responses.append(
                            create_error_response(
                                item.get("id") if isinstance(item, dict) else None,
                                MCP_ERRORS["INVALID_REQUEST"],
                                f"Invalid request format: {e}",
                            ).dict()
                        )

                return JSONResponse(
                    content=responses,
                    headers={"MCP-Session-Id": session.session_id, "Access-Control-Expose-Headers": "MCP-Session-Id"},
                )

            # Handle single message
            else:
                # Per MCP spec: notifications and responses return HTTP 202 Accepted
                if isinstance(body, dict):
                    if is_json_rpc_notification(body):
                        # Process the notification (no response)
                        method = body.get("method", "")
                        params = body.get("params", {})
                        await process_mcp_notification(method, params, session)
                        logger.debug(f"Processed notification: {method}")
                        return Response(
                            status_code=202,
                            headers={
                                "MCP-Session-Id": session.session_id,
                                "Access-Control-Expose-Headers": "MCP-Session-Id",
                            },
                        )
                    elif is_json_rpc_response(body):
                        # Client sending a response - just acknowledge
                        logger.debug("Received client response")
                        return Response(
                            status_code=202,
                            headers={
                                "MCP-Session-Id": session.session_id,
                                "Access-Control-Expose-Headers": "MCP-Session-Id",
                            },
                        )

                # Handle request
                try:
                    mcp_request = MCPRequest(**body)
                    response = await process_mcp_request(mcp_request, session)
                    return JSONResponse(
                        content=response.dict(),
                        headers={
                            "MCP-Session-Id": session.session_id,
                            "Access-Control-Expose-Headers": "MCP-Session-Id",
                        },
                    )
                except ValidationError as e:
                    return JSONResponse(
                        content=create_error_response(
                            body.get("id") if isinstance(body, dict) else None,
                            MCP_ERRORS["INVALID_REQUEST"],
                            f"Invalid request format: {e}",
                        ).dict(),
                        status_code=400,
                    )

        else:
            raise HTTPException(status_code=405, detail="Method not allowed")

    finally:
        ACTIVE_CONNECTIONS.dec()


# Official MCP Remote Server SSE endpoint - as per Anthropic standards
@app.get("/sse")
async def mcp_sse_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Official MCP SSE endpoint following Anthropic standards.
    URL format: https://<server_address>/sse
    This is the standard endpoint that Claude Desktop connects to.

    Supports authentication modes: bearer (default), oauth, none (authless)
    """
    # Verify authentication based on configured mode
    await verify_authentication(authorization, config)

    # Origin validation per MCP 2025-11-25 spec
    validate_origin_header(origin, config.ALLOWED_ORIGINS)

    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        headers = {"Retry-After": str(retry_after)} if retry_after else {}
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

    # Track metrics
    REQUEST_COUNT.labels(method="GET", endpoint="/sse", status_code=200).inc()
    ACTIVE_CONNECTIONS.inc()

    try:
        # Get or create session
        session = await get_or_create_session(mcp_session_id, origin)
        session.authenticated = True  # Mark as authenticated via bearer token

        # Return SSE stream
        response = StreamingResponse(
            generate_sse_events(session),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "MCP-Session-Id": session.session_id,
                "Access-Control-Expose-Headers": "MCP-Session-Id",
            },
        )
        return response

    except Exception as e:
        logger.error(f"SSE endpoint error: {e}")
        raise HTTPException(status_code=500, detail="SSE stream error")

    finally:
        ACTIVE_CONNECTIONS.dec()


# Standard MCP Endpoint - Streamable HTTP Transport (2025-11-25 Specification)
@app.post("/mcp")
@app.get("/mcp")
async def mcp_streamable_http_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    mcp_protocol_version: Optional[str] = Header(None, alias="MCP-Protocol-Version"),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    accept: Optional[str] = Header("application/json"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Standard MCP endpoint using Streamable HTTP transport (2025-11-25 spec).

    Supports:
    - POST: JSON-RPC requests (single message per 2025-11-25 spec)
    - GET: SSE stream initiation (requires Accept: text/event-stream)
    - DELETE: Session termination (see separate endpoint)

    This is the RECOMMENDED endpoint for MCP clients. Legacy /sse remains for backwards compatibility.
    Supports authentication modes: bearer (default), oauth, none (authless)
    """
    # Validate protocol version per 2025-11-25 spec (strict mode returns 400 for invalid)
    protocol_version = validate_protocol_version(mcp_protocol_version, strict=True)

    # Verify authentication based on configured mode
    await verify_authentication(authorization, config)

    # Origin validation per 2025-11-25 spec
    # Only validate if Origin is present; if present and invalid, return 403
    validate_origin_header(origin, config.ALLOWED_ORIGINS)

    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        headers = {"Retry-After": str(retry_after)} if retry_after else {}
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

    # Track metrics
    REQUEST_COUNT.labels(method=request.method, endpoint="/mcp", status_code=200).inc()
    ACTIVE_CONNECTIONS.inc()

    try:
        # Session validation per MCP Streamable HTTP spec:
        # If client provides session ID but session doesn't exist, return 404
        if mcp_session_id:
            existing_session = await sessions.get(mcp_session_id)
            if not existing_session:
                raise HTTPException(
                    status_code=404, detail="Session not found. Please start a new session with InitializeRequest."
                )
            session = existing_session
            session.update_activity()
            await sessions.set(mcp_session_id, session)
        else:
            # Create new session only if no session ID provided
            session = await get_or_create_session(None, origin)

        session.authenticated = True  # Mark as authenticated

        # Common response headers
        response_headers = {
            "MCP-Session-Id": session.session_id,
            "MCP-Protocol-Version": protocol_version,
            "Access-Control-Expose-Headers": "MCP-Session-Id, MCP-Protocol-Version",
        }

        # Handle GET request per MCP Streamable HTTP spec
        if request.method == "GET":
            # Per spec: server MUST return text/event-stream OR HTTP 405
            if accept and "text/event-stream" in accept:
                # Return SSE stream for real-time communication
                response = StreamingResponse(
                    generate_sse_events(session),
                    media_type="text/event-stream",
                    headers={**response_headers, "Cache-Control": "no-cache", "Connection": "keep-alive"},
                )
                return response
            else:
                # Per MCP spec: GET without Accept: text/event-stream MUST return 405
                raise HTTPException(
                    status_code=405, detail="GET requires Accept: text/event-stream header for SSE stream"
                )

        # Handle POST request (JSON-RPC)
        elif request.method == "POST":
            try:
                body = await request.json()
            except json.JSONDecodeError:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["PARSE_ERROR"], "Invalid JSON").dict(),
                    status_code=400,
                    headers=response_headers,
                )

            # Handle batch messages per MCP Streamable HTTP spec
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], "Empty batch request"
                        ).dict(),
                        status_code=400,
                        headers=response_headers,
                    )

                # Check if batch contains any requests
                has_requests = any(is_json_rpc_request(item) if isinstance(item, dict) else False for item in body)

                if not has_requests:
                    # Process all notifications before returning 202
                    for item in body:
                        if isinstance(item, dict) and is_json_rpc_notification(item):
                            method = item.get("method", "")
                            params = item.get("params", {})
                            await process_mcp_notification(method, params, session)
                    return Response(status_code=202, headers=response_headers)

                # Process requests in batch
                responses = []
                for item in body:
                    # Process notifications but don't add to responses
                    if isinstance(item, dict) and is_json_rpc_notification(item):
                        method = item.get("method", "")
                        params = item.get("params", {})
                        await process_mcp_notification(method, params, session)
                        continue
                    # Skip responses
                    if isinstance(item, dict) and is_json_rpc_response(item):
                        continue
                    try:
                        mcp_request = MCPRequest(**item)
                        resp = await process_mcp_request(mcp_request, session)
                        responses.append(resp.dict())
                    except ValidationError as e:
                        responses.append(
                            create_error_response(
                                item.get("id") if isinstance(item, dict) else None,
                                MCP_ERRORS["INVALID_REQUEST"],
                                f"Invalid request format: {e}",
                            ).dict()
                        )

                return JSONResponse(content=responses, headers=response_headers)

            # Handle single message
            if isinstance(body, dict):
                # Notifications and responses return 202 Accepted
                if is_json_rpc_notification(body):
                    # Process the notification (no response)
                    method = body.get("method", "")
                    params = body.get("params", {})
                    await process_mcp_notification(method, params, session)
                    logger.debug(f"Processed notification: {method}")
                    return Response(status_code=202, headers=response_headers)
                elif is_json_rpc_response(body):
                    # Client sending a response - just acknowledge
                    return Response(status_code=202, headers=response_headers)

            # Validate JSON-RPC request
            try:
                mcp_request = MCPRequest(**body) if isinstance(body, dict) else None
            except ValidationError as e:
                return JSONResponse(
                    content=create_error_response(
                        None, MCP_ERRORS["INVALID_REQUEST"], f"Invalid MCP request: {str(e)}"
                    ).dict(),
                    status_code=400,
                    headers=response_headers,
                )

            # Process the request
            if mcp_request:
                mcp_response = await process_mcp_request(mcp_request, session)

                # Check if client accepts SSE for streaming response
                # (For long-running operations, we could upgrade to SSE here)
                if accept and "text/event-stream" in accept:
                    # Optional: Stream the response via SSE for long operations
                    # For now, return JSON response
                    return JSONResponse(content=mcp_response.dict(), headers=response_headers)
                else:
                    # Standard JSON response
                    return JSONResponse(content=mcp_response.dict(), headers=response_headers)
            else:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["INVALID_REQUEST"], "Invalid request format").dict(),
                    status_code=400,
                    headers=response_headers,
                )

        else:
            raise HTTPException(status_code=405, detail="Method not allowed")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"MCP endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        ACTIVE_CONNECTIONS.dec()


@app.delete("/mcp")
async def close_mcp_session(
    mcp_session_id: str = Header(..., alias="MCP-Session-Id"), authorization: str = Header(None)
):
    """
    Close MCP session explicitly (2025-11-25 spec).
    Allows clients to cleanly terminate sessions.
    """
    # Use the same auth logic as other endpoints (respects authless mode)
    await verify_authentication(authorization, config)

    # Remove session
    try:
        await sessions.remove(mcp_session_id)
        _initialized_sessions.pop(mcp_session_id, None)
        logger.info(f"Session {mcp_session_id} closed via DELETE")
        return Response(status_code=204)  # No content
    except KeyError:
        raise HTTPException(status_code=404, detail="Session not found")


@app.get("/health")
async def health_check():
    """Health check endpoint with detailed status."""
    try:
        # Test Wazuh connectivity
        wazuh_status = "healthy"
        try:
            await wazuh_client.get_manager_info()
        except Exception as e:
            wazuh_status = f"unhealthy: {str(e)}"

        # Test Wazuh Indexer connectivity (if configured)
        indexer_status = "not_configured"
        if wazuh_client._indexer_client:
            try:
                health = await wazuh_client._indexer_client.health_check()
                if health.get("status") in ("green", "yellow"):
                    indexer_status = "healthy"
                elif health.get("status") == "red":
                    indexer_status = "degraded"
                else:
                    indexer_status = health.get("status", "unknown")
            except Exception as e:
                indexer_status = f"unhealthy: {str(e)}"

        # Check session count
        all_sessions = await sessions.get_all()
        active_sessions = len([s for s in all_sessions.values() if not s.is_expired()])

        # Build auth info
        auth_info = {
            "mode": config.AUTH_MODE,
            "bearer_enabled": config.is_bearer,
            "oauth_enabled": config.is_oauth,
            "authless": config.is_authless,
        }
        if config.is_oauth:
            auth_info["oauth_dcr"] = config.OAUTH_ENABLE_DCR
            auth_info["oauth_endpoints"] = ["/oauth/authorize", "/oauth/token", "/oauth/register"]
            auth_info["oauth_discovery"] = "/.well-known/oauth-authorization-server"

        # Determine overall status from component health
        if wazuh_status != "healthy":
            overall_status = "degraded"
        elif isinstance(indexer_status, str) and indexer_status.startswith("unhealthy"):
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        status_code = 200 if overall_status == "healthy" else 503
        return JSONResponse(
            content={
                "status": overall_status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": __version__,
                "mcp_protocol_version": MCP_PROTOCOL_VERSION,
                "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
                "transport": {
                    "streamable_http": "enabled",
                    "legacy_sse": "enabled",
                },
                "authentication": auth_info,
                "services": {"wazuh_manager": wazuh_status, "wazuh_indexer": indexer_status, "mcp": "healthy"},
                "vulnerability_tools": {
                    "available": wazuh_client._indexer_client is not None,
                    "note": (
                        "Vulnerability tools require Wazuh Indexer (4.8.0+). Set WAZUH_INDEXER_HOST to enable."
                        if not wazuh_client._indexer_client
                        else "Wazuh Indexer configured"
                    ),
                },
                "metrics": {"active_sessions": active_sessions, "total_sessions": len(all_sessions)},
                "endpoints": {
                    "recommended": "/mcp (Streamable HTTP - 2025-11-25)",
                    "legacy": "/sse (SSE only)",
                    "authentication": (
                        "/auth/token" if config.is_bearer else ("/oauth/token" if config.is_oauth else None)
                    ),
                    "monitoring": ["/health", "/metrics"],
                },
            },
            status_code=status_code,
        )
    except Exception as e:
        return JSONResponse(
            content={"status": "unhealthy", "timestamp": datetime.now(timezone.utc).isoformat(), "error": str(e)},
            status_code=503,
        )


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# OAuth 2.0 Discovery Endpoint (RFC 8414)
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    """
    OAuth 2.0 Authorization Server Metadata endpoint.
    Required for Claude Desktop OAuth integration.
    """
    global _oauth_manager
    if not config.is_oauth or not _oauth_manager:
        raise HTTPException(status_code=404, detail="OAuth not enabled. Set AUTH_MODE=oauth to enable.")

    return JSONResponse(_oauth_manager.get_metadata(request))


# Authentication endpoint for API key validation
@app.post("/auth/token")
async def get_auth_token(request: Request):
    """Get JWT token using API key.

    Accepts API key in request body as JSON: {"api_key": "wazuh_..."}
    Validates against configured API keys (MCP_API_KEY env var or auto-generated).
    """
    try:
        body = await request.json()
        api_key = body.get("api_key")

        if not api_key:
            raise HTTPException(status_code=400, detail="API key required")

        # Validate API key format
        if not isinstance(api_key, str) or not api_key.startswith("wazuh_"):
            raise HTTPException(status_code=401, detail="Invalid API key format")

        # Validate against configured API key
        # Priority: MCP_API_KEY env var > auto-generated key
        configured_key = os.getenv("MCP_API_KEY", "")

        if configured_key:
            # Use constant-time comparison to prevent timing attacks
            import hmac

            if not hmac.compare_digest(api_key, configured_key):
                raise HTTPException(status_code=401, detail="Invalid API key")
        else:
            # Fall back to auth_manager validation
            from wazuh_mcp_server.auth import auth_manager

            if not auth_manager.validate_api_key(api_key):
                raise HTTPException(status_code=401, detail="Invalid API key")

        # Create JWT token with safe payload (no API key exposure)
        token = create_access_token(
            data={
                "sub": "wazuh_mcp_user",
                "iat": datetime.now(timezone.utc).timestamp(),
                "scope": "wazuh:read wazuh:write",
            },
            secret_key=config.AUTH_SECRET_KEY,
        )

        return {"access_token": token, "token_type": "bearer", "expires_in": 86400}  # 24 hours

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logger.error(f"Token generation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


if __name__ == "__main__":
    import uvicorn

    config = get_config()

    uvicorn.run(app, host=config.MCP_HOST, port=config.MCP_PORT, log_level=config.LOG_LEVEL.lower(), access_log=True)
