#!/usr/bin/env python3
"""
Wazuh MCP Server - Complete MCP-Compliant Remote Server
Full compliance with Model Context Protocol 2025-06-18 specification
Production-ready with Streamable HTTP and legacy SSE transport, authentication, and monitoring
"""

# MCP Protocol Version Support
MCP_PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]

import os
import json
import asyncio
import secrets
import logging
import threading
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse
import uuid

from fastapi import FastAPI, Request, Response, HTTPException, Header
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ValidationError
import httpx

from wazuh_mcp_server.config import get_config, WazuhConfig
from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError
from wazuh_mcp_server.auth import create_access_token, verify_token
from wazuh_mcp_server.security import RateLimiter, validate_input
from wazuh_mcp_server.monitoring import REQUEST_COUNT, REQUEST_DURATION, ACTIVE_CONNECTIONS
from wazuh_mcp_server.resilience import GracefulShutdown
from wazuh_mcp_server.session_store import create_session_store, SessionStore

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
            status_code=401,
            detail="Authorization header required",
            headers={"WWW-Authenticate": "Bearer"}
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
            status_code=401,
            detail="Invalid or expired OAuth token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Bearer token mode (default)
    try:
        from wazuh_mcp_server.auth import verify_bearer_token
        await verify_bearer_token(authorization)
        return True
    except ValueError as e:
        raise HTTPException(
            status_code=401,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )

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
        
    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)
        
    def is_expired(self, timeout_minutes: int = 30) -> bool:
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
            "authenticated": self.authenticated
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
        session = MCPSession(data['session_id'], data.get('origin'))
        session.created_at = datetime.fromisoformat(data['created_at'].replace('Z', '+00:00'))
        session.last_activity = datetime.fromisoformat(data['last_activity'].replace('Z', '+00:00'))
        session.capabilities = data.get('capabilities', {})
        session.client_info = data.get('client_info', {})
        session.authenticated = data.get('authenticated', False)
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

    def __getitem__(self, session_id: str) -> MCPSession:
        """Synchronous dict-like access (blocks)."""
        loop = asyncio.get_event_loop()
        session = loop.run_until_complete(self.get(session_id))
        if session is None:
            raise KeyError(f"Session {session_id} not found")
        return session

    def __setitem__(self, session_id: str, session: MCPSession) -> None:
        """Synchronous dict-like access (blocks)."""
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.set(session_id, session))

    def __delitem__(self, session_id: str) -> None:
        """Synchronous delete (blocks)."""
        loop = asyncio.get_event_loop()
        loop.run_until_complete(self.remove(session_id))

    async def __contains__(self, session_id: str) -> bool:
        """Check if session exists."""
        return await self._store.exists(session_id)

    async def remove(self, session_id: str) -> bool:
        """Remove session by ID."""
        return await self._store.delete(session_id)

    def pop(self, session_id: str, default=None) -> Optional[MCPSession]:
        """Remove and return session (synchronous, blocks)."""
        loop = asyncio.get_event_loop()
        session = loop.run_until_complete(self.get(session_id))
        if session:
            loop.run_until_complete(self.remove(session_id))
            return session
        return default

    async def clear(self) -> bool:
        """Clear all sessions."""
        return await self._store.clear()

    def values(self) -> List[MCPSession]:
        """Get all session values (synchronous, blocks)."""
        loop = asyncio.get_event_loop()
        sessions_dict = loop.run_until_complete(self.get_all())
        return list(sessions_dict.values())

    def keys(self) -> List[str]:
        """Get all session keys (synchronous, blocks)."""
        loop = asyncio.get_event_loop()
        sessions_dict = loop.run_until_complete(self.get_all())
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
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")
    
    return session

# Initialize FastAPI app for MCP compliance
app = FastAPI(
    title="Wazuh MCP Server",
    description="MCP-compliant remote server for Wazuh SIEM integration. Supports Streamable HTTP, SSE, OAuth, and authless modes.",
    version="4.0.4",
    docs_url="/docs",
    openapi_url="/openapi.json"
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

# Initialize rate limiter
rate_limiter = RateLimiter(max_requests=100, window_seconds=60)

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
                except Exception:
                    continue
            else:
                origins.append(origin)
    
    return origins if origins else ["https://claude.ai"]

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
        "Mcp-Session-Id",  # Session ID header
        "Last-Event-ID"  # SSE reconnection header
    ],  # Specific headers only, no wildcard
    expose_headers=["Mcp-Session-Id", "MCP-Protocol-Version", "Content-Type"],
    max_age=600  # Cache preflight for 10 minutes
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
    "RESOURCE_NOT_FOUND": -32003
}

def create_error_response(request_id: Optional[Union[str, int]], code: int, message: str, data: Any = None) -> MCPResponse:
    """Create MCP error response."""
    error = MCPError(code=code, message=message, data=data)
    return MCPResponse(id=request_id, error=error.dict())

def create_success_response(request_id: Optional[Union[str, int]], result: Any) -> MCPResponse:
    """Create MCP success response."""
    return MCPResponse(id=request_id, result=result)

def validate_protocol_version(version: Optional[str]) -> str:
    """
    Validate and normalize MCP protocol version.
    Returns the validated version or defaults to 2025-03-26 for backwards compatibility.
    """
    if not version:
        # Per spec: assume 2025-03-26 if no header provided (backwards compatibility)
        return "2025-03-26"

    if version in SUPPORTED_PROTOCOL_VERSIONS:
        return version

    # Check if it's a newer version we might support
    if version > MCP_PROTOCOL_VERSION:
        logger.warning(f"Client requested newer protocol version {version}, using {MCP_PROTOCOL_VERSION}")
        return MCP_PROTOCOL_VERSION

    # Unknown or too old version
    logger.warning(f"Unsupported protocol version {version}, using 2025-03-26 for compatibility")
    return "2025-03-26"

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
    """Handle MCP initialize method."""
    protocol_version = params.get("protocolVersion", "")
    capabilities = params.get("capabilities", {})
    client_info = params.get("clientInfo", {})
    
    # Store client information
    session.capabilities = capabilities
    session.client_info = client_info
    
    # Server capabilities
    server_capabilities = {
        "logging": {},
        "prompts": {
            "listChanged": True
        },
        "resources": {
            "subscribe": True,
            "listChanged": True
        },
        "tools": {
            "listChanged": True
        }
    }
    
    # Server information
    server_info = {
        "name": "Wazuh MCP Server",
        "version": "4.0.4",
        "vendor": "GenSec AI",
        "description": "MCP-compliant remote server for Wazuh SIEM integration"
    }
    
    return {
        "protocolVersion": "2025-03-26",
        "capabilities": server_capabilities,
        "serverInfo": server_info,
        "instructions": "Connected to Wazuh MCP Server. Use available tools for security operations."
    }

async def handle_tools_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/list method - All 29 Wazuh Security Tools."""
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
                    "compact": {"type": "boolean", "default": True, "description": "Return compact alerts with essential fields only (recommended to avoid token limits)"}
                },
                "required": []
            }
        },
        {
            "name": "get_wazuh_alert_summary",
            "description": "Get a summary of Wazuh alerts grouped by specified field",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "24h", "7d"], "default": "24h"},
                    "group_by": {"type": "string", "default": "rule.level"}
                },
                "required": []
            }
        },
        {
            "name": "analyze_alert_patterns",
            "description": "Analyze alert patterns to identify trends and anomalies",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1h", "6h", "24h", "7d"], "default": "24h"},
                    "min_frequency": {"type": "integer", "minimum": 1, "default": 5}
                },
                "required": []
            }
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
                    "compact": {"type": "boolean", "default": True, "description": "Return compact events with essential fields only (recommended to avoid token limits)"}
                },
                "required": ["query"]
            }
        },

        # Agent Management Tools (6 tools)
        {
            "name": "get_wazuh_agents",
            "description": "Retrieve information about Wazuh agents",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Specific agent ID to query"},
                    "status": {"type": "string", "enum": ["active", "disconnected", "never_connected"], "description": "Filter by agent status"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
                },
                "required": []
            }
        },
        {
            "name": "get_wazuh_running_agents",
            "description": "Get list of currently running/active Wazuh agents",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "check_agent_health",
            "description": "Check the health status of a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent to check"}
                },
                "required": ["agent_id"]
            }
        },
        {
            "name": "get_agent_processes",
            "description": "Get running processes from a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
                },
                "required": ["agent_id"]
            }
        },
        {
            "name": "get_agent_ports",
            "description": "Get open ports from a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
                },
                "required": ["agent_id"]
            }
        },
        {
            "name": "get_agent_configuration",
            "description": "Get configuration details for a specific Wazuh agent",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "ID of the agent"}
                },
                "required": ["agent_id"]
            }
        },

        # Vulnerability Management Tools (3 tools) - Requires Wazuh Indexer (4.8.0+)
        {
            "name": "get_wazuh_vulnerabilities",
            "description": "Retrieve vulnerability information from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Filter by specific agent ID"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Filter by severity level"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100},
                    "compact": {"type": "boolean", "default": True, "description": "Return compact vulnerabilities with essential fields only (recommended to avoid token limits)"}
                },
                "required": []
            }
        },
        {
            "name": "get_wazuh_critical_vulnerabilities",
            "description": "Get critical vulnerabilities from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                    "compact": {"type": "boolean", "default": True, "description": "Return compact vulnerabilities with essential fields only (recommended to avoid token limits)"}
                },
                "required": []
            }
        },
        {
            "name": "get_wazuh_vulnerability_summary",
            "description": "Get vulnerability summary statistics from Wazuh Indexer (requires WAZUH_INDEXER_HOST configuration)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "time_range": {"type": "string", "enum": ["1d", "7d", "30d"], "default": "7d"}
                },
                "required": []
            }
        },

        # Security Analysis Tools (6 tools)
        {
            "name": "analyze_security_threat",
            "description": "Analyze a security threat indicator using AI-powered analysis",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "The threat indicator to analyze (IP, hash, domain)"},
                    "indicator_type": {"type": "string", "enum": ["ip", "hash", "domain", "url"], "default": "ip"}
                },
                "required": ["indicator"]
            }
        },
        {
            "name": "check_ioc_reputation",
            "description": "Check reputation of an Indicator of Compromise (IoC)",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "indicator": {"type": "string", "description": "The IoC to check (IP, domain, hash, etc.)"},
                    "indicator_type": {"type": "string", "enum": ["ip", "domain", "hash", "url"], "default": "ip"}
                },
                "required": ["indicator"]
            }
        },
        {
            "name": "perform_risk_assessment",
            "description": "Perform comprehensive risk assessment for agents or the entire environment",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Specific agent ID to assess (if None, assess entire environment)"}
                },
                "required": []
            }
        },
        {
            "name": "get_top_security_threats",
            "description": "Get top security threats based on alert frequency and severity",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10},
                    "time_range": {"type": "string", "enum": ["1h", "6h", "24h", "7d"], "default": "24h"}
                },
                "required": []
            }
        },
        {
            "name": "generate_security_report",
            "description": "Generate comprehensive security report",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "report_type": {"type": "string", "enum": ["daily", "weekly", "monthly", "incident"], "default": "daily"},
                    "include_recommendations": {"type": "boolean", "default": True}
                },
                "required": []
            }
        },
        {
            "name": "run_compliance_check",
            "description": "Run compliance check against security frameworks",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "framework": {"type": "string", "enum": ["PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST"], "default": "PCI-DSS"},
                    "agent_id": {"type": "string", "description": "Specific agent ID to check (if None, check entire environment)"}
                },
                "required": []
            }
        },

        # System Monitoring Tools (10 tools)
        {
            "name": "get_wazuh_statistics",
            "description": "Get comprehensive Wazuh statistics and metrics",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "get_wazuh_weekly_stats",
            "description": "Get weekly statistics from Wazuh including alerts, agents, and trends",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "get_wazuh_cluster_health",
            "description": "Get Wazuh cluster health information",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "get_wazuh_cluster_nodes",
            "description": "Get information about Wazuh cluster nodes",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "get_wazuh_rules_summary",
            "description": "Get summary of Wazuh rules and their effectiveness",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "get_wazuh_remoted_stats",
            "description": "Get Wazuh remoted (agent communication) statistics",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "get_wazuh_log_collector_stats",
            "description": "Get Wazuh log collector statistics",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "required": []
            }
        },
        {
            "name": "search_wazuh_manager_logs",
            "description": "Search Wazuh manager logs for specific patterns",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query/pattern"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
                },
                "required": ["query"]
            }
        },
        {
            "name": "get_wazuh_manager_error_logs",
            "description": "Get recent error logs from Wazuh manager",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
                },
                "required": []
            }
        },
        {
            "name": "validate_wazuh_connection",
            "description": "Validate connection to Wazuh server and return status",
            "inputSchema": {
                "type": "object", 
                "properties": {},
                "required": []
            }
        }
    ]
    
    return {"tools": tools}

async def handle_tools_call(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/call method - All 29 Wazuh Security Tools."""
    tool_name = params.get("name")
    arguments = params.get("arguments", {})
    
    if not tool_name:
        raise ValueError("Tool name is required")
    
    # Validate input
    validate_input(tool_name, max_length=100)
    
    try:
        # Alert Management Tools
        if tool_name == "get_wazuh_alerts":
            limit = arguments.get("limit", 100)
            rule_id = arguments.get("rule_id")
            level = arguments.get("level")
            agent_id = arguments.get("agent_id")
            timestamp_start = arguments.get("timestamp_start")
            timestamp_end = arguments.get("timestamp_end")
            compact = arguments.get("compact", True)
            result = await wazuh_client.get_alerts(
                limit=limit, rule_id=rule_id, level=level,
                agent_id=agent_id, timestamp_start=timestamp_start,
                timestamp_end=timestamp_end
            )
            if compact:
                result = _compact_alerts_result(result)
            return {"content": [{"type": "text", "text": f"Wazuh Alerts:\n{json.dumps(result, indent=2 if not compact else None)}"}]}
            
        elif tool_name == "get_wazuh_alert_summary":
            time_range = arguments.get("time_range", "24h")
            group_by = arguments.get("group_by", "rule.level")
            result = await wazuh_client.get_alert_summary(time_range, group_by)
            return {"content": [{"type": "text", "text": f"Alert Summary:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "analyze_alert_patterns":
            time_range = arguments.get("time_range", "24h")
            min_frequency = arguments.get("min_frequency", 5)
            result = await wazuh_client.analyze_alert_patterns(time_range, min_frequency)
            return {"content": [{"type": "text", "text": f"Alert Patterns:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "search_security_events":
            query = arguments.get("query")
            time_range = arguments.get("time_range", "24h")
            limit = arguments.get("limit", 100)
            compact = arguments.get("compact", True)
            result = await wazuh_client.search_security_events(query, time_range, limit)
            if compact:
                result = _compact_alerts_result(result)
            return {"content": [{"type": "text", "text": f"Security Events:\n{json.dumps(result, indent=2 if not compact else None)}"}]}

        # Agent Management Tools
        elif tool_name == "get_wazuh_agents":
            agent_id = arguments.get("agent_id")
            status = arguments.get("status")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.get_agents(agent_id=agent_id, status=status, limit=limit)
            return {"content": [{"type": "text", "text": f"Wazuh Agents:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_wazuh_running_agents":
            result = await wazuh_client.get_running_agents()
            return {"content": [{"type": "text", "text": f"Running Agents:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "check_agent_health":
            agent_id = arguments.get("agent_id")
            result = await wazuh_client.check_agent_health(agent_id)
            return {"content": [{"type": "text", "text": f"Agent Health:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_agent_processes":
            agent_id = arguments.get("agent_id")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.get_agent_processes(agent_id, limit)
            return {"content": [{"type": "text", "text": f"Agent Processes:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_agent_ports":
            agent_id = arguments.get("agent_id")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.get_agent_ports(agent_id, limit)
            return {"content": [{"type": "text", "text": f"Agent Ports:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_agent_configuration":
            agent_id = arguments.get("agent_id")
            result = await wazuh_client.get_agent_configuration(agent_id)
            return {"content": [{"type": "text", "text": f"Agent Configuration:\n{json.dumps(result, indent=2)}"}]}

        # Vulnerability Management Tools
        elif tool_name == "get_wazuh_vulnerabilities":
            agent_id = arguments.get("agent_id")
            severity = arguments.get("severity")
            limit = arguments.get("limit", 100)
            compact = arguments.get("compact", True)
            result = await wazuh_client.get_vulnerabilities(agent_id=agent_id, severity=severity, limit=limit)
            if compact:
                result = _compact_vulns_result(result)
            return {"content": [{"type": "text", "text": f"Vulnerabilities:\n{json.dumps(result, indent=2 if not compact else None)}"}]}
            
        elif tool_name == "get_wazuh_critical_vulnerabilities":
            limit = arguments.get("limit", 50)
            compact = arguments.get("compact", True)
            result = await wazuh_client.get_critical_vulnerabilities(limit)
            if compact:
                result = _compact_vulns_result(result)
            return {"content": [{"type": "text", "text": f"Critical Vulnerabilities:\n{json.dumps(result, indent=2 if not compact else None)}"}]}
            
        elif tool_name == "get_wazuh_vulnerability_summary":
            time_range = arguments.get("time_range", "7d")
            result = await wazuh_client.get_vulnerability_summary(time_range)
            return {"content": [{"type": "text", "text": f"Vulnerability Summary:\n{json.dumps(result, indent=2)}"}]}

        # Security Analysis Tools  
        elif tool_name == "analyze_security_threat":
            indicator = arguments.get("indicator")
            indicator_type = arguments.get("indicator_type", "ip")
            result = await wazuh_client.analyze_security_threat(indicator, indicator_type)
            return {"content": [{"type": "text", "text": f"Threat Analysis:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "check_ioc_reputation":
            indicator = arguments.get("indicator")
            indicator_type = arguments.get("indicator_type", "ip")
            result = await wazuh_client.check_ioc_reputation(indicator, indicator_type)
            return {"content": [{"type": "text", "text": f"IoC Reputation:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "perform_risk_assessment":
            agent_id = arguments.get("agent_id")
            result = await wazuh_client.perform_risk_assessment(agent_id)
            return {"content": [{"type": "text", "text": f"Risk Assessment:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_top_security_threats":
            limit = arguments.get("limit", 10)
            time_range = arguments.get("time_range", "24h")
            result = await wazuh_client.get_top_security_threats(limit, time_range)
            return {"content": [{"type": "text", "text": f"Top Security Threats:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "generate_security_report":
            report_type = arguments.get("report_type", "daily")
            include_recommendations = arguments.get("include_recommendations", True)
            result = await wazuh_client.generate_security_report(report_type, include_recommendations)
            return {"content": [{"type": "text", "text": f"Security Report:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "run_compliance_check":
            framework = arguments.get("framework", "PCI-DSS")
            agent_id = arguments.get("agent_id")
            result = await wazuh_client.run_compliance_check(framework, agent_id)
            return {"content": [{"type": "text", "text": f"Compliance Check:\n{json.dumps(result, indent=2)}"}]}

        # System Monitoring Tools
        elif tool_name == "get_wazuh_statistics":
            result = await wazuh_client.get_wazuh_statistics()
            return {"content": [{"type": "text", "text": f"Wazuh Statistics:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_wazuh_weekly_stats":
            result = await wazuh_client.get_weekly_stats()
            return {"content": [{"type": "text", "text": f"Weekly Statistics:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_wazuh_cluster_health":
            result = await wazuh_client.get_cluster_health()
            return {"content": [{"type": "text", "text": f"Cluster Health:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_wazuh_cluster_nodes":
            result = await wazuh_client.get_cluster_nodes()
            return {"content": [{"type": "text", "text": f"Cluster Nodes:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_wazuh_rules_summary":
            result = await wazuh_client.get_rules_summary()
            return {"content": [{"type": "text", "text": f"Rules Summary:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_wazuh_remoted_stats":
            result = await wazuh_client.get_remoted_stats()
            return {"content": [{"type": "text", "text": f"Remoted Statistics:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_wazuh_log_collector_stats":
            result = await wazuh_client.get_log_collector_stats()
            return {"content": [{"type": "text", "text": f"Log Collector Statistics:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "search_wazuh_manager_logs":
            query = arguments.get("query")
            limit = arguments.get("limit", 100)
            result = await wazuh_client.search_manager_logs(query, limit)
            return {"content": [{"type": "text", "text": f"Manager Logs:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_wazuh_manager_error_logs":
            limit = arguments.get("limit", 100)
            result = await wazuh_client.get_manager_error_logs(limit)
            return {"content": [{"type": "text", "text": f"Manager Error Logs:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "validate_wazuh_connection":
            result = await wazuh_client.validate_connection()
            return {"content": [{"type": "text", "text": f"Connection Validation:\n{json.dumps(result, indent=2)}"}]}

        else:
            raise ValueError(f"Unknown tool: {tool_name}")

    except IndexerNotConfiguredError as e:
        # Provide helpful error for vulnerability tools when indexer is not configured
        logger.warning(f"Indexer not configured for tool {tool_name}: {e}")
        raise ValueError(str(e))

    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        raise ValueError(f"Tool execution failed: {str(e)}")

# MCP Method Registry
MCP_METHODS = {
    "initialize": handle_initialize,
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
}

async def process_mcp_request(request: MCPRequest, session: MCPSession) -> MCPResponse:
    """Process individual MCP request."""
    try:
        # Check if method exists
        if request.method not in MCP_METHODS:
            return create_error_response(
                request.id,
                MCP_ERRORS["METHOD_NOT_FOUND"],
                f"Method '{request.method}' not found"
            )
        
        # Execute method handler
        handler = MCP_METHODS[request.method]
        result = await handler(request.params or {}, session)
        
        return create_success_response(request.id, result)
        
    except ValueError as e:
        return create_error_response(
            request.id,
            MCP_ERRORS["INVALID_PARAMS"],
            str(e)
        )
    except Exception as e:
        logger.error(f"Internal error processing {request.method}: {e}")
        return create_error_response(
            request.id,
            MCP_ERRORS["INTERNAL_ERROR"],
            "Internal server error"
        )

async def generate_sse_events(session: MCPSession, event_id_counter: int = 0):
    """
    Generate Server-Sent Events for MCP Streamable HTTP transport.

    Per MCP spec, SSE events may include an 'id' field for resumability.
    The data field contains JSON-RPC formatted messages.
    """
    event_id = event_id_counter

    # Send session info as a JSON-RPC notification
    event_id += 1
    session_notification = {
        "jsonrpc": "2.0",
        "method": "notifications/session",
        "params": session.to_dict()
    }
    yield f"id: {event_id}\nevent: message\ndata: {json.dumps(session_notification)}\n\n"

    # Send capabilities notification
    event_id += 1
    capabilities_notification = {
        "jsonrpc": "2.0",
        "method": "notifications/capabilities",
        "params": {"tools": True, "resources": True, "prompts": True, "logging": True}
    }
    yield f"id: {event_id}\nevent: message\ndata: {json.dumps(capabilities_notification)}\n\n"

    # Send periodic keepalive (ping) to maintain connection
    while True:
        event_id += 1
        ping_notification = {
            "jsonrpc": "2.0",
            "method": "notifications/ping",
            "params": {"timestamp": datetime.now(timezone.utc).isoformat()}
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
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID")
):
    """
    Main MCP protocol endpoint supporting both GET and POST.
    GET: Returns SSE stream for real-time communication
    POST: Handles JSON-RPC requests
    """
    # Track metrics
    REQUEST_COUNT.labels(
        method=request.method,
        endpoint="/",
        status_code=200
    ).inc()
    
    ACTIVE_CONNECTIONS.inc()
    
    try:
        # Origin validation for security
        if not origin:
            raise HTTPException(status_code=403, detail="Origin header required")
        
        # Validate origin against allowed list
        allowed_origins_list = config.ALLOWED_ORIGINS.split(",") if config.ALLOWED_ORIGINS else []
        if allowed_origins_list and origin not in allowed_origins_list:
            # Check for wildcard patterns
            origin_allowed = False
            for allowed in allowed_origins_list:
                if allowed == "*" or allowed == origin:
                    origin_allowed = True
                    break
                elif allowed.startswith("*") and origin.endswith(allowed[1:]):
                    origin_allowed = True
                    break
                elif "localhost" in allowed and "localhost" in origin:
                    origin_allowed = True
                    break
            
            if not origin_allowed:
                raise HTTPException(status_code=403, detail="Origin not allowed")
        
        # Rate limiting
        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            headers = {"Retry-After": str(retry_after)} if retry_after else {}
            raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)
        
        # Get or create session
        session = await get_or_create_session(mcp_session_id, origin)

        # Handle GET request (SSE)
        if request.method == "GET":
            if accept and "text/event-stream" in accept:
                response = StreamingResponse(
                    generate_sse_events(session),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive",
                        "Mcp-Session-Id": session.session_id,
                        "Access-Control-Expose-Headers": "Mcp-Session-Id"
                    }
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
                            "serverInfo": {
                                "name": "Wazuh MCP Server",
                                "version": "4.0.4"
                            },
                            "session": session.to_dict()
                        }
                    },
                    headers={
                        "Mcp-Session-Id": session.session_id,
                        "Access-Control-Expose-Headers": "Mcp-Session-Id"
                    }
                )
        
        # Handle POST request (JSON-RPC)
        elif request.method == "POST":
            try:
                body = await request.json()
            except json.JSONDecodeError:
                return JSONResponse(
                    content=create_error_response(
                        None,
                        MCP_ERRORS["PARSE_ERROR"],
                        "Invalid JSON"
                    ).dict(),
                    status_code=400
                )
            
            # Handle batch requests
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        content=create_error_response(
                            None,
                            MCP_ERRORS["INVALID_REQUEST"],
                            "Empty batch request"
                        ).dict(),
                        status_code=400
                    )

                # Per MCP Streamable HTTP spec: If the input consists solely of
                # notifications or responses, return HTTP 202 Accepted with no body
                has_requests = any(
                    is_json_rpc_request(item) if isinstance(item, dict) else False
                    for item in body
                )

                if not has_requests:
                    # All items are notifications or responses - accept and return 202
                    logger.debug(f"Received batch of {len(body)} notifications/responses")
                    return Response(
                        status_code=202,
                        headers={
                            "Mcp-Session-Id": session.session_id,
                            "Access-Control-Expose-Headers": "Mcp-Session-Id"
                        }
                    )

                # Process batch containing requests
                responses = []
                for item in body:
                    # Skip notifications and responses in batch
                    if isinstance(item, dict) and not is_json_rpc_request(item):
                        continue
                    try:
                        mcp_request = MCPRequest(**item)
                        response = await process_mcp_request(mcp_request, session)
                        responses.append(response.dict())
                    except ValidationError as e:
                        responses.append(create_error_response(
                            item.get("id") if isinstance(item, dict) else None,
                            MCP_ERRORS["INVALID_REQUEST"],
                            f"Invalid request format: {e}"
                        ).dict())

                return JSONResponse(
                    content=responses,
                    headers={
                        "Mcp-Session-Id": session.session_id,
                        "Access-Control-Expose-Headers": "Mcp-Session-Id"
                    }
                )
            
            # Handle single message
            else:
                # Per MCP spec: notifications and responses return HTTP 202 Accepted
                if isinstance(body, dict):
                    if is_json_rpc_notification(body) or is_json_rpc_response(body):
                        logger.debug(f"Received single notification/response")
                        return Response(
                            status_code=202,
                            headers={
                                "Mcp-Session-Id": session.session_id,
                                "Access-Control-Expose-Headers": "Mcp-Session-Id"
                            }
                        )

                # Handle request
                try:
                    mcp_request = MCPRequest(**body)
                    response = await process_mcp_request(mcp_request, session)
                    return JSONResponse(
                        content=response.dict(),
                        headers={
                            "Mcp-Session-Id": session.session_id,
                            "Access-Control-Expose-Headers": "Mcp-Session-Id"
                        }
                    )
                except ValidationError as e:
                    return JSONResponse(
                        content=create_error_response(
                            body.get("id") if isinstance(body, dict) else None,
                            MCP_ERRORS["INVALID_REQUEST"],
                            f"Invalid request format: {e}"
                        ).dict(),
                        status_code=400
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
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID")
):
    """
    Official MCP SSE endpoint following Anthropic standards.
    URL format: https://<server_address>/sse
    This is the standard endpoint that Claude Desktop connects to.

    Supports authentication modes: bearer (default), oauth, none (authless)
    """
    # Verify authentication based on configured mode
    await verify_authentication(authorization, config)

    # Origin validation for security
    if not origin:
        raise HTTPException(status_code=403, detail="Origin header required")
    
    # Validate origin against allowed list
    allowed_origins_list = config.ALLOWED_ORIGINS.split(",") if config.ALLOWED_ORIGINS else []
    if allowed_origins_list and origin not in allowed_origins_list:
        # Check for wildcard patterns
        origin_allowed = False
        for allowed in allowed_origins_list:
            if allowed == "*" or allowed == origin:
                origin_allowed = True
                break
            elif allowed.startswith("*") and origin.endswith(allowed[1:]):
                origin_allowed = True
                break
            elif "localhost" in allowed and "localhost" in origin:
                origin_allowed = True
                break
        
        if not origin_allowed:
            raise HTTPException(status_code=403, detail="Origin not allowed")
    
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
                "Mcp-Session-Id": session.session_id,
                "Access-Control-Expose-Headers": "Mcp-Session-Id"
            }
        )
        return response
        
    except Exception as e:
        logger.error(f"SSE endpoint error: {e}")
        raise HTTPException(status_code=500, detail="SSE stream error")
    
    finally:
        ACTIVE_CONNECTIONS.dec()

# Standard MCP Endpoint - Streamable HTTP Transport (2025-06-18 Specification)
@app.post("/mcp")
@app.get("/mcp")
async def mcp_streamable_http_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    mcp_protocol_version: Optional[str] = Header(None, alias="MCP-Protocol-Version"),
    mcp_session_id: Optional[str] = Header(None, alias="Mcp-Session-Id"),
    accept: Optional[str] = Header("application/json"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID")
):
    """
    Standard MCP endpoint using Streamable HTTP transport (2025-06-18 spec).

    Supports:
    - POST: JSON-RPC requests with optional SSE streaming for long operations
    - GET: Session information or SSE stream initiation
    - DELETE: Session termination (see separate endpoint)

    This is the RECOMMENDED endpoint for MCP clients. Legacy /sse remains for backwards compatibility.
    Supports authentication modes: bearer (default), oauth, none (authless)
    """
    # Validate protocol version
    protocol_version = validate_protocol_version(mcp_protocol_version)

    # Verify authentication based on configured mode
    await verify_authentication(authorization, config)

    # Origin validation for security (DNS rebinding protection)
    if not origin:
        raise HTTPException(status_code=403, detail="Origin header required")

    # Validate origin against allowed list
    allowed_origins_list = config.ALLOWED_ORIGINS.split(",") if config.ALLOWED_ORIGINS else []
    if allowed_origins_list and origin not in allowed_origins_list:
        origin_allowed = False
        for allowed in allowed_origins_list:
            if allowed == "*" or allowed == origin:
                origin_allowed = True
                break
            elif allowed.startswith("*") and origin.endswith(allowed[1:]):
                origin_allowed = True
                break
            elif "localhost" in allowed and "localhost" in origin:
                origin_allowed = True
                break

        if not origin_allowed:
            raise HTTPException(status_code=403, detail="Origin not allowed")

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
        # Get or create session
        session = await get_or_create_session(mcp_session_id, origin)
        session.authenticated = True  # Mark as authenticated via bearer token

        # Common response headers
        response_headers = {
            "Mcp-Session-Id": session.session_id,
            "MCP-Protocol-Version": protocol_version,
            "Access-Control-Expose-Headers": "Mcp-Session-Id, MCP-Protocol-Version"
        }

        # Handle GET request
        if request.method == "GET":
            # Check if client wants SSE stream
            if accept and "text/event-stream" in accept:
                # Return SSE stream for real-time communication
                response = StreamingResponse(
                    generate_sse_events(session),
                    media_type="text/event-stream",
                    headers={
                        **response_headers,
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive"
                    }
                )
                return response
            else:
                # Return session information as JSON
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "id": None,
                        "result": {
                            "protocolVersion": protocol_version,
                            "serverInfo": {
                                "name": "Wazuh MCP Server",
                                "version": "4.0.4"
                            },
                            "capabilities": {
                                "tools": True,
                                "resources": True,
                                "prompts": True,
                                "logging": True
                            },
                            "session": session.to_dict()
                        }
                    },
                    headers=response_headers
                )

        # Handle POST request (JSON-RPC)
        elif request.method == "POST":
            try:
                body = await request.json()
            except json.JSONDecodeError:
                return JSONResponse(
                    content=create_error_response(
                        None,
                        MCP_ERRORS["PARSE_ERROR"],
                        "Invalid JSON"
                    ).dict(),
                    status_code=400,
                    headers=response_headers
                )

            # Handle batch messages per MCP Streamable HTTP spec
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        content=create_error_response(
                            None,
                            MCP_ERRORS["INVALID_REQUEST"],
                            "Empty batch request"
                        ).dict(),
                        status_code=400,
                        headers=response_headers
                    )

                # Check if batch contains any requests
                has_requests = any(
                    is_json_rpc_request(item) if isinstance(item, dict) else False
                    for item in body
                )

                if not has_requests:
                    # All notifications/responses - return 202 Accepted
                    return Response(status_code=202, headers=response_headers)

                # Process requests in batch
                responses = []
                for item in body:
                    if isinstance(item, dict) and not is_json_rpc_request(item):
                        continue  # Skip notifications/responses
                    try:
                        mcp_request = MCPRequest(**item)
                        resp = await process_mcp_request(mcp_request, session)
                        responses.append(resp.dict())
                    except ValidationError as e:
                        responses.append(create_error_response(
                            item.get("id") if isinstance(item, dict) else None,
                            MCP_ERRORS["INVALID_REQUEST"],
                            f"Invalid request format: {e}"
                        ).dict())

                return JSONResponse(content=responses, headers=response_headers)

            # Handle single message
            if isinstance(body, dict):
                # Notifications and responses return 202 Accepted
                if is_json_rpc_notification(body) or is_json_rpc_response(body):
                    return Response(status_code=202, headers=response_headers)

            # Validate JSON-RPC request
            try:
                mcp_request = MCPRequest(**body) if isinstance(body, dict) else None
            except ValidationError as e:
                return JSONResponse(
                    content=create_error_response(
                        None,
                        MCP_ERRORS["INVALID_REQUEST"],
                        f"Invalid MCP request: {str(e)}"
                    ).dict(),
                    status_code=400,
                    headers=response_headers
                )

            # Process the request
            if mcp_request:
                mcp_response = await process_mcp_request(mcp_request, session)

                # Check if client accepts SSE for streaming response
                # (For long-running operations, we could upgrade to SSE here)
                if accept and "text/event-stream" in accept:
                    # Optional: Stream the response via SSE for long operations
                    # For now, return JSON response
                    return JSONResponse(
                        content=mcp_response.dict(),
                        headers=response_headers
                    )
                else:
                    # Standard JSON response
                    return JSONResponse(
                        content=mcp_response.dict(),
                        headers=response_headers
                    )
            else:
                return JSONResponse(
                    content=create_error_response(
                        None,
                        MCP_ERRORS["INVALID_REQUEST"],
                        "Invalid request format"
                    ).dict(),
                    status_code=400,
                    headers=response_headers
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
    mcp_session_id: str = Header(..., alias="Mcp-Session-Id"),
    authorization: str = Header(None)
):
    """
    Close MCP session explicitly (2025-06-18 spec).
    Allows clients to cleanly terminate sessions.
    """
    # Authentication required
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Authorization required",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        from wazuh_mcp_server.auth import verify_bearer_token
        await verify_bearer_token(authorization)
    except ValueError as e:
        raise HTTPException(
            status_code=401,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Remove session
    try:
        await sessions.remove(mcp_session_id)
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

        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "version": "4.0.4",
            "mcp_protocol_version": MCP_PROTOCOL_VERSION,
            "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
            "transport": {
                "streamable_http": "enabled",  # New standard
                "legacy_sse": "enabled"  # Backwards compatibility
            },
            "authentication": auth_info,
            "services": {
                "wazuh_manager": wazuh_status,
                "wazuh_indexer": indexer_status,
                "mcp": "healthy"
            },
            "vulnerability_tools": {
                "available": wazuh_client._indexer_client is not None,
                "note": "Vulnerability tools require Wazuh Indexer (4.8.0+). Set WAZUH_INDEXER_HOST to enable." if not wazuh_client._indexer_client else "Wazuh Indexer configured"
            },
            "metrics": {
                "active_sessions": active_sessions,
                "total_sessions": len(all_sessions)
            },
            "endpoints": {
                "recommended": "/mcp (Streamable HTTP - 2025-06-18)",
                "legacy": "/sse (SSE only)",
                "authentication": "/auth/token" if config.is_bearer else ("/oauth/token" if config.is_oauth else None),
                "monitoring": ["/health", "/metrics"]
            }
        }
    except Exception as e:
        return JSONResponse(
            content={
                "status": "unhealthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "error": str(e)
            },
            status_code=503
        )

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


# OAuth 2.0 Discovery Endpoint (RFC 8414)
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    """
    OAuth 2.0 Authorization Server Metadata endpoint.
    Required for Claude Desktop OAuth integration.
    """
    global _oauth_manager
    if not config.is_oauth or not _oauth_manager:
        raise HTTPException(
            status_code=404,
            detail="OAuth not enabled. Set AUTH_MODE=oauth to enable."
        )

    return JSONResponse(_oauth_manager.get_metadata(request))


# Authentication endpoint for API key validation
@app.post("/auth/token")
async def get_auth_token(request: Request):
    """Get JWT token using API key."""
    try:
        body = await request.json()
        api_key = body.get("api_key")
        
        if not api_key:
            raise HTTPException(status_code=400, detail="API key required")
        
        # In a real implementation, validate API key against database
        # For now, accept any key that starts with "wazuh_" 
        if not api_key.startswith("wazuh_"):
            raise HTTPException(status_code=401, detail="Invalid API key")
        
        # Create JWT token with safe payload (no API key exposure)
        token = create_access_token(
            data={
                "sub": "wazuh_mcp_user",
                "iat": datetime.now(timezone.utc).timestamp(),
                "scope": "wazuh:read wazuh:write"
            },
            secret_key=config.AUTH_SECRET_KEY
        )
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 86400  # 24 hours
        }
    
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except Exception as e:
        logger.error(f"Token generation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize server on startup with graceful shutdown support."""
    global _oauth_manager

    logger.info("🚀 Wazuh MCP Server v4.0.3 starting up...")
    logger.info(f"📡 MCP Protocol: {MCP_PROTOCOL_VERSION}")
    logger.info(f"🔗 Wazuh Host: {config.WAZUH_HOST}")
    logger.info(f"🌐 CORS Origins: {config.ALLOWED_ORIGINS}")
    logger.info(f"🔐 Auth Mode: {config.AUTH_MODE}")

    # Log Indexer configuration status
    if config.WAZUH_INDEXER_HOST:
        logger.info(f"📊 Wazuh Indexer: {config.WAZUH_INDEXER_HOST}:{config.WAZUH_INDEXER_PORT}")
    else:
        logger.warning("⚠️  Wazuh Indexer not configured. Vulnerability tools require Wazuh 4.8.0+")
        logger.warning("   Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS to enable.")

    # Initialize OAuth if enabled
    if config.is_oauth:
        try:
            from wazuh_mcp_server.oauth import init_oauth_manager, create_oauth_router
            _oauth_manager = init_oauth_manager(config)
            oauth_router = create_oauth_router(_oauth_manager)
            app.include_router(oauth_router)
            logger.info("✅ OAuth 2.0 with DCR initialized")
            logger.info(f"   OAuth endpoints: /oauth/authorize, /oauth/token, /oauth/register")
            logger.info(f"   Discovery: /.well-known/oauth-authorization-server")
        except Exception as e:
            logger.error(f"❌ OAuth initialization failed: {e}")

    # Log auth mode status
    if config.is_authless:
        logger.warning("⚠️  Running in AUTHLESS mode - no authentication required!")
    elif config.is_bearer:
        logger.info("🔐 Bearer token authentication enabled")

    # Initialize Wazuh client
    try:
        await wazuh_client.initialize()
        logger.info("✅ Wazuh client initialized successfully")

        # Register Wazuh client cleanup
        async def cleanup_wazuh():
            if hasattr(wazuh_client, 'close'):
                await wazuh_client.close()
                logger.info("Wazuh client connections closed")

        shutdown_manager.add_cleanup_task(cleanup_wazuh)

    except Exception as e:
        logger.warning(f"⚠️  Wazuh client initialization failed: {e}")

    # Test Wazuh connectivity
    try:
        await wazuh_client.get_manager_info()
        logger.info("✅ Wazuh connectivity test passed")
    except Exception as e:
        logger.warning(f"⚠️  Wazuh connectivity test failed: {e}")

    logger.info("✅ Server startup complete with high availability features enabled")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on server shutdown with graceful resource management."""
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
        logger.info("Sessions cleared")

        # Cleanup rate limiter
        if hasattr(rate_limiter, 'cleanup'):
            rate_limiter.cleanup()

        # Force garbage collection
        import gc
        gc.collect()
        logger.info("Garbage collection completed")

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
    finally:
        logger.info("✅ Graceful shutdown completed")

if __name__ == "__main__":
    import uvicorn
    
    config = get_config()
    
    uvicorn.run(
        app,
        host=config.MCP_HOST,
        port=config.MCP_PORT,
        log_level=config.LOG_LEVEL.lower(),
        access_log=True
    )