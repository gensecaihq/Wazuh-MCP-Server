#!/usr/bin/env python3
"""
Remote MCP Server Implementation for Claude Desktop and Web Clients
Compliant with MCP Remote Server Specifications
"""

import os
import json
import asyncio
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import logging

from fastapi import FastAPI, Request, HTTPException, Depends, status
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import httpx

from wazuh_mcp_server.server import mcp, get_config, get_wazuh_client


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security scheme for bearer token authentication
security = HTTPBearer()

# OAuth configuration (will be implemented in Phase 2)
OAUTH_CONFIG = {
    "authorization_endpoint": None,  # Will be set when OAuth is implemented
    "token_endpoint": None,
    "client_registration_endpoint": None,
}

# Simple bearer token validation (Phase 1 - will be replaced with OAuth in Phase 2)
VALID_TOKENS = set()  # In production, this would be a proper token store

class MCPRequest(BaseModel):
    """MCP protocol request model."""
    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Optional[str] = Field(default=None, description="Request ID")
    method: str = Field(description="MCP method to call")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Method parameters")

class MCPResponse(BaseModel):
    """MCP protocol response model."""
    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Optional[str] = Field(default=None, description="Request ID")
    result: Optional[Any] = Field(default=None, description="Method result")
    error: Optional[Dict[str, Any]] = Field(default=None, description="Error details")

class MCPCapabilities(BaseModel):
    """MCP server capabilities."""
    tools: Optional[Dict[str, Any]] = Field(default=None)
    resources: Optional[Dict[str, Any]] = Field(default=None)
    prompts: Optional[Dict[str, Any]] = Field(default=None)

def create_remote_mcp_app() -> FastAPI:
    """Create FastAPI app with MCP remote server endpoints."""
    
    # Get configuration for custom paths and URLs
    base_path = os.getenv("MCP_BASE_PATH", "").rstrip("/")
    public_url = os.getenv("MCP_PUBLIC_URL", "http://localhost:3000")
    
    # Configure app with custom base path
    app = FastAPI(
        title="Wazuh MCP Remote Server",
        description="Remote MCP server for Wazuh SIEM integration with Claude Desktop support",  
        version="2.0.0",
        root_path=base_path,
        docs_url=f"{base_path}/docs" if base_path else "/docs",
        redoc_url=f"{base_path}/redoc" if base_path else "/redoc"
    )
    
    # Add CORS middleware for web client access
    cors_origins = os.getenv("CORS_ORIGINS", "https://claude.ai,https://*.anthropic.com").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )
    
    # Basic authentication dependency (Phase 1 - simple bearer token)
    async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
        """Verify bearer token (Phase 1 implementation)."""
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authorization header required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        # Phase 1: Simple token validation
        # Phase 2: Will implement proper OAuth token validation
        token = credentials.credentials
        
        # For development/testing, accept any token that starts with 'wazuh_'
        # In production, this will be replaced with proper OAuth validation
        if not token.startswith('wazuh_'):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token format",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        return {"token": token, "authenticated": True}
    
    @app.get("/")
    async def root():
        """Root endpoint with server information."""
        base_path = os.getenv("MCP_BASE_PATH", "").rstrip("/")
        public_url = os.getenv("MCP_PUBLIC_URL", "http://localhost:3000")
        
        return {
            "name": "Wazuh MCP Remote Server",
            "version": "2.0.0",
            "description": "Remote MCP server for Wazuh SIEM integration",
            "mcp_version": "2025-06-18",
            "transport": ["sse", "http"],
            "authentication": "bearer",
            "public_url": public_url,
            "base_path": base_path or "/",
            "endpoints": {
                "sse": f"{public_url}{base_path}/sse",
                "message": f"{public_url}{base_path}/message", 
                "capabilities": f"{public_url}{base_path}/capabilities",
                "health": f"{public_url}{base_path}/health",
                "oauth_metadata": f"{public_url}{base_path}/.well-known/oauth-authorization-server"
            }
        }
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        try:
            # Test Wazuh connection
            config = await get_config()
            client = await get_wazuh_client()
            
            return {
                "status": "healthy",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "wazuh_host": config.wazuh_host,
                "version": "2.0.0"
            }
        except Exception as e:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )
    
    @app.get("/capabilities")
    async def get_capabilities(auth: Dict[str, Any] = Depends(verify_token)):
        """Get MCP server capabilities."""
        try:
            # Get tools and resources from FastMCP
            tools = await mcp.get_tools()
            resources = await mcp.get_resources()
            
            capabilities = MCPCapabilities(
                tools={"list_tools": {"description": f"{len(tools)} security analysis tools available"}},
                resources={"list_resources": {"description": f"{len(resources)} real-time resources available"}},
                prompts={"list_prompts": {"description": "Security analysis prompts available"}}
            )
            
            return {
                "capabilities": capabilities.dict(),
                "tools_count": len(tools),
                "resources_count": len(resources),
                "server_info": {
                    "name": "Wazuh MCP Server",
                    "version": "2.0.0"
                }
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to get capabilities: {e}")
    
    @app.post("/message")
    async def handle_message(
        request: MCPRequest,
        auth: Dict[str, Any] = Depends(verify_token)
    ):
        """Handle MCP protocol messages."""
        try:
            method = request.method
            params = request.params or {}
            
            # Handle MCP protocol methods
            if method == "initialize":
                response_data = {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {
                        "tools": {"listChanged": True},
                        "resources": {"subscribe": False, "listChanged": True},  
                        "prompts": {"listChanged": True}
                    },
                    "serverInfo": {
                        "name": "Wazuh MCP Server",
                        "version": "2.0.0"
                    }
                }
            
            elif method == "tools/list":
                tools = await mcp.get_tools()
                response_data = {
                    "tools": [
                        {
                            "name": name,
                            "description": tool.get("description", "Wazuh security tool"),
                            "inputSchema": tool.get("inputSchema", {})
                        }
                        for name, tool in tools.items()
                    ]
                }
            
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                
                if not tool_name:
                    raise HTTPException(status_code=400, detail="Tool name required")
                
                # Get the tool from FastMCP and call it
                tools = await mcp.get_tools()
                if tool_name not in tools:
                    raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found")
                
                # Call the FastMCP tool directly
                # This is a simplified implementation - in Phase 2 we'll improve this
                try:
                    # Import the tool function dynamically
                    from wazuh_mcp_server.server import (
                        get_wazuh_alerts, get_agent_status, search_wazuh_logs,
                        get_vulnerability_summary, analyze_security_threats
                    )
                    
                    tool_map = {
                        "get_wazuh_alerts": get_wazuh_alerts,
                        "get_agent_status": get_agent_status,
                        "search_wazuh_logs": search_wazuh_logs,
                        "get_vulnerability_summary": get_vulnerability_summary,
                        "analyze_security_threats": analyze_security_threats
                    }
                    
                    if tool_name in tool_map:
                        result = await tool_map[tool_name](**arguments)
                        response_data = {
                            "content": [
                                {
                                    "type": "text",
                                    "text": json.dumps(result, indent=2, default=str)
                                }
                            ]
                        }
                    else:
                        raise HTTPException(status_code=501, detail=f"Tool '{tool_name}' not yet implemented for remote access")
                
                except TypeError as e:
                    raise HTTPException(status_code=400, detail=f"Invalid arguments for tool '{tool_name}': {e}")
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Tool execution failed: {e}")
            
            elif method == "resources/list":
                resources = await mcp.get_resources()
                response_data = {
                    "resources": [
                        {
                            "uri": uri,
                            "name": resource.get("name", uri),
                            "description": resource.get("description", "Wazuh resource"),
                            "mimeType": resource.get("mimeType", "application/json")
                        }
                        for uri, resource in resources.items()
                    ]
                }
            
            elif method == "resources/read":
                uri = params.get("uri")
                if not uri:
                    raise HTTPException(status_code=400, detail="Resource URI required")
                
                # Handle resource reading - simplified for Phase 1
                response_data = {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "text": json.dumps({"message": "Resource content", "uri": uri})
                        }
                    ]
                }
            
            else:
                raise HTTPException(status_code=404, detail=f"Method '{method}' not supported")
            
            return MCPResponse(
                id=request.id,
                result=response_data
            ).dict()
        
        except HTTPException:
            raise
        except Exception as e:
            logger.error(f"Message handling error: {e}")
            return MCPResponse(
                id=request.id,
                error={
                    "code": -32603,
                    "message": "Internal error",
                    "data": str(e)
                }
            ).dict()
    
    @app.get("/sse")
    async def sse_endpoint(
        request: Request,
        auth: Dict[str, Any] = Depends(verify_token)
    ):
        """Server-Sent Events endpoint for real-time MCP communication."""
        
        async def event_stream():
            """Generate SSE events."""
            try:
                # Send initial connection event
                yield f"data: {json.dumps({'type': 'connection', 'status': 'connected', 'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
                
                # Send server capabilities
                tools = await mcp.get_tools()
                resources = await mcp.get_resources()
                
                capabilities_event = {
                    "type": "capabilities",
                    "data": {
                        "tools": list(tools.keys()),
                        "resources": list(resources.keys()),
                        "server_info": {
                            "name": "Wazuh MCP Server",
                            "version": "2.0.0"
                        }
                    }
                }
                yield f"data: {json.dumps(capabilities_event)}\n\n"
                
                # Keep connection alive with periodic heartbeats
                while True:
                    # Check if client is still connected
                    if await request.is_disconnected():
                        break
                    
                    # Send heartbeat every 30 seconds
                    heartbeat = {
                        "type": "heartbeat",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                    yield f"data: {json.dumps(heartbeat)}\n\n"
                    
                    await asyncio.sleep(30)
                    
            except asyncio.CancelledError:
                logger.info("SSE connection cancelled")
                break
            except Exception as e:
                logger.error(f"SSE stream error: {e}")
                error_event = {
                    "type": "error",
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
                yield f"data: {json.dumps(error_event)}\n\n"
        
        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no"  # Disable nginx buffering
            }
        )
    
    # OAuth endpoints (Phase 2 - placeholder implementations)
    @app.get("/.well-known/oauth-authorization-server")
    async def oauth_metadata():
        """OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
        public_url = os.getenv("MCP_PUBLIC_URL", "http://localhost:3000")
        base_path = os.getenv("MCP_BASE_PATH", "").rstrip("/")
        oauth_base = os.getenv("OAUTH_BASE_URL", public_url)
        
        return {
            "issuer": oauth_base,
            "authorization_endpoint": f"{oauth_base}{base_path}/oauth/authorize",
            "token_endpoint": f"{oauth_base}{base_path}/oauth/token",
            "registration_endpoint": f"{oauth_base}{base_path}/oauth/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["wazuh:read", "wazuh:alerts", "wazuh:agents"]
        }
    
    @app.post("/oauth/register")
    async def oauth_register():
        """Dynamic Client Registration (RFC 7591) - Phase 2 implementation."""
        return HTTPException(
            status_code=501,
            detail="OAuth Dynamic Client Registration will be implemented in Phase 2"
        )
    
    @app.get("/oauth/authorize")
    async def oauth_authorize():
        """OAuth Authorization Endpoint - Phase 2 implementation."""
        return HTTPException(
            status_code=501,
            detail="OAuth Authorization will be implemented in Phase 2"
        )
    
    @app.post("/oauth/token")
    async def oauth_token():
        """OAuth Token Endpoint - Phase 2 implementation."""
        return HTTPException(
            status_code=501,
            detail="OAuth Token endpoint will be implemented in Phase 2"
        )
    
    return app

# Create the remote MCP app instance
remote_app = create_remote_mcp_app()

# For debugging and development
if __name__ == "__main__":
    import uvicorn
    
    # Development server with auto-reload
    uvicorn.run(
        "wazuh_mcp_server.remote_server:remote_app",
        host="0.0.0.0",
        port=3000,
        reload=True,
        log_level="info"
    )