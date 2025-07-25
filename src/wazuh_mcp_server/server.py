#!/usr/bin/env python3
"""FastMCP-powered Wazuh SIEM integration server."""

import os
import sys
from typing import Dict, Any, Optional, Annotated
from datetime import datetime, timedelta

# Check Python version
if sys.version_info < (3, 10):
    print(f"ERROR: Python 3.10+ required. Current: {sys.version_info}")
    sys.exit(1)

try:
    from fastmcp import FastMCP, Context
    from pydantic import Field
    from dotenv import load_dotenv
except ImportError as e:
    print(f"CRITICAL: Missing dependency: {e}")
    sys.exit(1)

load_dotenv()

from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.api.wazuh_client import WazuhClient


# Global state
_config: Optional[WazuhConfig] = None
_wazuh_client: Optional[WazuhClient] = None

async def get_config() -> WazuhConfig:
    """Get global configuration."""
    global _config
    if _config is None:
        _config = WazuhConfig.from_env()
    return _config

async def get_wazuh_client() -> WazuhClient:
    """Get Wazuh API client."""
    global _wazuh_client
    if _wazuh_client is None:
        config = await get_config()
        _wazuh_client = WazuhClient(config)
        await _wazuh_client.initialize()
    return _wazuh_client


# Create FastMCP server
mcp = FastMCP(name="Wazuh MCP Server", version="2.0.0")


@mcp.tool
async def get_wazuh_alerts(
    limit: Annotated[int, Field(description="Maximum number of alerts", ge=1, le=1000)] = 100,
    level: Annotated[Optional[int], Field(description="Minimum alert level", ge=1, le=15)] = None,
    ctx: Context = None
) -> dict:
    """Retrieve Wazuh security alerts."""
    try:
        client = await get_wazuh_client()
        
        params = {"limit": limit}
        if level:
            params["level"] = level
            
        response = await client.get_alerts(**params)
        alerts = response.get("data", {}).get("affected_items", [])
        
        return {
            "alerts": alerts,
            "total": len(alerts),
            "query_time": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise ValueError(f"Failed to retrieve alerts: {e}")


@mcp.tool  
async def get_agent_status(
    agent_id: Annotated[Optional[str], Field(description="Specific agent ID")] = None,
    ctx: Context = None
) -> dict:
    """Get Wazuh agent status information."""
    try:
        client = await get_wazuh_client()
        
        params = {}
        if agent_id:
            params["agents_list"] = agent_id
            
        response = await client.get_agents(**params)
        agents = response.get("data", {}).get("affected_items", [])
        
        # Count by status
        status_counts = {}
        for agent in agents:
            status = agent.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "agents": agents,
            "total_agents": len(agents),
            "status_summary": status_counts,
            "query_time": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise ValueError(f"Failed to retrieve agent status: {e}")


@mcp.tool
async def get_vulnerability_summary(
    agent_id: Annotated[Optional[str], Field(description="Agent ID")] = None,
    ctx: Context = None
) -> dict:
    """Get vulnerability information from Wazuh."""
    try:
        client = await get_wazuh_client()
        
        params = {}
        if agent_id:
            params["agent_id"] = agent_id
            
        response = await client.get_vulnerabilities(**params)
        vulnerabilities = response.get("data", {}).get("affected_items", [])
        
        # Count by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("vulnerability", {}).get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "vulnerabilities": vulnerabilities,
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": severity_counts,
            "query_time": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise ValueError(f"Failed to retrieve vulnerabilities: {e}")


@mcp.tool
async def get_cluster_status(ctx: Context = None) -> dict:
    """Get Wazuh cluster status."""
    try:
        client = await get_wazuh_client()
        response = await client.get_cluster_status()
        
        return {
            "cluster_data": response.get("data", {}),
            "query_time": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise ValueError(f"Failed to retrieve cluster status: {e}")


async def initialize_server():
    """Initialize server components."""
    try:
        # Test configuration
        config = await get_config()
        print(f"✅ Configuration loaded for {config.wazuh_host}")
        
        # Test Wazuh connection
        client = await get_wazuh_client()
        print("✅ Wazuh connection established")
        
    except Exception as e:
        print(f"❌ Server initialization failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    import uvicorn
    import asyncio
    
    # Initialize server
    asyncio.run(initialize_server())
    
    # Start based on transport mode
    transport = os.getenv("MCP_TRANSPORT", "stdio").lower()
    
    if transport == "http":
        host = os.getenv("MCP_HOST", "0.0.0.0")
        port = int(os.getenv("MCP_PORT", "3000"))
        print(f"🌐 Starting HTTP server on {host}:{port}")
        uvicorn.run(mcp.create_app(), host=host, port=port)
    else:
        print("📱 Starting STDIO server for Claude Desktop")
        mcp.run()