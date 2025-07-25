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


# Create FastMCP server with comprehensive metadata
mcp = FastMCP(
    name="Wazuh MCP Server",
    version="2.0.0",
    description="Production-grade FastMCP server for Wazuh SIEM integration with comprehensive security analysis capabilities"
)


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


@mcp.tool
async def analyze_security_threats(
    time_range_hours: Annotated[int, Field(description="Analysis time range in hours", ge=1, le=168)] = 24,
    severity_threshold: Annotated[int, Field(description="Minimum severity level", ge=1, le=15)] = 5,
    ctx: Context = None
) -> dict:
    """Analyze security threats with AI-powered insights."""
    try:
        client = await get_wazuh_client()
        
        # Get recent alerts for analysis
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        if ctx:
            await ctx.info(f"Analyzing threats from last {time_range_hours} hours with severity >= {severity_threshold}")
        
        response = await client.get_alerts(
            limit=500,
            level=severity_threshold
        )
        
        alerts = response.get("data", {}).get("affected_items", [])
        
        # Analyze threat patterns
        threat_categories = {}
        affected_agents = set()
        rule_frequency = {}
        
        for alert in alerts:
            # Categorize by rule description
            rule_desc = alert.get("rule", {}).get("description", "Unknown")
            category = _categorize_threat(rule_desc)
            threat_categories[category] = threat_categories.get(category, 0) + 1
            
            # Track affected agents
            agent_id = alert.get("agent", {}).get("id")
            if agent_id:
                affected_agents.add(agent_id)
            
            # Track rule frequency
            rule_id = alert.get("rule", {}).get("id")
            if rule_id:
                rule_frequency[rule_id] = rule_frequency.get(rule_id, 0) + 1
        
        # Create analysis summary
        analysis = {
            "summary": {
                "total_threats": len(alerts),
                "time_range_hours": time_range_hours,
                "severity_threshold": severity_threshold,
                "affected_agents": len(affected_agents),
                "unique_rules_triggered": len(rule_frequency)
            },
            "threat_categories": threat_categories,
            "top_rules": sorted(rule_frequency.items(), key=lambda x: x[1], reverse=True)[:10],
            "risk_score": _calculate_risk_score(alerts),
            "query_time": datetime.utcnow().isoformat()
        }
        
        if ctx:
            await ctx.info(f"Analysis complete: {len(alerts)} threats found across {len(affected_agents)} agents")
        
        return analysis
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Threat analysis failed: {e}")
        raise ValueError(f"Failed to analyze security threats: {e}")


def _categorize_threat(description: str) -> str:
    """Categorize threat based on rule description."""
    description_lower = description.lower()
    
    if any(word in description_lower for word in ["malware", "virus", "trojan", "rootkit"]):
        return "Malware"
    elif any(word in description_lower for word in ["login", "authentication", "failed", "brute"]):
        return "Authentication"
    elif any(word in description_lower for word in ["intrusion", "attack", "exploit", "vulnerability"]):
        return "Intrusion"
    elif any(word in description_lower for word in ["network", "connection", "traffic", "firewall"]):
        return "Network"
    elif any(word in description_lower for word in ["file", "integrity", "modification", "changed"]):
        return "File Integrity"
    else:
        return "Other"


def _calculate_risk_score(alerts: list) -> dict:
    """Calculate overall risk score based on alerts."""
    if not alerts:
        return {"score": 0, "level": "Low", "factors": []}
    
    total_severity = sum(alert.get("rule", {}).get("level", 0) for alert in alerts)
    avg_severity = total_severity / len(alerts)
    
    # Calculate risk factors
    factors = []
    if len(alerts) > 50:
        factors.append("High alert volume")
    if avg_severity > 10:
        factors.append("High average severity")
    if len(set(alert.get("agent", {}).get("id") for alert in alerts)) > 5:
        factors.append("Multiple affected agents")
    
    # Determine risk level
    if avg_severity >= 12:
        risk_level = "Critical"
        score = min(100, int(avg_severity * 8 + len(alerts) * 0.5))
    elif avg_severity >= 8:
        risk_level = "High"
        score = min(80, int(avg_severity * 6 + len(alerts) * 0.3))
    elif avg_severity >= 5:
        risk_level = "Medium"
        score = min(60, int(avg_severity * 4 + len(alerts) * 0.2))
    else:
        risk_level = "Low"
        score = min(40, int(avg_severity * 2 + len(alerts) * 0.1))
    
    return {
        "score": score,
        "level": risk_level,
        "factors": factors,
        "total_alerts": len(alerts),
        "average_severity": round(avg_severity, 2)
    }


# MCP Resources for real-time data
@mcp.resource("wazuh://status/server")
async def get_server_status() -> str:
    """Get current server status and health."""
    try:
        config = await get_config()
        client = await get_wazuh_client()
        
        # Test connection with a simple API call
        response = await client.get_cluster_status()
        
        status_info = {
            "server": "online",
            "wazuh_host": config.wazuh_host,
            "wazuh_port": config.wazuh_port,
            "connection": "active",
            "last_check": datetime.utcnow().isoformat(),
            "cluster_enabled": response.get("data", {}).get("enabled", False)
        }
        
        return f"""# Wazuh MCP Server Status

**Server Status**: ✅ Online  
**Wazuh Host**: {status_info['wazuh_host']}:{status_info['wazuh_port']}  
**Connection**: ✅ Active  
**Cluster**: {'✅ Enabled' if status_info['cluster_enabled'] else '❌ Disabled'}  
**Last Check**: {status_info['last_check']}

The MCP server is successfully connected to Wazuh and ready to process security queries.
"""
    except Exception as e:
        return f"""# Wazuh MCP Server Status

**Server Status**: ❌ Error  
**Connection**: ❌ Failed  
**Error**: {str(e)}  
**Last Check**: {datetime.utcnow().isoformat()}

Please check your Wazuh configuration and network connectivity.
"""


@mcp.resource("wazuh://dashboard/summary")
async def get_dashboard_summary() -> str:
    """Get security dashboard summary."""
    try:
        client = await get_wazuh_client()
        
        # Get recent alerts
        alerts_response = await client.get_alerts(limit=100)
        alerts = alerts_response.get("data", {}).get("affected_items", [])
        
        # Get agent status
        agents_response = await client.get_agents(limit=50)
        agents = agents_response.get("data", {}).get("affected_items", [])
        
        # Analyze data
        active_agents = len([a for a in agents if a.get("status") == "active"])
        total_agents = len(agents)
        
        # Count alerts by severity
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        for alert in alerts:
            level = alert.get("rule", {}).get("level", 0)
            if level >= 12:
                severity_counts["critical"] += 1
            elif level >= 8:
                severity_counts["high"] += 1
            elif level >= 5:
                severity_counts["medium"] += 1
            else:
                severity_counts["low"] += 1
        
        return f"""# Wazuh Security Dashboard

## 🖥️ Infrastructure Status
- **Active Agents**: {active_agents}/{total_agents}
- **Connection Health**: ✅ Good

## 🚨 Recent Alerts (Last 100)
- **Critical**: {severity_counts['critical']} alerts
- **High**: {severity_counts['high']} alerts  
- **Medium**: {severity_counts['medium']} alerts
- **Low**: {severity_counts['low']} alerts

## 📊 Summary
Total alerts in recent activity: **{len(alerts)}**

*Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*
"""
    except Exception as e:
        return f"""# Wazuh Security Dashboard

## ❌ Dashboard Error
Unable to retrieve dashboard data: {str(e)}

Please check your Wazuh connection and try again.

*Updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC*
"""


async def initialize_server():
    """Initialize server components."""
    try:
        # Test configuration
        config = await get_config()
        print(f"✅ Configuration loaded for {config.wazuh_host}")
        
        # Test Wazuh connection
        client = await get_wazuh_client()
        print("✅ Wazuh connection established")
        
        # Verify FastMCP tools are registered
        print(f"✅ FastMCP server initialized with {len(mcp._tools)} tools and {len(mcp._resources)} resources")
        
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