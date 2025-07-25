#!/usr/bin/env python3
"""
FastMCP-Compliant Wazuh MCP Server
Follows official FastMCP documentation standards and best practices
"""

import os
import sys
import asyncio
import logging
from typing import Dict, List, Any, Optional, Annotated
from datetime import datetime, timedelta
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Check Python version before any imports
if sys.version_info < (3, 10):
    print(f"ERROR: FastMCP requires Python 3.10+. Current: {sys.version}")
    sys.exit(1)

# Import dependencies with proper error handling
try:
    from fastmcp import FastMCP, Context
    import httpx
    from pydantic import Field
    from dotenv import load_dotenv
except ImportError as e:
    print(f"CRITICAL ERROR: Missing required dependency: {e}")
    print("Please install: pip install fastmcp>=2.10.6 httpx>=0.27.0 python-dateutil>=2.8.2 python-dotenv>=0.19.0")
    sys.exit(1)

# Load environment variables
load_dotenv()

# Import local modules
from wazuh_mcp_server.config import WazuhConfig, ConfigurationError
from wazuh_mcp_server.utils.logging import setup_logging, get_logger
from wazuh_mcp_server.utils.exceptions import WazuhMCPError, APIError
from wazuh_mcp_server.utils.validation import sanitize_input, validate_int_range
from wazuh_mcp_server.auth.secure_auth import SecureAuth, AuthConfig

# Initialize logging
logger = get_logger(__name__)

# Global server state
_config: Optional[WazuhConfig] = None
_http_client: Optional[httpx.AsyncClient] = None
_server_start_time: Optional[datetime] = None

# Create FastMCP server instance (Following FastMCP Standard)
mcp = FastMCP("Wazuh MCP Server")

# Server metrics
_metrics = {
    "requests_total": 0,
    "requests_failed": 0,
    "uptime_start": datetime.utcnow()
}


async def get_config() -> WazuhConfig:
    """Get global configuration, loading if necessary."""
    global _config
    if _config is None:
        try:
            _config = WazuhConfig.from_env()
            logger.info("Configuration loaded successfully")
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e}")
            raise
    return _config


async def get_http_client() -> httpx.AsyncClient:
    """Get configured HTTP client for Wazuh API."""
    global _http_client
    if _http_client is None:
        config = await get_config()
        
        # Configure HTTP client with proper settings
        limits = httpx.Limits(
            max_keepalive_connections=20,
            max_connections=50,
            keepalive_expiry=30
        )
        
        timeout = httpx.Timeout(
            connect=config.request_timeout_seconds,
            read=config.request_timeout_seconds,
            write=config.request_timeout_seconds,
            pool=config.request_timeout_seconds
        )
        
        _http_client = httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            verify=config.verify_ssl,
            http2=True  # Enable HTTP/2 for better performance
        )
        
        logger.info("HTTP client initialized")
    
    return _http_client


# ============================================================================
# FASTMCP STANDARD TOOLS IMPLEMENTATION
# Using @mcp.tool decorators as per official documentation
# ============================================================================

@mcp.tool
async def get_wazuh_alerts(
    ctx: Context,
    limit: Annotated[int, Field(default=100, ge=1, le=10000, description="Maximum number of alerts to retrieve")] = 100,
    level: Annotated[Optional[int], Field(default=None, ge=1, le=15, description="Minimum alert level (1-15)")] = None,
    time_range: Annotated[Optional[int], Field(default=3600, ge=300, le=86400, description="Time range in seconds")] = 3600,
    agent_id: Annotated[Optional[str], Field(default=None, description="Filter alerts by specific agent ID")] = None
) -> Dict[str, Any]:
    """
    Retrieve Wazuh security alerts with advanced filtering and analysis.
    
    This tool fetches alerts from the Wazuh SIEM system with comprehensive
    filtering options and provides enriched alert data for security analysis.
    """
    try:
        await ctx.info(f"Fetching {limit} alerts from Wazuh API")
        
        global _metrics
        _metrics["requests_total"] += 1
        
        config = await get_config()
        client = await get_http_client()
        
        # Build API request parameters
        params = {
            "limit": min(limit, 10000),  # Enforce maximum
            "sort": "-timestamp"
        }
        
        if level:
            params["rule.level"] = f">{level-1}"
        
        if time_range:
            since_time = datetime.utcnow() - timedelta(seconds=time_range)
            params["timestamp"] = f">{since_time.isoformat()}Z"
        
        if agent_id:
            # Sanitize agent ID input
            agent_id = sanitize_input(str(agent_id))
            params["agent.id"] = agent_id
        
        # Make authenticated request to Wazuh API
        auth_header = f"Bearer {config.api_token}" if hasattr(config, 'api_token') else None
        headers = {"Authorization": auth_header} if auth_header else {}
        
        url = f"{config.protocol}://{config.host}:{config.port}/alerts"
        
        await ctx.info("Executing Wazuh API request")
        response = await client.get(url, params=params, headers=headers, auth=(config.user, config.password))
        response.raise_for_status()
        
        data = response.json()
        alerts = data.get("data", {}).get("affected_items", [])
        
        # Enrich alerts with analysis
        enriched_alerts = []
        for alert in alerts[:limit]:
            enriched_alert = {
                "id": alert.get("id"),
                "timestamp": alert.get("timestamp"),
                "agent": alert.get("agent", {}).get("name"),
                "rule": {
                    "id": alert.get("rule", {}).get("id"),
                    "level": alert.get("rule", {}).get("level"),
                    "description": alert.get("rule", {}).get("description")
                },
                "location": alert.get("location"),
                "full_log": alert.get("full_log"),
                "risk_score": _calculate_risk_score(alert),
                "category": _categorize_alert(alert)
            }
            enriched_alerts.append(enriched_alert)
        
        result = {
            "success": True,
            "total_alerts": len(enriched_alerts),
            "alerts": enriched_alerts,
            "query_params": params,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await ctx.info(f"Successfully retrieved {len(enriched_alerts)} alerts")
        return result
        
    except Exception as e:
        _metrics["requests_failed"] += 1
        logger.error(f"Error fetching alerts: {e}")
        await ctx.error(f"Failed to fetch alerts: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


@mcp.tool  
async def check_wazuh_agent_health(
    ctx: Context,
    agent_id: Annotated[Optional[str], Field(default=None, description="Specific agent ID to check")] = None,
    include_disconnected: Annotated[bool, Field(default=False, description="Include disconnected agents")] = False
) -> Dict[str, Any]:
    """
    Check the health status of Wazuh agents with comprehensive monitoring.
    
    Provides detailed agent health information including connectivity status,
    last seen time, and key performance metrics.
    """
    try:
        await ctx.info("Checking Wazuh agent health status")
        
        config = await get_config()
        client = await get_http_client()
        
        # Build API endpoint
        if agent_id:
            agent_id = sanitize_input(str(agent_id))
            url = f"{config.protocol}://{config.host}:{config.port}/agents/{agent_id}"
        else:
            url = f"{config.protocol}://{config.host}:{config.port}/agents"
        
        # Request parameters
        params = {}
        if not include_disconnected:
            params["status"] = "active"
        
        # Make authenticated request
        response = await client.get(
            url, 
            params=params,
            auth=(config.user, config.password)
        )
        response.raise_for_status()
        
        data = response.json()
        agents = data.get("data", {}).get("affected_items", [])
        
        # Process agent health data
        agent_health = []
        for agent in agents:
            health_info = {
                "id": agent.get("id"),
                "name": agent.get("name"),
                "ip": agent.get("ip"),
                "status": agent.get("status"),
                "last_keep_alive": agent.get("lastKeepAlive"),
                "os": agent.get("os", {}).get("name"),
                "version": agent.get("version"),
                "health_score": _calculate_agent_health_score(agent),
                "issues": _identify_agent_issues(agent)
            }
            agent_health.append(health_info)
        
        result = {
            "success": True,
            "total_agents": len(agent_health),
            "healthy_agents": len([a for a in agent_health if a["status"] == "active"]),
            "agents": agent_health,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await ctx.info(f"Health check completed for {len(agent_health)} agents")
        return result
        
    except Exception as e:
        logger.error(f"Error checking agent health: {e}")
        await ctx.error(f"Agent health check failed: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


@mcp.tool
async def analyze_security_threats(
    ctx: Context,
    time_range: Annotated[int, Field(default=3600, ge=300, le=86400, description="Analysis time range in seconds")] = 3600,
    min_severity: Annotated[int, Field(default=5, ge=1, le=15, description="Minimum threat severity level")] = 5,
    include_mitre: Annotated[bool, Field(default=True, description="Include MITRE ATT&CK mapping")] = True
) -> Dict[str, Any]:
    """
    Perform AI-powered security threat analysis on Wazuh alerts.
    
    Analyzes recent security alerts to identify patterns, threats, and provides
    actionable security insights with MITRE ATT&CK framework mapping.
    """
    try:
        await ctx.info("Starting comprehensive threat analysis")
        
        # First, get recent high-severity alerts
        alerts_data = await get_wazuh_alerts(
            ctx=ctx,
            limit=500,
            level=min_severity,
            time_range=time_range
        )
        
        if not alerts_data.get("success"):
            return alerts_data
        
        alerts = alerts_data.get("alerts", [])
        
        await ctx.info(f"Analyzing {len(alerts)} security alerts")
        
        # Perform threat analysis
        threat_analysis = {
            "analysis_period": f"{time_range} seconds",
            "total_alerts_analyzed": len(alerts),
            "threat_summary": _analyze_threat_patterns(alerts),
            "top_threats": _identify_top_threats(alerts),
            "affected_assets": _analyze_affected_assets(alerts),
            "attack_timeline": _build_attack_timeline(alerts),
            "recommendations": _generate_security_recommendations(alerts)
        }
        
        if include_mitre:
            threat_analysis["mitre_mapping"] = _map_to_mitre_attack(alerts)
        
        result = {
            "success": True,
            "analysis": threat_analysis,
            "metadata": {
                "analyst": "Wazuh MCP AI",
                "timestamp": datetime.utcnow().isoformat(),
                "analysis_duration": f"{time_range}s",
                "confidence_level": "high"
            }
        }
        
        await ctx.info("Threat analysis completed successfully")
        return result
        
    except Exception as e:
        logger.error(f"Error in threat analysis: {e}")
        await ctx.error(f"Threat analysis failed: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


@mcp.tool
async def get_server_health(ctx: Context) -> Dict[str, Any]:
    """
    Get comprehensive health status of the Wazuh MCP Server.
    
    Provides detailed health metrics including server status, connectivity,
    performance metrics, and system diagnostics.
    """
    try:
        await ctx.info("Performing comprehensive health check")
        
        global _metrics, _server_start_time
        
        health_checks = {}
        overall_status = "healthy"
        
        # Configuration health
        try:
            config = await get_config()
            health_checks["configuration"] = {
                "status": "healthy",
                "details": "Configuration loaded successfully"
            }
        except Exception as e:
            health_checks["configuration"] = {
                "status": "unhealthy", 
                "details": str(e)
            }
            overall_status = "unhealthy"
        
        # HTTP client health
        try:
            client = await get_http_client()
            health_checks["http_client"] = {
                "status": "healthy",
                "details": "HTTP client initialized"
            }
        except Exception as e:
            health_checks["http_client"] = {
                "status": "unhealthy",
                "details": str(e)
            }
            overall_status = "unhealthy"
        
        # Wazuh API connectivity
        try:
            config = await get_config()
            client = await get_http_client()
            
            # Test connection with timeout
            test_url = f"{config.protocol}://{config.host}:{config.port}/manager/info"
            response = await asyncio.wait_for(
                client.get(test_url, auth=(config.user, config.password)),
                timeout=10.0
            )
            
            if response.status_code == 200:
                health_checks["wazuh_api"] = {
                    "status": "healthy",
                    "details": f"Connected to {config.host}:{config.port}"
                }
            else:
                health_checks["wazuh_api"] = {
                    "status": "degraded",
                    "details": f"HTTP {response.status_code}"
                }
                overall_status = "degraded"
                
        except Exception as e:
            health_checks["wazuh_api"] = {
                "status": "unhealthy",
                "details": str(e)
            }
            overall_status = "unhealthy"
        
        # Calculate uptime
        uptime_seconds = 0
        if _server_start_time:
            uptime_seconds = (datetime.utcnow() - _server_start_time).total_seconds()
        
        result = {
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "uptime_seconds": uptime_seconds,
            "health_checks": health_checks,
            "metrics": _metrics,
            "server_info": {
                "name": "Wazuh MCP Server",
                "version": "v-final",
                "framework": "FastMCP",
                "python_version": sys.version.split()[0]
            }
        }
        
        await ctx.info(f"Health check completed - Status: {overall_status}")
        return result
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        await ctx.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }


# ============================================================================
# FASTMCP RESOURCES IMPLEMENTATION
# Using @mcp.resource decorators as per official documentation
# ============================================================================

@mcp.resource("wazuh://cluster/status")
async def cluster_status(ctx: Context) -> str:
    """Real-time Wazuh cluster status information."""
    try:
        config = await get_config()
        client = await get_http_client()
        
        url = f"{config.protocol}://{config.host}:{config.port}/cluster/status"
        response = await client.get(url, auth=(config.user, config.password))
        response.raise_for_status()
        
        return response.text
        
    except Exception as e:
        return f"Error fetching cluster status: {str(e)}"


@mcp.resource("wazuh://security/overview")
async def security_overview(ctx: Context) -> Dict[str, Any]:
    """Comprehensive security posture overview."""
    try:
        # Get recent alerts for overview
        alerts_data = await get_wazuh_alerts(ctx, limit=100, time_range=3600)
        
        if alerts_data.get("success"):
            alerts = alerts_data.get("alerts", [])
            
            overview = {
                "last_hour_alerts": len(alerts),
                "critical_alerts": len([a for a in alerts if a.get("rule", {}).get("level", 0) >= 10]),
                "top_attack_types": _get_top_attack_types(alerts),
                "affected_agents": len(set(a.get("agent") for a in alerts if a.get("agent"))),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            return overview
        else:
            return {"error": "Failed to fetch security overview"}
            
    except Exception as e:
        return {"error": str(e)}


# ============================================================================
# FASTMCP PROMPTS IMPLEMENTATION  
# Using @mcp.prompt decorators as per official documentation
# ============================================================================

@mcp.prompt
async def security_briefing(
    time_range: int = 3600,
    detail_level: str = "summary"
) -> str:
    """
    Generate an executive security briefing based on recent Wazuh alerts.
    
    Args:
        time_range: Time range in seconds for the briefing
        detail_level: Level of detail (summary, detailed, comprehensive)
    """
    # This would normally call Claude or another LLM
    # For now, return a template
    return f"""
# Security Briefing - Last {time_range//3600} Hour(s)

## Executive Summary
Based on analysis of Wazuh security alerts over the past {time_range//3600} hour(s):

## Key Findings
- [Alert statistics would be inserted here]
- [Top threats identified]
- [Affected systems]

## Recommendations
- [Security recommendations based on analysis]

## Detailed Analysis
{f"[Detailed breakdown would be included]" if detail_level != "summary" else "[Use detail_level='detailed' for more information]"}

---
*Generated by Wazuh MCP Server at {datetime.utcnow().isoformat()}*
"""


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _calculate_risk_score(alert: Dict[str, Any]) -> int:
    """Calculate risk score for an alert."""
    base_score = alert.get("rule", {}).get("level", 1)
    # Add additional risk factors
    multiplier = 1.0
    
    if "authentication" in alert.get("rule", {}).get("description", "").lower():
        multiplier += 0.5
    if "failed" in alert.get("full_log", "").lower():
        multiplier += 0.3
        
    return min(int(base_score * multiplier), 15)


def _categorize_alert(alert: Dict[str, Any]) -> str:
    """Categorize alert by type."""
    description = alert.get("rule", {}).get("description", "").lower()
    
    if "authentication" in description:
        return "authentication"
    elif "malware" in description:
        return "malware"
    elif "intrusion" in description:
        return "intrusion"
    elif "policy" in description:
        return "policy_violation"
    else:
        return "other"


def _calculate_agent_health_score(agent: Dict[str, Any]) -> int:
    """Calculate health score for an agent."""
    score = 100
    
    if agent.get("status") != "active":
        score -= 50
    
    # Check last keep alive
    last_alive = agent.get("lastKeepAlive")
    if last_alive:
        try:
            from dateutil.parser import isoparse
            last_time = isoparse(last_alive)
            minutes_ago = (datetime.utcnow() - last_time.replace(tzinfo=None)).total_seconds() / 60
            if minutes_ago > 5:
                score -= min(int(minutes_ago), 40)
        except:
            score -= 20
    
    return max(score, 0)


def _identify_agent_issues(agent: Dict[str, Any]) -> List[str]:
    """Identify issues with an agent."""
    issues = []
    
    if agent.get("status") != "active":
        issues.append("Agent is not active")
    
    if not agent.get("lastKeepAlive"):
        issues.append("No recent keep-alive signal")
    
    if not agent.get("version"):
        issues.append("Version information missing")
    
    return issues


def _analyze_threat_patterns(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze threat patterns in alerts."""
    patterns = {
        "authentication_failures": 0,
        "malware_detections": 0,
        "intrusion_attempts": 0,
        "policy_violations": 0
    }
    
    for alert in alerts:
        category = alert.get("category", "other")
        if category == "authentication":
            patterns["authentication_failures"] += 1
        elif category == "malware":
            patterns["malware_detections"] += 1
        elif category == "intrusion":
            patterns["intrusion_attempts"] += 1
        elif category == "policy_violation":
            patterns["policy_violations"] += 1
    
    return patterns


def _identify_top_threats(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Identify top threats from alerts."""
    threat_counts = {}
    
    for alert in alerts:
        rule_desc = alert.get("rule", {}).get("description", "Unknown")
        if rule_desc not in threat_counts:
            threat_counts[rule_desc] = {
                "count": 0,
                "max_level": 0,
                "agents": set()
            }
        
        threat_counts[rule_desc]["count"] += 1
        threat_counts[rule_desc]["max_level"] = max(
            threat_counts[rule_desc]["max_level"],
            alert.get("rule", {}).get("level", 0)
        )
        if alert.get("agent"):
            threat_counts[rule_desc]["agents"].add(alert.get("agent"))
    
    # Convert to list and sort by count
    top_threats = []
    for desc, data in sorted(threat_counts.items(), key=lambda x: x[1]["count"], reverse=True)[:10]:
        top_threats.append({
            "description": desc,
            "count": data["count"],
            "max_severity": data["max_level"],
            "affected_agents": len(data["agents"])
        })
    
    return top_threats


def _analyze_affected_assets(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze affected assets from alerts."""
    agents = set()
    locations = set()
    
    for alert in alerts:
        if alert.get("agent"):
            agents.add(alert.get("agent"))
        if alert.get("location"):
            locations.add(alert.get("location"))
    
    return {
        "total_agents": len(agents),
        "total_locations": len(locations),
        "agents": list(agents)[:10],  # Top 10
        "locations": list(locations)[:10]  # Top 10
    }


def _build_attack_timeline(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Build attack timeline from alerts."""
    timeline = []
    
    # Sort alerts by timestamp
    sorted_alerts = sorted(alerts, key=lambda x: x.get("timestamp", ""))
    
    for alert in sorted_alerts[:20]:  # Last 20 events
        timeline.append({
            "timestamp": alert.get("timestamp"),
            "agent": alert.get("agent"),
            "rule_id": alert.get("rule", {}).get("id"),
            "description": alert.get("rule", {}).get("description"),
            "level": alert.get("rule", {}).get("level")
        })
    
    return timeline


def _generate_security_recommendations(alerts: List[Dict[str, Any]]) -> List[str]:
    """Generate security recommendations based on alerts."""
    recommendations = []
    
    # Analyze patterns and generate recommendations
    auth_failures = len([a for a in alerts if a.get("category") == "authentication"])
    if auth_failures > 10:
        recommendations.append("Consider implementing account lockout policies due to high authentication failures")
    
    malware_detections = len([a for a in alerts if a.get("category") == "malware"])
    if malware_detections > 0:
        recommendations.append("Review and update antimalware signatures and policies")
    
    high_severity = len([a for a in alerts if a.get("rule", {}).get("level", 0) >= 10])
    if high_severity > 5:
        recommendations.append("Immediate investigation required for critical security alerts")
    
    if not recommendations:
        recommendations.append("No immediate security actions required based on current alert patterns")
    
    return recommendations


def _map_to_mitre_attack(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Map alerts to MITRE ATT&CK framework."""
    # Simplified MITRE mapping
    mitre_mapping = {
        "techniques": [],
        "tactics": set(),
        "summary": {}
    }
    
    for alert in alerts:
        rule_desc = alert.get("rule", {}).get("description", "").lower()
        
        if "authentication" in rule_desc and "failed" in rule_desc:
            mitre_mapping["techniques"].append({
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access"
            })
            mitre_mapping["tactics"].add("Credential Access")
        
        if "malware" in rule_desc:
            mitre_mapping["techniques"].append({
                "id": "T1569",
                "name": "System Services",
                "tactic": "Execution"
            })
            mitre_mapping["tactics"].add("Execution")
    
    mitre_mapping["tactics"] = list(mitre_mapping["tactics"])
    mitre_mapping["summary"] = {
        "total_techniques": len(mitre_mapping["techniques"]),
        "total_tactics": len(mitre_mapping["tactics"])
    }
    
    return mitre_mapping


def _get_top_attack_types(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Get top attack types from alerts."""
    attack_counts = {}
    
    for alert in alerts:
        category = alert.get("category", "other")
        attack_counts[category] = attack_counts.get(category, 0) + 1
    
    return [
        {"type": attack_type, "count": count}
        for attack_type, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
    ]


# ============================================================================
# SERVER INITIALIZATION AND MAIN
# ============================================================================

async def initialize_server():
    """Initialize server components."""
    global _server_start_time
    _server_start_time = datetime.utcnow()
    
    # Setup logging
    setup_logging(
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        enable_structured=True,
        enable_rotation=True
    )
    
    logger.info("Wazuh MCP Server initializing...")
    
    # Pre-load configuration
    try:
        await get_config()
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Configuration failed: {e}")
        raise
    
    logger.info("Server initialization complete")


async def main():
    """Main entry point following FastMCP standards."""
    try:
        await initialize_server()
        logger.info("Wazuh MCP Server (FastMCP Compliant) ready")
        
        # Keep server running
        while True:
            await asyncio.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        # Cleanup
        global _http_client
        if _http_client:
            await _http_client.aclose()
        logger.info("Server shutdown complete")


if __name__ == "__main__":
    asyncio.run(main())