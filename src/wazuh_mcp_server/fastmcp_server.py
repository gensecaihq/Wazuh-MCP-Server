#!/usr/bin/env python3
"""
FastMCP-Compliant Wazuh MCP Server
Strictly follows official FastMCP documentation standards from gofastmcp.com
"""

import os
import sys
import asyncio
import json
from typing import Dict, List, Any, Optional, Annotated
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Check Python version before any imports
if sys.version_info < (3, 10):
    print(f"ERROR: FastMCP requires Python 3.10+. Current: {sys.version}")
    sys.exit(1)

# Import FastMCP with proper error handling
try:
    from fastmcp import FastMCP, Context
    from fastmcp.server.auth import BearerAuthProvider
    import httpx
    from pydantic import Field
    from dotenv import load_dotenv
except ImportError as e:
    print(f"CRITICAL ERROR: Missing required FastMCP dependency: {e}")
    print("Please install: pip install fastmcp>=2.11.0 httpx>=0.28.0 python-dotenv>=1.0.0")
    sys.exit(1)

# Load environment variables
load_dotenv()

# Import local modules
from wazuh_mcp_server.config import WazuhConfig, ConfigurationError
from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.api.wazuh_indexer_client import WazuhIndexerClient

# ============================================================================
# DATACLASSES FOR ELICITATION (Following FastMCP Standards)
# ============================================================================

@dataclass
class ThreatAnalysisConfig:
    """Configuration for threat analysis elicitation."""
    severity_threshold: int
    include_compliance: bool
    time_range_hours: int
    include_external_intel: bool

@dataclass
class AgentDeploymentConfig:
    """Configuration for agent deployment elicitation."""
    target_os: str
    deployment_method: str
    enable_monitoring: bool
    custom_rules: bool

# ============================================================================
# GLOBAL STATE MANAGEMENT
# ============================================================================

_config: Optional[WazuhConfig] = None
_wazuh_client: Optional[WazuhClient] = None
_indexer_client: Optional[WazuhIndexerClient] = None
_server_start_time: Optional[datetime] = None

async def get_config() -> WazuhConfig:
    """Get global configuration, loading if necessary."""
    global _config
    if _config is None:
        try:
            _config = WazuhConfig.from_env()
        except ConfigurationError as e:
            raise ValueError(f"Configuration error: {e}")
    return _config

async def get_wazuh_client() -> WazuhClient:
    """Get configured Wazuh API client."""
    global _wazuh_client
    if _wazuh_client is None:
        config = await get_config()
        _wazuh_client = WazuhClient(config)
        await _wazuh_client.initialize()
    return _wazuh_client

async def get_indexer_client() -> Optional[WazuhIndexerClient]:
    """Get configured Wazuh Indexer client if available."""
    global _indexer_client
    if _indexer_client is None:
        config = await get_config()
        if config.wazuh_indexer_host:
            _indexer_client = WazuhIndexerClient(config)
            await _indexer_client.initialize()
    return _indexer_client

# ============================================================================
# FASTMCP SERVER CONFIGURATION (Following Official Standards)
# ============================================================================

# Initialize authentication if configured
auth_provider = None
if os.getenv("ENABLE_BEARER_AUTH", "false").lower() == "true":
    jwks_uri = os.getenv("JWKS_URI")
    issuer = os.getenv("JWT_ISSUER")
    audience = os.getenv("JWT_AUDIENCE")
    
    if jwks_uri and issuer and audience:
        auth_provider = BearerAuthProvider(
            jwks_uri=jwks_uri,
            issuer=issuer,
            audience=audience,
            algorithm=os.getenv("JWT_ALGORITHM", "RS256"),
            required_scopes=os.getenv("REQUIRED_SCOPES", "").split(",") if os.getenv("REQUIRED_SCOPES") else None
        )

# Create FastMCP server instance (Following Official FastMCP Standards)
mcp = FastMCP(
    name="Wazuh MCP Server",
    version="2.0.0",
    description="Production-grade FastMCP server for Wazuh SIEM integration with AI-enhanced security operations",
    auth=auth_provider
)

# ============================================================================
# TOOLS IMPLEMENTATION (Following @mcp.tool Standards)
# ============================================================================

@mcp.tool
async def get_wazuh_alerts(
    limit: Annotated[int, Field(description="Maximum number of alerts to retrieve", ge=1, le=10000)] = 100,
    level: Annotated[Optional[int], Field(description="Minimum alert level (1-15)", ge=1, le=15)] = None,
    time_range: Annotated[Optional[int], Field(description="Time range in seconds", ge=300, le=86400)] = None,
    agent_id: Annotated[Optional[str], Field(description="Filter alerts by specific agent ID")] = None,
    ctx: Context = None
) -> dict:
    """Retrieve Wazuh security alerts with advanced filtering and AI analysis.
    
    This tool provides comprehensive access to Wazuh security alerts with intelligent
    filtering, severity analysis, and contextual threat assessment.
    """
    if ctx:
        await ctx.info(f"Retrieving up to {limit} Wazuh alerts")
        await ctx.report_progress(progress=10, total=100)
    
    try:
        client = await get_wazuh_client()
        
        # Build query parameters
        params = {"limit": limit}
        if level:
            params["level"] = level
        if time_range:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(seconds=time_range)
            params["timestamp"] = f"{start_time.isoformat()}..{end_time.isoformat()}"
        if agent_id:
            params["agent.id"] = agent_id
        
        if ctx:
            await ctx.report_progress(progress=50, total=100)
        
        # Fetch alerts from Wazuh
        response = await client.get_alerts(**params)
        
        if ctx:
            await ctx.report_progress(progress=80, total=100)
        
        # Process and analyze alerts
        alerts = response.get("data", {}).get("affected_items", [])
        
        # Add AI-powered analysis
        analysis = {
            "total_alerts": len(alerts),
            "severity_breakdown": _analyze_alert_severity(alerts),
            "top_rules": _get_top_alert_rules(alerts),
            "agent_distribution": _analyze_agent_distribution(alerts),
            "time_analysis": _analyze_temporal_patterns(alerts)
        }
        
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            await ctx.info(f"Successfully retrieved {len(alerts)} alerts")
        
        return {
            "alerts": alerts,
            "analysis": analysis,
            "metadata": {
                "query_time": datetime.utcnow().isoformat(),
                "parameters": params,
                "total_found": response.get("data", {}).get("total_affected_items", 0)
            }
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to retrieve alerts: {e}")
        raise ValueError(f"Failed to retrieve Wazuh alerts: {e}")

@mcp.tool
async def analyze_security_threats(
    time_range_hours: Annotated[int, Field(description="Analysis time range in hours", ge=1, le=168)] = 24,
    severity_threshold: Annotated[int, Field(description="Minimum severity level", ge=1, le=15)] = 5,
    include_compliance: Annotated[bool, Field(description="Include compliance analysis")] = True,
    ctx: Context = None
) -> dict:
    """Perform comprehensive AI-powered security threat analysis.
    
    Analyzes security alerts, patterns, and trends to provide actionable threat intelligence
    with compliance mapping and risk assessment.
    """
    if ctx:
        await ctx.info("Starting comprehensive security threat analysis")
        await ctx.report_progress(progress=0, total=100)
    
    try:
        client = await get_wazuh_client()
        
        # Fetch recent high-severity alerts
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        if ctx:
            await ctx.report_progress(progress=20, total=100)
        
        alerts_response = await client.get_alerts(
            timestamp=f"{start_time.isoformat()}..{end_time.isoformat()}",
            level=severity_threshold,
            limit=1000
        )
        
        alerts = alerts_response.get("data", {}).get("affected_items", [])
        
        if ctx:
            await ctx.report_progress(progress=40, total=100)
        
        # Perform threat analysis
        threat_analysis = {
            "summary": {
                "total_threats": len(alerts),
                "analysis_period": f"{time_range_hours} hours",
                "severity_threshold": severity_threshold,
                "highest_severity": max([alert.get("rule", {}).get("level", 0) for alert in alerts]) if alerts else 0
            },
            "threat_categories": _categorize_threats(alerts),
            "attack_patterns": _identify_attack_patterns(alerts),
            "affected_assets": _analyze_affected_assets(alerts),
            "risk_assessment": _calculate_risk_score(alerts)
        }
        
        if ctx:
            await ctx.report_progress(progress=70, total=100)
        
        # Add compliance analysis if requested
        if include_compliance:
            threat_analysis["compliance"] = await _analyze_compliance_impact(alerts, ctx)
        
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            await ctx.info(f"Threat analysis complete: {threat_analysis['summary']['total_threats']} threats analyzed")
        
        return threat_analysis
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Threat analysis failed: {e}")
        raise ValueError(f"Security threat analysis failed: {e}")

@mcp.tool
async def get_agent_status(
    agent_id: Annotated[Optional[str], Field(description="Specific agent ID to check")] = None,
    include_health_metrics: Annotated[bool, Field(description="Include detailed health metrics")] = True,
    ctx: Context = None
) -> dict:
    """Get comprehensive Wazuh agent status and health information.
    
    Provides detailed agent status, health metrics, configuration status,
    and performance indicators for monitoring and troubleshooting.
    """
    if ctx:
        await ctx.info("Retrieving agent status information")
        await ctx.report_progress(progress=0, total=100)
    
    try:
        client = await get_wazuh_client()
        
        if agent_id:
            # Get specific agent
            if ctx:
                await ctx.info(f"Getting status for agent {agent_id}")
            
            agent_response = await client.get_agent(agent_id)
            agents = [agent_response.get("data", {})]
        else:
            # Get all agents
            if ctx:
                await ctx.info("Getting status for all agents")
            
            agents_response = await client.get_agents()
            agents = agents_response.get("data", {}).get("affected_items", [])
        
        if ctx:
            await ctx.report_progress(progress=50, total=100)
        
        # Process agent information
        agent_status = {
            "total_agents": len(agents),
            "agents": [],
            "summary": {
                "active": 0,
                "disconnected": 0,
                "never_connected": 0,
                "pending": 0
            }
        }
        
        for agent in agents:
            status = agent.get("status", "unknown")
            agent_status["summary"][status] = agent_status["summary"].get(status, 0) + 1
            
            agent_info = {
                "id": agent.get("id"),
                "name": agent.get("name"),
                "ip": agent.get("ip"),
                "status": status,
                "os": agent.get("os", {}),
                "version": agent.get("version"),
                "last_keep_alive": agent.get("lastKeepAlive"),
                "registration_date": agent.get("dateAdd")
            }
            
            # Add health metrics if requested
            if include_health_metrics and status == "active":
                try:
                    health_data = await _get_agent_health_metrics(client, agent.get("id"), ctx)
                    agent_info["health_metrics"] = health_data
                except Exception as e:
                    if ctx:
                        await ctx.warning(f"Could not get health metrics for agent {agent.get('id')}: {e}")
            
            agent_status["agents"].append(agent_info)
        
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            await ctx.info(f"Retrieved status for {len(agents)} agents")
        
        return agent_status
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to get agent status: {e}")
        raise ValueError(f"Failed to retrieve agent status: {e}")

@mcp.tool
async def get_vulnerability_summary(
    agent_id: Annotated[Optional[str], Field(description="Filter by specific agent ID")] = None,
    severity: Annotated[Optional[str], Field(description="Filter by severity (Low, Medium, High, Critical)")] = None,
    limit: Annotated[int, Field(description="Maximum number of vulnerabilities", ge=1, le=5000)] = 500,
    ctx: Context = None
) -> dict:
    """Get comprehensive vulnerability assessment summary.
    
    Provides detailed vulnerability information, risk assessment, and remediation
    guidance with CVSS scoring and compliance mapping.
    """
    if ctx:
        await ctx.info("Generating vulnerability assessment summary")
        await ctx.report_progress(progress=0, total=100)
    
    try:
        client = await get_wazuh_client()
        indexer = await get_indexer_client()
        
        # Build query parameters
        params = {"limit": limit}
        if agent_id:
            params["agent.id"] = agent_id
        if severity:
            params["vulnerability.severity"] = severity.lower()
        
        if ctx:
            await ctx.report_progress(progress=30, total=100)
        
        # Get vulnerabilities from appropriate source
        if indexer and os.getenv("USE_INDEXER_FOR_VULNERABILITIES", "true").lower() == "true":
            vulnerabilities_data = await indexer.get_vulnerabilities(**params)
        else:
            vulnerabilities_data = await client.get_vulnerabilities(**params)
        
        vulnerabilities = vulnerabilities_data.get("data", {}).get("affected_items", [])
        
        if ctx:
            await ctx.report_progress(progress=70, total=100)
        
        # Analyze vulnerabilities
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": _analyze_vulnerability_severity(vulnerabilities),
            "top_cves": _get_top_cves(vulnerabilities),
            "affected_packages": _analyze_affected_packages(vulnerabilities),
            "risk_score": _calculate_vulnerability_risk(vulnerabilities),
            "remediation_priority": _prioritize_remediation(vulnerabilities)
        }
        
        # Add detailed vulnerability list
        summary["vulnerabilities"] = vulnerabilities[:50]  # Limit detailed list
        
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            await ctx.info(f"Vulnerability assessment complete: {len(vulnerabilities)} vulnerabilities found")
        
        return summary
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Vulnerability assessment failed: {e}")
        raise ValueError(f"Failed to get vulnerability summary: {e}")

@mcp.tool
async def interactive_threat_hunt(ctx: Context) -> dict:
    """Interactive threat hunting with user elicitation for parameters.
    
    Guides users through a comprehensive threat hunting process by collecting
    requirements and preferences through interactive prompts.
    """
    await ctx.info("Starting interactive threat hunting session")
    
    try:
        # Elicit threat hunting configuration from user
        config_result = await ctx.elicit(
            message="Configure your threat hunting parameters:",
            response_type=ThreatAnalysisConfig
        )
        
        if config_result.action == "decline":
            return {"status": "declined", "message": "User declined to provide threat hunting parameters"}
        
        if config_result.action == "cancel":
            return {"status": "cancelled", "message": "Threat hunting session cancelled by user"}
        
        config = config_result.data
        await ctx.info(f"Starting threat hunt with {config.time_range_hours}h range, severity >= {config.severity_threshold}")
        
        # Perform threat hunting based on user configuration
        hunt_results = await analyze_security_threats(
            time_range_hours=config.time_range_hours,
            severity_threshold=config.severity_threshold,
            include_compliance=config.include_compliance,
            ctx=ctx
        )
        
        # Add external threat intelligence if requested
        if config.include_external_intel:
            await ctx.info("Enriching with external threat intelligence")
            hunt_results["threat_intelligence"] = await _enrich_with_external_intel(hunt_results, ctx)
        
        return {
            "status": "completed",
            "configuration": config.__dict__,
            "results": hunt_results
        }
        
    except Exception as e:
        await ctx.error(f"Interactive threat hunt failed: {e}")
        raise ValueError(f"Threat hunting session failed: {e}")

# ============================================================================
# RESOURCES IMPLEMENTATION (Following @mcp.resource Standards)
# ============================================================================

@mcp.resource("wazuh://cluster/status")
async def get_cluster_status() -> dict:
    """Get comprehensive Wazuh cluster status and health information."""
    try:
        client = await get_wazuh_client()
        cluster_info = await client.get_cluster_status()
        
        return {
            "cluster_enabled": cluster_info.get("data", {}).get("enabled", False),
            "cluster_status": cluster_info.get("data", {}).get("running", "unknown"),
            "nodes": cluster_info.get("data", {}).get("nodes", []),
            "last_updated": datetime.utcnow().isoformat()
        }
    except Exception as e:
        raise ValueError(f"Failed to get cluster status: {e}")

@mcp.resource("wazuh://dashboard/security/{time_range}")
async def get_security_dashboard(time_range: str) -> dict:
    """Get security dashboard data for specified time range.
    
    Args:
        time_range: Time range (1h, 24h, 7d, 30d)
    """
    try:
        # Parse time range
        time_mapping = {
            "1h": 1,
            "24h": 24,
            "7d": 168,
            "30d": 720
        }
        
        hours = time_mapping.get(time_range, 24)
        
        # Get alerts for dashboard
        alerts = await get_wazuh_alerts(
            limit=1000,
            time_range=hours * 3600,
            level=3
        )
        
        # Build dashboard data
        dashboard = {
            "time_range": time_range,
            "summary": alerts["analysis"],
            "recent_alerts": alerts["alerts"][:10],
            "generated_at": datetime.utcnow().isoformat()
        }
        
        return dashboard
        
    except Exception as e:
        raise ValueError(f"Failed to get security dashboard: {e}")

@mcp.resource("wazuh://agents/{agent_id}/details")
async def get_agent_details(agent_id: str) -> dict:
    """Get detailed information for a specific agent."""
    try:
        client = await get_wazuh_client()
        agent_data = await client.get_agent(agent_id)
        
        # Enrich with additional data
        agent_info = agent_data.get("data", {})
        
        # Get agent configuration
        try:
            config_data = await client.get_agent_config(agent_id)
            agent_info["configuration"] = config_data.get("data", {})
        except:
            agent_info["configuration"] = "unavailable"
        
        return agent_info
        
    except Exception as e:
        raise ValueError(f"Failed to get agent details: {e}")

# ============================================================================
# PROMPTS IMPLEMENTATION (Following @mcp.prompt Standards)
# ============================================================================

@mcp.prompt
def security_analysis_prompt(
    alert_level: Annotated[int, Field(description="Minimum alert level for analysis", ge=1, le=15)] = 5,
    time_hours: Annotated[int, Field(description="Analysis time range in hours", ge=1, le=168)] = 24
) -> str:
    """Generate a comprehensive security analysis prompt for AI processing.
    
    Creates a structured prompt for analyzing Wazuh security data with specific
    parameters for alert level and time range.
    """
    return f"""
# Wazuh Security Analysis Request

## Analysis Parameters
- **Alert Level**: {alert_level} and above
- **Time Range**: Last {time_hours} hours
- **Analysis Type**: Comprehensive threat assessment

## Required Analysis
1. **Threat Categorization**: Classify security events by threat type
2. **Risk Assessment**: Calculate overall risk score and impact
3. **Attack Pattern Analysis**: Identify potential attack chains
4. **Remediation Recommendations**: Provide actionable security measures
5. **Compliance Impact**: Map findings to security frameworks

## Output Format
Please provide:
- Executive summary of findings
- Detailed threat breakdown
- Priority recommendations
- Compliance implications
- Suggested next steps

Use the Wazuh MCP Server tools to gather the necessary security data and provide comprehensive analysis.
"""

@mcp.prompt
def incident_response_prompt(
    incident_type: Annotated[str, Field(description="Type of security incident")] = "malware",
    severity: Annotated[str, Field(description="Incident severity level")] = "high"
) -> str:
    """Generate an incident response prompt for security events.
    
    Creates a structured prompt for incident response procedures based on
    incident type and severity level.
    """
    return f"""
# Security Incident Response Procedure

## Incident Details
- **Type**: {incident_type}
- **Severity**: {severity}
- **Response Level**: {"Immediate" if severity.lower() == "critical" else "Standard"}

## Response Checklist
1. **Containment**: Immediate isolation and containment steps
2. **Assessment**: Scope and impact evaluation
3. **Eradication**: Threat removal and system cleaning
4. **Recovery**: System restoration and monitoring
5. **Documentation**: Incident documentation and lessons learned

## Required Actions
- Use Wazuh tools to gather evidence
- Analyze affected systems and agents
- Document all findings and actions
- Implement containment measures
- Monitor for persistence or reoccurrence

Please use the Wazuh MCP Server to gather relevant security data and coordinate the incident response.
"""

# ============================================================================
# HELPER FUNCTIONS (Internal Implementation)
# ============================================================================

def _analyze_alert_severity(alerts: List[dict]) -> dict:
    """Analyze alert severity distribution."""
    severity_counts = {}
    for alert in alerts:
        level = alert.get("rule", {}).get("level", 0)
        if level >= 12:
            category = "Critical"
        elif level >= 8:
            category = "High"
        elif level >= 4:
            category = "Medium"
        else:
            category = "Low"
        
        severity_counts[category] = severity_counts.get(category, 0) + 1
    
    return severity_counts

def _get_top_alert_rules(alerts: List[dict]) -> List[dict]:
    """Get top triggered alert rules."""
    rule_counts = {}
    for alert in alerts:
        rule = alert.get("rule", {})
        rule_id = rule.get("id", "unknown")
        rule_desc = rule.get("description", "Unknown")
        
        if rule_id not in rule_counts:
            rule_counts[rule_id] = {
                "id": rule_id,
                "description": rule_desc,
                "count": 0,
                "level": rule.get("level", 0)
            }
        rule_counts[rule_id]["count"] += 1
    
    return sorted(rule_counts.values(), key=lambda x: x["count"], reverse=True)[:10]

def _analyze_agent_distribution(alerts: List[dict]) -> dict:
    """Analyze alert distribution across agents."""
    agent_counts = {}
    for alert in alerts:
        agent = alert.get("agent", {})
        agent_id = agent.get("id", "unknown")
        agent_name = agent.get("name", "Unknown")
        
        if agent_id not in agent_counts:
            agent_counts[agent_id] = {
                "id": agent_id,
                "name": agent_name,
                "count": 0
            }
        agent_counts[agent_id]["count"] += 1
    
    return sorted(agent_counts.values(), key=lambda x: x["count"], reverse=True)[:10]

def _analyze_temporal_patterns(alerts: List[dict]) -> dict:
    """Analyze temporal patterns in alerts."""
    hourly_counts = {}
    for alert in alerts:
        timestamp = alert.get("timestamp", "")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                hour = dt.hour
                hourly_counts[hour] = hourly_counts.get(hour, 0) + 1
            except:
                continue
    
    return {
        "hourly_distribution": hourly_counts,
        "peak_hour": max(hourly_counts, key=hourly_counts.get) if hourly_counts else None,
        "total_hours_active": len(hourly_counts)
    }

def _categorize_threats(alerts: List[dict]) -> dict:
    """Categorize threats based on alert patterns."""
    categories = {
        "malware": 0,
        "network_attacks": 0,
        "privilege_escalation": 0,
        "data_exfiltration": 0,
        "system_compromise": 0,
        "policy_violations": 0
    }
    
    for alert in alerts:
        rule_desc = alert.get("rule", {}).get("description", "").lower()
        
        if any(keyword in rule_desc for keyword in ["malware", "virus", "trojan", "rootkit"]):
            categories["malware"] += 1
        elif any(keyword in rule_desc for keyword in ["network", "scan", "brute", "dos"]):
            categories["network_attacks"] += 1
        elif any(keyword in rule_desc for keyword in ["privilege", "escalation", "sudo", "admin"]):
            categories["privilege_escalation"] += 1
        elif any(keyword in rule_desc for keyword in ["data", "exfil", "upload", "transfer"]):
            categories["data_exfiltration"] += 1
        elif any(keyword in rule_desc for keyword in ["compromise", "backdoor", "shell"]):
            categories["system_compromise"] += 1
        else:
            categories["policy_violations"] += 1
    
    return categories

def _identify_attack_patterns(alerts: List[dict]) -> List[dict]:
    """Identify potential attack patterns and chains."""
    patterns = []
    
    # Group alerts by agent and time
    agent_alerts = {}
    for alert in alerts:
        agent_id = alert.get("agent", {}).get("id", "unknown")
        if agent_id not in agent_alerts:
            agent_alerts[agent_id] = []
        agent_alerts[agent_id].append(alert)
    
    # Analyze patterns for each agent
    for agent_id, agent_alert_list in agent_alerts.items():
        if len(agent_alert_list) >= 3:  # Potential pattern
            patterns.append({
                "agent_id": agent_id,
                "agent_name": agent_alert_list[0].get("agent", {}).get("name", "Unknown"),
                "alert_count": len(agent_alert_list),
                "pattern_type": "Multiple alerts on single agent",
                "severity": "High" if len(agent_alert_list) >= 5 else "Medium",
                "time_span": _calculate_time_span(agent_alert_list)
            })
    
    return patterns[:10]  # Return top 10 patterns

def _analyze_affected_assets(alerts: List[dict]) -> dict:
    """Analyze affected assets and systems."""
    assets = {
        "total_agents": set(),
        "operating_systems": {},
        "ip_addresses": set(),
        "critical_assets": []
    }
    
    for alert in alerts:
        agent = alert.get("agent", {})
        assets["total_agents"].add(agent.get("id", "unknown"))
        assets["ip_addresses"].add(agent.get("ip", "unknown"))
        
        os_info = agent.get("os", {})
        os_name = os_info.get("name", "Unknown")
        assets["operating_systems"][os_name] = assets["operating_systems"].get(os_name, 0) + 1
        
        # Check for critical assets (high alert count)
        agent_id = agent.get("id")
        if agent_id and len([a for a in alerts if a.get("agent", {}).get("id") == agent_id]) >= 5:
            if agent_id not in [a["id"] for a in assets["critical_assets"]]:
                assets["critical_assets"].append({
                    "id": agent_id,
                    "name": agent.get("name", "Unknown"),
                    "ip": agent.get("ip", "Unknown"),
                    "alert_count": len([a for a in alerts if a.get("agent", {}).get("id") == agent_id])
                })
    
    return {
        "total_affected_agents": len(assets["total_agents"]),
        "operating_systems": assets["operating_systems"],
        "total_ip_addresses": len(assets["ip_addresses"]),
        "critical_assets": assets["critical_assets"]
    }

def _calculate_risk_score(alerts: List[dict]) -> dict:
    """Calculate overall risk score based on alerts."""
    if not alerts:
        return {"score": 0, "level": "Low", "factors": []}
    
    total_score = 0
    factors = []
    
    # Factor 1: Alert severity
    high_severity_count = len([a for a in alerts if a.get("rule", {}).get("level", 0) >= 10])
    if high_severity_count > 0:
        severity_score = min(high_severity_count * 10, 50)
        total_score += severity_score
        factors.append(f"High severity alerts: {high_severity_count}")
    
    # Factor 2: Affected assets
    unique_agents = len(set([a.get("agent", {}).get("id") for a in alerts]))
    if unique_agents > 1:
        asset_score = min(unique_agents * 5, 30)
        total_score += asset_score
        factors.append(f"Multiple affected assets: {unique_agents}")
    
    # Factor 3: Alert frequency
    if len(alerts) > 10:
        frequency_score = min(len(alerts), 20)
        total_score += frequency_score
        factors.append(f"High alert frequency: {len(alerts)}")
    
    # Determine risk level
    if total_score >= 80:
        level = "Critical"
    elif total_score >= 60:
        level = "High"
    elif total_score >= 30:
        level = "Medium"
    else:
        level = "Low"
    
    return {
        "score": total_score,
        "level": level,
        "factors": factors,
        "max_score": 100
    }

async def _analyze_compliance_impact(alerts: List[dict], ctx: Context = None) -> dict:
    """Analyze compliance impact of security alerts."""
    if ctx:
        await ctx.info("Analyzing compliance impact")
    
    compliance_frameworks = {
        "PCI_DSS": {"affected": False, "controls": []},
        "HIPAA": {"affected": False, "controls": []},
        "SOX": {"affected": False, "controls": []},
        "GDPR": {"affected": False, "controls": []},
        "NIST": {"affected": False, "controls": []}
    }
    
    for alert in alerts:
        rule_desc = alert.get("rule", {}).get("description", "").lower()
        
        # Check for PCI DSS impacts
        if any(keyword in rule_desc for keyword in ["payment", "card", "financial", "authentication"]):
            compliance_frameworks["PCI_DSS"]["affected"] = True
            compliance_frameworks["PCI_DSS"]["controls"].append("Access Control")
        
        # Check for HIPAA impacts
        if any(keyword in rule_desc for keyword in ["health", "medical", "patient", "privacy"]):
            compliance_frameworks["HIPAA"]["affected"] = True
            compliance_frameworks["HIPAA"]["controls"].append("Audit Controls")
        
        # Check for SOX impacts
        if any(keyword in rule_desc for keyword in ["financial", "audit", "accounting", "integrity"]):
            compliance_frameworks["SOX"]["affected"] = True
            compliance_frameworks["SOX"]["controls"].append("IT General Controls")
        
        # Check for GDPR impacts
        if any(keyword in rule_desc for keyword in ["data", "privacy", "personal", "breach"]):
            compliance_frameworks["GDPR"]["affected"] = True
            compliance_frameworks["GDPR"]["controls"].append("Data Protection")
        
        # NIST is generally affected by security incidents
        compliance_frameworks["NIST"]["affected"] = True
        compliance_frameworks["NIST"]["controls"].append("Incident Response")
    
    return compliance_frameworks

async def _get_agent_health_metrics(client: WazuhClient, agent_id: str, ctx: Context = None) -> dict:
    """Get detailed health metrics for an agent."""
    try:
        # Get agent statistics
        stats = await client.get_agent_stats(agent_id)
        return {
            "cpu_usage": stats.get("cpu", "unknown"),
            "memory_usage": stats.get("memory", "unknown"),
            "disk_usage": stats.get("disk", "unknown"),
            "network_status": "healthy",  # Placeholder
            "last_scan": stats.get("last_scan", "unknown")
        }
    except Exception as e:
        if ctx:
            await ctx.warning(f"Could not get health metrics: {e}")
        return {"status": "metrics_unavailable", "error": str(e)}

def _analyze_vulnerability_severity(vulnerabilities: List[dict]) -> dict:
    """Analyze vulnerability severity distribution."""
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    
    for vuln in vulnerabilities:
        severity = vuln.get("vulnerability", {}).get("severity", "").title()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    return severity_counts

def _get_top_cves(vulnerabilities: List[dict]) -> List[dict]:
    """Get top CVEs by occurrence."""
    cve_counts = {}
    
    for vuln in vulnerabilities:
        cve = vuln.get("vulnerability", {}).get("cve", "")
        if cve and cve != "N/A":
            if cve not in cve_counts:
                cve_counts[cve] = {
                    "cve": cve,
                    "count": 0,
                    "severity": vuln.get("vulnerability", {}).get("severity", "Unknown"),
                    "score": vuln.get("vulnerability", {}).get("cvss", {}).get("cvss3", {}).get("score", 0)
                }
            cve_counts[cve]["count"] += 1
    
    return sorted(cve_counts.values(), key=lambda x: (x["score"], x["count"]), reverse=True)[:10]

def _analyze_affected_packages(vulnerabilities: List[dict]) -> dict:
    """Analyze affected packages and software."""
    packages = {}
    
    for vuln in vulnerabilities:
        package = vuln.get("vulnerability", {}).get("package", {}).get("name", "Unknown")
        if package not in packages:
            packages[package] = {
                "name": package,
                "version": vuln.get("vulnerability", {}).get("package", {}).get("version", "Unknown"),
                "vulnerability_count": 0,
                "highest_severity": "Low"
            }
        packages[package]["vulnerability_count"] += 1
        
        # Update highest severity
        current_severity = vuln.get("vulnerability", {}).get("severity", "Low")
        if _severity_value(current_severity) > _severity_value(packages[package]["highest_severity"]):
            packages[package]["highest_severity"] = current_severity
    
    return sorted(packages.values(), key=lambda x: x["vulnerability_count"], reverse=True)[:10]

def _calculate_vulnerability_risk(vulnerabilities: List[dict]) -> dict:
    """Calculate overall vulnerability risk score."""
    if not vulnerabilities:
        return {"score": 0, "level": "Low"}
    
    total_score = 0
    critical_count = 0
    high_count = 0
    
    for vuln in vulnerabilities:
        severity = vuln.get("vulnerability", {}).get("severity", "").lower()
        cvss_score = vuln.get("vulnerability", {}).get("cvss", {}).get("cvss3", {}).get("score", 0)
        
        if severity == "critical":
            critical_count += 1
            total_score += 10
        elif severity == "high":
            high_count += 1
            total_score += 7
        elif severity == "medium":
            total_score += 4
        else:
            total_score += 1
        
        # Add CVSS score bonus
        total_score += cvss_score * 0.5
    
    # Calculate normalized score (0-100)
    normalized_score = min(total_score / len(vulnerabilities) * 10, 100)
    
    # Determine risk level
    if normalized_score >= 80 or critical_count >= 5:
        level = "Critical"
    elif normalized_score >= 60 or high_count >= 10:
        level = "High"
    elif normalized_score >= 30:
        level = "Medium"
    else:
        level = "Low"
    
    return {
        "score": normalized_score,
        "level": level,
        "critical_vulnerabilities": critical_count,
        "high_vulnerabilities": high_count,
        "total_vulnerabilities": len(vulnerabilities)
    }

def _prioritize_remediation(vulnerabilities: List[dict]) -> List[dict]:
    """Prioritize vulnerabilities for remediation."""
    prioritized = []
    
    for vuln in vulnerabilities:
        severity = vuln.get("vulnerability", {}).get("severity", "").lower()
        cvss_score = vuln.get("vulnerability", {}).get("cvss", {}).get("cvss3", {}).get("score", 0)
        exploitable = vuln.get("vulnerability", {}).get("exploitable", False)
        
        # Calculate priority score
        priority_score = 0
        if severity == "critical":
            priority_score += 40
        elif severity == "high":
            priority_score += 30
        elif severity == "medium":
            priority_score += 20
        else:
            priority_score += 10
        
        priority_score += cvss_score * 5
        if exploitable:
            priority_score += 20
        
        prioritized.append({
            "cve": vuln.get("vulnerability", {}).get("cve", "N/A"),
            "package": vuln.get("vulnerability", {}).get("package", {}).get("name", "Unknown"),
            "severity": severity.title(),
            "cvss_score": cvss_score,
            "priority_score": priority_score,
            "exploitable": exploitable,
            "fix_available": vuln.get("vulnerability", {}).get("fix_available", False)
        })
    
    return sorted(prioritized, key=lambda x: x["priority_score"], reverse=True)[:20]

async def _enrich_with_external_intel(hunt_results: dict, ctx: Context = None) -> dict:
    """Enrich threat hunting results with external intelligence."""
    if ctx:
        await ctx.info("Enriching with external threat intelligence")
    
    # Placeholder for external threat intelligence enrichment
    # In a real implementation, this would query VirusTotal, OTX, etc.
    external_intel = {
        "sources": ["VirusTotal", "AlienVault OTX", "AbuseIPDB"],
        "iocs_checked": 0,
        "malicious_indicators": 0,
        "threat_families": [],
        "attribution": "Unknown",
        "confidence": "Medium"
    }
    
    return external_intel

def _severity_value(severity: str) -> int:
    """Convert severity string to numeric value for comparison."""
    severity_map = {
        "critical": 4,
        "high": 3,
        "medium": 2,
        "low": 1
    }
    return severity_map.get(severity.lower(), 0)

def _calculate_time_span(alerts: List[dict]) -> str:
    """Calculate time span for a list of alerts."""
    timestamps = []
    for alert in alerts:
        timestamp = alert.get("timestamp", "")
        if timestamp:
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                timestamps.append(dt)
            except:
                continue
    
    if len(timestamps) >= 2:
        time_span = max(timestamps) - min(timestamps)
        return str(time_span)
    
    return "Unknown"

# ============================================================================
# SERVER INITIALIZATION AND LIFECYCLE
# ============================================================================

async def initialize_server():
    """Initialize server components and validate configuration."""
    global _server_start_time
    _server_start_time = datetime.utcnow()
    
    try:
        # Load and validate configuration
        config = await get_config()
        print(f"✅ Configuration loaded: {config.wazuh_host}:{config.wazuh_port}")
        
        # Initialize Wazuh client
        client = await get_wazuh_client()
        print("✅ Wazuh client initialized")
        
        # Initialize Indexer client if configured
        indexer = await get_indexer_client()
        if indexer:
            print("✅ Wazuh Indexer client initialized")
        
        print(f"🚀 FastMCP Wazuh Server initialized successfully")
        print(f"📊 Server start time: {_server_start_time.isoformat()}")
        
    except Exception as e:
        print(f"❌ Server initialization failed: {e}")
        raise

# ============================================================================
# MAIN SERVER ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Initialize server
    asyncio.run(initialize_server())
    
    # Run server based on transport mode
    transport_mode = os.getenv("MCP_TRANSPORT", "stdio").lower()
    
    if transport_mode == "http":
        # HTTP/SSE transport
        host = os.getenv("MCP_HOST", "0.0.0.0")
        port = int(os.getenv("MCP_PORT", "3000"))
        
        print(f"🌐 Starting FastMCP server in HTTP mode on {host}:{port}")
        uvicorn.run(mcp.create_app(), host=host, port=port, log_level="info")
    else:
        # STDIO transport (default)
        print("📱 Starting FastMCP server in STDIO mode")
        mcp.run()