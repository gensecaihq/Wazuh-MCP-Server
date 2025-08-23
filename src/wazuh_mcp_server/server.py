#!/usr/bin/env python3
"""
Wazuh MCP Server - FastMCP STDIO Implementation
==============================================
Production-ready FastMCP server for Wazuh SIEM integration with Claude Desktop.
STDIO transport only - no HTTP/remote capabilities.
"""

import os
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import json

try:
    from fastmcp import FastMCP
except ImportError:
    # Use stub if FastMCP not available
    from wazuh_mcp_server.fastmcp_stub import FastMCP

try:
    from pydantic import BaseModel, Field
except ImportError:
    # Basic fallback for Pydantic
    class BaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
    
    def Field(default=None, **kwargs):
        return default

# Import Wazuh components
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.api.wazuh_client_manager import WazuhClientManager
from wazuh_mcp_server.analyzers import SecurityAnalyzer, ComplianceAnalyzer
from wazuh_mcp_server.utils import setup_logging, get_logger
from wazuh_mcp_server.__version__ import __version__

# Initialize logger
logger = get_logger(__name__)

# Initialize FastMCP app
mcp = FastMCP(
    name="Wazuh MCP Server",
    version="2.1.2"
)

# Global instances
config: Optional[WazuhConfig] = None
client_manager: Optional[WazuhClientManager] = None
security_analyzer: Optional[SecurityAnalyzer] = None
compliance_analyzer: Optional[ComplianceAnalyzer] = None

# Pydantic models for request validation
class AlertQuery(BaseModel):
    limit: int = Field(default=100, ge=1, le=1000)
    rule_id: Optional[str] = None
    level: Optional[str] = None
    agent_id: Optional[str] = None
    timestamp_start: Optional[str] = None
    timestamp_end: Optional[str] = None

class AgentQuery(BaseModel):
    agent_id: Optional[str] = None
    status: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)

class VulnerabilityQuery(BaseModel):
    agent_id: Optional[str] = None
    severity: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=500)

async def initialize_server():
    """Initialize the Wazuh MCP server components with comprehensive health checks."""
    global config, client_manager, security_analyzer, compliance_analyzer
    
    try:
        # Setup logging first
        setup_logging()
        logger.info("🚀 Initializing Wazuh MCP Server v2.1.0 with FastMCP")
        
        # Load configuration
        config = WazuhConfig()
        logger.info(f"📋 Loaded configuration for Wazuh host: {config.host}:{config.port}")
        
        # Run comprehensive health checks
        from wazuh_mcp_server.utils.health_checks import run_startup_health_checks
        
        logger.info("🏥 Running startup health checks...")
        is_healthy = await run_startup_health_checks(config)
        
        if not is_healthy:
            raise RuntimeError("Server failed health checks - cannot start safely")
        
        logger.info("✅ All health checks passed - proceeding with initialization")
        
        # Initialize client manager
        client_manager = WazuhClientManager(config)
        logger.info("🔗 Wazuh client manager initialized")
        
        # Initialize analyzers
        security_analyzer = SecurityAnalyzer(client_manager)
        compliance_analyzer = ComplianceAnalyzer(client_manager)
        logger.info("🔍 Security and compliance analyzers initialized")
        
        logger.info("🎉 Wazuh MCP Server initialization completed successfully")
        logger.info("📡 Server ready for FastMCP STDIO connections")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize server: {e}")
        raise

@mcp.tool()
async def get_wazuh_alerts(
    limit: int = 100,
    rule_id: Optional[str] = None,
    level: Optional[str] = None,
    agent_id: Optional[str] = None,
    timestamp_start: Optional[str] = None,
    timestamp_end: Optional[str] = None
) -> str:
    """
    Retrieve Wazuh security alerts with optional filtering.
    
    Args:
        limit: Maximum number of alerts to retrieve (1-1000)
        rule_id: Filter by specific rule ID
        level: Filter by alert level (e.g., '12', '10+')
        agent_id: Filter by agent ID
        timestamp_start: Start timestamp (ISO format)
        timestamp_end: End timestamp (ISO format)
    
    Returns:
        JSON string containing alert data
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        query = AlertQuery(
            limit=limit,
            rule_id=rule_id,
            level=level,
            agent_id=agent_id,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end
        )
        
        alerts = await client_manager.get_alerts(query.dict(exclude_none=True))
        return json.dumps(alerts, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_agents(
    agent_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100
) -> str:
    """
    Retrieve information about Wazuh agents.
    
    Args:
        agent_id: Specific agent ID to query
        status: Filter by agent status (active, disconnected, etc.)
        limit: Maximum number of agents to retrieve
    
    Returns:
        JSON string containing agent data
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        query = AgentQuery(
            agent_id=agent_id,
            status=status,
            limit=limit
        )
        
        agents = await client_manager.get_agents(query.dict(exclude_none=True))
        return json.dumps(agents, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting agents: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_vulnerabilities(
    agent_id: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100
) -> str:
    """
    Retrieve vulnerability information from Wazuh.
    
    Args:
        agent_id: Filter by specific agent ID
        severity: Filter by severity level
        limit: Maximum number of vulnerabilities to retrieve
    
    Returns:
        JSON string containing vulnerability data
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        query = VulnerabilityQuery(
            agent_id=agent_id,
            severity=severity,
            limit=limit
        )
        
        vulnerabilities = await client_manager.get_vulnerabilities(query.dict(exclude_none=True))
        return json.dumps(vulnerabilities, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting vulnerabilities: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def analyze_security_threat(
    indicator: str,
    indicator_type: str = "ip"
) -> str:
    """
    Analyze a security threat indicator using AI-powered analysis.
    
    Args:
        indicator: The threat indicator to analyze (IP, hash, domain)
        indicator_type: Type of indicator (ip, hash, domain, url)
    
    Returns:
        JSON string containing threat analysis
    """
    try:
        if not security_analyzer:
            return json.dumps({"error": "Security analyzer not initialized"})
            
        analysis = await security_analyzer.analyze_threat(indicator, indicator_type)
        return json.dumps(analysis, indent=2)
        
    except Exception as e:
        logger.error(f"Error analyzing threat: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_alert_summary(
    time_range: str = "24h",
    group_by: str = "rule.level"
) -> str:
    """
    Get a summary of Wazuh alerts grouped by specified field.
    
    Args:
        time_range: Time range for alerts (1h, 6h, 24h, 7d)
        group_by: Field to group alerts by
    
    Returns:
        JSON string containing alert summary
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        summary = await client_manager.get_alert_summary(time_range, group_by)
        return json.dumps(summary, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting alert summary: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_running_agents() -> str:
    """
    Get list of currently running/active Wazuh agents.
    
    Returns:
        JSON string containing active agents data
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        agents = await client_manager.get_running_agents()
        return json.dumps(agents, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting running agents: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_cluster_health() -> str:
    """
    Get Wazuh cluster health information.
    
    Returns:
        JSON string containing cluster health data
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        health = await client_manager.get_cluster_health()
        return json.dumps(health, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting cluster health: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_rules_summary() -> str:
    """
    Get summary of Wazuh rules and their effectiveness.
    
    Returns:
        JSON string containing rules summary
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        rules = await client_manager.get_rules_summary()
        return json.dumps(rules, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting rules summary: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_weekly_stats() -> str:
    """
    Get weekly statistics from Wazuh including alerts, agents, and trends.
    
    Returns:
        JSON string containing weekly statistics
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        stats = await client_manager.get_weekly_stats()
        return json.dumps(stats, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting weekly stats: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def search_wazuh_manager_logs(
    query: str,
    limit: int = 100
) -> str:
    """
    Search Wazuh manager logs for specific patterns.
    
    Args:
        query: Search query/pattern
        limit: Maximum number of log entries to return
    
    Returns:
        JSON string containing log search results
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        logs = await client_manager.search_manager_logs(query, limit)
        return json.dumps(logs, indent=2)
        
    except Exception as e:
        logger.error(f"Error searching manager logs: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_critical_vulnerabilities(
    limit: int = 50
) -> str:
    """
    Get critical vulnerabilities from Wazuh.
    
    Args:
        limit: Maximum number of critical vulnerabilities to retrieve
    
    Returns:
        JSON string containing critical vulnerabilities
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        vulns = await client_manager.get_critical_vulnerabilities(limit)
        return json.dumps(vulns, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting critical vulnerabilities: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_vulnerability_summary(
    time_range: str = "7d"
) -> str:
    """
    Get vulnerability summary statistics from Wazuh.
    
    Args:
        time_range: Time range for vulnerability data (1d, 7d, 30d)
    
    Returns:
        JSON string containing vulnerability summary
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        summary = await client_manager.get_vulnerability_summary(time_range)
        return json.dumps(summary, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting vulnerability summary: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_cluster_nodes() -> str:
    """
    Get information about Wazuh cluster nodes.
    
    Returns:
        JSON string containing cluster nodes information
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        nodes = await client_manager.get_cluster_nodes()
        return json.dumps(nodes, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting cluster nodes: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_remoted_stats() -> str:
    """
    Get Wazuh remoted (agent communication) statistics.
    
    Returns:
        JSON string containing remoted statistics
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        stats = await client_manager.get_remoted_stats()
        return json.dumps(stats, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting remoted stats: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_log_collector_stats() -> str:
    """
    Get Wazuh log collector statistics.
    
    Returns:
        JSON string containing log collector statistics
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        stats = await client_manager.get_log_collector_stats()
        return json.dumps(stats, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting log collector stats: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_manager_error_logs(
    limit: int = 100
) -> str:
    """
    Get recent error logs from Wazuh manager.
    
    Args:
        limit: Maximum number of error log entries to retrieve
    
    Returns:
        JSON string containing error logs
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        logs = await client_manager.get_manager_error_logs(limit)
        return json.dumps(logs, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting manager error logs: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def check_agent_health(
    agent_id: str
) -> str:
    """
    Check the health status of a specific Wazuh agent.
    
    Args:
        agent_id: ID of the agent to check
    
    Returns:
        JSON string containing agent health information
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        health = await client_manager.check_agent_health(agent_id)
        return json.dumps(health, indent=2)
        
    except Exception as e:
        logger.error(f"Error checking agent health: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_agent_processes(
    agent_id: str,
    limit: int = 100
) -> str:
    """
    Get running processes from a specific Wazuh agent.
    
    Args:
        agent_id: ID of the agent
        limit: Maximum number of processes to retrieve
    
    Returns:
        JSON string containing agent processes
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        processes = await client_manager.get_agent_processes(agent_id, limit)
        return json.dumps(processes, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting agent processes: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_agent_ports(
    agent_id: str,
    limit: int = 100
) -> str:
    """
    Get open ports from a specific Wazuh agent.
    
    Args:
        agent_id: ID of the agent
        limit: Maximum number of ports to retrieve
    
    Returns:
        JSON string containing agent ports
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        ports = await client_manager.get_agent_ports(agent_id, limit)
        return json.dumps(ports, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting agent ports: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def check_ioc_reputation(
    indicator: str,
    indicator_type: str = "ip"
) -> str:
    """
    Check reputation of an Indicator of Compromise (IoC).
    
    Args:
        indicator: The IoC to check (IP, domain, hash, etc.)
        indicator_type: Type of indicator (ip, domain, hash, url)
    
    Returns:
        JSON string containing reputation information
    """
    try:
        if not security_analyzer:
            return json.dumps({"error": "Security analyzer not initialized"})
            
        reputation = await security_analyzer.check_ioc_reputation(indicator, indicator_type)
        return json.dumps(reputation, indent=2)
        
    except Exception as e:
        logger.error(f"Error checking IoC reputation: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def perform_risk_assessment(
    agent_id: Optional[str] = None
) -> str:
    """
    Perform comprehensive risk assessment for agents or the entire environment.
    
    Args:
        agent_id: Specific agent ID to assess (if None, assess entire environment)
    
    Returns:
        JSON string containing risk assessment results
    """
    try:
        if not security_analyzer:
            return json.dumps({"error": "Security analyzer not initialized"})
            
        risk_assessment = await security_analyzer.perform_risk_assessment(agent_id)
        return json.dumps(risk_assessment, indent=2)
        
    except Exception as e:
        logger.error(f"Error performing risk assessment: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def run_compliance_check(
    framework: str = "PCI-DSS",
    agent_id: Optional[str] = None
) -> str:
    """
    Run compliance check against security frameworks.
    
    Args:
        framework: Compliance framework (PCI-DSS, HIPAA, SOX, GDPR, NIST)
        agent_id: Specific agent ID to check (if None, check entire environment)
    
    Returns:
        JSON string containing compliance check results
    """
    try:
        if not compliance_analyzer:
            return json.dumps({"error": "Compliance analyzer not initialized"})
            
        compliance = await compliance_analyzer.run_compliance_check(framework, agent_id)
        return json.dumps(compliance, indent=2)
        
    except Exception as e:
        logger.error(f"Error running compliance check: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_wazuh_statistics() -> str:
    """
    Get comprehensive Wazuh statistics and metrics.
    
    Returns:
        JSON string containing comprehensive statistics
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        stats = await client_manager.get_wazuh_statistics()
        return json.dumps(stats, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting Wazuh statistics: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def analyze_alert_patterns(
    time_range: str = "24h",
    min_frequency: int = 5
) -> str:
    """
    Analyze alert patterns to identify trends and anomalies.
    
    Args:
        time_range: Time range for pattern analysis (1h, 6h, 24h, 7d)
        min_frequency: Minimum frequency for pattern detection
    
    Returns:
        JSON string containing pattern analysis results
    """
    try:
        if not security_analyzer:
            return json.dumps({"error": "Security analyzer not initialized"})
            
        patterns = await security_analyzer.analyze_alert_patterns(time_range, min_frequency)
        return json.dumps(patterns, indent=2)
        
    except Exception as e:
        logger.error(f"Error analyzing alert patterns: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_top_security_threats(
    limit: int = 10,
    time_range: str = "24h"
) -> str:
    """
    Get top security threats based on alert frequency and severity.
    
    Args:
        limit: Number of top threats to retrieve
        time_range: Time range for threat analysis (1h, 6h, 24h, 7d)
    
    Returns:
        JSON string containing top security threats
    """
    try:
        if not security_analyzer:
            return json.dumps({"error": "Security analyzer not initialized"})
            
        threats = await security_analyzer.get_top_security_threats(limit, time_range)
        return json.dumps(threats, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting top security threats: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def generate_security_report(
    report_type: str = "daily",
    include_recommendations: bool = True
) -> str:
    """
    Generate comprehensive security report.
    
    Args:
        report_type: Type of report (daily, weekly, monthly, incident)
        include_recommendations: Whether to include security recommendations
    
    Returns:
        JSON string containing security report
    """
    try:
        if not security_analyzer:
            return json.dumps({"error": "Security analyzer not initialized"})
            
        report = await security_analyzer.generate_security_report(report_type, include_recommendations)
        return json.dumps(report, indent=2)
        
    except Exception as e:
        logger.error(f"Error generating security report: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def search_security_events(
    query: str,
    time_range: str = "24h",
    limit: int = 100
) -> str:
    """
    Search for specific security events across all Wazuh data.
    
    Args:
        query: Search query or pattern
        time_range: Time range for event search (1h, 6h, 24h, 7d)
        limit: Maximum number of events to retrieve
    
    Returns:
        JSON string containing matching security events
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        events = await client_manager.search_security_events(query, time_range, limit)
        return json.dumps(events, indent=2)
        
    except Exception as e:
        logger.error(f"Error searching security events: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def get_agent_configuration(
    agent_id: str
) -> str:
    """
    Get configuration details for a specific Wazuh agent.
    
    Args:
        agent_id: ID of the agent
    
    Returns:
        JSON string containing agent configuration
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        config = await client_manager.get_agent_configuration(agent_id)
        return json.dumps(config, indent=2)
        
    except Exception as e:
        logger.error(f"Error getting agent configuration: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def validate_wazuh_connection() -> str:
    """
    Validate connection to Wazuh server and return status.
    
    Returns:
        JSON string containing connection validation results
    """
    try:
        if not client_manager:
            return json.dumps({"error": "Server not initialized"})
            
        validation = await client_manager.validate_connection()
        return json.dumps(validation, indent=2)
        
    except Exception as e:
        logger.error(f"Error validating Wazuh connection: {e}")
        return json.dumps({"error": str(e)})

# Server initialization will be handled by the main.py executable script
if __name__ == "__main__":
    # This should not be called directly - use wazuh-mcp-server executable instead
    print("Please use the wazuh-mcp-server executable to start the server", file=sys.stderr)
    print("Run: wazuh-mcp-server --help for usage information", file=sys.stderr)
    sys.exit(1)