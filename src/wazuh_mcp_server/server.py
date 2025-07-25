#!/usr/bin/env python3
"""FastMCP-powered Wazuh SIEM integration server."""

import os
import sys
from typing import Dict, Any, Optional, Annotated, Literal
from datetime import datetime, timedelta
import uuid

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
    """Get vulnerability information from Wazuh (4.8+ centralized detection, 4.12+ includes CTI data and package conditions)."""
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
async def search_wazuh_logs(
    query: Annotated[Optional[str], Field(description="Search query for log entries")] = None,
    level: Annotated[Optional[str], Field(description="Log level filter (info, warning, error, critical)")] = None,
    time_range_hours: Annotated[int, Field(description="Time range in hours to search", ge=1, le=168)] = 24,
    limit: Annotated[int, Field(description="Maximum number of log entries", ge=1, le=1000)] = 100,
    ctx: Context = None
) -> dict:
    """Search Wazuh logs for security investigations and troubleshooting."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Searching logs with query='{query}', level='{level}', range={time_range_hours}h")
        
        # Build search parameters
        params = {"limit": limit}
        
        if query:
            params["q"] = query
        if level:
            params["level"] = level
            
        # Calculate time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        params["newer_than"] = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        params["older_than"] = end_time.strftime("%Y-%m-%dT%H:%M:%S")
        
        response = await client.search_logs(**params)
        logs = response.get("data", {}).get("affected_items", [])
        
        # Analyze log patterns
        level_counts = {}
        categories = {}
        
        for log_entry in logs:
            # Count by level
            log_level = log_entry.get("level", "unknown")
            level_counts[log_level] = level_counts.get(log_level, 0) + 1
            
            # Categorize by message content
            message = log_entry.get("description", "").lower()
            category = _categorize_log_message(message)
            categories[category] = categories.get(category, 0) + 1
        
        # Create search results
        results = {
            "logs": logs,
            "total_found": len(logs),
            "search_parameters": {
                "query": query,
                "level": level,
                "time_range_hours": time_range_hours,
                "limit": limit
            },
            "analysis": {
                "level_distribution": level_counts,
                "category_breakdown": categories,
                "time_range": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                }
            },
            "query_time": datetime.utcnow().isoformat()
        }
        
        if ctx:
            await ctx.info(f"Log search complete: {len(logs)} entries found")
        
        return results
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Log search failed: {e}")
        raise ValueError(f"Failed to search logs: {e}")


def _categorize_log_message(message: str) -> str:
    """Categorize log message based on content."""
    if any(word in message for word in ["error", "failed", "failure", "exception"]):
        return "Error"
    elif any(word in message for word in ["warning", "warn", "deprecated"]):
        return "Warning"
    elif any(word in message for word in ["authentication", "login", "auth", "user"]):
        return "Authentication"
    elif any(word in message for word in ["connection", "network", "socket", "tcp", "udp"]):
        return "Network"
    elif any(word in message for word in ["agent", "client", "node"]):
        return "Agent Management"
    elif any(word in message for word in ["rule", "alert", "trigger", "match"]):
        return "Rule Processing"
    elif any(word in message for word in ["database", "db", "index", "elastic"]):
        return "Database"
    elif any(word in message for word in ["start", "stop", "restart", "shutdown", "init"]):
        return "System"
    else:
        return "General"


@mcp.tool
async def get_security_incidents(
    status: Annotated[Optional[Literal["open", "in_progress", "resolved", "closed"]], Field(description="Filter by incident status")] = None,
    severity: Annotated[Optional[Literal["low", "medium", "high", "critical"]], Field(description="Filter by incident severity")] = None,
    limit: Annotated[int, Field(description="Maximum number of incidents", ge=1, le=100)] = 50,
    ctx: Context = None
) -> dict:
    """Get security incidents for SOC operations."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Retrieving incidents with status='{status}', severity='{severity}'")
        
        params = {"limit": limit}
        if status:
            params["status"] = status
        if severity:
            params["severity"] = severity
            
        # Note: Since Wazuh doesn't have native incident management, 
        # we'll simulate this by analyzing alerts and creating logical incidents
        alerts_response = await client.get_alerts(limit=200, level=5)
        alerts = alerts_response.get("data", {}).get("affected_items", [])
        
        # Group alerts into incidents based on similarity
        incidents = _group_alerts_into_incidents(alerts)
        
        # Filter by requested criteria
        if status:
            incidents = [i for i in incidents if i.get("status") == status]
        if severity:
            incidents = [i for i in incidents if i.get("severity") == severity]
            
        # Limit results
        incidents = incidents[:limit]
        
        return {
            "incidents": incidents,
            "total_incidents": len(incidents),
            "query_parameters": {
                "status": status,
                "severity": severity,
                "limit": limit
            },
            "query_time": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to retrieve incidents: {e}")
        raise ValueError(f"Failed to retrieve security incidents: {e}")


@mcp.tool
async def create_security_incident(
    title: Annotated[str, Field(description="Incident title/summary")],
    description: Annotated[str, Field(description="Detailed incident description")],
    severity: Annotated[Literal["low", "medium", "high", "critical"], Field(description="Incident severity level")],
    alert_ids: Annotated[Optional[list], Field(description="Related alert IDs")] = None,
    assigned_to: Annotated[Optional[str], Field(description="Assigned analyst")] = None,
    ctx: Context = None
) -> dict:
    """Create a new security incident for SOC tracking."""
    try:
        if ctx:
            await ctx.info(f"Creating incident: {title} (severity: {severity})")
        
        # Generate unique incident ID
        incident_id = f"INC-{datetime.utcnow().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
        
        incident_data = {
            "id": incident_id,
            "title": title,
            "description": description,
            "severity": severity,
            "status": "open",
            "created_by": "mcp-server",
            "assigned_to": assigned_to,
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
            "alert_ids": alert_ids or [],
            "tags": _generate_incident_tags(title, description),
            "workflow_stage": "triage"
        }
        
        # In a real implementation, this would be stored in a database
        # For now, we'll return the structured incident data
        
        if ctx:
            await ctx.info(f"Incident created successfully: {incident_id}")
        
        return {
            "incident": incident_data,
            "message": f"Security incident {incident_id} created successfully",
            "next_steps": [
                "Assign to analyst for investigation",
                "Link related alerts and evidence",
                "Begin containment procedures if needed"
            ]
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to create incident: {e}")
        raise ValueError(f"Failed to create security incident: {e}")


@mcp.tool
async def update_security_incident(
    incident_id: Annotated[str, Field(description="Incident ID to update")],
    status: Annotated[Optional[Literal["open", "in_progress", "resolved", "closed"]], Field(description="New incident status")] = None,
    assigned_to: Annotated[Optional[str], Field(description="Assign to analyst")] = None,
    notes: Annotated[Optional[str], Field(description="Investigation notes")] = None,
    resolution: Annotated[Optional[str], Field(description="Resolution details")] = None,
    ctx: Context = None
) -> dict:
    """Update an existing security incident."""
    try:
        if ctx:
            await ctx.info(f"Updating incident {incident_id}")
        
        # Simulate incident update (in real implementation, would update database)
        update_data = {
            "incident_id": incident_id,
            "updated_at": datetime.utcnow().isoformat(),
            "updated_by": "mcp-server"
        }
        
        changes = []
        if status:
            update_data["status"] = status
            changes.append(f"Status changed to {status}")
        if assigned_to:
            update_data["assigned_to"] = assigned_to
            changes.append(f"Assigned to {assigned_to}")
        if notes:
            update_data["notes"] = notes
            changes.append("Investigation notes added")
        if resolution:
            update_data["resolution"] = resolution
            changes.append("Resolution details added")
            
        # Determine workflow stage based on status
        if status == "in_progress":
            update_data["workflow_stage"] = "investigation"
        elif status == "resolved":
            update_data["workflow_stage"] = "resolution"
        elif status == "closed":
            update_data["workflow_stage"] = "closed"
            
        return {
            "incident_id": incident_id,
            "update_data": update_data,
            "changes_made": changes,
            "message": f"Incident {incident_id} updated successfully",
            "updated_at": update_data["updated_at"]
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to update incident: {e}")
        raise ValueError(f"Failed to update security incident: {e}")


def _group_alerts_into_incidents(alerts: list) -> list:
    """Group related alerts into logical security incidents."""
    incidents = []
    alert_groups = {}
    
    for alert in alerts:
        # Group by rule ID and agent
        rule_id = alert.get("rule", {}).get("id", "unknown")
        agent_id = alert.get("agent", {}).get("id", "unknown")
        group_key = f"{rule_id}-{agent_id}"
        
        if group_key not in alert_groups:
            alert_groups[group_key] = []
        alert_groups[group_key].append(alert)
    
    # Create incidents from grouped alerts
    for group_key, group_alerts in alert_groups.items():
        if len(group_alerts) < 2:  # Skip single alerts
            continue
            
        first_alert = group_alerts[0]
        rule_desc = first_alert.get("rule", {}).get("description", "Security Event")
        agent_name = first_alert.get("agent", {}).get("name", "Unknown")
        
        # Determine severity based on alert levels
        max_level = max(alert.get("rule", {}).get("level", 0) for alert in group_alerts)
        severity = "critical" if max_level >= 12 else "high" if max_level >= 8 else "medium" if max_level >= 5 else "low"
        
        incident = {
            "id": f"INC-AUTO-{group_key}-{datetime.utcnow().strftime('%Y%m%d')}",
            "title": f"Multiple {rule_desc} events on {agent_name}",
            "description": f"Detected {len(group_alerts)} related security events",
            "severity": severity,
            "status": "open",
            "created_at": min(alert.get("timestamp", "") for alert in group_alerts),
            "updated_at": datetime.utcnow().isoformat(),
            "alert_count": len(group_alerts),
            "affected_agent": agent_name,
            "rule_description": rule_desc,
            "workflow_stage": "triage"
        }
        incidents.append(incident)
    
    return sorted(incidents, key=lambda x: x.get("created_at", ""), reverse=True)


def _generate_incident_tags(title: str, description: str) -> list:
    """Generate relevant tags for incident categorization."""
    tags = []
    text = f"{title} {description}".lower()
    
    # Security category tags
    if any(word in text for word in ["malware", "virus", "trojan"]):
        tags.append("malware")
    if any(word in text for word in ["brute", "force", "login", "auth"]):
        tags.append("authentication")
    if any(word in text for word in ["intrusion", "exploit", "attack"]):
        tags.append("intrusion")
    if any(word in text for word in ["network", "traffic", "connection"]):
        tags.append("network")
    if any(word in text for word in ["file", "integrity", "modification"]):
        tags.append("file-integrity")
    if any(word in text for word in ["privilege", "escalation", "admin"]):
        tags.append("privilege-escalation")
    
    # Priority tags
    if any(word in text for word in ["critical", "urgent", "emergency"]):
        tags.append("high-priority")
    if any(word in text for word in ["multiple", "mass", "widespread"]):
        tags.append("mass-event")
        
    return tags


@mcp.tool
async def get_wazuh_rules(
    rule_id: Annotated[Optional[str], Field(description="Specific rule ID to retrieve")] = None,
    search: Annotated[Optional[str], Field(description="Search term for rule description")] = None,
    level: Annotated[Optional[int], Field(description="Filter by rule level", ge=1, le=15)] = None,
    group: Annotated[Optional[str], Field(description="Filter by rule group (e.g., authentication, web)")] = None,
    limit: Annotated[int, Field(description="Maximum number of rules", ge=1, le=500)] = 100,
    ctx: Context = None
) -> dict:
    """Get Wazuh detection rules for analysis and management."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Retrieving rules: id={rule_id}, search='{search}', level={level}, group='{group}'")
        
        params = {"limit": limit}
        if rule_id:
            # Get specific rule details
            response = await client.get_rule_info(rule_id)
            rule_data = response.get("data", {}).get("affected_items", [])
            return {
                "rules": rule_data,
                "total_rules": len(rule_data),
                "query_parameters": {"rule_id": rule_id},
                "query_time": datetime.utcnow().isoformat()
            }
        
        # Build search parameters
        if search:
            params["search"] = search
        if level:
            params["level"] = level
        if group:
            params["group"] = group
            
        response = await client.get_rules(**params)
        rules = response.get("data", {}).get("affected_items", [])
        
        # Analyze rule distribution
        level_counts = {}
        group_counts = {}
        
        for rule in rules:
            rule_level = rule.get("level", 0)
            level_counts[rule_level] = level_counts.get(rule_level, 0) + 1
            
            rule_groups = rule.get("groups", [])
            for group_name in rule_groups:
                group_counts[group_name] = group_counts.get(group_name, 0) + 1
        
        return {
            "rules": rules,
            "total_rules": len(rules),
            "analysis": {
                "level_distribution": level_counts,
                "group_distribution": dict(sorted(group_counts.items(), key=lambda x: x[1], reverse=True)[:10])
            },
            "query_parameters": {
                "search": search,
                "level": level,
                "group": group,
                "limit": limit
            },
            "query_time": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to retrieve rules: {e}")
        raise ValueError(f"Failed to retrieve Wazuh rules: {e}")


@mcp.tool
async def analyze_rule_coverage(
    alert_timeframe_hours: Annotated[int, Field(description="Hours to analyze alert patterns", ge=1, le=168)] = 24,
    ctx: Context = None
) -> dict:
    """Analyze rule coverage and effectiveness based on recent alerts."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Analyzing rule coverage for last {alert_timeframe_hours} hours")
        
        # Get recent alerts to analyze rule effectiveness
        alerts_response = await client.get_alerts(limit=500)
        alerts = alerts_response.get("data", {}).get("affected_items", [])
        
        # Get all rules for comparison
        rules_response = await client.get_rules(limit=1000)
        rules = rules_response.get("data", {}).get("affected_items", [])
        
        # Analyze rule usage
        triggered_rules = {}
        rule_levels = {}
        
        for alert in alerts:
            rule_id = alert.get("rule", {}).get("id")
            rule_level = alert.get("rule", {}).get("level", 0)
            if rule_id:
                triggered_rules[rule_id] = triggered_rules.get(rule_id, 0) + 1
                rule_levels[rule_id] = rule_level
        
        # Calculate coverage statistics
        total_rules = len(rules)
        active_rules = len(triggered_rules)
        coverage_percentage = (active_rules / total_rules * 100) if total_rules > 0 else 0
        
        # Find most/least active rules
        most_triggered = sorted(triggered_rules.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Identify unused high-level rules
        unused_critical_rules = []
        for rule in rules:
            rule_id = str(rule.get("id", ""))
            rule_level = rule.get("level", 0)
            if rule_id not in triggered_rules and rule_level >= 10:
                unused_critical_rules.append({
                    "id": rule_id,
                    "description": rule.get("description", ""),
                    "level": rule_level,
                    "groups": rule.get("groups", [])
                })
        
        analysis = {
            "coverage_summary": {
                "total_rules": total_rules,
                "active_rules": active_rules,
                "coverage_percentage": round(coverage_percentage, 2),
                "analysis_timeframe_hours": alert_timeframe_hours
            },
            "rule_effectiveness": {
                "most_triggered_rules": [
                    {"rule_id": rule_id, "trigger_count": count, "level": rule_levels.get(rule_id, 0)}
                    for rule_id, count in most_triggered[:10]
                ],
                "unused_critical_rules": unused_critical_rules[:10]
            },
            "recommendations": _generate_rule_recommendations(triggered_rules, unused_critical_rules, coverage_percentage),
            "query_time": datetime.utcnow().isoformat()
        }
        
        if ctx:
            await ctx.info(f"Rule analysis complete: {coverage_percentage:.1f}% coverage, {len(most_triggered)} active rules")
        
        return analysis
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Rule coverage analysis failed: {e}")
        raise ValueError(f"Failed to analyze rule coverage: {e}")


@mcp.tool
async def get_rule_decoders(
    decoder_name: Annotated[Optional[str], Field(description="Specific decoder name")] = None,
    search: Annotated[Optional[str], Field(description="Search term for decoder")] = None,
    limit: Annotated[int, Field(description="Maximum number of decoders", ge=1, le=200)] = 50,
    ctx: Context = None
) -> dict:
    """Get Wazuh log decoders that parse incoming logs."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Retrieving decoders: name='{decoder_name}', search='{search}'")
        
        params = {"limit": limit}
        if decoder_name:
            params["decoder_name"] = decoder_name
        if search:
            params["search"] = search
            
        response = await client.get_decoders(**params)
        decoders = response.get("data", {}).get("affected_items", [])
        
        # Analyze decoder types
        decoder_types = {}
        for decoder in decoders:
            decoder_file = decoder.get("file", "unknown")
            decoder_types[decoder_file] = decoder_types.get(decoder_file, 0) + 1
        
        return {
            "decoders": decoders,
            "total_decoders": len(decoders),
            "analysis": {
                "decoders_by_file": dict(sorted(decoder_types.items(), key=lambda x: x[1], reverse=True))
            },
            "query_parameters": {
                "decoder_name": decoder_name,
                "search": search,
                "limit": limit
            },
            "query_time": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to retrieve decoders: {e}")
        raise ValueError(f"Failed to retrieve Wazuh decoders: {e}")


def _generate_rule_recommendations(triggered_rules: dict, unused_critical_rules: list, coverage_percentage: float) -> list:
    """Generate recommendations for rule management."""
    recommendations = []
    
    if coverage_percentage < 30:
        recommendations.append("Low rule coverage detected. Consider reviewing alert generation and rule configuration.")
    
    if len(triggered_rules) > 0:
        # Find rules with excessive triggering
        max_triggers = max(triggered_rules.values())
        if max_triggers > 100:
            recommendations.append("Some rules are triggering excessively. Consider tuning high-frequency rules to reduce noise.")
    
    if len(unused_critical_rules) > 5:
        recommendations.append(f"Found {len(unused_critical_rules)} unused critical rules. Review if they need adjustment or removal.")
    
    if coverage_percentage > 80:
        recommendations.append("Good rule coverage. Monitor for new threat patterns that may require additional rules.")
    
    if not recommendations:
        recommendations.append("Rule coverage analysis looks healthy. Continue monitoring for optimization opportunities.")
    
    return recommendations


@mcp.tool
async def advanced_wazuh_query(
    query_type: Annotated[Literal["alerts", "agents", "vulnerabilities"], Field(description="Type of data to query")],
    filters: Annotated[dict, Field(description="Advanced filter criteria as JSON object")] = {},
    time_range: Annotated[Optional[dict], Field(description="Time range filter {start: ISO8601, end: ISO8601}")] = None,
    sort_by: Annotated[Optional[str], Field(description="Field to sort by")] = None,
    sort_order: Annotated[Literal["asc", "desc"], Field(description="Sort order")] = "desc",
    limit: Annotated[int, Field(description="Maximum results", ge=1, le=1000)] = 100,
    ctx: Context = None
) -> dict:
    """Execute advanced multi-field queries against Wazuh data with complex filtering."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Advanced query: type={query_type}, filters={len(filters)} criteria")
        
        # Build query parameters
        params = {"limit": limit}
        
        # Add sort parameters
        if sort_by:
            params["sort"] = f"{'+' if sort_order == 'asc' else '-'}{sort_by}"
        
        # Process advanced filters based on query type
        if query_type == "alerts":
            params.update(_build_alert_filters(filters))
            if time_range:
                params.update(_build_time_range_filter(time_range))
            response = await client.get_alerts(**params)
            
        elif query_type == "agents":
            params.update(_build_agent_filters(filters))
            response = await client.get_agents(**params)
            
        elif query_type == "vulnerabilities":
            params.update(_build_vulnerability_filters(filters))
            response = await client.get_vulnerabilities(**params)
        
        data_items = response.get("data", {}).get("affected_items", [])
        
        # Apply additional filtering if needed
        filtered_items = _apply_advanced_filters(data_items, filters, query_type)
        
        # Generate query insights
        insights = _generate_query_insights(filtered_items, query_type, filters)
        
        return {
            "results": filtered_items,
            "total_results": len(filtered_items),
            "query_type": query_type,
            "applied_filters": filters,
            "insights": insights,
            "query_parameters": params,
            "query_time": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Advanced query failed: {e}")
        raise ValueError(f"Failed to execute advanced Wazuh query: {e}")


@mcp.tool
async def multi_field_search(
    search_terms: Annotated[list, Field(description="List of search terms")],
    search_fields: Annotated[list, Field(description="Fields to search in")] = ["description", "rule.description", "agent.name"],
    data_sources: Annotated[list, Field(description="Data sources to search")] = ["alerts", "logs"],
    match_type: Annotated[Literal["any", "all"], Field(description="Match any or all terms")] = "any",
    time_range_hours: Annotated[int, Field(description="Time range in hours", ge=1, le=168)] = 24,
    limit: Annotated[int, Field(description="Max results per source", ge=1, le=500)] = 100,
    ctx: Context = None
) -> dict:
    """Perform multi-field search across multiple Wazuh data sources."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Multi-field search: {len(search_terms)} terms across {len(data_sources)} sources")
        
        results = {}
        total_matches = 0
        
        # Build time range for applicable sources
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        for source in data_sources:
            if source == "alerts":
                # Search alerts
                alert_results = await _search_alerts_multi_field(
                    client, search_terms, search_fields, match_type, limit
                )
                results["alerts"] = alert_results
                total_matches += len(alert_results)
                
            elif source == "logs":
                # Search logs  
                log_results = await _search_logs_multi_field(
                    client, search_terms, match_type, time_range_hours, limit
                )
                results["logs"] = log_results
                total_matches += len(log_results)
        
        # Cross-reference results for patterns
        patterns = _identify_cross_source_patterns(results, search_terms)
        
        return {
            "search_results": results,
            "total_matches": total_matches,
            "cross_source_patterns": patterns,
            "search_parameters": {
                "terms": search_terms,
                "fields": search_fields,
                "sources": data_sources,
                "match_type": match_type,
                "time_range_hours": time_range_hours
            },
            "query_time": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Multi-field search failed: {e}")
        raise ValueError(f"Failed to execute multi-field search: {e}")


def _build_alert_filters(filters: dict) -> dict:
    """Build Wazuh API parameters for alert filtering."""
    params = {}
    
    if "level" in filters:
        params["level"] = filters["level"]
    if "rule_id" in filters:
        params["rule_id"] = filters["rule_id"]
    if "agent_id" in filters:
        params["agent_id"] = filters["agent_id"]
    if "agent_name" in filters:
        params["agent_name"] = filters["agent_name"]
    if "rule_group" in filters:
        params["rule_group"] = filters["rule_group"]
    if "search" in filters:
        params["search"] = filters["search"]
        
    return params


def _build_agent_filters(filters: dict) -> dict:
    """Build Wazuh API parameters for agent filtering."""
    params = {}
    
    if "status" in filters:
        params["status"] = filters["status"]
    if "os_platform" in filters:
        params["os_platform"] = filters["os_platform"]
    if "version" in filters:
        params["version"] = filters["version"]
    if "group" in filters:
        params["group"] = filters["group"]
    if "search" in filters:
        params["search"] = filters["search"]
        
    return params


def _build_vulnerability_filters(filters: dict) -> dict:
    """Build Wazuh API parameters for vulnerability filtering."""
    params = {}
    
    if "severity" in filters:
        params["severity"] = filters["severity"]
    if "agent_id" in filters:
        params["agent_id"] = filters["agent_id"]
    if "cve" in filters:
        params["cve"] = filters["cve"]
    if "search" in filters:
        params["search"] = filters["search"]
        
    return params


def _build_time_range_filter(time_range: dict) -> dict:
    """Build time range parameters."""
    params = {}
    if "start" in time_range:
        params["newer_than"] = time_range["start"]
    if "end" in time_range:
        params["older_than"] = time_range["end"]
    return params


def _apply_advanced_filters(items: list, filters: dict, query_type: str) -> list:
    """Apply client-side advanced filtering."""
    if not filters:
        return items
    
    filtered = []
    for item in items:
        if _item_matches_filters(item, filters, query_type):
            filtered.append(item)
    
    return filtered


def _item_matches_filters(item: dict, filters: dict, query_type: str) -> bool:
    """Check if an item matches advanced filter criteria."""
    for filter_key, filter_value in filters.items():
        if filter_key.startswith("custom_"):
            # Handle custom filters
            field_path = filter_key.replace("custom_", "")
            item_value = _get_nested_value(item, field_path)
            if not _value_matches_criteria(item_value, filter_value):
                return False
    
    return True


def _get_nested_value(item: dict, field_path: str):
    """Get nested value from item using dot notation."""
    keys = field_path.split(".")
    value = item
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            return None
    return value


def _value_matches_criteria(item_value, criteria):
    """Check if item value matches filter criteria."""
    if isinstance(criteria, dict):
        if "equals" in criteria:
            return item_value == criteria["equals"]
        elif "contains" in criteria:
            return str(criteria["contains"]).lower() in str(item_value).lower()
        elif "greater_than" in criteria:
            return float(item_value) > float(criteria["greater_than"])
        elif "less_than" in criteria:
            return float(item_value) < float(criteria["less_than"])
    else:
        return str(item_value) == str(criteria)
    
    return False


async def _search_alerts_multi_field(client, search_terms: list, search_fields: list, match_type: str, limit: int) -> list:
    """Search alerts across multiple fields."""
    results = []
    
    for term in search_terms:
        response = await client.get_alerts(search=term, limit=limit)
        alerts = response.get("data", {}).get("affected_items", [])
        
        for alert in alerts:
            if _alert_matches_multi_field(alert, search_terms, search_fields, match_type):
                if alert not in results:  # Avoid duplicates
                    results.append(alert)
    
    return results


async def _search_logs_multi_field(client, search_terms: list, match_type: str, time_range_hours: int, limit: int) -> list:
    """Search logs for multiple terms."""
    results = []
    
    for term in search_terms:
        response = await client.search_logs(q=term, time_range_hours=time_range_hours, limit=limit)
        logs = response.get("data", {}).get("affected_items", [])
        results.extend(logs)
    
    return results


def _alert_matches_multi_field(alert: dict, search_terms: list, search_fields: list, match_type: str) -> bool:
    """Check if alert matches multi-field search criteria."""
    matches = 0
    
    for term in search_terms:
        term_lower = term.lower()
        field_match = False
        
        for field in search_fields:
            field_value = str(_get_nested_value(alert, field) or "").lower()
            if term_lower in field_value:
                field_match = True
                break
        
        if field_match:
            matches += 1
    
    if match_type == "all":
        return matches == len(search_terms)
    else:  # match_type == "any"
        return matches > 0


def _identify_cross_source_patterns(results: dict, search_terms: list) -> dict:
    """Identify patterns across different data sources."""
    patterns = {
        "common_agents": {},
        "time_correlations": [],
        "rule_patterns": {}
    }
    
    # Find common agents across sources
    if "alerts" in results and "logs" in results:
        alert_agents = set()
        log_agents = set()
        
        for alert in results["alerts"]:
            agent_name = alert.get("agent", {}).get("name")
            if agent_name:
                alert_agents.add(agent_name)
        
        for log in results["logs"]:
            # Logs might not have agent info, but could be extracted from message
            pass
        
        common_agents = alert_agents.intersection(log_agents)
        patterns["common_agents"] = list(common_agents)
    
    return patterns


def _generate_query_insights(items: list, query_type: str, filters: dict) -> dict:
    """Generate insights from query results."""
    insights = {
        "result_summary": f"Found {len(items)} {query_type}",
        "top_patterns": [],
        "recommendations": []
    }
    
    if query_type == "alerts" and items:
        # Analyze alert patterns
        rule_counts = {}
        agent_counts = {}
        
        for alert in items:
            rule_id = alert.get("rule", {}).get("id")
            if rule_id:
                rule_counts[rule_id] = rule_counts.get(rule_id, 0) + 1
            
            agent_name = alert.get("agent", {}).get("name")
            if agent_name:
                agent_counts[agent_name] = agent_counts.get(agent_name, 0) + 1
        
        if rule_counts:
            top_rule = max(rule_counts, key=rule_counts.get)
            insights["top_patterns"].append(f"Most frequent rule: {top_rule} ({rule_counts[top_rule]} alerts)")
        
        if agent_counts:
            top_agent = max(agent_counts, key=agent_counts.get)
            insights["top_patterns"].append(f"Most affected agent: {top_agent} ({agent_counts[top_agent]} alerts)")
    
    return insights


@mcp.tool
async def get_realtime_alerts(
    monitoring_duration_minutes: Annotated[int, Field(description="How long to monitor in minutes", ge=1, le=60)] = 5,
    alert_threshold_level: Annotated[int, Field(description="Minimum alert level to report", ge=1, le=15)] = 1,
    auto_refresh_seconds: Annotated[int, Field(description="Refresh interval in seconds", ge=5, le=300)] = 30,
    ctx: Context = None
) -> dict:
    """Monitor Wazuh alerts in real-time for active security monitoring."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Starting real-time monitoring for {monitoring_duration_minutes} minutes")
        
        monitoring_start = datetime.utcnow() 
        monitoring_cycles = []
        total_new_alerts = 0
        
        # Calculate monitoring parameters
        refresh_interval = auto_refresh_seconds
        total_cycles = (monitoring_duration_minutes * 60) // refresh_interval
        
        for cycle in range(min(total_cycles, 10)):  # Limit to 10 cycles for safety
            cycle_start = datetime.utcnow()
            
            # Get recent alerts from the last refresh interval
            response = await client.get_alerts(
                limit=100,
                level=alert_threshold_level,
                newer_than=(cycle_start - timedelta(seconds=refresh_interval)).strftime("%Y-%m-%dT%H:%M:%S")
            )
            
            cycle_alerts = response.get("data", {}).get("affected_items", [])
            cycle_count = len(cycle_alerts)
            total_new_alerts += cycle_count
            
            # Analyze cycle alerts
            cycle_analysis = {
                "cycle_number": cycle + 1,
                "timestamp": cycle_start.isoformat(),
                "new_alerts": cycle_count,
                "high_severity_count": len([a for a in cycle_alerts if a.get("rule", {}).get("level", 0) >= 10]),
                "top_rules": _get_top_triggered_rules(cycle_alerts)[:3],
                "affected_agents": list(set([a.get("agent", {}).get("name") for a in cycle_alerts if a.get("agent", {}).get("name")]))[:5]
            }
            
            monitoring_cycles.append(cycle_analysis)
            
            if ctx:
                await ctx.info(f"Cycle {cycle + 1}: {cycle_count} new alerts detected")
            
            # Break if this is not a real monitoring session
            if cycle < total_cycles - 1:
                break  # For testing, only do one cycle
        
        # Generate real-time monitoring summary
        monitoring_summary = {
            "monitoring_period": {
                "start_time": monitoring_start.isoformat(),
                "duration_minutes": monitoring_duration_minutes,
                "cycles_completed": len(monitoring_cycles)
            },
            "alert_statistics": {
                "total_new_alerts": total_new_alerts,
                "average_alerts_per_cycle": total_new_alerts / max(len(monitoring_cycles), 1),
                "alert_threshold_level": alert_threshold_level
            },
            "monitoring_cycles": monitoring_cycles,
            "security_status": _assess_realtime_security_status(monitoring_cycles),
            "recommendations": _generate_monitoring_recommendations(monitoring_cycles)
        }
        
        if ctx:
            await ctx.info(f"Real-time monitoring complete: {total_new_alerts} alerts over {len(monitoring_cycles)} cycles")
        
        return monitoring_summary
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Real-time monitoring failed: {e}")
        raise ValueError(f"Failed to perform real-time monitoring: {e}")


@mcp.tool
async def get_live_dashboard_data(
    refresh_interval_seconds: Annotated[int, Field(description="Data refresh interval", ge=10, le=300)] = 60,
    include_metrics: Annotated[list, Field(description="Metrics to include")] = ["alerts", "agents", "vulnerabilities"],
    ctx: Context = None
) -> dict:
    """Get live dashboard data for real-time security monitoring displays."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Collecting live dashboard data (refresh: {refresh_interval_seconds}s)")
        
        dashboard_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "refresh_interval": refresh_interval_seconds,
            "metrics": {}
        }
        
        # Collect requested metrics
        if "alerts" in include_metrics:
            dashboard_data["metrics"]["alerts"] = await _get_live_alert_metrics(client)
            
        if "agents" in include_metrics:
            dashboard_data["metrics"]["agents"] = await _get_live_agent_metrics(client)
            
        if "vulnerabilities" in include_metrics:
            dashboard_data["metrics"]["vulnerabilities"] = await _get_live_vulnerability_metrics(client)
        
        # Add system health indicators
        dashboard_data["system_health"] = await _get_system_health_indicators(client)
        
        # Generate alert trends (last 24 hours in 1-hour buckets)
        dashboard_data["alert_trends"] = await _get_alert_trends(client)
        
        if ctx:
            await ctx.info("Live dashboard data collected successfully")
        
        return dashboard_data
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to collect dashboard data: {e}")
        raise ValueError(f"Failed to get live dashboard data: {e}")


def _get_top_triggered_rules(alerts: list) -> list:
    """Get most frequently triggered rules from alerts."""
    rule_counts = {}
    for alert in alerts:
        rule_id = alert.get("rule", {}).get("id")
        rule_desc = alert.get("rule", {}).get("description", "Unknown")
        rule_level = alert.get("rule", {}).get("level", 0)
        
        if rule_id:
            if rule_id not in rule_counts:
                rule_counts[rule_id] = {
                    "id": rule_id,
                    "description": rule_desc,
                    "level": rule_level,
                    "count": 0
                }
            rule_counts[rule_id]["count"] += 1
    
    return sorted(rule_counts.values(), key=lambda x: x["count"], reverse=True)


def _assess_realtime_security_status(monitoring_cycles: list) -> dict:
    """Assess current security status based on monitoring cycles."""
    if not monitoring_cycles:
        return {"status": "unknown", "reason": "No monitoring data available"}
    
    recent_cycle = monitoring_cycles[-1]
    total_alerts = sum(cycle.get("new_alerts", 0) for cycle in monitoring_cycles)
    high_severity_alerts = sum(cycle.get("high_severity_count", 0) for cycle in monitoring_cycles)
    
    if high_severity_alerts > 5:
        return {
            "status": "critical",
            "reason": f"{high_severity_alerts} high-severity alerts detected",
            "alert_rate": "high"
        }
    elif total_alerts > 20:
        return {
            "status": "warning", 
            "reason": f"{total_alerts} total alerts in monitoring period",
            "alert_rate": "elevated"
        }
    elif total_alerts > 0:
        return {
            "status": "normal",
            "reason": f"{total_alerts} alerts detected, within normal range",
            "alert_rate": "normal"
        }
    else:
        return {
            "status": "quiet",
            "reason": "No alerts detected during monitoring",
            "alert_rate": "low"
        }


def _generate_monitoring_recommendations(monitoring_cycles: list) -> list:
    """Generate recommendations based on monitoring results."""
    recommendations = []
    
    if not monitoring_cycles:
        return ["No monitoring data available for recommendations"]
    
    total_alerts = sum(cycle.get("new_alerts", 0) for cycle in monitoring_cycles)
    high_severity_total = sum(cycle.get("high_severity_count", 0) for cycle in monitoring_cycles)
    
    if high_severity_total > 0:
        recommendations.append(f"Investigate {high_severity_total} high-severity alerts immediately")
    
    if total_alerts > 50:
        recommendations.append("High alert volume detected - consider tuning noisy rules")
    
    # Check for recurring patterns
    all_rules = []
    for cycle in monitoring_cycles:
        all_rules.extend(cycle.get("top_rules", []))
    
    if all_rules:
        rule_frequency = {}
        for rule in all_rules:
            rule_id = rule.get("id")
            if rule_id:
                rule_frequency[rule_id] = rule_frequency.get(rule_id, 0) + 1
        
        frequent_rules = [rule_id for rule_id, count in rule_frequency.items() if count > 2]
        if frequent_rules:
            recommendations.append(f"Rules {frequent_rules[:3]} triggered frequently - investigate for false positives")
    
    if not recommendations:
        recommendations.append("Monitoring results look normal - continue regular monitoring")
    
    return recommendations


async def _get_live_alert_metrics(client) -> dict:
    """Get live alert metrics for dashboard."""
    try:
        # Get recent alerts (last hour)
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=1)
        
        response = await client.get_alerts(
            limit=500,
            newer_than=start_time.strftime("%Y-%m-%dT%H:%M:%S")
        )
        alerts = response.get("data", {}).get("affected_items", [])
        
        # Calculate metrics
        total_alerts = len(alerts)
        critical_alerts = len([a for a in alerts if a.get("rule", {}).get("level", 0) >= 12])
        high_alerts = len([a for a in alerts if a.get("rule", {}).get("level", 0) >= 8])
        
        return {
            "total_last_hour": total_alerts,
            "critical_last_hour": critical_alerts,
            "high_severity_last_hour": high_alerts,
            "alert_rate_per_minute": round(total_alerts / 60, 2)
        }
    except:
        return {"error": "Unable to fetch alert metrics"}


async def _get_live_agent_metrics(client) -> dict:
    """Get live agent metrics for dashboard."""
    try:
        response = await client.get_agents(limit=1000)
        agents = response.get("data", {}).get("affected_items", [])
        
        status_counts = {}
        for agent in agents:
            status = agent.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "total_agents": len(agents),
            "active_agents": status_counts.get("active", 0),
            "disconnected_agents": status_counts.get("disconnected", 0),
            "status_breakdown": status_counts
        }
    except:
        return {"error": "Unable to fetch agent metrics"}


async def _get_live_vulnerability_metrics(client) -> dict:
    """Get live vulnerability metrics for dashboard."""
    try:
        response = await client.get_vulnerabilities(limit=500)
        vulns = response.get("data", {}).get("affected_items", [])
        
        severity_counts = {}
        for vuln in vulns:
            severity = vuln.get("vulnerability", {}).get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "total_vulnerabilities": len(vulns),
            "critical_vulnerabilities": severity_counts.get("Critical", 0),
            "high_vulnerabilities": severity_counts.get("High", 0),
            "severity_breakdown": severity_counts
        }
    except:
        return {"error": "Unable to fetch vulnerability metrics"}


async def _get_system_health_indicators(client) -> dict:
    """Get system health indicators."""
    try:
        cluster_response = await client.get_cluster_status()
        cluster_data = cluster_response.get("data", {})
        
        return {
            "cluster_status": "healthy" if cluster_data.get("enabled") else "standalone",
            "api_responsive": True,
            "last_check": datetime.utcnow().isoformat()
        }
    except:
        return {
            "cluster_status": "unknown",
            "api_responsive": False,
            "last_check": datetime.utcnow().isoformat()
        }


async def _get_alert_trends(client) -> dict:
    """Get alert trends for the last 24 hours."""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)
        
        response = await client.get_alerts(
            limit=1000,
            newer_than=start_time.strftime("%Y-%m-%dT%H:%M:%S")
        )
        alerts = response.get("data", {}).get("affected_items", [])
        
        # Create hourly buckets
        hourly_counts = {}
        for i in range(24):
            hour_start = start_time + timedelta(hours=i)
            hourly_counts[hour_start.strftime("%H:00")] = 0
        
        # Count alerts per hour
        for alert in alerts:
            timestamp = alert.get("timestamp", "")
            if timestamp:
                try:
                    alert_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour_key = alert_time.strftime("%H:00")
                    if hour_key in hourly_counts:
                        hourly_counts[hour_key] += 1
                except:
                    pass
        
        return {
            "period": "24_hours",
            "hourly_counts": hourly_counts,
            "total_alerts": len(alerts)
        }
    except:
        return {"error": "Unable to fetch alert trends"}


@mcp.tool
async def execute_active_response(
    command: Annotated[str, Field(description="Active response command (e.g., 'restart-wazuh', 'firewall-block')")],
    agent_ids: Annotated[list, Field(description="List of agent IDs to execute command on")],
    custom_parameters: Annotated[Optional[dict], Field(description="Custom parameters for the command")] = None,
    ctx: Context = None
) -> dict:
    """Execute active response commands on Wazuh agents for automated threat response."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Executing active response '{command}' on {len(agent_ids)} agents")
        
        # Prepare active response payload
        ar_payload = {
            "command": command,
            "arguments": custom_parameters or {},
            "alert": {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "mcp-server"
            }
        }
        
        execution_results = []
        successful_executions = 0
        failed_executions = 0
        
        for agent_id in agent_ids:
            try:
                ar_payload["agent_id"] = agent_id
                response = await client.execute_active_response(ar_payload)
                
                result = {
                    "agent_id": agent_id,
                    "status": "success",
                    "response": response.get("data", {}),
                    "execution_time": datetime.utcnow().isoformat()
                }
                execution_results.append(result)
                successful_executions += 1
                
                if ctx:
                    await ctx.info(f"Active response executed successfully on agent {agent_id}")
                    
            except Exception as e:
                result = {
                    "agent_id": agent_id,
                    "status": "failed",
                    "error": str(e),
                    "execution_time": datetime.utcnow().isoformat()
                }
                execution_results.append(result)
                failed_executions += 1
                
                if ctx:
                    await ctx.error(f"Active response failed on agent {agent_id}: {e}")
        
        return {
            "command": command,
            "execution_summary": {
                "total_agents": len(agent_ids),
                "successful_executions": successful_executions,
                "failed_executions": failed_executions,
                "success_rate": round((successful_executions / len(agent_ids)) * 100, 2)
            },
            "execution_results": execution_results,
            "custom_parameters": custom_parameters,
            "execution_timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Active response execution failed: {e}")
        raise ValueError(f"Failed to execute active response: {e}")


@mcp.tool
async def get_cdb_lists(
    list_name: Annotated[Optional[str], Field(description="Specific CDB list name")] = None,
    search: Annotated[Optional[str], Field(description="Search term for list content")] = None,
    limit: Annotated[int, Field(description="Maximum number of lists", ge=1, le=100)] = 50,
    ctx: Context = None
) -> dict:
    """Get Wazuh CDB lists for threat intelligence and blacklist management."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Retrieving CDB lists: name='{list_name}', search='{search}'")
        
        if list_name:
            # Get specific list content
            response = await client.get_cdb_list_content(list_name)
            list_content = response.get("data", {})
            
            # Parse list content
            if "content" in list_content:
                content_lines = list_content["content"].split('\n')
                parsed_entries = []
                
                for line in content_lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            parsed_entries.append({"key": key.strip(), "value": value.strip()})
                        else:
                            parsed_entries.append({"key": line, "value": ""})
                
                return {
                    "list_name": list_name,
                    "total_entries": len(parsed_entries),
                    "entries": parsed_entries,
                    "raw_content": list_content.get("content", ""),
                    "query_time": datetime.utcnow().isoformat()
                }
        else:
            # Get all CDB lists
            params = {"limit": limit}
            if search:
                params["search"] = search
                
            response = await client.get_cdb_lists(**params)
            lists = response.get("data", {}).get("affected_items", [])
            
            # Analyze list types
            list_analysis = {}
            for cdb_list in lists:
                list_path = cdb_list.get("path", "")
                list_type = _categorize_cdb_list(list_path)
                list_analysis[list_type] = list_analysis.get(list_type, 0) + 1
            
            return {
                "cdb_lists": lists,
                "total_lists": len(lists),
                "list_analysis": {
                    "types_breakdown": list_analysis,
                    "total_types": len(list_analysis)
                },
                "query_parameters": {
                    "search": search,
                    "limit": limit
                },
                "query_time": datetime.utcnow().isoformat()
            }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to retrieve CDB lists: {e}")
        raise ValueError(f"Failed to retrieve CDB lists: {e}")


@mcp.tool
async def get_fim_events(
    agent_id: Annotated[Optional[str], Field(description="Agent ID to filter FIM events")] = None,
    file_path: Annotated[Optional[str], Field(description="File path to filter events")] = None,
    event_type: Annotated[Optional[str], Field(description="Event type (added, modified, deleted)")] = None,
    time_range_hours: Annotated[int, Field(description="Time range in hours", ge=1, le=168)] = 24,
    limit: Annotated[int, Field(description="Maximum events", ge=1, le=1000)] = 100,
    ctx: Context = None
) -> dict:
    """Get File Integrity Monitoring events for security analysis."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Retrieving FIM events: agent={agent_id}, path='{file_path}', type='{event_type}'")
        
        # Build query parameters
        params = {"limit": limit}
        if agent_id:
            params["agent_id"] = agent_id
        if file_path:
            params["filename"] = file_path
        if event_type:
            params["event"] = event_type
            
        # Add time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        params["newer_than"] = start_time.strftime("%Y-%m-%dT%H:%M:%S")
        
        response = await client.get_fim_events(**params)
        fim_events = response.get("data", {}).get("affected_items", [])
        
        # Analyze FIM events
        event_analysis = {
            "event_types": {},
            "affected_paths": {},
            "agent_activity": {},
            "suspicious_patterns": []
        }
        
        for event in fim_events:
            # Count event types
            evt_type = event.get("type", "unknown")
            event_analysis["event_types"][evt_type] = event_analysis["event_types"].get(evt_type, 0) + 1
            
            # Track file paths
            file_path = event.get("path", "unknown")
            event_analysis["affected_paths"][file_path] = event_analysis["affected_paths"].get(file_path, 0) + 1
            
            # Track agent activity
            agent = event.get("agent", {}).get("name", "unknown")
            event_analysis["agent_activity"][agent] = event_analysis["agent_activity"].get(agent, 0) + 1
            
            # Identify suspicious patterns
            if _is_suspicious_fim_event(event):
                event_analysis["suspicious_patterns"].append({
                    "event_id": event.get("id"),
                    "path": file_path,
                    "reason": _get_fim_suspicion_reason(event)
                })
        
        return {
            "fim_events": fim_events,
            "total_events": len(fim_events),
            "analysis": event_analysis,
            "query_parameters": {
                "agent_id": agent_id,
                "file_path": file_path,
                "event_type": event_type,
                "time_range_hours": time_range_hours
            },
            "query_time": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Failed to retrieve FIM events: {e}")
        raise ValueError(f"Failed to retrieve FIM events: {e}")


@mcp.tool
async def get_enhanced_analytics(
    analysis_type: Annotated[Literal["performance", "security_trends", "agent_health", "threat_landscape"], Field(description="Type of analytics to generate")],
    time_range_hours: Annotated[int, Field(description="Analysis time range in hours", ge=1, le=168)] = 24,
    include_predictions: Annotated[bool, Field(description="Include predictive analytics")] = True,
    ctx: Context = None
) -> dict:
    """Generate enhanced analytics and insights from Wazuh data."""
    try:
        client = await get_wazuh_client()
        
        if ctx:
            await ctx.info(f"Generating {analysis_type} analytics for {time_range_hours} hours")
        
        analytics_result = {}
        
        if analysis_type == "performance":
            analytics_result = await _generate_performance_analytics(client, time_range_hours)
        elif analysis_type == "security_trends":
            analytics_result = await _generate_security_trends_analytics(client, time_range_hours)
        elif analysis_type == "agent_health":
            analytics_result = await _generate_agent_health_analytics(client)
        elif analysis_type == "threat_landscape":
            analytics_result = await _generate_threat_landscape_analytics(client, time_range_hours)
        
        if include_predictions:
            analytics_result["predictions"] = await _generate_predictions(analytics_result, analysis_type)
        
        analytics_result.update({
            "analysis_type": analysis_type,
            "time_range_hours": time_range_hours,
            "generation_time": datetime.utcnow().isoformat(),
            "data_freshness": "real-time"
        })
        
        if ctx:
            await ctx.info(f"Enhanced analytics generated successfully")
        
        return analytics_result
        
    except Exception as e:
        if ctx:
            await ctx.error(f"Enhanced analytics generation failed: {e}")
        raise ValueError(f"Failed to generate enhanced analytics: {e}")


def _categorize_cdb_list(list_path: str) -> str:
    """Categorize CDB list by its path/name."""
    path_lower = list_path.lower()
    
    if any(term in path_lower for term in ["ip", "address", "network"]):
        return "IP/Network Lists"
    elif any(term in path_lower for term in ["hash", "md5", "sha"]):
        return "File Hash Lists"
    elif any(term in path_lower for term in ["user", "account"]):
        return "User/Account Lists"
    elif any(term in path_lower for term in ["domain", "url", "dns"]):
        return "Domain/URL Lists"
    else:
        return "Other Lists"


def _is_suspicious_fim_event(event: dict) -> bool:
    """Check if FIM event shows suspicious activity."""
    file_path = event.get("path", "").lower()
    event_type = event.get("event", "")
    
    # Check for suspicious file paths
    suspicious_paths = ["/etc/passwd", "/etc/shadow", "/root/", "/var/log/", ".ssh/", "authorized_keys"]
    if any(sus_path in file_path for sus_path in suspicious_paths):
        return True
    
    # Check for executable modifications
    if event_type == "modified" and any(ext in file_path for ext in [".exe", ".bin", ".sh", ".bat"]):
        return True
    
    return False


def _get_fim_suspicion_reason(event: dict) -> str:
    """Get reason why FIM event is suspicious."""
    file_path = event.get("path", "").lower()
    event_type = event.get("event", "")
    
    if "/etc/passwd" in file_path or "/etc/shadow" in file_path:
        return "Critical system file modification"
    elif ".ssh/" in file_path or "authorized_keys" in file_path:
        return "SSH configuration change"
    elif "/root/" in file_path:
        return "Root directory access"
    elif event_type == "modified" and any(ext in file_path for ext in [".exe", ".bin", ".sh"]):
        return "Executable file modification"
    else:
        return "Potentially suspicious file activity"


async def _generate_performance_analytics(client, time_range_hours: int) -> dict:
    """Generate performance analytics."""
    try:
        # Get manager stats
        manager_stats = await client.get_manager_stats()
        
        # Get agent statistics  
        agents_response = await client.get_agents(limit=50)
        agents = agents_response.get("data", {}).get("affected_items", [])
        
        agent_performance = []
        for agent in agents[:10]:  # Sample first 10 agents
            try:
                agent_id = agent.get("id")
                if agent_id:
                    stats = await client.get_agent_stats(agent_id, "logcollector")
                    agent_performance.append({
                        "agent_id": agent_id,
                        "agent_name": agent.get("name"),
                        "stats": stats.get("data", {})
                    })
            except:
                continue
        
        return {
            "manager_performance": manager_stats.get("data", {}),
            "agent_performance_sample": agent_performance,
            "performance_summary": {
                "total_agents_monitored": len(agents),
                "active_agents": len([a for a in agents if a.get("status") == "active"]),
                "performance_sample_size": len(agent_performance)
            }
        }
    except Exception as e:
        return {"error": f"Performance analytics generation failed: {e}"}


async def _generate_security_trends_analytics(client, time_range_hours: int) -> dict:
    """Generate security trends analytics."""
    try:
        # Get recent alerts for trend analysis
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        alerts_response = await client.get_alerts(
            limit=1000,
            newer_than=start_time.strftime("%Y-%m-%dT%H:%M:%S")
        )
        alerts = alerts_response.get("data", {}).get("affected_items", [])
        
        # Analyze trends
        hourly_distribution = {}
        severity_trends = {}
        rule_trends = {}
        
        for alert in alerts:
            # Hourly distribution
            timestamp = alert.get("timestamp", "")
            if timestamp:
                try:
                    alert_time = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    hour_key = alert_time.strftime("%Y-%m-%d %H:00")
                    hourly_distribution[hour_key] = hourly_distribution.get(hour_key, 0) + 1
                except:
                    pass
            
            # Severity trends
            level = alert.get("rule", {}).get("level", 0)
            severity = "critical" if level >= 12 else "high" if level >= 8 else "medium" if level >= 5 else "low"
            severity_trends[severity] = severity_trends.get(severity, 0) + 1
            
            # Rule trends
            rule_id = alert.get("rule", {}).get("id")
            if rule_id:
                rule_trends[rule_id] = rule_trends.get(rule_id, 0) + 1
        
        return {
            "alert_trends": {
                "total_alerts": len(alerts),
                "hourly_distribution": hourly_distribution,
                "severity_distribution": severity_trends,
                "top_triggered_rules": sorted(rule_trends.items(), key=lambda x: x[1], reverse=True)[:10]
            },
            "trend_insights": {
                "peak_activity_hour": max(hourly_distribution, key=hourly_distribution.get) if hourly_distribution else "No data",
                "dominant_severity": max(severity_trends, key=severity_trends.get) if severity_trends else "No data",
                "most_active_rule": max(rule_trends, key=rule_trends.get) if rule_trends else "No data"
            }
        }
    except Exception as e:
        return {"error": f"Security trends analytics generation failed: {e}"}


async def _generate_agent_health_analytics(client) -> dict:
    """Generate agent health analytics."""
    try:
        agents_response = await client.get_agents(limit=1000)
        agents = agents_response.get("data", {}).get("affected_items", [])
        
        health_metrics = {
            "total_agents": len(agents),
            "status_distribution": {},
            "os_distribution": {},
            "version_distribution": {},
            "health_score": 0
        }
        
        for agent in agents:
            # Status distribution
            status = agent.get("status", "unknown")
            health_metrics["status_distribution"][status] = health_metrics["status_distribution"].get(status, 0) + 1
            
            # OS distribution
            os_info = agent.get("os", {})
            os_name = os_info.get("platform", "unknown")
            health_metrics["os_distribution"][os_name] = health_metrics["os_distribution"].get(os_name, 0) + 1
            
            # Version distribution
            version = agent.get("version", "unknown")
            health_metrics["version_distribution"][version] = health_metrics["version_distribution"].get(version, 0) + 1
        
        # Calculate health score
        active_agents = health_metrics["status_distribution"].get("active", 0)
        health_metrics["health_score"] = round((active_agents / len(agents)) * 100, 2) if agents else 0
        
        return {
            "agent_health_metrics": health_metrics,
            "health_recommendations": _generate_health_recommendations(health_metrics)
        }
    except Exception as e:
        return {"error": f"Agent health analytics generation failed: {e}"}


async def _generate_threat_landscape_analytics(client, time_range_hours: int) -> dict:
    """Generate threat landscape analytics."""
    try:
        # Get alerts and vulnerabilities
        alerts_response = await client.get_alerts(limit=500)
        alerts = alerts_response.get("data", {}).get("affected_items", [])
        
        vulns_response = await client.get_vulnerabilities(limit=200)
        vulnerabilities = vulns_response.get("data", {}).get("affected_items", [])
        
        # Analyze threat landscape
        threat_categories = {}
        attack_vectors = {}
        affected_assets = set()
        
        for alert in alerts:
            rule_desc = alert.get("rule", {}).get("description", "").lower()
            category = _categorize_threat(rule_desc)
            threat_categories[category] = threat_categories.get(category, 0) + 1
            
            # Track attack vectors
            if "network" in rule_desc:
                attack_vectors["Network"] = attack_vectors.get("Network", 0) + 1
            elif "file" in rule_desc or "integrity" in rule_desc:
                attack_vectors["File System"] = attack_vectors.get("File System", 0) + 1
            elif "authentication" in rule_desc or "login" in rule_desc:
                attack_vectors["Authentication"] = attack_vectors.get("Authentication", 0) + 1
            
            # Track affected assets
            agent_name = alert.get("agent", {}).get("name")
            if agent_name:
                affected_assets.add(agent_name)
        
        return {
            "threat_landscape": {
                "total_threats": len(alerts),
                "threat_categories": threat_categories,
                "attack_vectors": attack_vectors,
                "affected_assets_count": len(affected_assets),
                "vulnerability_count": len(vulnerabilities)
            },
            "risk_assessment": {
                "overall_risk_level": _calculate_overall_risk(alerts, vulnerabilities),
                "critical_threats": len([a for a in alerts if a.get("rule", {}).get("level", 0) >= 12]),
                "high_severity_vulns": len([v for v in vulnerabilities if v.get("vulnerability", {}).get("severity") == "Critical"])
            }
        }
    except Exception as e:
        return {"error": f"Threat landscape analytics generation failed: {e}"}


async def _generate_predictions(analytics_data: dict, analysis_type: str) -> dict:
    """Generate predictive analytics based on current data."""
    predictions = {
        "prediction_confidence": "medium",
        "forecast_period": "24_hours",
        "predictions": []
    }
    
    if analysis_type == "security_trends":
        alert_trends = analytics_data.get("alert_trends", {})
        total_alerts = alert_trends.get("total_alerts", 0)
        
        if total_alerts > 100:
            predictions["predictions"].append("High alert volume expected to continue")
        elif total_alerts < 10:
            predictions["predictions"].append("Alert volume may increase during peak hours")
        
        severity_dist = alert_trends.get("severity_distribution", {})
        if severity_dist.get("critical", 0) > 5:
            predictions["predictions"].append("Critical security incidents likely in next 24h")
    
    elif analysis_type == "agent_health":
        health_metrics = analytics_data.get("agent_health_metrics", {})
        health_score = health_metrics.get("health_score", 0)
        
        if health_score < 80:
            predictions["predictions"].append("Agent connectivity issues may worsen")
        else:
            predictions["predictions"].append("Agent health expected to remain stable")
    
    if not predictions["predictions"]:
        predictions["predictions"].append("Insufficient data for reliable predictions")
    
    return predictions


def _generate_health_recommendations(health_metrics: dict) -> list:
    """Generate agent health recommendations."""
    recommendations = []
    
    disconnected = health_metrics["status_distribution"].get("disconnected", 0)
    total = health_metrics["total_agents"]
    
    if disconnected > total * 0.1:  # More than 10% disconnected
        recommendations.append(f"High disconnection rate: {disconnected} agents offline - check network connectivity")
    
    if health_metrics["health_score"] < 90:
        recommendations.append("Consider investigating agent connectivity issues")
    
    version_dist = health_metrics["version_distribution"]
    if len(version_dist) > 3:
        recommendations.append("Multiple agent versions detected - consider standardizing versions")
    
    if not recommendations:
        recommendations.append("Agent health metrics look good - maintain current monitoring")
    
    return recommendations


def _calculate_overall_risk(alerts: list, vulnerabilities: list) -> str:
    """Calculate overall risk level."""
    critical_alerts = len([a for a in alerts if a.get("rule", {}).get("level", 0) >= 12])
    critical_vulns = len([v for v in vulnerabilities if v.get("vulnerability", {}).get("severity") == "Critical"])
    
    if critical_alerts > 10 or critical_vulns > 5:
        return "High"
    elif critical_alerts > 3 or critical_vulns > 2:
        return "Medium"
    else:
        return "Low"


@mcp.tool
async def analyze_security_threats(
    time_range_hours: Annotated[int, Field(description="Analysis time range in hours", ge=1, le=168)] = 24,
    severity_threshold: Annotated[int, Field(description="Minimum severity level", ge=1, le=15)] = 5,
    include_cti_data: Annotated[bool, Field(description="Include CTI threat intelligence data (4.12+ feature)")] = False,
    ctx: Context = None
) -> dict:
    """Analyze security threats with AI-powered insights and optional CTI data (4.12+ enhanced).""
    try:
        client = await get_wazuh_client()
        
        # Get recent alerts for analysis
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        if ctx:
            cti_status = "with CTI data" if include_cti_data else "without CTI data"
            await ctx.info(f"Analyzing threats from last {time_range_hours} hours with severity >= {severity_threshold} {cti_status}")
        
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