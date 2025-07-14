#!/usr/bin/env python3
"""
Wazuh MCP Server for Claude Desktop Integration - Production Edition
-------------------------------------------------------------------
Production-grade MCP server with advanced security analysis capabilities,
comprehensive validation, and enterprise-ready features.
"""

import os
import sys
import json
import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from pathlib import Path

import urllib3
from mcp.server import Server, NotificationOptions
from mcp.server.models import InitializationOptions
import mcp.server.stdio
import mcp.types as types

# Clean absolute imports within the package
from wazuh_mcp_server.config import WazuhConfig, ComplianceFramework
from wazuh_mcp_server.__version__ import __version__
from wazuh_mcp_server.api.wazuh_client_manager import WazuhClientManager
from wazuh_mcp_server.analyzers import SecurityAnalyzer, ComplianceAnalyzer
from wazuh_mcp_server.utils import (
    setup_logging, get_logger, LogContext,
    validate_alert_query, validate_agent_query, validate_threat_analysis,
    validate_ip_address, validate_file_hash, ValidationError,
    WazuhMCPError, ConfigurationError, APIError
)

# SSL warnings will be disabled per-request basis in clients if needed
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # SECURITY: Removed global disable


class WazuhMCPServer:
    """Production-grade MCP Server implementation for Wazuh integration."""
    
    def __init__(self):
        # Initialize configuration first
        try:
            self.config = WazuhConfig.from_env()
        except Exception:
            raise ConfigurationError(f"Failed to load configuration: {str(e)}") from e
        
        # Setup logging with configuration
        self.logger = setup_logging(
            log_level=self.config.log_level,
            log_dir="logs" if not self.config.debug else None,
            enable_structured=True,
            enable_rotation=True
        )
        
        self.logger.info(f"Initializing Wazuh MCP Server v{__version__}")
        
        # Initialize components
        self.server = Server("wazuh-mcp")
        self.api_client = WazuhClientManager(self.config)
        self.security_analyzer = SecurityAnalyzer()
        self.compliance_analyzer = ComplianceAnalyzer()
        
        # Setup handlers
        self._setup_handlers()
        
        self.logger.info("Wazuh MCP Server initialized successfully")
    
    def _format_error_response(self, error: Exception, request_id: str = None, 
                               execution_time: float = None) -> str:
        """Format error response consistently."""
        error_data = {
            "error": str(error),
            "error_type": type(error).__name__
        }
        
        if request_id:
            error_data["request_id"] = request_id
        
        if execution_time is not None:
            error_data["execution_time"] = round(execution_time, 2)
        
        error_data["timestamp"] = datetime.utcnow().isoformat()
        
        return json.dumps(error_data, indent=2)
    
    async def initialize_connections(self):
        """Initialize connections and detect Wazuh version."""
        try:
            async with self.api_client as client:
                version = await client.detect_wazuh_version()
                if version:
                    self.logger.info(f"Connected to Wazuh {version}")
                else:
                    self.logger.warning("Could not detect Wazuh version")
        except Exception:
            self.logger.error(f"Failed to initialize connections: {str(e)}")
    
    def _setup_handlers(self):
        """Setup MCP protocol handlers with production-grade capabilities."""
        
        @self.server.list_resources()
        async def handle_list_resources() -> list[types.Resource]:
            """List available Wazuh resources."""
            return [
                types.Resource(
                    uri="wazuh://alerts/recent",
                    name="Recent Alerts",
                    description="Most recent security alerts from Wazuh",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://alerts/summary",
                    name="Alert Summary",
                    description="Statistical summary of alerts",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://agents/status",
                    name="Agent Status",
                    description="Status of all Wazuh agents",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://vulnerabilities/critical",
                    name="Critical Vulnerabilities",
                    description="Critical vulnerabilities across all agents",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://compliance/status",
                    name="Compliance Status",
                    description="Current compliance posture",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://threats/active",
                    name="Active Threats",
                    description="Currently active threat indicators",
                    mimeType="application/json"
                ),
                types.Resource(
                    uri="wazuh://system/health",
                    name="System Health",
                    description="Overall system health metrics",
                    mimeType="application/json"
                )
            ]
        
        @self.server.list_prompts()
        async def handle_list_prompts() -> list[types.Prompt]:
            """List available security analysis prompts."""
            return [
                types.Prompt(
                    name="security-incident-analysis",
                    description="Analyze a security incident from Wazuh alerts with comprehensive investigation steps",
                    arguments=[
                        types.PromptArgument(
                            name="alert_id",
                            description="The ID of the alert to analyze",
                            required=True
                        ),
                        types.PromptArgument(
                            name="include_context",
                            description="Include surrounding context and related alerts",
                            required=False
                        )
                    ]
                ),
                types.Prompt(
                    name="threat-hunting-query",
                    description="Generate threat hunting queries based on IOCs and attack patterns",
                    arguments=[
                        types.PromptArgument(
                            name="threat_type",
                            description="Type of threat to hunt for (malware, intrusion, data_exfiltration, etc.)",
                            required=True
                        ),
                        types.PromptArgument(
                            name="time_range",
                            description="Time range for the hunt (e.g., '24h', '7d', '30d')",
                            required=False
                        ),
                        types.PromptArgument(
                            name="target_agents",
                            description="Specific agents to focus on (comma-separated IDs)",
                            required=False
                        )
                    ]
                ),
                types.Prompt(
                    name="compliance-assessment",
                    description="Perform a comprehensive compliance assessment against security frameworks",
                    arguments=[
                        types.PromptArgument(
                            name="framework",
                            description="Compliance framework (pci_dss, hipaa, gdpr, nist, iso27001)",
                            required=True
                        ),
                        types.PromptArgument(
                            name="scope",
                            description="Assessment scope (full, critical_controls, specific_section)",
                            required=False
                        )
                    ]
                ),
                types.Prompt(
                    name="security-report-generation",
                    description="Generate executive security reports with recommendations",
                    arguments=[
                        types.PromptArgument(
                            name="report_type",
                            description="Type of report (executive, technical, compliance, incident)",
                            required=True
                        ),
                        types.PromptArgument(
                            name="time_period",
                            description="Reporting period (daily, weekly, monthly, quarterly)",
                            required=False
                        ),
                        types.PromptArgument(
                            name="audience",
                            description="Target audience (executives, security_team, compliance_team)",
                            required=False
                        )
                    ]
                ),
                types.Prompt(
                    name="vulnerability-prioritization",
                    description="Prioritize vulnerabilities based on risk, exploitability, and business impact",
                    arguments=[
                        types.PromptArgument(
                            name="severity_threshold",
                            description="Minimum severity level (low, medium, high, critical)",
                            required=False
                        ),
                        types.PromptArgument(
                            name="asset_criticality",
                            description="Focus on assets with specific criticality (low, medium, high, critical)",
                            required=False
                        )
                    ]
                ),
                types.Prompt(
                    name="forensic-analysis",
                    description="Perform forensic analysis of security incidents with timeline reconstruction",
                    arguments=[
                        types.PromptArgument(
                            name="incident_id",
                            description="Incident identifier or alert ID to investigate",
                            required=True
                        ),
                        types.PromptArgument(
                            name="analysis_depth",
                            description="Depth of analysis (surface, detailed, comprehensive)",
                            required=False
                        )
                    ]
                )
            ]
        
        @self.server.get_prompt()
        async def handle_get_prompt(name: str, arguments: dict) -> types.GetPromptResult:
            """Get specific security analysis prompt with context."""
            request_id = str(uuid.uuid4())
            
            try:
                with LogContext(request_id):
                    self.logger.info(f"Generating prompt: {name}", extra={"details": arguments})
                    
                    if name == "security-incident-analysis":
                        return await self._get_security_incident_analysis_prompt(arguments)
                    elif name == "threat-hunting-query":
                        return await self._get_threat_hunting_query_prompt(arguments)
                    elif name == "compliance-assessment":
                        return await self._get_compliance_assessment_prompt(arguments)
                    elif name == "security-report-generation":
                        return await self._get_security_report_generation_prompt(arguments)
                    elif name == "vulnerability-prioritization":
                        return await self._get_vulnerability_prioritization_prompt(arguments)
                    elif name == "forensic-analysis":
                        return await self._get_forensic_analysis_prompt(arguments)
                    else:
                        raise ValueError(f"Unknown prompt: {name}")
                        
            except Exception as e:
                self.logger.error(f"Error generating prompt {name}: {str(e)}")
                return types.GetPromptResult(
                    description=f"Error generating prompt: {str(e)}",
                    messages=[
                        types.PromptMessage(
                            role="user",
                            content=types.TextContent(
                                type="text",
                                text=f"Error: {str(e)}"
                            )
                        )
                    ]
                )
        
        @self.server.read_resource()
        async def handle_read_resource(uri: str) -> str:
            """Read specific Wazuh resource with comprehensive error handling."""
            request_id = str(uuid.uuid4())
            
            try:
                with LogContext(request_id):
                    self.logger.info(f"Reading resource: {uri}")
                    
                    if uri == "wazuh://alerts/recent":
                        data = await self.api_client.get_alerts(limit=50)
                        return json.dumps(self._format_alerts(data), indent=2)
                    
                    elif uri == "wazuh://alerts/summary":
                        data = await self.api_client.get_alerts(limit=1000)
                        summary = self._generate_alert_summary(data)
                        return json.dumps(summary, indent=2)
                    
                    elif uri == "wazuh://agents/status":
                        data = await self.api_client.get_agents()
                        return json.dumps(self._format_agents(data), indent=2)
                    
                    elif uri == "wazuh://vulnerabilities/critical":
                        agents_data = await self.api_client.get_agents(status="active")
                        critical_vulns = await self._get_critical_vulnerabilities(agents_data)
                        return json.dumps(critical_vulns, indent=2)
                    
                    elif uri == "wazuh://compliance/status":
                        # Quick compliance overview
                        agents_data = await self.api_client.get_agents()
                        alerts_data = await self.api_client.get_alerts(limit=500)
                        compliance_overview = await self._get_compliance_overview(agents_data, alerts_data)
                        return json.dumps(compliance_overview, indent=2)
                    
                    elif uri == "wazuh://threats/active":
                        alerts_data = await self.api_client.get_alerts(limit=500, time_range=3600)
                        threat_summary = await self._get_active_threats(alerts_data)
                        return json.dumps(threat_summary, indent=2)
                    
                    elif uri == "wazuh://system/health":
                        health_data = await self.api_client.health_check()
                        return json.dumps(health_data, indent=2)
                    
                    else:
                        raise ValueError(f"Unknown or unsupported resource URI: {uri}")
                        
            except Exception as e:
                self.logger.error(f"Error reading resource {uri}: {str(e)}")
                return self._format_error_response(e, request_id)
        
        @self.server.list_tools()
        async def handle_list_tools() -> list[types.Tool]:
            """List available Wazuh tools with comprehensive capabilities."""
            return [
                types.Tool(
                    name="get_alerts",
                    description="Retrieve Wazuh alerts with advanced filtering and validation",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of alerts to retrieve",
                                "default": 100,
                                "minimum": 1,
                                "maximum": 10000
                            },
                            "level": {
                                "type": "integer",
                                "description": "Minimum alert level (1-15)",
                                "minimum": 1,
                                "maximum": 15
                            },
                            "time_range": {
                                "type": "integer",
                                "description": "Time range in seconds (e.g., 3600 for last hour)",
                                "minimum": 300,
                                "maximum": 86400
                            },
                            "agent_id": {
                                "type": "string",
                                "description": "Filter alerts by specific agent ID"
                            }
                        }
                    }
                ),
                types.Tool(
                    name="analyze_threats",
                    description="Perform comprehensive threat analysis with ML-based risk assessment",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "category": {
                                "type": "string",
                                "description": "Threat category to analyze",
                                "enum": ["all", "intrusion", "malware", "vulnerability", "compliance", "authentication"]
                            },
                            "time_range": {
                                "type": "integer",
                                "description": "Analysis time window in seconds",
                                "default": 3600,
                                "minimum": 300,
                                "maximum": 86400
                            },
                            "include_patterns": {
                                "type": "boolean",
                                "description": "Include attack pattern detection",
                                "default": False
                            }
                        }
                    }
                ),
                types.Tool(
                    name="check_agent_health",
                    description="Comprehensive agent health monitoring and diagnostics",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "agent_id": {
                                "type": "string",
                                "description": "Specific agent ID to check (optional)"
                            },
                            "include_stats": {
                                "type": "boolean",
                                "description": "Include detailed statistics",
                                "default": False
                            }
                        }
                    }
                ),
                types.Tool(
                    name="compliance_check",
                    description="Perform compliance assessment against security frameworks",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "framework": {
                                "type": "string",
                                "description": "Compliance framework to assess",
                                "enum": ["pci_dss", "hipaa", "gdpr", "nist", "iso27001"]
                            },
                            "include_evidence": {
                                "type": "boolean",
                                "description": "Include detailed evidence and recommendations",
                                "default": True
                            }
                        }
                    }
                ),
                types.Tool(
                    name="check_ioc",
                    description="Check indicators of compromise against threat intelligence",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "ip_address": {
                                "type": "string",
                                "description": "IP address to check",
                                "pattern": "^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$"
                            },
                            "file_hash": {
                                "type": "string",
                                "description": "File hash to check (MD5, SHA1, or SHA256)"
                            }
                        }
                    }
                ),
                types.Tool(
                    name="risk_assessment",
                    description="Perform comprehensive risk assessment of the environment",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "time_window_hours": {
                                "type": "integer",
                                "description": "Time window in hours for risk assessment",
                                "default": 24,
                                "minimum": 1,
                                "maximum": 168
                            },
                            "include_vulnerabilities": {
                                "type": "boolean",
                                "description": "Include vulnerability analysis in risk assessment",
                                "default": True
                            }
                        }
                    }
                ),
                types.Tool(
                    name="get_agent_processes",
                    description="Get running processes for a specific agent.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "agent_id": {
                                "type": "string",
                                "description": "The ID of the agent to query."
                            }
                        },
                        "required": ["agent_id"]
                    }
                ),
                types.Tool(
                    name="get_agent_ports",
                    description="Get open ports for a specific agent.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "agent_id": {
                                "type": "string",
                                "description": "The ID of the agent to query."
                            }
                        },
                        "required": ["agent_id"]
                    }
                ),
                types.Tool(
                    name="get_wazuh_stats",
                    description="Query specific statistical information from the Wazuh manager or a specific agent.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "component": {
                                "type": "string",
                                "description": "The component to query.",
                                "enum": ["manager", "agent"]
                            },
                            "stat_type": {
                                "type": "string",
                                "description": "The type of statistics to retrieve.",
                                "enum": ["weekly", "log_collector", "remoted"]
                            },
                            "agent_id": {
                                "type": "string",
                                "description": "Required if component is agent."
                            }
                        },
                        "required": ["component", "stat_type"]
                    }
                ),
                types.Tool(
                    name="search_wazuh_logs",
                    description="Search the Wazuh manager or agent logs for specific patterns.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "log_source": {
                                "type": "string",
                                "description": "The source of the logs.",
                                "enum": ["manager", "agent"]
                            },
                            "agent_id": {
                                "type": "string",
                                "description": "Required if log_source is agent."
                            },
                            "query": {
                                "type": "string",
                                "description": "The search query or pattern."
                            },
                            "limit": {
                                "type": "integer",
                                "description": "The maximum number of log entries to return.",
                                "default": 100
                            }
                        },
                        "required": ["log_source", "query"]
                    }
                ),
                types.Tool(
                    name="get_cluster_health",
                    description="Retrieve the overall health and status of the Wazuh cluster, including node information.",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                )
            ]
        
        @self.server.call_tool()
        async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent]:
            """Execute Wazuh tools with comprehensive validation and error handling."""
            request_id = str(uuid.uuid4())
            start_time = datetime.utcnow()
            
            try:
                with LogContext(request_id):
                    self.logger.info(f"Executing tool: {name}", extra={"details": arguments})
                    
                    # Apply timeout to all tool executions
                    timeout = self.config.request_timeout_seconds * 2  # Double timeout for complex operations
                    
                    if name == "get_alerts":
                        result = await asyncio.wait_for(self._handle_get_alerts(arguments), timeout=timeout)
                    elif name == "analyze_threats":
                        result = await asyncio.wait_for(self._handle_analyze_threats(arguments), timeout=timeout)
                    elif name == "check_agent_health":
                        result = await asyncio.wait_for(self._handle_check_agent_health(arguments), timeout=timeout)
                    elif name == "compliance_check":
                        result = await asyncio.wait_for(self._handle_compliance_check(arguments), timeout=timeout)
                    elif name == "check_ioc":
                        result = await asyncio.wait_for(self._handle_check_ioc(arguments), timeout=timeout)
                    elif name == "risk_assessment":
                        result = await asyncio.wait_for(self._handle_risk_assessment(arguments), timeout=timeout)
                    elif name == "get_agent_processes":
                        result = await asyncio.wait_for(self._handle_get_agent_processes(arguments), timeout=timeout)
                    elif name == "get_agent_ports":
                        result = await asyncio.wait_for(self._handle_get_agent_ports(arguments), timeout=timeout)
                    elif name == "get_wazuh_stats":
                        result = await asyncio.wait_for(self._handle_get_wazuh_stats(arguments), timeout=timeout)
                    elif name == "search_wazuh_logs":
                        result = await asyncio.wait_for(self._handle_search_wazuh_logs(arguments), timeout=timeout)
                    elif name == "get_cluster_health":
                        result = await asyncio.wait_for(self._handle_get_cluster_health(arguments), timeout=timeout)
                    else:
                        raise ValueError(f"Unknown tool: {name}")
                    
                    execution_time = (datetime.utcnow() - start_time).total_seconds()
                    self.logger.info(f"Tool {name} completed in {execution_time:.2f}s")
                    return result
                        
            except asyncio.TimeoutError:
                execution_time = (datetime.utcnow() - start_time).total_seconds()
                self.logger.error(f"Tool {name} timed out after {execution_time:.2f}s")
                return [types.TextContent(
                    type="text",
                    text=self._format_error_response(
                        asyncio.TimeoutError(f"Tool execution timed out after {timeout} seconds"),
                        request_id,
                        execution_time
                    )
                )]
            except ValidationError as e:
                self.logger.warning(f"Validation error in tool {name}: {str(e)}")
                return [types.TextContent(
                    type="text",
                    text=self._format_error_response(e, request_id)
                )]
            except Exception as e:
                execution_time = (datetime.utcnow() - start_time).total_seconds()
                self.logger.error(f"Error executing tool {name} after {execution_time:.2f}s: {str(e)}")
                return [types.TextContent(
                    type="text",
                    text=self._format_error_response(e, request_id, execution_time)
                )]
    
    async def _handle_get_alerts(self, arguments: dict) -> list[types.TextContent]:
        """Handle get_alerts tool execution."""
        # Validate parameters
        validated_query = validate_alert_query(arguments)
        
        data = await self.api_client.get_alerts(
            limit=validated_query.limit,
            level=arguments.get("level"),
            time_range=arguments.get("time_range"),
            agent_id=arguments.get("agent_id")
        )
        
        # Check for critical alerts and send notifications
        alerts = data.get("data", {}).get("affected_items", [])
        for alert in alerts:
            await self._send_critical_alert_notification(alert)
        
        formatted = self._format_alerts(data)
        
        return [types.TextContent(
            type="text",
            text=json.dumps(formatted, indent=2)
        )]
    
    async def _handle_analyze_threats(self, arguments: dict) -> list[types.TextContent]:
        """Handle threat analysis tool execution."""
        validated_query = validate_threat_analysis(arguments)
        
        # Get alerts for analysis
        alerts_data = await self.api_client.get_alerts(
            limit=1000, 
            time_range=validated_query.time_range
        )
        alerts = alerts_data.get("data", {}).get("affected_items", [])
        
        # Perform risk assessment
        risk_assessment = self.security_analyzer.calculate_comprehensive_risk_score(
            alerts, time_window_hours=validated_query.time_range // 3600
        )
        
        analysis = {
            "category": validated_query.category,
            "total_alerts": len(alerts),
            "time_range_seconds": validated_query.time_range,
            "risk_assessment": {
                "overall_score": risk_assessment.overall_score,
                "risk_level": risk_assessment.risk_level.value,
                "confidence": risk_assessment.confidence,
                "factors": [
                    {
                        "name": factor.name,
                        "score": factor.score,
                        "weight": factor.weight,
                        "description": factor.description
                    }
                    for factor in risk_assessment.factors
                ],
                "recommendations": risk_assessment.recommendations
            },
            "timestamp": risk_assessment.timestamp.isoformat()
        }
        
        # Include attack patterns if requested
        if arguments.get("include_patterns", False):
            patterns = self.security_analyzer.detect_attack_patterns(alerts)
            analysis["attack_patterns"] = patterns
        
        return [types.TextContent(
            type="text",
            text=json.dumps(analysis, indent=2)
        )]
    
    async def _handle_check_agent_health(self, arguments: dict) -> list[types.TextContent]:
        """Handle agent health check tool execution."""
        agent_id = arguments.get("agent_id")
        include_stats = arguments.get("include_stats", False)
        
        if agent_id:
            # Validate agent query
            validated_query = validate_agent_query({"agent_id": agent_id})
            
            # Get specific agent data
            agents_data = await self.api_client.get_agents()
            agents = agents_data.get("data", {}).get("affected_items", [])
            agent = next((a for a in agents if a.get("id") == agent_id), None)
            
            if not agent:
                return [types.TextContent(
                    type="text",
                    text=self._format_error_response(ValueError(f"Agent ID {agent_id} not found"))
                )]
            
            health = self._assess_agent_health(agent)
            
            if include_stats:
                try:
                    stats = await self.api_client.get_agent_stats(agent_id)
                    health["statistics"] = stats.get("data", {})
                except Exception:
                    health["statistics_error"] = str(e)
            
            return [types.TextContent(
                type="text",
                text=json.dumps(health, indent=2)
            )]
        else:
            # Get all agents health
            data = await self.api_client.get_agents()
            health_report = self._assess_all_agents_health(data)
            
            return [types.TextContent(
                type="text",
                text=json.dumps(health_report, indent=2)
            )]
    
    async def _handle_compliance_check(self, arguments: dict) -> list[types.TextContent]:
        """Handle compliance check tool execution."""
        framework_str = arguments.get("framework", "pci_dss")
        include_evidence = arguments.get("include_evidence", True)
        
        # Map string to enum
        framework_map = {
            "pci_dss": ComplianceFramework.PCI_DSS,
            "hipaa": ComplianceFramework.HIPAA,
            "gdpr": ComplianceFramework.GDPR,
            "nist": ComplianceFramework.NIST,
            "iso27001": ComplianceFramework.ISO27001
        }
        
        framework = framework_map.get(framework_str, ComplianceFramework.PCI_DSS)
        
        # Gather data for compliance assessment
        alerts_data = await self.api_client.get_alerts(limit=1000)
        alerts = alerts_data.get("data", {}).get("affected_items", [])
        
        agents_data = await self.api_client.get_agents()
        agents = agents_data.get("data", {}).get("affected_items", [])
        
        # Get vulnerabilities for a sample of agents
        vulnerabilities = []
        active_agents = [a for a in agents if a.get("status") == "active"][:5]  # Sample 5 agents
        
        for agent in active_agents:
            try:
                vuln_data = await self.api_client.get_agent_vulnerabilities(agent["id"])
                agent_vulns = vuln_data.get("data", {}).get("affected_items", [])
                vulnerabilities.extend(agent_vulns)
            except Exception:
                self.logger.warning(f"Could not get vulnerabilities for agent {agent['id']}: {str(e)}")
        
        # Perform compliance assessment
        report = self.compliance_analyzer.assess_compliance(
            framework, alerts, agents, vulnerabilities
        )
        
        # Format response
        compliance_result = {
            "framework": framework.value,
            "overall_score": report.overall_score,
            "status": report.status.value,
            "summary": report.summary,
            "timestamp": report.timestamp.isoformat()
        }
        
        if include_evidence:
            compliance_result["requirements"] = [
                {
                    "id": req.id,
                    "title": req.title,
                    "description": req.description,
                    "status": req.status.value,
                    "score": req.score,
                    "evidence": req.evidence,
                    "gaps": req.gaps,
                    "recommendations": req.recommendations
                }
                for req in report.requirements
            ]
            compliance_result["recommendations"] = report.recommendations
        
        return [types.TextContent(
            type="text",
            text=json.dumps(compliance_result, indent=2)
        )]
    
    async def _handle_check_ioc(self, arguments: dict) -> list[types.TextContent]:
        """Handle IOC checking tool execution."""
        ip_address = arguments.get("ip_address")
        file_hash = arguments.get("file_hash")
        
        results = {"indicators": []}
        
        if ip_address:
            try:
                validated_ip = validate_ip_address(ip_address)
                results["indicators"].append({
                    "type": "ip_address",
                    "value": validated_ip.ip,
                    "status": "validated",
                    "message": "IP address validated successfully"
                })
            except ValidationError as e:
                results["indicators"].append({
                    "type": "ip_address",
                    "value": ip_address,
                    "status": "error",
                    "message": str(e)
                })
        
        if file_hash:
            try:
                validated_hash = validate_file_hash(file_hash)
                results["indicators"].append({
                    "type": "file_hash",
                    "value": validated_hash.hash_value,
                    "hash_type": validated_hash.hash_type,
                    "status": "validated",
                    "message": "File hash validated successfully"
                })
            except ValidationError as e:
                results["indicators"].append({
                    "type": "file_hash",
                    "value": file_hash,
                    "status": "error",
                    "message": str(e)
                })
        
        if not results["indicators"]:
            results["error"] = "No valid indicators provided."
        
        return [types.TextContent(
            type="text",
            text=json.dumps(results, indent=2)
        )]
    
    async def _handle_risk_assessment(self, arguments: dict) -> list[types.TextContent]:
        """Handle comprehensive risk assessment tool execution."""
        time_window_hours = arguments.get("time_window_hours", 24)
        include_vulnerabilities = arguments.get("include_vulnerabilities", True)
        
        # Initialize progress tracking
        total_steps = 4 if include_vulnerabilities else 2
        current_step = 0
        
        # Step 1: Get alerts for the time window
        current_step += 1
        await self._report_progress(current_step, total_steps, "Fetching security alerts...")
        
        time_range_seconds = time_window_hours * 3600
        alerts_data = await self.api_client.get_alerts(
            limit=2000, 
            time_range=time_range_seconds
        )
        alerts = alerts_data.get("data", {}).get("affected_items", [])
        
        vulnerabilities = []
        if include_vulnerabilities:
            # Step 2: Get agents
            current_step += 1
            await self._report_progress(current_step, total_steps, "Fetching agent information...")
            
            agents_data = await self.api_client.get_agents(status="active")
            active_agents = agents_data.get("data", {}).get("affected_items", [])[:10]  # Sample 10 agents
            
            # Step 3: Get vulnerabilities
            current_step += 1
            await self._report_progress(current_step, total_steps, "Analyzing vulnerabilities...")
            
            for i, agent in enumerate(active_agents):
                try:
                    vuln_data = await self.api_client.get_agent_vulnerabilities(agent["id"])
                    agent_vulns = vuln_data.get("data", {}).get("affected_items", [])
                    vulnerabilities.extend(agent_vulns)
                    
                    # Report sub-progress
                    if i % 2 == 0:  # Report every 2nd agent
                        await self._report_progress(
                            current_step, 
                            total_steps, 
                            f"Analyzing vulnerabilities... ({i+1}/{len(active_agents)} agents processed)"
                        )
                except Exception:
                    self.logger.warning(f"Could not get vulnerabilities for agent {agent['id']}: {str(e)}")
        
        # Final step: Perform comprehensive risk assessment
        current_step += 1
        await self._report_progress(current_step, total_steps, "Calculating risk assessment...")
        
        risk_assessment = self.security_analyzer.calculate_comprehensive_risk_score(
            alerts, vulnerabilities, time_window_hours
        )
        
        # Complete progress
        await self._report_progress(total_steps, total_steps, "Risk assessment completed!")
        
        # Format result
        result = {
            "assessment_period": {
                "time_window_hours": time_window_hours,
                "alerts_analyzed": len(alerts),
                "vulnerabilities_analyzed": len(vulnerabilities)
            },
            "risk_score": risk_assessment.overall_score,
            "risk_level": risk_assessment.risk_level.value,
            "confidence": risk_assessment.confidence,
            "factors": [
                {
                    "name": factor.name,
                    "score": factor.score,
                    "weight": factor.weight,
                    "description": factor.description
                }
                for factor in risk_assessment.factors
            ],
            "recommendations": risk_assessment.recommendations,
            "timestamp": risk_assessment.timestamp.isoformat()
        }
        
        return [types.TextContent(
            type="text",
            text=json.dumps(result, indent=2)
        )]

    async def _handle_get_agent_processes(self, arguments: dict) -> list[types.TextContent]:
        """Handle get_agent_processes tool execution."""
        agent_id = arguments.get("agent_id")
        validated_query = validate_agent_query({"agent_id": agent_id})

        data = await self.api_client.get_agent_processes(validated_query.agent_id)

        return [types.TextContent(
            type="text",
            text=json.dumps(data, indent=2)
        )]

    async def _handle_get_agent_ports(self, arguments: dict) -> list[types.TextContent]:
        """Handle get_agent_ports tool execution."""
        agent_id = arguments.get("agent_id")
        validated_query = validate_agent_query({"agent_id": agent_id})

        data = await self.api_client.get_agent_ports(validated_query.agent_id)

        return [types.TextContent(
            type="text",
            text=json.dumps(data, indent=2)
        )]

    async def _handle_get_wazuh_stats(self, arguments: dict) -> list[types.TextContent]:
        """Handle get_wazuh_stats tool execution."""
        component = arguments.get("component")
        stat_type = arguments.get("stat_type")
        agent_id = arguments.get("agent_id")

        data = await self.api_client.get_wazuh_stats(component, stat_type, agent_id)

        return [types.TextContent(
            type="text",
            text=json.dumps(data, indent=2)
        )]

    async def _handle_search_wazuh_logs(self, arguments: dict) -> list[types.TextContent]:
        """Handle search_wazuh_logs tool execution."""
        log_source = arguments.get("log_source")
        query = arguments.get("query")
        limit = arguments.get("limit", 100)
        agent_id = arguments.get("agent_id")
        
        # Validate required parameters
        if not log_source:
            return [types.TextContent(
                type="text",
                text=self._format_error_response(ValueError("log_source is required"))
            )]
        
        if not query:
            return [types.TextContent(
                type="text",
                text=self._format_error_response(ValueError("query is required"))
            )]

        data = await self.api_client.search_wazuh_logs(log_source, query, limit, agent_id)

        return [types.TextContent(
            type="text",
            text=json.dumps(data, indent=2)
        )]

    async def _handle_get_cluster_health(self, arguments: dict) -> list[types.TextContent]:
        """Handle get_cluster_health tool execution."""
        data = await self.api_client.get_cluster_info()
        nodes_data = await self.api_client.get_cluster_nodes()

        # Combine cluster info and node info
        cluster_health = {
            "cluster_info": data.get("data", {}),
            "nodes": nodes_data.get("data", {}).get("affected_items", [])
        }

        return [types.TextContent(
            type="text",
            text=json.dumps(cluster_health, indent=2)
        )]
    
    def _format_alerts(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format alerts for better readability."""
        alerts = data.get("data", {}).get("affected_items", [])
        
        formatted_alerts = []
        for alert in alerts:
            formatted_alerts.append({
                "id": alert.get("id"),
                "timestamp": alert.get("timestamp"),
                "rule": {
                    "id": alert.get("rule", {}).get("id"),
                    "description": alert.get("rule", {}).get("description"),
                    "level": alert.get("rule", {}).get("level"),
                    "groups": alert.get("rule", {}).get("groups", [])
                },
                "agent": {
                    "id": alert.get("agent", {}).get("id"),
                    "name": alert.get("agent", {}).get("name"),
                    "ip": alert.get("agent", {}).get("ip")
                },
                "location": alert.get("location")
            })
        
        return {
            "total_alerts": data.get("data", {}).get("total_affected_items", 0),
            "alerts": formatted_alerts,
            "query_time": datetime.utcnow().isoformat()
        }
    
    def _format_agents(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Format agent data with enhanced metrics."""
        agents = data.get("data", {}).get("affected_items", [])
        
        status_summary = {
            "active": 0,
            "disconnected": 0,
            "never_connected": 0,
            "pending": 0
        }
        
        formatted_agents = []
        for agent in agents:
            status = agent.get("status", "unknown")
            if status in status_summary:
                status_summary[status] += 1
            
            formatted_agents.append({
                "id": agent.get("id"),
                "name": agent.get("name"),
                "ip": agent.get("ip"),
                "status": status,
                "os": agent.get("os", {}).get("platform"),
                "version": agent.get("version"),
                "last_keep_alive": agent.get("lastKeepAlive")
            })
        
        return {
            "summary": status_summary,
            "total_agents": len(agents),
            "agents": formatted_agents
        }
    
    def _assess_agent_health(self, agent: Dict[str, Any]) -> Dict[str, Any]:
        """Assess health of a single agent."""
        status = agent.get("status", "unknown")
        health_status = "healthy" if status == "active" else "unhealthy"
        
        return {
            "agent_id": agent.get("id"),
            "agent_name": agent.get("name"),
            "health_status": health_status,
            "status": status,
            "details": {
                "ip": agent.get("ip"),
                "os": agent.get("os", {}).get("platform"),
                "version": agent.get("version"),
                "last_keep_alive": agent.get("lastKeepAlive")
            }
        }
    
    def _assess_all_agents_health(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess health of all agents."""
        agents = data.get("data", {}).get("affected_items", [])
        
        health_report = {
            "total_agents": len(agents),
            "healthy": 0,
            "unhealthy": 0,
            "agents": []
        }
        
        for agent in agents:
            agent_health = self._assess_agent_health(agent)
            health_report["agents"].append(agent_health)
            
            if agent_health["health_status"] == "healthy":
                health_report["healthy"] += 1
            else:
                health_report["unhealthy"] += 1
        
        health_report["health_percentage"] = (
            (health_report["healthy"] / len(agents) * 100) if agents else 0
        )
        
        return health_report
    
    def _generate_alert_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate statistical summary of alerts."""
        alerts = data.get("data", {}).get("affected_items", [])
        
        if not alerts:
            return {"message": "No alerts to summarize"}
        
        # Basic statistics
        total_alerts = len(alerts)
        levels = [alert.get("rule", {}).get("level", 0) for alert in alerts]
        
        summary = {
            "total_alerts": total_alerts,
            "severity_distribution": {
                "low": len([l for l in levels if 1 <= l <= 5]),
                "medium": len([l for l in levels if 6 <= l <= 10]),
                "high": len([l for l in levels if 11 <= l <= 15])
            },
            "top_rules": {},
            "top_agents": {},
            "time_analysis": {}
        }
        
        # Top rules
        rule_counter = {}
        for alert in alerts:
            rule_id = alert.get("rule", {}).get("id")
            if rule_id:
                rule_counter[rule_id] = rule_counter.get(rule_id, 0) + 1
        
        summary["top_rules"] = dict(sorted(rule_counter.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Top agents
        agent_counter = {}
        for alert in alerts:
            agent_id = alert.get("agent", {}).get("id")
            if agent_id:
                agent_counter[agent_id] = agent_counter.get(agent_id, 0) + 1
        
        summary["top_agents"] = dict(sorted(agent_counter.items(), key=lambda x: x[1], reverse=True)[:10])
        
        return summary
    
    async def _get_critical_vulnerabilities(self, agents_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get critical vulnerabilities across agents."""
        agents = agents_data.get("data", {}).get("affected_items", [])
        active_agents = [a for a in agents if a.get("status") == "active"][:10]  # Limit to 10 agents
        
        critical_vulns = []
        
        # Fetch vulnerabilities concurrently for better performance
        async def fetch_agent_vulnerabilities(agent):
            try:
                vuln_data = await self.api_client.get_agent_vulnerabilities(agent["id"])
                vulns = vuln_data.get("data", {}).get("affected_items", [])
                
                agent_critical_vulns = []
                for vuln in vulns:
                    severity = vuln.get("severity", "").lower()
                    if severity in ["critical", "high"]:
                        agent_critical_vulns.append({
                            "agent_id": agent["id"],
                            "agent_name": agent.get("name"),
                            "vulnerability": vuln.get("title"),
                            "severity": severity,
                            "cve": vuln.get("cve", "N/A")
                        })
                return agent_critical_vulns
            except Exception as e:
                self.logger.warning(f"Could not get vulnerabilities for agent {agent['id']}: {str(e)}")
                return []
        
        # Execute all vulnerability fetches concurrently
        tasks = [fetch_agent_vulnerabilities(agent) for agent in active_agents]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Flatten results and filter out exceptions
        for result in results:
            if isinstance(result, list):
                critical_vulns.extend(result)
        
        return {
            "total_critical_vulnerabilities": len(critical_vulns),
            "vulnerabilities": critical_vulns[:50],  # Limit response size
            "agents_checked": len(active_agents)
        }
    
    async def _get_compliance_overview(self, agents_data: Dict[str, Any], alerts_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get quick compliance overview."""
        agents = agents_data.get("data", {}).get("affected_items", [])
        alerts = alerts_data.get("data", {}).get("affected_items", [])
        
        # Simple compliance metrics
        total_agents = len(agents)
        active_agents = len([a for a in agents if a.get("status") == "active"])
        
        # Alert severity analysis
        high_severity_alerts = len([a for a in alerts if a.get("rule", {}).get("level", 0) >= 10])
        
        coverage_score = (active_agents / total_agents * 100) if total_agents > 0 else 0
        
        return {
            "agent_coverage": {
                "total_agents": total_agents,
                "active_agents": active_agents,
                "coverage_percentage": round(coverage_score, 1)
            },
            "alert_analysis": {
                "total_alerts": len(alerts),
                "high_severity_alerts": high_severity_alerts
            },
            "compliance_score": round(max(0, 100 - (high_severity_alerts * 2) - (100 - coverage_score)), 1),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _get_active_threats(self, alerts_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get active threat summary."""
        alerts = alerts_data.get("data", {}).get("affected_items", [])
        
        if not alerts:
            return {"message": "No recent threats detected"}
        
        # Analyze patterns
        patterns = self.security_analyzer.detect_attack_patterns(alerts)
        
        # Get threat categories
        threat_categories = {}
        for alert in alerts:
            groups = alert.get("rule", {}).get("groups", [])
            for group in groups:
                if any(keyword in group.lower() for keyword in 
                      ["attack", "intrusion", "malware", "exploit", "breach"]):
                    threat_categories[group] = threat_categories.get(group, 0) + 1
        
        return {
            "total_recent_alerts": len(alerts),
            "detected_patterns": patterns.get("detected_patterns", {}),
            "threat_categories": dict(sorted(threat_categories.items(), key=lambda x: x[1], reverse=True)[:10]),
            "analysis_window": "Last hour",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _get_security_incident_analysis_prompt(self, arguments: dict) -> types.GetPromptResult:
        """Generate security incident analysis prompt with context."""
        alert_id = arguments.get("alert_id")
        include_context = arguments.get("include_context", "true").lower() == "true"
        
        # Fetch alert data for context
        context_data = ""
        if alert_id:
            try:
                alerts_data = await self.api_client.get_alerts(limit=100)
                alerts = alerts_data.get("data", {}).get("affected_items", [])
                target_alert = next((a for a in alerts if str(a.get("id")) == str(alert_id)), None)
                
                if target_alert:
                    context_data = f"""
### Alert Details:
- **ID**: {target_alert.get('id')}
- **Timestamp**: {target_alert.get('timestamp')}
- **Rule**: {target_alert.get('rule', {}).get('description')} (Level: {target_alert.get('rule', {}).get('level')})
- **Agent**: {target_alert.get('agent', {}).get('name')} ({target_alert.get('agent', {}).get('ip')})
- **Location**: {target_alert.get('location')}
"""
                    
                    if include_context:
                        # Get related alerts
                        agent_id = target_alert.get('agent', {}).get('id')
                        related_alerts = [a for a in alerts if a.get('agent', {}).get('id') == agent_id and a.get('id') != alert_id][:5]
                        
                        if related_alerts:
                            context_data += "\n### Related Alerts on Same Agent:\n"
                            for alert in related_alerts:
                                context_data += f"- {alert.get('timestamp')}: {alert.get('rule', {}).get('description')} (Level: {alert.get('rule', {}).get('level')})\n"
                else:
                    context_data = f"\n### Alert ID {alert_id} not found in recent alerts."
            except Exception:
                context_data = f"\n### Error fetching alert context: {str(e)}"
        
        prompt_text = f"""You are a cybersecurity analyst investigating a security incident from Wazuh SIEM. Please analyze the following security alert and provide a comprehensive incident analysis.

{context_data}

### Analysis Framework:
Please provide a structured analysis covering:

1. **Incident Summary**
   - Brief description of what happened
   - Severity assessment and business impact
   - Initial classification (malware, intrusion, policy violation, etc.)

2. **Technical Analysis**
   - Detailed breakdown of the alert and its indicators
   - Attack vectors and techniques used (map to MITRE ATT&CK if applicable)
   - Affected systems and potential lateral movement

3. **Timeline Reconstruction**
   - Chronological sequence of events
   - Key timestamps and their significance
   - Potential attack progression

4. **Risk Assessment**
   - Immediate risks and threats
   - Potential for further compromise
   - Business impact evaluation

5. **Containment Recommendations**
   - Immediate actions to contain the threat
   - Isolation procedures for affected systems
   - Evidence preservation steps

6. **Investigation Steps**
   - Additional data sources to examine
   - Forensic artifacts to collect
   - Queries to run for deeper analysis

7. **Remediation Plan**
   - Step-by-step remediation actions
   - System hardening recommendations
   - Prevention measures for future incidents

Please provide actionable insights and prioritize recommendations based on risk level."""

        return types.GetPromptResult(
            description="Comprehensive security incident analysis with investigation framework",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=prompt_text
                    )
                )
            ]
        )
    
    async def _get_threat_hunting_query_prompt(self, arguments: dict) -> types.GetPromptResult:
        """Generate threat hunting query prompt."""
        threat_type = arguments.get("threat_type", "general")
        time_range = arguments.get("time_range", "24h")
        target_agents = arguments.get("target_agents", "")
        
        # Get recent alerts for context
        context_data = ""
        try:
            alerts_data = await self.api_client.get_alerts(limit=50)
            alerts = alerts_data.get("data", {}).get("affected_items", [])
            
            if alerts:
                # Analyze recent threat patterns
                rule_counts = {}
                for alert in alerts:
                    rule_desc = alert.get('rule', {}).get('description', 'Unknown')
                    rule_counts[rule_desc] = rule_counts.get(rule_desc, 0) + 1
                
                top_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                context_data = f"""
### Recent Threat Landscape (Last 50 alerts):
{chr(10).join([f"- {rule}: {count} occurrences" for rule, count in top_rules])}
"""
        except Exception:
            context_data = f"\n### Error fetching threat context: {str(e)}"
        
        prompt_text = f"""You are a threat hunter developing proactive hunting queries for a Wazuh SIEM environment. Generate comprehensive threat hunting queries and strategies.

### Hunting Parameters:
- **Threat Type**: {threat_type}
- **Time Range**: {time_range}
- **Target Agents**: {target_agents if target_agents else "All agents"}

{context_data}

### Generate Threat Hunting Strategy:

1. **Threat Hypothesis**
   - What specific threats are we hunting for?
   - Threat actor behaviors and TTPs to look for
   - MITRE ATT&CK techniques to focus on

2. **Hunting Queries**
   - Specific Wazuh queries to identify suspicious activity
   - Log sources and data types to examine
   - Correlation rules to create or modify

3. **Indicators of Compromise (IOCs)**
   - File hashes, IP addresses, domains to investigate
   - Process names and command line patterns
   - Network traffic patterns and anomalies

4. **Behavioral Analysis**
   - User behavior anomalies to detect
   - System behavior patterns that indicate compromise
   - Temporal patterns and frequency analysis

5. **Detection Logic**
   - Boolean logic for combining indicators
   - Thresholds and baselines for anomaly detection
   - Statistical analysis approaches

6. **Validation Steps**
   - How to validate potential findings
   - False positive reduction techniques
   - Escalation criteria for confirmed threats

7. **Automation Opportunities**
   - Automated hunting rules to implement
   - Orchestration and response workflows
   - Continuous monitoring improvements

Please provide actionable hunting queries and methodologies tailored to the {threat_type} threat landscape."""

        return types.GetPromptResult(
            description="Comprehensive threat hunting strategy and query generation",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=prompt_text
                    )
                )
            ]
        )
    
    async def _get_compliance_assessment_prompt(self, arguments: dict) -> types.GetPromptResult:
        """Generate compliance assessment prompt."""
        framework = arguments.get("framework", "pci_dss")
        scope = arguments.get("scope", "full")
        
        # Get system context
        context_data = ""
        try:
            agents_data = await self.api_client.get_agents()
            agents = agents_data.get("data", {}).get("affected_items", [])
            
            alerts_data = await self.api_client.get_alerts(limit=100)
            alerts = alerts_data.get("data", {}).get("affected_items", [])
            
            context_data = f"""
### Current Environment Status:
- **Total Agents**: {len(agents)}
- **Active Agents**: {len([a for a in agents if a.get('status') == 'active'])}
- **Recent Alerts**: {len(alerts)}
- **High Severity Alerts**: {len([a for a in alerts if a.get('rule', {}).get('level', 0) >= 10])}
"""
        except Exception:
            context_data = f"\n### Error fetching environment context: {str(e)}"
        
        framework_details = {
            "pci_dss": {
                "name": "Payment Card Industry Data Security Standard",
                "focus": "protecting cardholder data",
                "key_areas": ["network security", "access control", "monitoring", "encryption"]
            },
            "hipaa": {
                "name": "Health Insurance Portability and Accountability Act",
                "focus": "protecting healthcare information",
                "key_areas": ["administrative safeguards", "physical safeguards", "technical safeguards"]
            },
            "gdpr": {
                "name": "General Data Protection Regulation",
                "focus": "data privacy and protection",
                "key_areas": ["data processing", "consent", "breach notification", "data subject rights"]
            },
            "nist": {
                "name": "NIST Cybersecurity Framework",
                "focus": "cybersecurity risk management",
                "key_areas": ["identify", "protect", "detect", "respond", "recover"]
            },
            "iso27001": {
                "name": "ISO 27001 Information Security Management",
                "focus": "information security management systems",
                "key_areas": ["risk assessment", "security controls", "monitoring", "improvement"]
            }
        }
        
        framework_info = framework_details.get(framework, framework_details["pci_dss"])
        
        prompt_text = f"""You are a compliance officer conducting a comprehensive assessment against {framework_info['name']} standards. Analyze the current security posture and provide detailed compliance recommendations.

### Assessment Parameters:
- **Framework**: {framework_info['name']}
- **Scope**: {scope}
- **Focus Area**: {framework_info['focus']}
- **Key Areas**: {', '.join(framework_info['key_areas'])}

{context_data}

### Compliance Assessment Framework:

1. **Current Compliance Status**
   - Overall compliance posture assessment
   - Strengths and weaknesses identification
   - Gap analysis against framework requirements

2. **Control Assessment**
   - Technical controls evaluation
   - Administrative controls review
   - Physical controls assessment (where applicable)

3. **Risk Analysis**
   - Compliance risks and their impact
   - Regulatory penalties and consequences
   - Business risks from non-compliance

4. **Evidence Collection**
   - Required documentation and evidence
   - Audit trail and logging requirements
   - Monitoring and reporting mechanisms

5. **Remediation Roadmap**
   - Prioritized action items
   - Timeline and resource requirements
   - Quick wins and long-term improvements

6. **Monitoring and Maintenance**
   - Continuous compliance monitoring
   - Regular assessment schedules
   - Key performance indicators (KPIs)

7. **Reporting and Documentation**
   - Compliance report structure
   - Stakeholder communication
   - Audit preparation guidance

Please provide a detailed compliance assessment with actionable recommendations prioritized by risk and regulatory importance."""

        return types.GetPromptResult(
            description=f"Comprehensive {framework_info['name']} compliance assessment",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=prompt_text
                    )
                )
            ]
        )
    
    async def _get_security_report_generation_prompt(self, arguments: dict) -> types.GetPromptResult:
        """Generate security report generation prompt."""
        report_type = arguments.get("report_type", "executive")
        time_period = arguments.get("time_period", "weekly")
        audience = arguments.get("audience", "executives")
        
        # Get comprehensive metrics
        context_data = ""
        try:
            # Get alerts for reporting period
            time_range_map = {"daily": 86400, "weekly": 604800, "monthly": 2592000, "quarterly": 7776000}
            time_range = time_range_map.get(time_period, 604800)
            
            alerts_data = await self.api_client.get_alerts(limit=1000, time_range=time_range)
            alerts = alerts_data.get("data", {}).get("affected_items", [])
            
            agents_data = await self.api_client.get_agents()
            agents = agents_data.get("data", {}).get("affected_items", [])
            
            # Calculate metrics
            total_alerts = len(alerts)
            high_severity = len([a for a in alerts if a.get('rule', {}).get('level', 0) >= 10])
            critical_alerts = len([a for a in alerts if a.get('rule', {}).get('level', 0) >= 12])
            
            context_data = f"""
### Security Metrics ({time_period.title()} Period):
- **Total Alerts**: {total_alerts}
- **High Severity Alerts**: {high_severity}
- **Critical Alerts**: {critical_alerts}
- **Total Agents**: {len(agents)}
- **Active Agents**: {len([a for a in agents if a.get('status') == 'active'])}
- **Agent Coverage**: {len([a for a in agents if a.get('status') == 'active']) / len(agents) * 100 if agents else 0:.1f}%
"""
        except Exception:
            context_data = f"\n### Error fetching metrics: {str(e)}"
        
        audience_details = {
            "executives": {
                "focus": "business impact, risk levels, and strategic recommendations",
                "style": "high-level, business-focused, with executive summary"
            },
            "security_team": {
                "focus": "technical details, incident analysis, and operational metrics",
                "style": "detailed technical analysis with actionable insights"
            },
            "compliance_team": {
                "focus": "regulatory compliance, audit findings, and control effectiveness",
                "style": "compliance-focused with regulatory mapping"
            }
        }
        
        audience_info = audience_details.get(audience, audience_details["executives"])
        
        prompt_text = f"""You are a security analyst generating a comprehensive {report_type} security report for {audience}. Create a professional, actionable report that communicates security posture effectively.

### Report Parameters:
- **Report Type**: {report_type.title()}
- **Time Period**: {time_period.title()}
- **Target Audience**: {audience.title()}
- **Focus**: {audience_info['focus']}
- **Style**: {audience_info['style']}

{context_data}

### Security Report Structure:

1. **Executive Summary**
   - Key findings and security posture overview
   - Critical issues requiring immediate attention
   - Overall risk assessment and trending

2. **Threat Landscape Analysis**
   - Attack patterns and threat actor activity
   - Emerging threats and vulnerabilities
   - Industry-specific threat intelligence

3. **Incident Analysis**
   - Significant security incidents and their impact
   - Response effectiveness and lessons learned
   - Trend analysis and pattern recognition

4. **Metrics and KPIs**
   - Security operations metrics
   - Incident response performance
   - Compliance and audit metrics

5. **Risk Assessment**
   - Current risk levels and classifications
   - Risk trend analysis
   - Mitigation effectiveness

6. **Recommendations**
   - Strategic security improvements
   - Tactical operational enhancements
   - Resource and investment priorities

7. **Appendices**
   - Detailed technical findings
   - Compliance mapping
   - Methodology and data sources

Please generate a comprehensive, professional security report that is appropriate for the {audience} audience and provides actionable insights for improving security posture."""

        return types.GetPromptResult(
            description=f"Professional {report_type} security report for {audience}",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=prompt_text
                    )
                )
            ]
        )
    
    async def _get_vulnerability_prioritization_prompt(self, arguments: dict) -> types.GetPromptResult:
        """Generate vulnerability prioritization prompt."""
        severity_threshold = arguments.get("severity_threshold", "medium")
        asset_criticality = arguments.get("asset_criticality", "high")
        
        # Get vulnerability data
        context_data = ""
        try:
            agents_data = await self.api_client.get_agents(status="active")
            agents = agents_data.get("data", {}).get("affected_items", [])[:10]  # Sample 10 agents
            
            total_vulns = 0
            critical_vulns = 0
            high_vulns = 0
            
            for agent in agents:
                try:
                    vuln_data = await self.api_client.get_agent_vulnerabilities(agent["id"])
                    vulns = vuln_data.get("data", {}).get("affected_items", [])
                    total_vulns += len(vulns)
                    
                    for vuln in vulns:
                        severity = vuln.get("severity", "").lower()
                        if severity == "critical":
                            critical_vulns += 1
                        elif severity == "high":
                            high_vulns += 1
                except Exception:
                    continue
            
            context_data = f"""
### Vulnerability Landscape:
- **Total Vulnerabilities**: {total_vulns}
- **Critical Vulnerabilities**: {critical_vulns}
- **High Vulnerabilities**: {high_vulns}
- **Agents Analyzed**: {len(agents)}
"""
        except Exception:
            context_data = f"\n### Error fetching vulnerability data: {str(e)}"
        
        prompt_text = f"""You are a vulnerability management specialist developing a risk-based prioritization strategy for security vulnerabilities. Create a comprehensive framework for prioritizing remediation efforts.

### Prioritization Parameters:
- **Severity Threshold**: {severity_threshold}
- **Asset Criticality**: {asset_criticality}
- **Risk-Based Approach**: Business impact and exploitability focus

{context_data}

### Vulnerability Prioritization Framework:

1. **Risk Scoring Matrix**
   - CVSS score integration with business context
   - Threat intelligence and exploit availability
   - Asset criticality and business impact weighting

2. **Threat Context Analysis**
   - Active exploitation in the wild
   - Threat actor capabilities and intentions
   - Industry-specific threat landscape

3. **Business Impact Assessment**
   - Critical business processes affected
   - Data sensitivity and regulatory implications
   - Financial and operational impact potential

4. **Remediation Feasibility**
   - Patch availability and testing requirements
   - System dependencies and change windows
   - Resource requirements and technical complexity

5. **Compensating Controls**
   - Existing security controls effectiveness
   - Network segmentation and access controls
   - Monitoring and detection capabilities

6. **Prioritization Methodology**
   - Scoring algorithm and weighting factors
   - Decision matrices and automated scoring
   - Regular re-evaluation criteria

7. **Remediation Roadmap**
   - Immediate actions (0-30 days)
   - Short-term remediation (1-3 months)
   - Long-term strategic improvements (3-12 months)

8. **Metrics and Tracking**
   - Key performance indicators
   - Remediation progress tracking
   - Risk reduction measurement

Please provide a comprehensive vulnerability prioritization strategy that balances technical risk with business impact and operational constraints."""

        return types.GetPromptResult(
            description="Risk-based vulnerability prioritization framework",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=prompt_text
                    )
                )
            ]
        )
    
    async def _get_forensic_analysis_prompt(self, arguments: dict) -> types.GetPromptResult:
        """Generate forensic analysis prompt."""
        incident_id = arguments.get("incident_id")
        analysis_depth = arguments.get("analysis_depth", "detailed")
        
        # Get incident context
        context_data = ""
        try:
            # Try to fetch the specific incident/alert
            alerts_data = await self.api_client.get_alerts(limit=200)
            alerts = alerts_data.get("data", {}).get("affected_items", [])
            
            target_incident = None
            if incident_id:
                target_incident = next((a for a in alerts if str(a.get("id")) == str(incident_id)), None)
            
            if target_incident:
                agent_id = target_incident.get('agent', {}).get('id')
                agent_alerts = [a for a in alerts if a.get('agent', {}).get('id') == agent_id]
                
                context_data = f"""
### Incident Context:
- **Incident ID**: {incident_id}
- **Timestamp**: {target_incident.get('timestamp')}
- **Agent**: {target_incident.get('agent', {}).get('name')} ({target_incident.get('agent', {}).get('ip')})
- **Rule**: {target_incident.get('rule', {}).get('description')}
- **Severity**: Level {target_incident.get('rule', {}).get('level')}

### Related Events on Same Agent:
{chr(10).join([f"- {a.get('timestamp')}: {a.get('rule', {}).get('description')} (Level {a.get('rule', {}).get('level')})" for a in agent_alerts[:10]])}
"""
            else:
                context_data = f"\n### Incident ID {incident_id} not found in recent alerts. Proceeding with general forensic analysis framework."
        except Exception:
            context_data = f"\n### Error fetching incident context: {str(e)}"
        
        analysis_levels = {
            "surface": "high-level overview with key findings",
            "detailed": "comprehensive analysis with technical details",
            "comprehensive": "exhaustive examination with all available evidence"
        }
        
        analysis_description = analysis_levels.get(analysis_depth, "detailed analysis")
        
        prompt_text = f"""You are a digital forensics investigator conducting a {analysis_description} of a security incident. Perform systematic forensic analysis to reconstruct the incident timeline and identify all relevant evidence.

### Investigation Parameters:
- **Incident ID**: {incident_id}
- **Analysis Depth**: {analysis_depth.title()}
- **Investigation Type**: {analysis_description}

{context_data}

### Forensic Analysis Framework:

1. **Initial Assessment**
   - Incident scope and affected systems
   - Evidence preservation status
   - Investigation objectives and priorities

2. **Timeline Reconstruction**
   - Chronological sequence of events
   - Event correlation across systems
   - Attack progression and lateral movement

3. **Evidence Collection**
   - Log files and system artifacts
   - Network traffic analysis
   - File system examination
   - Memory dump analysis (if available)

4. **Artifact Analysis**
   - Malware analysis and IOC extraction
   - User activity reconstruction
   - System changes and modifications
   - Network connections and data exfiltration

5. **Attack Vector Analysis**
   - Initial compromise method
   - Privilege escalation techniques
   - Persistence mechanisms
   - Command and control communications

6. **Attribution Assessment**
   - Threat actor indicators
   - Tactics, techniques, and procedures (TTPs)
   - Campaign indicators and similarities
   - Geolocation and infrastructure analysis

7. **Impact Assessment**
   - Data accessed or compromised
   - System integrity status
   - Business process disruption
   - Regulatory and compliance implications

8. **Recovery Recommendations**
   - Evidence-based remediation steps
   - System restoration procedures
   - Security improvements
   - Monitoring enhancements

9. **Legal and Reporting**
   - Chain of custody documentation
   - Executive summary for stakeholders
   - Legal implications and requirements
   - Lessons learned and process improvements

Please conduct a thorough forensic analysis that follows industry best practices and provides actionable insights for incident response and security improvement."""

        return types.GetPromptResult(
            description=f"Comprehensive {analysis_depth} forensic analysis of security incident",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(
                        type="text",
                        text=prompt_text
                    )
                )
            ]
        )
    
    async def _send_critical_alert_notification(self, alert: dict):
        """Send notification for critical security alerts."""
        try:
            severity_level = alert.get('rule', {}).get('level', 0)
            if severity_level >= 12:  # Critical alerts
                await self.server.send_notification(
                    "security/critical-alert",
                    {
                        "alert_id": alert.get('id'),
                        "timestamp": alert.get('timestamp'),
                        "rule_description": alert.get('rule', {}).get('description'),
                        "severity": severity_level,
                        "agent": {
                            "id": alert.get('agent', {}).get('id'),
                            "name": alert.get('agent', {}).get('name'),
                            "ip": alert.get('agent', {}).get('ip')
                        },
                        "location": alert.get('location'),
                        "message": f"Critical security alert: {alert.get('rule', {}).get('description')}"
                    }
                )
                self.logger.info(f"Sent critical alert notification for alert {alert.get('id')}")
        except Exception:
            self.logger.error(f"Failed to send critical alert notification: {str(e)}")
    
    async def _send_agent_status_notification(self, agent_id: str, status: str, previous_status: str):
        """Send notification for agent status changes."""
        try:
            if status != previous_status:
                await self.server.send_notification(
                    "agents/status-change",
                    {
                        "agent_id": agent_id,
                        "new_status": status,
                        "previous_status": previous_status,
                        "timestamp": datetime.utcnow().isoformat(),
                        "message": f"Agent {agent_id} status changed from {previous_status} to {status}"
                    }
                )
                self.logger.info(f"Sent agent status notification for agent {agent_id}: {previous_status} -> {status}")
        except Exception:
            self.logger.error(f"Failed to send agent status notification: {str(e)}")
    
    async def _send_system_health_notification(self, health_status: str, details: dict):
        """Send notification for system health changes."""
        try:
            await self.server.send_notification(
                "system/health-status",
                {
                    "health_status": health_status,
                    "timestamp": datetime.utcnow().isoformat(),
                    "details": details,
                    "message": f"System health status: {health_status}"
                }
            )
            self.logger.info(f"Sent system health notification: {health_status}")
        except Exception:
            self.logger.error(f"Failed to send system health notification: {str(e)}")
    
    async def _report_progress(self, current: int, total: int, message: str):
        """Report progress for long-running operations."""
        try:
            progress = (current / total) * 100
            await self.server.send_notification(
                "operations/progress",
                {
                    "progress": progress,
                    "current_step": current,
                    "total_steps": total,
                    "message": message,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            self.logger.debug(f"Progress reported: {progress:.1f}% - {message}")
        except Exception:
            self.logger.error(f"Failed to report progress: {str(e)}")
    
    async def run(self):
        """Run the MCP server with robust error handling and logging."""
        api_client_entered = False
        try:
            self.logger.info("Starting Wazuh MCP Server session...")
            await self.api_client.__aenter__()
            api_client_entered = True
            
            self.logger.info(f"Wazuh MCP Server v{__version__} starting...")
            self.logger.info(f"Connecting to Wazuh at {self.config.base_url}")
            
            # Test connection with timeout and better error handling
            try:
                health_data = await asyncio.wait_for(
                    self.api_client.health_check(), 
                    timeout=self.config.request_timeout_seconds
                )
                if health_data.get("status") != "healthy":
                    self.logger.warning(f"Wazuh API health check returned: {health_data}")
                    # Continue anyway - some Wazuh versions may not have health endpoint
                else:
                    self.logger.info("Wazuh API connection verified successfully")
            except asyncio.TimeoutError:
                self.logger.warning("Wazuh API health check timed out, continuing anyway")
            except Exception:
                self.logger.warning(f"Wazuh API health check failed: {str(e)}, continuing anyway")
            
            init_options = InitializationOptions(
                server_name="wazuh-mcp",
                server_version=__version__,
                capabilities=self.server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={}
                )
            )
            
            # Use stdio transport for MCP compatibility
            async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
                self.logger.info("MCP server started successfully on stdio transport")
                await self.server.run(
                    read_stream,
                    write_stream,
                    init_options
                )
                
        except Exception as e:
            self.logger.error(f"Server runtime error: {str(e)}")
            raise
        finally:
            self.logger.info("Shutting down Wazuh MCP Server...")
            try:
                if api_client_entered:
                    await self.api_client.__aexit__(None, None, None)
            except Exception:
                self.logger.error(f"Error during cleanup: {str(e)}")
            self.logger.info("Server shutdown completed")


async def main():
    """Main entry point with comprehensive error handling."""
    logger = get_logger(__name__)
    try:
        server = WazuhMCPServer()
        await server.run()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except ConfigurationError as e:
        logger.error(f"Configuration error: {str(e)}")
        logger.error("Please check your .env file and environment variables")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())