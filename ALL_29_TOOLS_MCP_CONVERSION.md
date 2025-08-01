# Complete 29 Tools MCP Conversion for v-final Branch

## Overview
This document provides the complete conversion of all 29 FastMCP tools from the main branch to MCP-compliant format for integration into the v-final branch server.

## Integration Steps

### 1. Update tools/list handler in server.py

Replace the existing tools array in `handle_tools_list()` function with this comprehensive list:

```python
async def handle_tools_list(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/list method."""
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
                    "timestamp_end": {"type": "string", "description": "End timestamp (ISO format)"}
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
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100}
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

        # Vulnerability Management Tools (3 tools)
        {
            "name": "get_wazuh_vulnerabilities",
            "description": "Retrieve vulnerability information from Wazuh",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id": {"type": "string", "description": "Filter by specific agent ID"},
                    "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Filter by severity level"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}
                },
                "required": []
            }
        },
        {
            "name": "get_wazuh_critical_vulnerabilities",
            "description": "Get critical vulnerabilities from Wazuh",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50}
                },
                "required": []
            }
        },
        {
            "name": "get_wazuh_vulnerability_summary",
            "description": "Get vulnerability summary statistics from Wazuh",
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
                    "include_recommendations": {"type": "boolean", "default": true}
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
```

### 2. Update tools/call handler in server.py

Replace the existing tool handling logic in `handle_tools_call()` function with this comprehensive implementation:

```python
async def handle_tools_call(params: Dict[str, Any], session: MCPSession) -> Dict[str, Any]:
    """Handle tools/call method."""
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
            result = await wazuh_client.get_alerts(
                limit=limit, rule_id=rule_id, level=level, 
                agent_id=agent_id, timestamp_start=timestamp_start, 
                timestamp_end=timestamp_end
            )
            return {"content": [{"type": "text", "text": f"Wazuh Alerts:\n{json.dumps(result, indent=2)}"}]}
            
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
            result = await wazuh_client.search_security_events(query, time_range, limit)
            return {"content": [{"type": "text", "text": f"Security Events:\n{json.dumps(result, indent=2)}"}]}

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
            result = await wazuh_client.get_vulnerabilities(agent_id=agent_id, severity=severity, limit=limit)
            return {"content": [{"type": "text", "text": f"Vulnerabilities:\n{json.dumps(result, indent=2)}"}]}
            
        elif tool_name == "get_wazuh_critical_vulnerabilities":
            limit = arguments.get("limit", 50)
            result = await wazuh_client.get_critical_vulnerabilities(limit)
            return {"content": [{"type": "text", "text": f"Critical Vulnerabilities:\n{json.dumps(result, indent=2)}"}]}
            
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
            
    except Exception as e:
        logger.error(f"Tool execution error: {e}")
        raise ValueError(f"Tool execution failed: {str(e)}")
```

### 3. Required Wazuh Client Extensions

Your existing `wazuh_client.py` needs these additional methods to support all 29 tools:

```python
# Add these methods to your WazuhClient class in api/wazuh_client.py

async def get_manager_info(self) -> Dict[str, Any]:
    """Get Wazuh manager information."""
    return await self._request("GET", "/")

async def get_alert_summary(self, time_range: str, group_by: str) -> Dict[str, Any]:
    """Get alert summary grouped by field."""
    params = {"time_range": time_range, "group_by": group_by}
    return await self._request("GET", "/alerts/summary", params=params)

async def analyze_alert_patterns(self, time_range: str, min_frequency: int) -> Dict[str, Any]:
    """Analyze alert patterns."""
    params = {"time_range": time_range, "min_frequency": min_frequency}
    return await self._request("GET", "/alerts/patterns", params=params)

async def search_security_events(self, query: str, time_range: str, limit: int) -> Dict[str, Any]:
    """Search security events."""
    params = {"q": query, "time_range": time_range, "limit": limit}
    return await self._request("GET", "/security/events", params=params)

async def get_running_agents(self) -> Dict[str, Any]:
    """Get running agents."""
    return await self._request("GET", "/agents", params={"status": "active"})

async def check_agent_health(self, agent_id: str) -> Dict[str, Any]:
    """Check agent health."""
    return await self._request("GET", f"/agents/{agent_id}/health")

async def get_agent_processes(self, agent_id: str, limit: int) -> Dict[str, Any]:
    """Get agent processes."""
    return await self._request("GET", f"/syscollector/{agent_id}/processes", params={"limit": limit})

async def get_agent_ports(self, agent_id: str, limit: int) -> Dict[str, Any]:
    """Get agent ports."""
    return await self._request("GET", f"/syscollector/{agent_id}/ports", params={"limit": limit})

async def get_agent_configuration(self, agent_id: str) -> Dict[str, Any]:
    """Get agent configuration."""
    return await self._request("GET", f"/agents/{agent_id}/config")

async def get_critical_vulnerabilities(self, limit: int) -> Dict[str, Any]:
    """Get critical vulnerabilities."""
    return await self._request("GET", "/vulnerability/agents", params={"severity": "critical", "limit": limit})

async def get_vulnerability_summary(self, time_range: str) -> Dict[str, Any]:
    """Get vulnerability summary."""
    return await self._request("GET", "/vulnerability/summary", params={"time_range": time_range})

async def analyze_security_threat(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
    """Analyze security threat."""
    data = {"indicator": indicator, "type": indicator_type}
    return await self._request("POST", "/security/threat/analyze", json=data)

async def check_ioc_reputation(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
    """Check IoC reputation."""
    params = {"indicator": indicator, "type": indicator_type}
    return await self._request("GET", "/security/ioc/reputation", params=params)

async def perform_risk_assessment(self, agent_id: str = None) -> Dict[str, Any]:
    """Perform risk assessment."""
    endpoint = f"/security/risk/{agent_id}" if agent_id else "/security/risk"
    return await self._request("GET", endpoint)

async def get_top_security_threats(self, limit: int, time_range: str) -> Dict[str, Any]:
    """Get top security threats."""
    params = {"limit": limit, "time_range": time_range}
    return await self._request("GET", "/security/threats/top", params=params)

async def generate_security_report(self, report_type: str, include_recommendations: bool) -> Dict[str, Any]:
    """Generate security report."""
    data = {"type": report_type, "include_recommendations": include_recommendations}
    return await self._request("POST", "/security/reports/generate", json=data)

async def run_compliance_check(self, framework: str, agent_id: str = None) -> Dict[str, Any]:
    """Run compliance check."""
    data = {"framework": framework}
    if agent_id:
        data["agent_id"] = agent_id
    return await self._request("POST", "/security/compliance/check", json=data)

async def get_wazuh_statistics(self) -> Dict[str, Any]:
    """Get Wazuh statistics."""
    return await self._request("GET", "/manager/stats/all")

async def get_weekly_stats(self) -> Dict[str, Any]:
    """Get weekly statistics."""
    return await self._request("GET", "/manager/stats/weekly")

async def get_cluster_health(self) -> Dict[str, Any]:
    """Get cluster health."""
    return await self._request("GET", "/cluster/health")

async def get_cluster_nodes(self) -> Dict[str, Any]:
    """Get cluster nodes."""
    return await self._request("GET", "/cluster/nodes")

async def get_rules_summary(self) -> Dict[str, Any]:
    """Get rules summary."""
    return await self._request("GET", "/rules/summary")

async def get_remoted_stats(self) -> Dict[str, Any]:
    """Get remoted statistics."""
    return await self._request("GET", "/manager/stats/remoted")

async def get_log_collector_stats(self) -> Dict[str, Any]:
    """Get log collector statistics."""
    return await self._request("GET", "/manager/stats/logcollector")

async def search_manager_logs(self, query: str, limit: int) -> Dict[str, Any]:
    """Search manager logs."""
    params = {"q": query, "limit": limit}
    return await self._request("GET", "/manager/logs", params=params)

async def get_manager_error_logs(self, limit: int) -> Dict[str, Any]:
    """Get manager error logs."""
    params = {"level": "error", "limit": limit}
    return await self._request("GET", "/manager/logs", params=params)

async def validate_connection(self) -> Dict[str, Any]:
    """Validate Wazuh connection."""
    try:
        result = await self._request("GET", "/")
        return {"status": "connected", "details": result}
    except Exception as e:
        return {"status": "failed", "error": str(e)}
```

## Summary

This conversion provides:

1. **Complete MCP-compliant tool definitions** for all 29 FastMCP tools
2. **Proper JSON schemas** for input validation
3. **Tool categorization** by functionality (Alert Management, Agent Management, etc.)
4. **Error handling** and consistent response formatting
5. **Required Wazuh client extensions** to support all tool operations

The tools are organized into 5 categories:
- **Alert Management** (4 tools)
- **Agent Management** (6 tools) 
- **Vulnerability Management** (3 tools)
- **Security Analysis** (6 tools)
- **System Monitoring** (10 tools)

This maintains full functionality from the main branch while being fully MCP-compliant for the v-final branch.