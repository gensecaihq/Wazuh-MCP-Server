# Available Tools

Wazuh MCP Server provides 26 security tools organized by category.

## Alert Management

### get_wazuh_alerts
Query security alerts with flexible filtering.
```
Parameters:
- query: Search query (optional)
- time_range: Time range (1h, 24h, 7d, 30d)
- severity: Filter by severity
- agent_id: Filter by agent
- limit: Max results (default: 100)

Example: "Show me critical alerts from web servers in the last hour"
```

### get_wazuh_alert_summary
Get statistical summary of alerts.
```
Parameters:
- time_range: Time range for analysis
- group_by: Group by field (rule, agent, level)

Example: "Give me an alert summary for the last 24 hours"
```

### analyze_wazuh_threats
AI-powered threat analysis with recommendations.
```
Parameters:
- time_range: Time range to analyze
- focus_area: Specific area (network, file, process)
- min_severity: Minimum severity level

Example: "Analyze network threats from the past week"
```

## Agent Monitoring

### check_wazuh_agent_health
Check health status of Wazuh agents.
```
Parameters:
- agent_id: Specific agent ID (optional)
- include_disconnected: Include offline agents

Example: "Check if any agents are disconnected"
```

### get_wazuh_running_agents
List all active/running agents.
```
Parameters:
- os_platform: Filter by OS
- version: Filter by agent version

Example: "Show me all running Windows agents"
```

### get_wazuh_agent_processes
Get running processes from an agent.
```
Parameters:
- agent_id: Agent ID (required)
- filter: Process name filter

Example: "Show processes running on agent 001"
```

### get_wazuh_agent_ports
Get network connections from an agent.
```
Parameters:
- agent_id: Agent ID (required)
- state: Connection state (listening, established)
- protocol: TCP or UDP

Example: "Show listening ports on the web server"
```

## Vulnerability Management

### get_wazuh_vulnerability_summary
Overview of vulnerabilities across environment.
```
Parameters:
- severity: Filter by severity
- limit: Max results

Example: "Show vulnerability summary"
```

### get_wazuh_critical_vulnerabilities
Get critical severity vulnerabilities.
```
Parameters:
- limit: Max results
- cve_id: Specific CVE lookup

Example: "List all critical vulnerabilities"
```

## Compliance & Risk

### check_wazuh_compliance
Check compliance with security standards.
```
Parameters:
- standard: CIS, PCI-DSS, HIPAA, GDPR
- agent_id: Specific agent (optional)

Example: "Check PCI-DSS compliance status"
```

### get_wazuh_risk_assessment
Comprehensive risk assessment of environment.
```
Parameters:
- scope: full, agents, vulnerabilities
- include_recommendations: Include remediation advice

Example: "Perform a full risk assessment"
```

## Statistics & Reporting

### get_wazuh_weekly_stats
Weekly statistics and trends.
```
Parameters:
- weeks: Number of weeks (default: 1)

Example: "Show weekly statistics"
```

### get_wazuh_remoted_stats
Remote daemon statistics.
```
Example: "Get remote connection statistics"
```

### get_wazuh_log_collector_stats
Log collection statistics.
```
Example: "Show log collector stats"
```

## Cluster Management

### get_wazuh_cluster_health
Check Wazuh cluster health.
```
Example: "Check cluster health status"
```

### get_wazuh_cluster_nodes
List all cluster nodes.
```
Example: "Show all cluster nodes"
```

### search_wazuh_manager_logs
Search Wazuh manager logs.
```
Parameters:
- query: Search query
- log_type: Log type filter

Example: "Search for authentication errors in manager logs"
```

### get_wazuh_manager_error_logs
Get recent error logs from manager.
```
Parameters:
- limit: Max results
- time_range: Time range

Example: "Show recent manager errors"
```

## Security Intelligence

### check_wazuh_ioc
Check for indicators of compromise.
```
Parameters:
- ioc_type: ip, domain, hash, file
- value: IOC value to check

Example: "Check if IP 192.168.1.100 is malicious"
```

### get_wazuh_rules_summary
Summary of active detection rules.
```
Parameters:
- status: enabled, disabled
- level: Minimum rule level

Example: "Show summary of detection rules"
```

## Usage Tips

1. **Natural Language**: Claude understands context, so use natural descriptions
2. **Time Ranges**: Use human-friendly terms like "last hour", "past week"
3. **Filtering**: Be specific about what you want to see
4. **Analysis**: Ask for insights and recommendations, not just data

## Common Workflows

### Daily Security Check
```
1. "Check agent health status"
2. "Show critical alerts from last 24 hours"
3. "List any new vulnerabilities"
4. "Check compliance status"
```

### Incident Investigation
```
1. "Show alerts from [specific time]"
2. "Analyze threats on [agent/server]"
3. "Check processes on affected agent"
4. "Look for IOCs related to [threat]"
```

### Compliance Audit
```
1. "Check PCI-DSS compliance"
2. "Show non-compliant agents"
3. "Generate risk assessment"
4. "List remediation steps"
```