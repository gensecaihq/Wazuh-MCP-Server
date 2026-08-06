# MCP Tools API Reference

Complete reference for all 55 tools available in Wazuh MCP Server v4.3.0.

## 🛠️ Tool Categories

### 🚨 [Alert Management](alerts.md) (5 tools)
Query and analyze security alerts from Wazuh with advanced filtering and pattern analysis. Timestamps accept ISO 8601 or relative date math (e.g. `now-24h`).

- **get_wazuh_alerts** - Retrieve security alerts with filtering options
- **get_wazuh_alert_summary** - Alert summaries grouped by criteria
- **get_alerts_aggregated** - Summarize a whole time range via Indexer aggregations (no document limit)
- **analyze_alert_patterns** - Pattern analysis for trend identification
- **search_security_events** - Advanced security event search

### 🖥️ [Agent Management](agents.md) (6 tools)
Monitor and manage Wazuh agents across your infrastructure.

- **get_wazuh_agents** - Agent information and status
- **get_wazuh_running_agents** - Active agents only
- **check_agent_health** - Agent health validation
- **get_agent_processes** - Running processes per agent
- **get_agent_ports** - Open ports per agent
- **get_agent_configuration** - Agent configuration details

### 🛡️ [Vulnerability Management](vulnerabilities.md) (3 tools)
Identify and analyze security vulnerabilities across your environment.

- **get_wazuh_vulnerabilities** - Comprehensive vulnerability data
- **get_wazuh_critical_vulnerabilities** - Critical vulnerabilities only
- **get_wazuh_vulnerability_summary** - Vulnerability statistics and trends

### 🔍 [Security Analysis](security-analysis.md) (5 tools)
Security analysis and threat intelligence capabilities.

- **analyze_security_threat** - Threat analysis
- **check_ioc_reputation** - IoC reputation checking
- **perform_risk_assessment** - Comprehensive risk analysis
- **get_top_security_threats** - Top threats by severity
- **generate_security_report** - Automated security reporting

### 📋 [Compliance & Reporting](compliance-reporting.md) (6 tools)
Compliance scoring grounded in live Wazuh data.

- **run_compliance_check** - Framework validation: PCI-DSS, HIPAA, SOX, GDPR, NIST, ISO27001
- **get_iso27001_dashboard** - ISO 27001:2022 posture by Annex A domain
- **get_iso27001_control_detail** - Drill into a control (e.g. `A.8.8`) with live evidence
- **get_iso27001_gap_analysis** - Prioritized gap list with remediation hints
- **get_iso27001_alerts** - Recent alerts mapped to ISO 27001 control domains
- **get_sca_policy_checks** - Check-level SCA detail (pass/fail, rationale, remediation)

Also adds an `iso27001_assessment` guided prompt.

### 📊 [System Monitoring](system-monitoring.md) (10 tools)
Monitor system health, performance, and operational metrics.

- **get_wazuh_statistics** - Comprehensive system statistics
- **get_wazuh_weekly_stats** - Weekly trend analysis
- **get_wazuh_cluster_health** - Cluster health monitoring
- **get_wazuh_cluster_nodes** - Cluster node information
- **get_wazuh_rules_summary** - Rule effectiveness metrics
- **get_wazuh_remoted_stats** - Agent communication statistics
- **get_wazuh_log_collector_stats** - Log collector metrics
- **search_wazuh_manager_logs** - Manager log search
- **get_wazuh_manager_error_logs** - Error log retrieval
- **validate_wazuh_connection** - Connection validation

### ⚡ Active Response (9 tools)
Execute active response actions on Wazuh agents.

- **wazuh_block_ip** - Block IP address via active response
- **wazuh_isolate_host** - Isolate a host from the network
- **wazuh_kill_process** - Kill a running process on an agent
- **wazuh_disable_user** - Disable a user account
- **wazuh_quarantine_file** - Quarantine a suspicious file
- **wazuh_active_response** - Send custom active response command
- **wazuh_firewall_drop** - Add firewall drop rule
- **wazuh_host_deny** - Add host deny rule
- **wazuh_restart** - Restart Wazuh agent

### ✅ Verification (5 tools)
Verify the status of active response actions.

- **wazuh_check_blocked_ip** - Verify IP is blocked
- **wazuh_check_agent_isolation** - Verify agent isolation status
- **wazuh_check_process** - Check if process is running
- **wazuh_check_user_status** - Check user account status
- **wazuh_check_file_quarantine** - Check file quarantine status

### ↩️ Rollback (5 tools)
Reverse active response actions.

- **wazuh_unisolate_host** - Remove host isolation
- **wazuh_enable_user** - Re-enable a disabled user
- **wazuh_restore_file** - Restore a quarantined file
- **wazuh_firewall_allow** - Remove firewall drop rule
- **wazuh_host_allow** - Remove host deny rule

## 🎯 Quick Examples

### Basic Usage
```
Ask Claude: "Show me the latest security alerts"
Uses: get_wazuh_alerts

Ask Claude: "What are my active agents?"
Uses: get_wazuh_running_agents

Ask Claude: "Check for critical vulnerabilities"
Uses: get_wazuh_critical_vulnerabilities
```

### Advanced Queries
```
Ask Claude: "Analyze threat patterns from the last 24 hours"
Uses: analyze_alert_patterns + analyze_security_threat

Ask Claude: "Generate a security report for compliance"
Uses: generate_security_report + run_compliance_check

Ask Claude: "Check system health and performance"
Uses: validate_wazuh_connection + get_wazuh_cluster_health
```

## 📝 Tool Usage Patterns

### Parameter Validation
All tools use Pydantic v2 models for parameter validation:

```python
class AlertQuery(BaseModel):
    limit: int = Field(default=100, ge=1, le=1000)
    rule_id: Optional[str] = None
    level: Optional[str] = None
    agent_id: Optional[str] = None
    timestamp_start: Optional[str] = None
    timestamp_end: Optional[str] = None
```

### Response Format
All tools return JSON responses with consistent structure:

```json
{
  "data": [...],
  "total": 150,
  "pagination": {
    "limit": 100,
    "offset": 0,
    "pages": 2
  },
  "metadata": {
    "query_time": "2024-01-01T12:00:00Z",
    "api_source": "wazuh_server",
    "version": "4.2.1"
  }
}
```

### Error Handling
Consistent error responses across all tools:

```json
{
  "error": "Connection timeout to Wazuh server",
  "error_code": "CONNECTION_TIMEOUT",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## 🔄 API Integration

### Which backend each tool uses

Each tool targets one backend by design (there is no cross-fallback between them):

- **Wazuh Manager API** — agents, rules, cluster, manager logs/stats, active response, verification, rollback, SCA.
- **Wazuh Indexer (OpenSearch)** — alert query/summary/aggregation, security event search, and vulnerabilities.

Indexer-backed tools require `WAZUH_INDEXER_HOST`. When it isn't configured, those tools return a clear `IndexerNotConfiguredError` rather than silently falling back.

### Resilience
- Transient failures (5xx, connection, timeout) are retried with exponential backoff.
- Repeated failures open a per-client **circuit breaker** for ~60s, then a single trial request probes recovery.
- A 429 (upstream rate-limit) is retried but does **not** trip the breaker.

## 🎨 Tool Development

### Adding New Tools
See [Development Guide](../development/api.md) for creating custom MCP tools.

### Tool Categories
Tools are organized by functionality:
- **Data Retrieval**: Get information from Wazuh
- **Analysis**: Process and analyze data
- **Health**: Monitor system status
- **Utilities**: Helper and validation tools

## 📊 Performance Considerations

### Rate Limiting
- Default: 1000 requests/minute per tool
- Burst: 100 requests allowed
- Configurable via environment variables

### Caching
- Query results cached for 5 minutes (configurable)
- Cache invalidated on configuration changes
- Disabled for real-time queries

### Pagination
- Default limit: 100 items
- Maximum limit: 1000 items (alerts/agents), 500 items (vulnerabilities)
- Automatic pagination for large datasets

## 🔒 Security Features

### Input Validation
- All parameters validated with Pydantic models
- SQL injection protection for query parameters
- XSS protection for string inputs

### Access Control
- Tool access controlled by Wazuh user permissions
- API key authentication for enhanced security
- Audit logging for all tool usage

### Data Sanitization
- Sensitive data removed from responses
- Error messages sanitized to prevent information disclosure
- Request/response logging excludes credentials

## 📞 Support

### Tool-Specific Issues
Each tool category has detailed documentation:
- Parameter specifications
- Example usage
- Common errors and solutions
- Performance optimization tips

### General API Issues
- **Connection problems**: Check [Connection Troubleshooting](../troubleshooting/connection.md)
- **Authentication errors**: See [Security Configuration](../security/auth.md)
- **Performance issues**: Review [Performance Tuning](../troubleshooting/performance.md)

---

**Ready to explore?** Click on any tool category above to see detailed documentation and examples.