# FastMCP Tools API Reference

Complete reference for all 29 FastMCP tools available in Wazuh MCP Server v2.1.0.

## 🛠️ Tool Categories

### 🚨 [Alert Management](alerts.md) (4 tools)
Query and analyze security alerts from Wazuh with advanced filtering and pattern analysis.

- **get_wazuh_alerts** - Retrieve security alerts with filtering options
- **get_wazuh_alert_summary** - Alert summaries grouped by criteria
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

### 🔍 [Security Analysis](security.md) (6 tools)
AI-powered security analysis and threat intelligence capabilities.

- **analyze_security_threat** - AI-powered threat analysis
- **check_ioc_reputation** - IoC reputation checking
- **perform_risk_assessment** - Comprehensive risk analysis
- **get_top_security_threats** - Top threats by severity
- **generate_security_report** - Automated security reporting
- **run_compliance_check** - Compliance framework validation

### 📊 [System Monitoring](monitoring.md) (10 tools)
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
    "version": "2.1.0"
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

### Intelligent API Routing
Tools automatically choose the optimal API based on:

- **Wazuh Server API**: For agent management, rules, configuration
- **Wazuh Indexer API**: For alerts, vulnerabilities, event search

```python
# Automatic API selection
if indexer_available and use_indexer_for_alerts:
    return await indexer_client.search_alerts(query)
else:
    return await server_client.get_alerts(query)
```

### Fallback Mechanisms
- **Server API fails** → Auto-retry with Indexer API
- **Indexer API fails** → Auto-retry with Server API
- **Both fail** → Return structured error response

## 🎨 Tool Development

### Adding New Tools
See [Development Guide](../development/api.md) for creating custom FastMCP tools.

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