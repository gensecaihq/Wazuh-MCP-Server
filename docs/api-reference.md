# API Reference - Wazuh MCP Server

Complete reference for all available tools, resources, and prompts in the Wazuh MCP Server.

## Overview

The Wazuh MCP Server provides a comprehensive API for security operations through the Model Context Protocol (MCP). All tools are designed with production security, performance optimization, and comprehensive error handling.

## Tools

### Security Operations

#### `get_wazuh_alerts`

Retrieve and enrich Wazuh alerts with advanced filtering and risk scoring.

**Parameters:**
- `limit` (int, optional): Maximum number of alerts (1-10000, default: 100)
- `level` (int, optional): Minimum alert level (1-15)
- `time_range` (int, optional): Time range in seconds (300-86400)
- `agent_id` (string, optional): Filter by specific agent ID

**Returns:**
```json
{
  "success": true,
  "alerts": [
    {
      "id": "alert_id",
      "timestamp": "2024-01-01T12:00:00Z",
      "rule": {
        "id": 1002,
        "level": 5,
        "description": "User authentication failure"
      },
      "agent": {
        "id": "001",
        "name": "web-server-01",
        "ip": "192.168.1.10"
      },
      "enrichment": {
        "risk_score": 65,
        "severity_label": "medium",
        "category": "authentication",
        "is_high_priority": false,
        "requires_investigation": false
      }
    }
  ],
  "total_count": 150,
  "query_params": {
    "limit": 100,
    "level": 5,
    "agent_id": "001"
  },
  "metadata": {
    "timestamp": "2024-01-01T12:00:00Z",
    "source": "wazuh_api",
    "enrichment_enabled": true,
    "server_version": "3.1.0"
  }
}
```

**Example Usage:**
```python
# Get high-severity alerts from last hour
alerts = await get_wazuh_alerts(
    limit=50,
    level=8,
    time_range=3600
)

# Get all alerts for specific agent
agent_alerts = await get_wazuh_alerts(
    agent_id="001",
    limit=200
)
```

#### `analyze_security_threats`

AI-powered threat analysis using Claude models with comprehensive insights.

**Parameters:**
- `time_range` (string, optional): Time range ("1h", "6h", "24h", "7d", "30d", default: "24h")
- `focus_area` (string, optional): Analysis focus ("network", "file", "process", "authentication", "all", default: "all")
- `min_severity` (int, optional): Minimum severity level (1-15, default: 5)

**Returns:**
```json
{
  "success": true,
  "threat_level": "MEDIUM",
  "ai_analysis": {
    "executive_summary": "Analysis of 1,247 security events reveals...",
    "key_findings": [
      "Increased authentication failures from external IPs",
      "Suspicious file access patterns detected",
      "Network scanning activity identified"
    ],
    "attack_patterns": [
      "Brute force authentication attempts",
      "Lateral movement indicators"
    ],
    "affected_systems": [
      "web-server-01",
      "db-server-02"
    ],
    "immediate_actions": [
      "Block suspicious IP addresses",
      "Review authentication logs",
      "Implement additional monitoring"
    ],
    "strategic_recommendations": [
      "Enhance MFA implementation",
      "Deploy additional network segmentation",
      "Update incident response procedures"
    ],
    "urgency_level": "MEDIUM",
    "confidence_score": 0.85
  },
  "statistical_summary": {
    "total_alerts": 1247,
    "high_severity_alerts": 23,
    "unique_rules": 45,
    "affected_agents": 12,
    "time_distribution": {
      "00:00": 45,
      "01:00": 38,
      "02:00": 52
    }
  },
  "metadata": {
    "analysis_timestamp": "2024-01-01T12:00:00Z",
    "model_used": "claude-3-sonnet-20240229",
    "server_version": "3.1.0"
  }
}
```

#### `check_wazuh_agent_health`

Comprehensive agent health monitoring with diagnostics and recommendations.

**Parameters:**
- `agent_id` (string, optional): Specific agent ID (empty for all agents)
- `include_disconnected` (bool, optional): Include offline agents (default: true)
- `health_threshold` (float, optional): Health score threshold 0-100 (default: 0.0)

**Returns:**
```json
{
  "success": true,
  "health_summary": {
    "total_agents": 25,
    "active_agents": 23,
    "disconnected_agents": 2,
    "health_percentage": 92.0,
    "avg_health_score": 87.5,
    "overall_status": "HEALTHY"
  },
  "agent_details": {
    "active": [
      {
        "id": "001",
        "name": "web-server-01",
        "ip": "192.168.1.10",
        "status": "active",
        "last_keep_alive": "2024-01-01T11:59:30Z",
        "version": "4.8.0",
        "os_name": "Ubuntu",
        "os_version": "22.04",
        "health_score": 95.2,
        "health_status": "excellent",
        "registration_time": "2023-12-01T10:00:00Z"
      }
    ],
    "disconnected": [],
    "never_connected": [],
    "pending": []
  },
  "recommendations": [
    "✅ Excellent: Agent infrastructure is healthy",
    "📦 Updates Available: 3 agents need version updates"
  ],
  "metadata": {
    "timestamp": "2024-01-01T12:00:00Z",
    "health_threshold": 0.0,
    "include_disconnected": true,
    "server_version": "3.1.0"
  }
}
```

### System Monitoring

#### `get_server_health`

Real-time server health status and performance metrics.

**Parameters:**
None

**Returns:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "uptime_seconds": 86400,
  "version": "3.1.0",
  "checks": {
    "configuration": {
      "status": "healthy",
      "details": "Configuration loaded"
    },
    "http_client": {
      "status": "healthy",
      "details": "HTTP client ready"
    },
    "wazuh_api": {
      "status": "healthy",
      "details": "API connection and functionality verified"
    }
  },
  "metrics": {
    "requests_total": 1543,
    "requests_failed": 12,
    "success_rate": 99.22,
    "avg_response_time_ms": 245.67,
    "last_error": null
  }
}
```

## Resources

Resources provide real-time access to Wazuh data streams.

### `wazuh://cluster/status`

Real-time Wazuh cluster status with comprehensive information.

**Returns:**
```json
{
  "cluster_info": {
    "enabled": true,
    "running": "yes",
    "name": "wazuh-cluster",
    "node_name": "master-node",
    "node_type": "master"
  },
  "manager_info": {
    "version": "4.8.0",
    "compilation_date": "2024-01-01",
    "installation_date": "2023-12-01",
    "hostname": "wazuh-manager"
  },
  "nodes": [
    {
      "name": "master-node",
      "type": "master",
      "version": "4.8.0",
      "ip": "192.168.1.100"
    },
    {
      "name": "worker-node-01",
      "type": "worker",
      "version": "4.8.0",
      "ip": "192.168.1.101"
    }
  ],
  "status": "healthy",
  "last_updated": "2024-01-01T12:00:00Z"
}
```

### `wazuh://security/overview`

Comprehensive security overview with real-time threat assessment.

**Returns:**
```json
{
  "overall_status": "MEDIUM",
  "risk_score": 65,
  "risk_factors": {
    "alert_volume": 15,
    "critical_alerts": 20,
    "infrastructure_health": 5,
    "threat_diversity": 10
  },
  "recent_activity": {
    "last_hour_alerts": 45,
    "critical_alerts_24h": 8,
    "alert_rate_trend": "stable",
    "top_alert_rules": [
      {
        "rule_id": 5712,
        "description": "Multiple authentication failures",
        "count": 23
      }
    ]
  },
  "infrastructure": {
    "total_agents": 25,
    "active_agents": 23,
    "agent_health_percentage": 92.0,
    "disconnected_agents": 2
  },
  "threat_indicators": {
    "high_severity_alerts": 8,
    "unique_threats": 12,
    "affected_agents": 5,
    "attack_patterns": [
      "Authentication failures",
      "Network scanning"
    ]
  },
  "recommendations": [
    "🔍 INVESTIGATE: Multiple critical alerts detected",
    "✅ MAINTAIN: Agent infrastructure is stable"
  ],
  "last_updated": "2024-01-01T12:00:00Z"
}
```

## Prompts

AI-powered prompts for security analysis and reporting.

### `security_briefing`

Generate comprehensive security briefing reports.

**Parameters:**
- `time_range` (string, optional): Time range for analysis (default: "24h")

**Generated Prompt:**
```
Create a comprehensive security briefing for the last 24h based on Wazuh SIEM data.

**Required Sections:**

1. **Executive Summary**
   - Overall security posture assessment
   - Key risk indicators and trends
   - Critical items requiring immediate attention
   - Risk level classification (LOW/MEDIUM/HIGH/CRITICAL)

2. **Threat Landscape Analysis**
   - Most frequent alert types and their significance
   - Emerging threat patterns or anomalous activity
   - Geographic, temporal, or behavioral attack patterns
   - Threat actor TTPs (Tactics, Techniques, Procedures)

3. **Infrastructure Health Assessment**
   - Agent connectivity and coverage status
   - Monitoring effectiveness and blind spots
   - System performance and reliability metrics
   - Configuration compliance status

4. **Critical Security Incidents**
   - High-severity alerts requiring investigation
   - Potential security incidents and impact assessment
   - Evidence of coordinated or advanced attacks
   - Incident response recommendations

5. **Strategic Recommendations**
   - Immediate actions required (next 24 hours)
   - Short-term improvements (next 7 days)
   - Strategic security enhancements (next 30 days)
   - Resource allocation recommendations

**Format Requirements:**
- Professional executive briefing suitable for security leadership
- Clear, concise language with quantified metrics where possible
- Actionable insights with specific next steps
- Risk-based prioritization of recommendations
```

### `incident_investigation`

Structured incident investigation framework.

**Parameters:**
- `incident_data` (string): Incident data to investigate

**Generated Prompt:**
```
Conduct a thorough security incident investigation using the provided data:

**Incident Data:** [incident_data]

**Investigation Framework:**

1. **Initial Assessment**
   - Incident classification and severity rating
   - Affected systems and potential blast radius
   - Initial containment status
   - Evidence preservation requirements

2. **Technical Analysis**
   - Attack vector identification and analysis
   - Indicators of Compromise (IOCs) extraction
   - Malware analysis (if applicable)
   - Network traffic analysis patterns

3. **Timeline Reconstruction**
   - Chronological sequence of events
   - Attack progression and lateral movement
   - Data exfiltration timeline (if applicable)
   - Response actions timeline

4. **Scope and Impact Assessment**
   - Affected systems and data inventory
   - Business impact quantification
   - Regulatory notification requirements
   - Customer/stakeholder impact

5. **Response Recommendations**
   - Immediate containment actions
   - Eradication procedures
   - Recovery planning
   - Lessons learned integration

**Deliverables:**
- Executive incident summary
- Technical investigation report
- Evidence package with IOCs
- Recovery and remediation plan
```

## Error Handling

All API calls return consistent error structures:

```json
{
  "success": false,
  "error": "Error description",
  "error_code": "ERROR_CODE",
  "timestamp": "2024-01-01T12:00:00Z",
  "details": {
    "additional": "context"
  }
}
```

### Common Error Codes

- `AUTHENTICATION_ERROR`: Invalid credentials or expired tokens
- `AUTHORIZATION_ERROR`: Insufficient permissions
- `VALIDATION_ERROR`: Invalid input parameters
- `RATE_LIMIT_ERROR`: Too many requests
- `CONNECTION_ERROR`: Network connectivity issues
- `API_ERROR`: Wazuh API errors
- `TIMEOUT_ERROR`: Request timeout

## Rate Limiting

API calls are rate-limited for security and performance:

- **Standard Limit**: 60 requests per minute
- **Burst Allowance**: 10 additional requests
- **Per-IP Limiting**: Enabled in production
- **Headers**: Rate limit information in response headers

## Authentication

For HTTP transport mode, authentication is required:

```bash
# Obtain JWT token
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "password"}'

# Use token in requests
curl -H "Authorization: Bearer <token>" \
  http://localhost:3000/api/alerts
```

## Security Considerations

- All inputs are validated and sanitized
- SQL injection protection enabled
- Rate limiting prevents abuse
- Comprehensive audit logging
- Secure credential handling
- SSL/TLS encryption for all communications

## Performance Optimization

- Connection pooling for HTTP clients
- Chunked processing for large datasets
- Memory-efficient alert processing
- Timeout management for all operations
- Resource cleanup and garbage collection

## Monitoring

All API calls are monitored and logged:

- Request/response times
- Success/failure rates
- Error patterns
- Security events
- Performance metrics

For detailed monitoring setup, see the [Monitoring Guide](monitoring-guide.md).