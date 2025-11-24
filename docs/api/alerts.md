# Alert Management API

Complete reference for Wazuh alert management tools. These tools provide comprehensive access to Wazuh security alerts with advanced filtering, pattern analysis, and threat intelligence capabilities.

## Overview

The alert management tools offer four main capabilities:
- **Alert Retrieval**: Query alerts with flexible filtering options
- **Alert Summarization**: Statistical analysis and grouping of alerts
- **Pattern Analysis**: AI-powered trend identification and anomaly detection
- **Event Search**: Advanced full-text search across security events

---

## 🚨 get_wazuh_alerts

Retrieve Wazuh security alerts with comprehensive filtering options.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `limit` | integer | `100` | No | Maximum number of alerts to retrieve (1-1000) |
| `rule_id` | string | `null` | No | Filter by specific Wazuh rule ID |
| `level` | string | `null` | No | Filter by alert level (e.g., '12', '10+', '5-8') |
| `agent_id` | string | `null` | No | Filter by specific agent ID |
| `timestamp_start` | string | `null` | No | Start timestamp in ISO format (2024-01-01T00:00:00Z) |
| `timestamp_end` | string | `null` | No | End timestamp in ISO format (2024-01-01T23:59:59Z) |

### Usage Examples

#### Basic Alert Retrieval
```
Ask Claude: "Show me the latest 50 security alerts"
```

This queries:
- `limit`: 50
- Other parameters: default values

#### Filter by Alert Level
```
Ask Claude: "Show me all critical alerts from the last hour"
```

This queries:
- `level`: "12+" (critical and above)
- `timestamp_start`: 1 hour ago
- `limit`: 100 (default)

#### Filter by Specific Agent
```
Ask Claude: "Get alerts from agent 001 for the last 24 hours"
```

This queries:
- `agent_id`: "001"
- `timestamp_start`: 24 hours ago
- `limit`: 100 (default)

#### Complex Filtering
```
Ask Claude: "Show me rule 5715 alerts from agent 001 in the last 6 hours"
```

This queries:
- `rule_id`: "5715"
- `agent_id`: "001"
- `timestamp_start`: 6 hours ago

### Response Format

```json
{
  "data": [
    {
      "id": "alert_12345",
      "timestamp": "2024-01-01T14:30:00Z",
      "rule": {
        "id": 5715,
        "level": 8,
        "description": "Multiple authentication failures"
      },
      "agent": {
        "id": "001",
        "name": "web-server-01",
        "ip": "192.168.1.100"
      },
      "location": "/var/log/auth.log",
      "full_log": "Failed password for admin from 192.168.1.200",
      "decoder": {
        "name": "sshd"
      }
    }
  ],
  "total": 156,
  "pagination": {
    "limit": 100,
    "offset": 0,
    "pages": 2
  },
  "metadata": {
    "query_time": "2024-01-01T15:00:00Z",
    "api_source": "wazuh_indexer",
    "search_time_ms": 234
  }
}
```

### Common Use Cases

1. **Security Dashboard**: Real-time alert monitoring
2. **Incident Investigation**: Historical alert analysis
3. **Compliance Reporting**: Alert documentation for audits
4. **Threat Hunting**: Pattern identification across time ranges

### Error Responses

```json
{
  "error": "Invalid timestamp format. Use ISO format: YYYY-MM-DDTHH:MM:SSZ",
  "error_code": "INVALID_TIMESTAMP",
  "timestamp": "2024-01-01T15:00:00Z"
}
```

---

## 📊 get_wazuh_alert_summary

Get statistical summaries of alerts grouped by specified criteria.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `time_range` | string | `"24h"` | No | Time range for analysis: 1h, 6h, 24h, 7d, 30d |
| `group_by` | string | `"rule.level"` | No | Field to group alerts by |

### Grouping Options

| Group By | Description | Example Output |
|----------|-------------|----------------|
| `rule.level` | Alert severity levels | Level 12: 45 alerts, Level 10: 23 alerts |
| `rule.id` | Specific rules | Rule 5715: 12 alerts, Rule 1002: 8 alerts |
| `agent.name` | Agent hostnames | web-server-01: 15 alerts, db-server-02: 7 alerts |
| `agent.id` | Agent IDs | Agent 001: 15 alerts, Agent 002: 7 alerts |
| `decoder.name` | Log decoders | sshd: 20 alerts, apache: 15 alerts |
| `location` | Log file locations | /var/log/auth.log: 25 alerts |

### Usage Examples

#### Alert Level Summary
```
Ask Claude: "Give me a summary of alerts by severity for the last 24 hours"
```

This queries:
- `time_range`: "24h"
- `group_by`: "rule.level"

#### Agent-Based Summary
```
Ask Claude: "Show me which agents have the most alerts this week"
```

This queries:
- `time_range`: "7d"
- `group_by`: "agent.name"

#### Rule Analysis
```
Ask Claude: "What are the most frequent alert rules in the last hour?"
```

This queries:
- `time_range`: "1h"
- `group_by`: "rule.id"

### Response Format

```json
{
  "summary": {
    "time_range": "24h",
    "total_alerts": 342,
    "grouped_by": "rule.level",
    "groups": [
      {
        "key": "12",
        "label": "Critical (Level 12)",
        "count": 45,
        "percentage": 13.16,
        "trend": "increasing"
      },
      {
        "key": "10",
        "label": "High (Level 10)",
        "count": 89,
        "percentage": 26.02,
        "trend": "stable"
      },
      {
        "key": "8",
        "label": "Medium (Level 8)",
        "count": 156,
        "percentage": 45.61,
        "trend": "decreasing"
      }
    ]
  },
  "metadata": {
    "query_time": "2024-01-01T15:00:00Z",
    "period_start": "2024-01-01T15:00:00Z",
    "period_end": "2024-01-02T15:00:00Z"
  }
}
```

---

## 🔍 analyze_alert_patterns

AI-powered analysis of alert patterns to identify trends, anomalies, and potential security issues.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `time_range` | string | `"24h"` | No | Time range for pattern analysis |
| `min_frequency` | integer | `5` | No | Minimum frequency for pattern detection |

### Usage Examples

#### Daily Pattern Analysis
```
Ask Claude: "Analyze alert patterns from the last 24 hours"
```

#### Anomaly Detection
```
Ask Claude: "Find unusual alert patterns that occurred more than 10 times today"
```

This queries:
- `time_range`: "24h"
- `min_frequency`: 10

### Response Format

```json
{
  "analysis": {
    "time_range": "24h",
    "total_patterns": 12,
    "anomalies_detected": 3,
    "patterns": [
      {
        "pattern_id": "pattern_001",
        "type": "temporal_clustering",
        "description": "SSH brute force attacks concentrated between 02:00-04:00 UTC",
        "frequency": 45,
        "severity": "high",
        "agents_affected": ["001", "003", "007"],
        "rules_involved": [5715, 5716],
        "recommendation": "Implement rate limiting on SSH service during off-hours"
      },
      {
        "pattern_id": "pattern_002",
        "type": "geographical_anomaly",
        "description": "Login attempts from unusual geographic locations",
        "frequency": 12,
        "severity": "medium",
        "source_countries": ["Unknown", "TOR Exit Node"],
        "recommendation": "Review and potentially block suspicious IP ranges"
      }
    ],
    "trends": {
      "overall_trend": "increasing",
      "hourly_distribution": {
        "peak_hours": ["02:00", "03:00", "14:00"],
        "quiet_hours": ["06:00", "07:00", "08:00"]
      }
    }
  }
}
```

---

## 🔎 search_security_events

Advanced full-text search across all Wazuh security events and logs.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `query` | string | - | **Yes** | Search query or pattern |
| `time_range` | string | `"24h"` | No | Time range for event search |
| `limit` | integer | `100` | No | Maximum number of events to retrieve |

### Search Query Syntax

#### Basic Search
```
Ask Claude: "Search for events containing 'failed login'"
```

#### IP Address Search
```
Ask Claude: "Find all events related to IP address 192.168.1.100"
```

#### Pattern Search
```
Ask Claude: "Search for SSH connection attempts in the last 6 hours"
```

#### Complex Queries
```
Ask Claude: "Find events with 'authentication failure' AND 'root' in the last hour"
```

### Response Format

```json
{
  "search_results": {
    "query": "failed login",
    "time_range": "24h",
    "total_matches": 89,
    "events": [
      {
        "timestamp": "2024-01-01T14:30:00Z",
        "agent": {
          "id": "001",
          "name": "web-server-01"
        },
        "rule": {
          "id": 5715,
          "level": 8,
          "description": "Multiple authentication failures"
        },
        "full_log": "Failed password for root from 192.168.1.200 port 22 ssh2",
        "matched_terms": ["failed", "login"],
        "context": {
          "location": "/var/log/auth.log",
          "decoder": "sshd"
        }
      }
    ]
  },
  "search_metadata": {
    "search_time_ms": 156,
    "indexes_searched": ["wazuh-alerts", "wazuh-events"],
    "query_complexity": "simple"
  }
}
```

---

## 💡 Best Practices

### Performance Optimization

1. **Use Appropriate Time Ranges**: Shorter time ranges return results faster
2. **Limit Result Sets**: Use reasonable limits to prevent timeouts
3. **Specific Filtering**: Use agent_id and rule_id filters when possible

### Security Considerations

1. **Input Validation**: All parameters are validated for security
2. **Access Control**: Respect Wazuh user permissions
3. **Rate Limiting**: Don't exceed API rate limits

### Common Patterns

#### Investigation Workflow
1. Start with `get_wazuh_alert_summary` for overview
2. Use `get_wazuh_alerts` for specific alert details
3. Apply `analyze_alert_patterns` for anomaly detection
4. Use `search_security_events` for detailed forensics

#### Dashboard Integration
1. `get_wazuh_alert_summary` for statistics widgets
2. `get_wazuh_alerts` with recent timestamps for real-time feeds
3. `analyze_alert_patterns` for trending information

---

## 🔧 Troubleshooting

### Common Issues

#### No Results Returned
- Check time range - may be too restrictive
- Verify agent_id exists and is accessible
- Ensure rule_id is valid

#### Timeout Errors
- Reduce limit parameter
- Narrow time range
- Use more specific filters

#### Invalid Parameter Errors
- Validate timestamp format (ISO 8601)
- Check alert level format (numeric or range)
- Verify agent_id format (alphanumeric, 3-8 characters)

### Performance Tips

1. **Indexer vs Server API**: Tools automatically choose optimal API
2. **Caching**: Results are cached for 5 minutes
3. **Pagination**: Use limit and offset for large datasets

---

**Next**: See [Agent Management API](agents.md) for agent monitoring tools.