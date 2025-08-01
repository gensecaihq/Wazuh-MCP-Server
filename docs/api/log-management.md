# Log Management API

Complete reference for Wazuh log management and search tools. These tools provide advanced log search capabilities and security event analysis across all monitored systems and infrastructure.

## Overview

The log management tools offer two main capabilities:
- **Manager Log Search**: Advanced search and analysis of Wazuh manager logs for troubleshooting and monitoring
- **Security Event Search**: Comprehensive search across all security events and logs for threat hunting and forensic analysis

---

## 🔍 search_wazuh_manager_logs

Search through Wazuh manager logs with advanced pattern matching and filtering capabilities.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `query` | string | - | **Yes** | Search query or pattern to match |
| `limit` | integer | `100` | No | Maximum number of log entries to return (1-1000) |

### Search Query Syntax

#### Basic Text Search
- Simple text matching: `"error"`
- Case-insensitive by default
- Supports partial word matching

#### Pattern Matching
- Wildcards: `"conn*"` matches "connection", "connected", etc.
- Exact phrases: `"connection timeout"`
- Multiple terms: `"error connection"` (AND logic)

#### Advanced Operators
- Boolean OR: `"error OR warning"`
- Boolean AND: `"error AND timeout"`
- Exclusion: `"error NOT network"`
- Regular expressions: `/error:\s+\d+/`

### Usage Examples

#### Error Investigation
```
Ask Claude: "Search manager logs for 'error' messages"
```

This searches for:
- All log entries containing the word "error"
- Case-insensitive matching
- Returns up to 100 results

#### Connection Issues
```
Ask Claude: "Find connection timeout events in manager logs"
```

This searches for:
- Log entries related to connection timeouts
- Useful for troubleshooting agent connectivity

#### Service Status Monitoring
```
Ask Claude: "Search for 'service started' OR 'service stopped' in the last 500 log entries"
```

This searches for:
- Service lifecycle events
- Extended result set (500 entries)

#### Rule Processing Errors
```
Ask Claude: "Find rule parsing errors in manager logs"
```

This searches for:
- Rule configuration and parsing issues
- Helpful for custom rule troubleshooting

### Response Format

```json
{
  "log_search_results": {
    "query": "error",
    "search_timestamp": "2024-01-16T15:00:00Z",
    "total_matches": 23,
    "search_parameters": {
      "limit": 100,
      "case_sensitive": false,
      "include_context": true
    },
    "log_entries": [
      {
        "timestamp": "2024-01-16T14:45:32.123Z",
        "log_level": "ERROR",
        "component": "wazuh-remoted",
        "process_id": 1234,
        "thread_id": "worker-01",
        "message": "Connection timeout for agent 045 (db-server-03)",
        "raw_log": "2024/01/16 14:45:32 wazuh-remoted: ERROR: (1234): Connection timeout for agent 045 (db-server-03) - No response after 30 seconds",
        "context": {
          "agent_id": "045",
          "agent_name": "db-server-03",
          "error_code": "CONN_TIMEOUT",
          "timeout_duration": "30s",
          "retry_count": 3
        },
        "severity": "high",
        "category": "connectivity"
      },
      {
        "timestamp": "2024-01-16T14:30:15.456Z",
        "log_level": "ERROR",
        "component": "wazuh-analysisd",
        "process_id": 1235,
        "thread_id": "rule-engine",
        "message": "Rule parsing error in custom_rules.xml at line 42",
        "raw_log": "2024/01/16 14:30:15 wazuh-analysisd: ERROR: (1235): Rule parsing error in custom_rules.xml at line 42: Invalid XML syntax",
        "context": {
          "file": "custom_rules.xml",
          "line_number": 42,
          "error_type": "XML_SYNTAX",
          "rule_id": "100001"
        },
        "severity": "medium",
        "category": "configuration"
      },
      {
        "timestamp": "2024-01-16T14:15:08.789Z",
        "log_level": "ERROR",
        "component": "wazuh-db",
        "process_id": 1236,
        "thread_id": "db-worker",
        "message": "Database operation failed: INSERT timeout",
        "raw_log": "2024/01/16 14:15:08 wazuh-db: ERROR: (1236): Database operation failed: INSERT timeout after 120 seconds",
        "context": {
          "operation": "INSERT",
          "table": "agent_events",
          "timeout_duration": "120s",
          "affected_rows": 0
        },
        "severity": "critical",
        "category": "database"
      }
    ],
    "search_statistics": {
      "search_time_ms": 145,
      "log_files_searched": 3,
      "total_log_entries": 15678,
      "match_percentage": 0.147
    },
    "log_analysis": {
      "error_distribution": {
        "wazuh-remoted": 12,
        "wazuh-analysisd": 8,
        "wazuh-db": 3
      },
      "severity_breakdown": {
        "critical": 3,
        "high": 8,
        "medium": 10,
        "low": 2
      },
      "time_pattern": {
        "peak_error_time": "14:30-15:00 UTC",
        "error_frequency": "1.2 per minute"
      },
      "common_error_categories": [
        "connectivity",
        "configuration", 
        "database",
        "rule_processing"
      ]
    },
    "recommendations": [
      "Investigate agent 045 connectivity issues",
      "Review custom_rules.xml syntax at line 42",
      "Monitor database performance and consider optimization"
    ]
  }
}
```

### Log Entry Fields Explained

| Field | Description | Usage |
|-------|-------------|-------|
| `timestamp` | Precise log entry timestamp | Temporal correlation |
| `log_level` | Severity level (ERROR, WARN, INFO, DEBUG) | Priority filtering |
| `component` | Wazuh service that generated the log | Service-specific analysis |
| `process_id` | Operating system process ID | Process correlation |
| `message` | Human-readable log message | Primary information |
| `context` | Structured metadata | Automated analysis |
| `severity` | Business impact assessment | Risk prioritization |
| `category` | Functional categorization | Pattern analysis |

### Log Categories

| Category | Description | Typical Issues |
|----------|-------------|----------------|
| `connectivity` | Agent communication problems | Timeouts, network issues |
| `configuration` | Rule and config parsing errors | Syntax errors, invalid settings |
| `database` | Database operation failures | Performance, corruption |
| `rule_processing` | Rule evaluation issues | Logic errors, performance |
| `authentication` | Authentication failures | Invalid credentials, expired tokens |
| `file_system` | File access problems | Permissions, disk space |

---

## 🔎 search_security_events

Perform advanced search across all Wazuh security events and logs for threat hunting and forensic analysis.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `query` | string | - | **Yes** | Search query or pattern |
| `time_range` | string | `"24h"` | No | Time range for event search |
| `limit` | integer | `100` | No | Maximum number of events to retrieve (1-1000) |

### Time Range Options

| Range | Description | Use Case |
|-------|-------------|----------|
| `1h` | Last hour | Real-time incident response |
| `6h` | Last 6 hours | Recent activity analysis |
| `24h` | Last 24 hours | Daily threat hunting |
| `7d` | Last week | Weekly security review |
| `30d` | Last month | Historical analysis |
| `90d` | Last quarter | Compliance reporting |

### Advanced Search Capabilities

#### IP Address Search
- IPv4: `192.168.1.100`
- IPv6: `2001:db8::1`
- CIDR ranges: `192.168.1.0/24`
- Multiple IPs: `192.168.1.100 OR 10.0.0.5`

#### Domain and URL Search
- Domains: `malicious.com`
- Subdomains: `*.suspicious.org`
- URLs: `http://malicious.com/payload`
- Protocol specific: `https://` 

#### User and Process Search
- Usernames: `admin`, `root`, `service_account`
- Process names: `cmd.exe`, `powershell.exe`, `bash`
- Command lines: `"wget http://malicious.com"`

#### File and Hash Search
- File paths: `/etc/passwd`, `C:\Windows\System32\`
- File names: `malware.exe`, `suspicious.dll`
- Hash values: SHA256, MD5, SHA1 hashes

### Usage Examples

#### IP Address Investigation
```
Ask Claude: "Search for all security events related to IP address 203.0.113.15"
```

This searches for:
- All events containing the specified IP address
- Source and destination IP matches
- Last 24 hours by default

#### Failed Authentication Analysis
```
Ask Claude: "Find all failed login attempts in the last 6 hours"
```

This searches for:
- Authentication failure events
- Login and authentication-related activities
- 6-hour time window

#### Malware Detection
```
Ask Claude: "Search for malware detection events in the last week"
```

This searches for:
- Malware-related security events
- Antivirus detections and quarantine events
- 7-day historical period

#### Network Reconnaissance
```
Ask Claude: "Find port scanning and network reconnaissance activities"
```

This searches for:
- Port scan detection events
- Network reconnaissance patterns
- Unusual network activity

#### File Integrity Monitoring
```
Ask Claude: "Search for file modification events on critical system files"
```

This searches for:
- File integrity monitoring alerts
- System file modifications
- Configuration change events

### Response Format

```json
{
  "security_event_search": {
    "query": "failed login",
    "time_range": "24h",
    "search_timestamp": "2024-01-16T15:00:00Z",
    "period_start": "2024-01-15T15:00:00Z",
    "period_end": "2024-01-16T15:00:00Z",
    "total_matches": 156,
    "events_returned": 100,
    "search_performance": {
      "search_time_ms": 234,
      "indexes_searched": ["wazuh-alerts", "wazuh-events", "wazuh-archives"],
      "query_complexity": "medium"
    },
    "events": [
      {
        "event_id": "evt_20240116_145532_001",
        "timestamp": "2024-01-16T14:55:32.123Z",
        "agent": {
          "id": "001",
          "name": "web-server-01",
          "ip": "192.168.1.100"
        },
        "rule": {
          "id": 5715,
          "level": 8,
          "description": "Multiple authentication failures",
          "groups": ["authentication_failed", "brute_force"]
        },
        "event_details": {
          "source_ip": "203.0.113.25",
          "destination_ip": "192.168.1.100",
          "source_port": 45672,
          "destination_port": 22,
          "protocol": "SSH",
          "username": "admin",
          "authentication_method": "password",
          "failure_reason": "invalid_credentials"
        },
        "log_source": {
          "file": "/var/log/auth.log",
          "decoder": "sshd"
        },
        "full_log": "Jan 16 14:55:32 web-server-01 sshd[12345]: Failed password for admin from 203.0.113.25 port 45672 ssh2",
        "matched_terms": ["failed", "login", "authentication"],
        "threat_intelligence": {
          "source_ip_reputation": "malicious",
          "geolocation": {
            "country": "Unknown",
            "region": "Unknown",
            "organization": "Tor Network"
          },
          "known_campaigns": ["SSH Brute Force Campaign"]
        },
        "context": {
          "previous_attempts": 15,
          "time_window": "5 minutes",
          "pattern": "brute_force_attack",
          "risk_score": 85
        }
      },
      {
        "event_id": "evt_20240116_144212_002", 
        "timestamp": "2024-01-16T14:42:12.456Z",
        "agent": {
          "id": "003",
          "name": "db-server-01",
          "ip": "192.168.1.103"
        },
        "rule": {
          "id": 5503,
          "level": 5,
          "description": "User login failed",
          "groups": ["authentication_failed"]
        },
        "event_details": {
          "source_ip": "192.168.1.50",
          "username": "backup_user",
          "service": "mysql",
          "failure_reason": "account_locked"
        },
        "log_source": {
          "file": "/var/log/mysql/error.log",
          "decoder": "mysql"
        },
        "full_log": "2024-01-16T14:42:12.456789Z mysqld: Access denied for user 'backup_user'@'192.168.1.50' (account locked)",
        "matched_terms": ["failed", "login"],
        "context": {
          "account_status": "locked",
          "lock_duration": "24 hours",
          "previous_failures": 5,
          "risk_score": 35
        }
      }
    ],
    "event_analysis": {
      "attack_patterns": [
        {
          "pattern": "ssh_brute_force",
          "confidence": 95,
          "events_count": 45,
          "source_ips": ["203.0.113.25", "198.51.100.10"],
          "targets": ["web-server-01", "web-server-02"]
        },
        {
          "pattern": "credential_stuffing",
          "confidence": 78,
          "events_count": 23,
          "unique_usernames": 15,
          "success_rate": 0
        }
      ],
      "geographic_analysis": {
        "source_countries": [
          {"country": "Unknown/Tor", "events": 67, "percentage": 42.9},
          {"country": "China", "events": 34, "percentage": 21.8},
          {"country": "Russia", "events": 28, "percentage": 17.9}
        ]
      },
      "temporal_analysis": {
        "peak_activity": "14:30-15:00 UTC",
        "events_per_hour": 6.5,
        "duration": "continuous",
        "pattern": "sustained_attack"
      },
      "affected_systems": {
        "total_agents": 8,
        "most_targeted": [
          {"agent": "web-server-01", "events": 45},
          {"agent": "web-server-02", "events": 23},
          {"agent": "db-server-01", "events": 12}
        ]
      }
    },
    "threat_assessment": {
      "overall_threat_level": "high",
      "active_campaigns": 2,
      "indicators_of_compromise": [
        {
          "type": "ip_address",
          "value": "203.0.113.25",
          "confidence": 95,
          "threat_type": "brute_force_source"
        },
        {
          "type": "attack_pattern",
          "value": "ssh_brute_force_campaign",
          "confidence": 92,
          "threat_type": "coordinated_attack"
        }
      ],
      "recommended_actions": [
        "Block source IPs: 203.0.113.25, 198.51.100.10",
        "Implement rate limiting on SSH service",
        "Enable fail2ban or similar protection",
        "Review and strengthen authentication policies"
      ]
    },
    "correlation_analysis": {
      "related_events": 67,
      "event_chains": [
        {
          "chain_id": "chain_001",
          "events": 45,
          "timeline": "14:30-15:00 UTC",
          "pattern": "Multi-stage brute force attack"
        }
      ],
      "cross_system_correlation": {
        "systems_involved": 3,
        "attack_progression": "Lateral movement detected",
        "success_indicators": "No successful authentications"
      }
    }
  }
}
```

### Search Optimization Tips

#### Performance Optimization
1. **Use Specific Time Ranges**: Shorter time ranges return results faster
2. **Targeted Queries**: Specific terms reduce search scope
3. **Appropriate Limits**: Use reasonable limits for large datasets
4. **Index Optimization**: Queries on indexed fields perform better

#### Query Effectiveness
1. **Combine Terms**: Use multiple relevant terms for precision
2. **Use Exclusions**: Filter out known false positives
3. **Leverage Context**: Include system or user context in queries
4. **Pattern Recognition**: Look for repeating patterns and sequences

### Event Correlation Capabilities

#### Automatic Correlation
- **Temporal Correlation**: Events occurring within time windows
- **Source Correlation**: Events from same sources or targets
- **Attack Chain Detection**: Multi-stage attack identification
- **Pattern Recognition**: Behavioral pattern analysis

#### Cross-System Analysis
- **Multi-Agent Events**: Events spanning multiple systems
- **Network Flow Correlation**: Network-based event relationships
- **User Activity Tracking**: User behavior across systems
- **Attack Progression**: Lateral movement detection

---

## 💡 Best Practices

### Log Search Strategy

1. **Start Broad, Refine Narrow**: Begin with general terms, then add specificity
2. **Use Time Boundaries**: Always specify appropriate time ranges
3. **Combine Multiple Searches**: Use various query approaches for comprehensive analysis
4. **Document Findings**: Maintain records of successful search patterns

### Threat Hunting Approach

1. **Hypothesis-Driven**: Start with specific threat hypotheses
2. **Iterative Refinement**: Continuously refine search parameters
3. **Pattern Recognition**: Look for unusual patterns and anomalies
4. **Historical Context**: Compare current events with historical baselines

### Forensic Analysis Best Practices

1. **Preserve Evidence**: Maintain chain of custody for log evidence
2. **Timeline Construction**: Build comprehensive event timelines
3. **Multi-Source Correlation**: Use multiple log sources for validation
4. **Impact Assessment**: Determine scope and impact of security events

### Performance Optimization

1. **Index Utilization**: Structure queries to leverage search indexes
2. **Batch Processing**: Process large searches in manageable chunks
3. **Result Caching**: Cache frequently accessed search results
4. **Resource Management**: Monitor search resource utilization

---

## 🔧 Troubleshooting

### Common Issues

#### No Search Results
```json
{
  "total_matches": 0,
  "message": "No events found matching search criteria",
  "suggestions": [
    "Expand time range",
    "Check query syntax",
    "Verify log source availability"
  ]
}
```

**Solutions**:
- Verify search terms are correct
- Expand time range for historical events
- Check if relevant log sources are active

#### Search Timeout
```json
{
  "error": "Search request timeout - query too complex or dataset too large",
  "error_code": "SEARCH_TIMEOUT",
  "recommendations": [
    "Reduce time range",
    "Simplify query terms",
    "Use more specific filters"
  ]
}
```

**Solutions**:
- Break complex searches into smaller queries
- Use more specific search terms
- Implement pagination for large result sets

#### Index Unavailable
```json
{
  "error": "Search index temporarily unavailable",
  "error_code": "INDEX_UNAVAILABLE",
  "estimated_recovery": "5 minutes"
}
```

**Solutions**:
- Wait for index recovery
- Check Wazuh Indexer status
- Verify system resources and connectivity

### Performance Troubleshooting

1. **Slow Searches**: Optimize query patterns and use appropriate time ranges
2. **High Resource Usage**: Monitor and limit concurrent search operations
3. **Memory Issues**: Implement result pagination and streaming
4. **Network Bottlenecks**: Optimize network connectivity to search backends

### Search Query Optimization

1. **Use Indexed Fields**: Structure queries around indexed fields
2. **Avoid Wildcards**: Minimize wildcard usage, especially leading wildcards
3. **Specific Terms**: Use specific terms rather than generic patterns
4. **Field Targeting**: Target specific fields when possible

---

**Summary**: The log management tools provide comprehensive search and analysis capabilities across all Wazuh logs and security events, enabling effective threat hunting, incident response, and forensic analysis.