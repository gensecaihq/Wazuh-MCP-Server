# System Monitoring API

Complete reference for Wazuh system monitoring and infrastructure health tools. These tools provide comprehensive visibility into cluster health, node status, service statistics, and system performance across your Wazuh deployment.

## Overview

The system monitoring tools offer ten main capabilities:
- **Cluster Health**: Monitor Wazuh cluster status and node health
- **Node Management**: Track individual cluster nodes and their status
- **Service Statistics**: Monitor core Wazuh services (remoted, log collector, etc.)
- **Rule Management**: Analyze rule effectiveness and performance
- **Weekly Analytics**: Comprehensive weekly trend analysis
- **System Statistics**: Overall Wazuh deployment metrics
- **Log Analysis**: Manager log search and error tracking
- **Connection Validation**: Verify Wazuh connectivity and configuration
- **Manager Logs**: Error log monitoring and analysis
- **Performance Metrics**: System resource usage and performance indicators

---

## 🏥 get_wazuh_cluster_health

Monitor overall Wazuh cluster health and status across all nodes.

### Parameters

None - returns comprehensive cluster health information.

### Usage Examples

#### Cluster Status Overview
```
Ask Claude: "Check the health of the Wazuh cluster"
```

#### Infrastructure Monitoring
```
Ask Claude: "What's the current status of our Wazuh deployment?"
```

### Response Format

```json
{
  "cluster_health": {
    "cluster_name": "wazuh-cluster-prod",
    "cluster_status": "green",
    "health_score": 92,
    "last_updated": "2024-01-16T15:00:00Z",
    "nodes": {
      "total": 3,
      "active": 3,
      "inactive": 0,
      "master": "wazuh-master-01"
    },
    "cluster_metrics": {
      "total_agents": 156,
      "active_agents": 142,
      "events_per_second": 1247.3,
      "storage_used_gb": 2.4,
      "storage_total_gb": 100.0,
      "storage_usage_percent": 2.4
    },
    "health_indicators": {
      "node_connectivity": {
        "status": "healthy",
        "score": 100,
        "details": "All nodes responding normally"
      },
      "data_synchronization": {
        "status": "healthy",
        "score": 98,
        "sync_delay_ms": 45,
        "details": "Synchronization within acceptable limits"
      },
      "resource_usage": {
        "status": "healthy",
        "score": 85,
        "cpu_usage": 45,
        "memory_usage": 67,
        "disk_usage": 12
      },
      "service_availability": {
        "status": "healthy",
        "score": 95,
        "services_up": 8,
        "services_total": 8
      }
    },
    "performance_metrics": {
      "average_response_time": "150ms",
      "throughput": "1.2K events/sec",
      "queue_usage": 15,
      "error_rate": 0.02
    },
    "recent_issues": [],
    "recommendations": [
      "Monitor CPU usage trends - currently at 45%",
      "Consider log rotation optimization"
    ]
  }
}
```

### Health Status Indicators

| Status | Description | Score Range | Action Required |
|--------|-------------|-------------|-----------------|
| `green` | All systems operating normally | 90-100 | Routine monitoring |
| `yellow` | Minor issues or warnings | 70-89 | Investigation recommended |
| `orange` | Performance degradation | 50-69 | Action required |
| `red` | Critical issues affecting operations | 0-49 | Immediate attention |

---

## 🖥️ get_wazuh_cluster_nodes 

Get detailed information about individual Wazuh cluster nodes.

### Parameters

None - returns information about all cluster nodes.

### Usage Examples

#### Node Status Check
```
Ask Claude: "Show me the status of all Wazuh cluster nodes"
```

#### Capacity Planning
```
Ask Claude: "What's the resource usage across cluster nodes?"
```

### Response Format

```json
{
  "cluster_nodes": {
    "cluster_name": "wazuh-cluster-prod",
    "total_nodes": 3,
    "discovery_time": "2024-01-16T15:00:00Z",
    "nodes": [
      {
        "node_id": "wazuh-master-01",
        "node_name": "wazuh-master-01",
        "node_type": "master",
        "status": "active",
        "ip_address": "192.168.1.10",
        "version": "4.8.0",
        "uptime": "15d 4h 23m",
        "last_keep_alive": "2024-01-16T14:59:45Z",
        "performance": {
          "cpu_usage": 35,
          "memory_usage": 45,
          "disk_usage": 12,
          "network_io": {
            "bytes_in": 1247382,
            "bytes_out": 892734
          }
        },
        "services": {
          "wazuh-manager": {
            "status": "running",
            "pid": 1234,
            "uptime": "15d 4h 23m"
          },
          "wazuh-remoted": {
            "status": "running", 
            "pid": 1235,
            "connections": 142
          },
          "wazuh-analysisd": {
            "status": "running",
            "pid": 1236,
            "events_processed": 1247382
          }
        },
        "agents_connected": 142,
        "cluster_role": "master",
        "configuration_hash": "ab12cd34ef56"
      },
      {
        "node_id": "wazuh-worker-01",
        "node_name": "wazuh-worker-01", 
        "node_type": "worker",
        "status": "active",
        "ip_address": "192.168.1.11",
        "version": "4.8.0",
        "uptime": "12d 8h 15m",
        "last_keep_alive": "2024-01-16T14:59:42Z",
        "performance": {
          "cpu_usage": 28,
          "memory_usage": 38,
          "disk_usage": 8,
          "load_average": [0.45, 0.52, 0.48]
        },
        "cluster_role": "worker",
        "sync_status": "synchronized",
        "sync_delay": "23ms"
      }
    ],
    "cluster_summary": {
      "master_nodes": 1,
      "worker_nodes": 2,
      "total_agents": 156,
      "total_events_processed": 4923847,
      "average_cpu_usage": 30.3,
      "average_memory_usage": 43.7
    }
  }
}
```

### Node Types and Roles

| Node Type | Description | Responsibilities | Typical Count |
|-----------|-------------|------------------|---------------|
| `master` | Primary cluster coordinator | Configuration management, agent assignment | 1 |
| `worker` | Processing and analysis node | Event processing, rule evaluation | 1-N |
| `api` | API gateway node | REST API serving, authentication | 1-2 |

---

## 📊 get_wazuh_remoted_stats

Monitor Wazuh remoted service statistics for agent communication health.

### Parameters

None - returns comprehensive remoted statistics.

### Usage Examples

#### Agent Communication Health
```
Ask Claude: "Show me the remoted service statistics"
```

#### Network Performance Analysis
```
Ask Claude: "How is the agent communication performing?"
```

### Response Format

```json
{
  "remoted_statistics": {
    "service_status": "running",
    "uptime": "15d 4h 23m",
    "last_updated": "2024-01-16T15:00:00Z",
    "connection_stats": {
      "total_agents_connected": 142,
      "active_connections": 142,
      "pending_connections": 0,
      "failed_connections": 3,
      "connection_success_rate": 97.9
    },
    "traffic_statistics": {
      "messages_received": 1247382,
      "messages_sent": 892734,
      "bytes_received": 524288000,
      "bytes_sent": 387420160,
      "average_message_size": 421,
      "throughput": {
        "messages_per_second": 247.3,
        "bytes_per_second": 104857
      }
    },
    "queue_statistics": {
      "receive_queue": {
        "size": 1024,
        "usage": 156,
        "usage_percent": 15.23,
        "max_usage": 1024
      },
      "send_queue": {
        "size": 1024,
        "usage": 89,
        "usage_percent": 8.69,
        "max_usage": 1024
      }
    },
    "protocol_distribution": {
      "tcp": {
        "connections": 138,
        "percentage": 97.18
      },
      "udp": {
        "connections": 4,
        "percentage": 2.82
      }
    },
    "performance_metrics": {
      "average_response_time": "12ms",
      "connection_establishment_time": "34ms",
      "keepalive_interval": "10s",
      "timeout_events": 2
    },
    "error_statistics": {
      "connection_errors": 3,
      "timeout_errors": 2,
      "protocol_errors": 0,
      "authentication_failures": 1,
      "total_errors": 6,
      "error_rate": 0.48
    }
  }
}
```

### Performance Thresholds

| Metric | Good | Warning | Critical | Action |
|--------|------|---------|----------|--------|
| Connection Success Rate | >95% | 90-95% | <90% | Check network/agents |
| Queue Usage | <50% | 50-80% | >80% | Scale resources |
| Error Rate | <1% | 1-5% | >5% | Investigate errors |
| Response Time | <50ms | 50-200ms | >200ms | Performance tuning |

---

## 📋 get_wazuh_log_collector_stats

Monitor log collector service statistics and performance.

### Parameters

None - returns comprehensive log collector metrics.

### Usage Examples

#### Log Processing Health
```
Ask Claude: "Show me log collector statistics"
```

#### Data Ingestion Monitoring
```
Ask Claude: "How is log collection performing?"
```

### Response Format

```json
{
  "log_collector_statistics": {
    "service_status": "running",
    "uptime": "15d 4h 23m",
    "last_updated": "2024-01-16T15:00:00Z",
    "collection_summary": {
      "total_log_sources": 245,
      "active_sources": 238,
      "inactive_sources": 7,
      "error_sources": 3,
      "success_rate": 97.14
    },
    "processing_statistics": {
      "events_processed": 1247382,
      "events_per_second": 247.3,
      "bytes_processed": 2147483648,
      "average_event_size": 1724,
      "processing_latency": "45ms"
    },
    "source_types": {
      "file_monitoring": {
        "sources": 156,
        "events": 892734,
        "status": "healthy"
      },
      "windows_eventlog": {
        "sources": 45,
        "events": 234567,
        "status": "healthy"
      },
      "syslog": {
        "sources": 34,
        "events": 120081,
        "status": "healthy"
      },
      "command_output": {
        "sources": 10,
        "events": 0,
        "status": "warning"
      }
    },
    "queue_statistics": {
      "input_queue": {
        "size": 4096,
        "usage": 567,
        "usage_percent": 13.84,
        "throughput": "247 events/sec"
      },
      "output_queue": {
        "size": 4096,
        "usage": 234,
        "usage_percent": 5.71,
        "throughput": "239 events/sec"
      }
    },
    "performance_metrics": {
      "cpu_usage": 25,
      "memory_usage": 45,
      "disk_io": {
        "read_bytes": 1073741824,
        "write_bytes": 536870912,
        "read_operations": 104857,
        "write_operations": 52428
      }
    },
    "error_analysis": {
      "permission_errors": 2,
      "file_not_found": 1,
      "parsing_errors": 0,
      "network_errors": 0,
      "total_errors": 3
    }
  }
}
```

---

## 📈 get_wazuh_rules_summary

Analyze Wazuh rules effectiveness and performance metrics.

### Parameters

None - returns comprehensive rules analysis.

### Usage Examples

#### Rule Effectiveness Analysis
```
Ask Claude: "Show me a summary of Wazuh rules performance"
```

#### Detection Optimization
```
Ask Claude: "Which rules are most effective?"
```

### Response Format

```json
{
  "rules_summary": {
    "analysis_timestamp": "2024-01-16T15:00:00Z",
    "total_rules": 3245,
    "active_rules": 3198,
    "custom_rules": 47,
    "effectiveness_metrics": {
      "rules_triggered": 1456,
      "unique_rules_used": 234,
      "rule_utilization_rate": 7.31,
      "average_alerts_per_rule": 5.33
    },
    "top_performing_rules": [
      {
        "rule_id": 5715,
        "description": "Multiple authentication failures",
        "level": 8,
        "alerts_generated": 234,
        "effectiveness_score": 89,
        "false_positive_rate": 2.1,
        "categories": ["authentication", "brute_force"]
      },
      {
        "rule_id": 31151,
        "description": "Web application attack detected",
        "level": 10,
        "alerts_generated": 156,
        "effectiveness_score": 92,
        "false_positive_rate": 1.3,
        "categories": ["web", "attack"]
      }
    ],
    "rule_categories": {
      "authentication": {
        "rules_count": 45,
        "alerts_generated": 567,
        "effectiveness": "high"
      },
      "web": {
        "rules_count": 123,
        "alerts_generated": 234,
        "effectiveness": "medium"
      },
      "malware": {
        "rules_count": 234,
        "alerts_generated": 89,
        "effectiveness": "high"
      }
    },
    "performance_analysis": {
      "most_active_rules": [5715, 31151, 1002],
      "least_active_rules": [9001, 9002, 9003],
      "potential_tuning_candidates": [
        {
          "rule_id": 5501,
          "issue": "high_false_positive_rate",
          "rate": 15.2,
          "recommendation": "Consider adjusting thresholds"
        }
      ]
    },
    "coverage_analysis": {
      "mitre_coverage": {
        "tactics_covered": 12,
        "techniques_covered": 87,
        "coverage_percentage": 67.5
      },
      "compliance_coverage": {
        "pci_dss": 89.2,
        "hipaa": 84.6,
        "nist": 76.3
      }
    }
  }
}
```

---

## 📅 get_wazuh_weekly_stats

Generate comprehensive weekly statistics and trend analysis.

### Parameters

None - returns weekly statistics for the past 7 days.

### Usage Examples

#### Weekly Security Report
```
Ask Claude: "Give me the weekly Wazuh statistics"
```

#### Trend Analysis
```
Ask Claude: "How did our security metrics perform this week?"
```

### Response Format

```json
{
  "weekly_statistics": {
    "week_period": "2024-01-09 to 2024-01-16",
    "generated_timestamp": "2024-01-16T15:00:00Z",
    "summary": {
      "total_alerts": 8734,
      "daily_average": 1247.7,
      "peak_day": "2024-01-14",
      "peak_alerts": 1895,
      "trend": "increasing"
    },
    "alert_trends": {
      "daily_breakdown": [
        {
          "date": "2024-01-10",
          "alerts": 1156,
          "critical": 8,
          "high": 23,
          "medium": 67,
          "low": 1058
        },
        {
          "date": "2024-01-11", 
          "alerts": 1234,
          "critical": 12,
          "high": 31,
          "medium": 89,
          "low": 1102
        }
      ],
      "severity_trends": {
        "critical": {
          "total": 78,
          "trend": "increasing",
          "change_percentage": 23.5
        },
        "high": {
          "total": 234,
          "trend": "stable",
          "change_percentage": 2.1
        }
      }
    },
    "agent_statistics": {
      "total_agents": 156,
      "active_agents": 142,
      "new_agents": 3,
      "disconnected_agents": 14,
      "agent_activity": {
        "most_active": [
          {
            "agent_id": "001",
            "agent_name": "web-server-01",
            "alerts": 234
          }
        ],
        "least_active": [
          {
            "agent_id": "099",
            "agent_name": "test-server-01",
            "alerts": 5
          }
        ]
      }
    },
    "performance_metrics": {
      "average_processing_time": "45ms",
      "peak_events_per_second": 456.7,
      "storage_growth": "1.2GB",
      "system_availability": 99.8
    },
    "threat_landscape": {
      "top_attack_types": [
        {
          "type": "brute_force",
          "count": 567,
          "percentage": 6.49
        },
        {
          "type": "web_attack",
          "count": 234,
          "percentage": 2.68
        }
      ],
      "geographic_distribution": {
        "attacks_by_country": [
          {"country": "Unknown", "count": 234},
          {"country": "CN", "count": 156},
          {"country": "RU", "count": 89}
        ]
      }
    },
    "recommendations": [
      "Investigate increasing critical alert trend",
      "Review performance on peak day (2024-01-14)",
      "Consider adding more agents for better coverage"
    ]
  }
}
```

---

## 📊 get_wazuh_statistics

Get comprehensive Wazuh deployment statistics and metrics.

### Parameters

None - returns overall system statistics.

### Usage Examples

#### System Overview
```
Ask Claude: "Show me comprehensive Wazuh statistics"
```

#### Performance Dashboard
```
Ask Claude: "What are the current system metrics?"
```

### Response Format

```json
{
  "wazuh_statistics": {
    "collection_timestamp": "2024-01-16T15:00:00Z",
    "deployment_info": {
      "version": "4.8.0",
      "installation_date": "2023-06-15T10:00:00Z",
      "uptime": "214d 5h 32m",
      "cluster_mode": true,
      "node_count": 3
    },
    "agent_statistics": {
      "total_agents": 156,
      "active_agents": 142,
      "disconnected_agents": 12,
      "never_connected": 2,
      "pending_agents": 0,
      "platform_distribution": {
        "linux": 89,
        "windows": 45,
        "macos": 8,
        "other": 14
      }
    },
    "event_statistics": {
      "total_events_processed": 15678234,
      "events_today": 124782,
      "events_per_second": 247.3,
      "alerts_generated": 8734,
      "rules_triggered": 1456,
      "average_processing_latency": "45ms"
    },
    "storage_statistics": {
      "total_storage_used": "124.5GB",
      "alerts_storage": "45.2GB",
      "events_storage": "67.8GB",
      "other_storage": "11.5GB",
      "storage_growth_rate": "2.3GB/week",
      "retention_period": "90 days"
    },
    "performance_metrics": {
      "cpu_usage": {
        "current": 35,
        "average_24h": 42,
        "peak_24h": 67
      },
      "memory_usage": {
        "current": 45,
        "average_24h": 48,
        "peak_24h": 72
      },
      "disk_io": {
        "read_iops": 234,
        "write_iops": 156,
        "read_throughput": "12.4MB/s",
        "write_throughput": "8.7MB/s"
      },
      "network_io": {
        "bytes_in": 1247382,
        "bytes_out": 892734,
        "packets_in": 124738,
        "packets_out": 89273
      }
    },
    "service_health": {
      "wazuh-manager": "running",
      "wazuh-remoted": "running",
      "wazuh-analysisd": "running",
      "wazuh-logtest": "running",
      "wazuh-syscheckd": "running",
      "wazuh-monitord": "running",
      "wazuh-execd": "running",
      "wazuh-db": "running"
    },
    "vulnerability_summary": {
      "total_vulnerabilities": 156,
      "critical": 12,
      "high": 34,
      "medium": 78,
      "low": 32
    }
  }
}
```

---

## 🔍 search_wazuh_manager_logs

Search through Wazuh manager logs for specific patterns and events.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `query` | string | - | **Yes** | Search query or pattern |
| `limit` | integer | `100` | No | Maximum number of log entries to return |

### Usage Examples

#### Error Investigation
```
Ask Claude: "Search manager logs for 'error' messages"
```

#### Service Monitoring
```
Ask Claude: "Find recent 'connection' events in manager logs"
```

### Response Format

```json
{
  "log_search_results": {
    "query": "error",
    "search_timestamp": "2024-01-16T15:00:00Z",
    "total_matches": 23,
    "entries": [
      {
        "timestamp": "2024-01-16T14:45:32Z",
        "level": "ERROR",
        "component": "wazuh-remoted",
        "message": "Connection timeout for agent 045",
        "details": {
          "agent_id": "045",
          "error_code": "TIMEOUT",
          "retry_count": 3
        }
      },
      {
        "timestamp": "2024-01-16T14:30:15Z",
        "level": "ERROR",
        "component": "wazuh-analysisd",
        "message": "Rule parsing error in rule 5001",
        "details": {
          "rule_id": 5001,
          "file": "custom_rules.xml",
          "line": 42
        }
      }
    ],
    "summary": {
      "error_levels": {
        "ERROR": 18,
        "CRITICAL": 3,
        "WARNING": 2
      },
      "components": {
        "wazuh-remoted": 12,
        "wazuh-analysisd": 8,
        "wazuh-monitord": 3
      },
      "time_range": "Last 24 hours"
    }
  }
}
```

---

## 🚨 get_wazuh_manager_error_logs

Retrieve recent error logs from Wazuh manager for troubleshooting.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `limit` | integer | `100` | No | Maximum number of error log entries to retrieve |

### Usage Examples

#### Error Monitoring
```
Ask Claude: "Show me recent manager error logs"
```

#### Troubleshooting
```
Ask Claude: "Get the last 50 error messages from Wazuh manager"
```

### Response Format

```json
{
  "manager_error_logs": {
    "collection_timestamp": "2024-01-16T15:00:00Z",
    "total_errors": 23,
    "error_entries": [
      {
        "timestamp": "2024-01-16T14:55:12Z",
        "severity": "ERROR",
        "component": "wazuh-remoted",
        "error_code": "CONN_TIMEOUT",
        "message": "Agent connection timeout",
        "details": {
          "agent_id": "045",
          "agent_name": "db-server-03",
          "timeout_duration": "30s",
          "retry_attempts": 3
        },
        "impact": "Agent disconnected, events may be lost",
        "recommended_action": "Check agent connectivity and network"
      },
      {
        "timestamp": "2024-01-16T14:50:45Z",
        "severity": "CRITICAL",
        "component": "wazuh-db",
        "error_code": "DB_LOCK",
        "message": "Database lock timeout",
        "details": {
          "database": "global",
          "operation": "INSERT",
          "lock_duration": "120s"
        },
        "impact": "Database operations blocked",
        "recommended_action": "Restart wazuh-db service"
      }
    ],
    "error_analysis": {
      "most_frequent_errors": [
        {
          "error_code": "CONN_TIMEOUT",
          "count": 12,
          "percentage": 52.17
        },
        {
          "error_code": "RULE_PARSE",
          "count": 8,
          "percentage": 34.78
        }
      ],
      "error_trends": {
        "last_hour": 5,
        "last_6_hours": 15,
        "last_24_hours": 23,
        "trend": "increasing"
      },
      "components_affected": {
        "wazuh-remoted": 12,
        "wazuh-analysisd": 6,
        "wazuh-db": 3,
        "wazuh-monitord": 2
      }
    },
    "recommended_actions": [
      "Investigate network connectivity issues with agents",
      "Review custom rule configurations",
      "Consider database performance optimization"
    ]
  }
}
```

---

## ✅ validate_wazuh_connection

Validate connection to Wazuh server and return comprehensive status information.

### Parameters

None - performs comprehensive connection validation.

### Usage Examples

#### Health Check
```
Ask Claude: "Validate the connection to Wazuh server"
```

#### Troubleshooting
```
Ask Claude: "Check if Wazuh is accessible and working properly"
```

### Response Format

```json
{
  "connection_validation": {
    "validation_timestamp": "2024-01-16T15:00:00Z",
    "overall_status": "healthy",
    "connection_score": 95,
    "tests_performed": 8,
    "tests_passed": 8,
    "tests_failed": 0,
    "validation_results": {
      "server_connectivity": {
        "status": "pass",
        "response_time": "45ms",
        "endpoint": "https://192.168.1.10:55000",
        "ssl_valid": true
      },
      "authentication": {
        "status": "pass",
        "user": "wazuh-api-user",
        "token_valid": true,
        "permissions": ["read", "write"]
      },
      "api_endpoints": {
        "status": "pass",
        "endpoints_tested": [
          "/agents",
          "/rules",
          "/alerts",
          "/cluster/nodes"
        ],
        "all_responding": true
      },
      "indexer_connectivity": {
        "status": "pass",
        "endpoint": "https://192.168.1.10:9200",
        "response_time": "23ms",
        "indexes_accessible": true
      },
      "version_compatibility": {
        "status": "pass",
        "server_version": "4.8.0",
        "client_version": "4.8.0",
        "compatible": true
      },
      "service_health": {
        "status": "pass",
        "services_checked": [
          "wazuh-manager",
          "wazuh-api",
          "wazuh-indexer"
        ],
        "all_healthy": true
      },
      "data_access": {
        "status": "pass",
        "agents_readable": true,
        "alerts_readable": true,
        "rules_readable": true
      },
      "performance": {
        "status": "pass",
        "average_response_time": "34ms",
        "throughput": "normal",
        "resource_usage": "optimal"
      }
    },
    "server_information": {
      "version": "4.8.0",
      "api_version": "v4",
      "cluster_mode": true,
      "node_name": "wazuh-master-01",
      "uptime": "15d 4h 23m"
    },
    "performance_metrics": {
      "connection_latency": "12ms",
      "ssl_handshake_time": "67ms",
      "authentication_time": "23ms",
      "query_response_time": "45ms"
    },
    "recommendations": [
      "Connection is healthy - no actions required",
      "Continue monitoring response times"
    ]
  }
}
```

### Connection Status Levels

| Status | Description | Score Range | Implications |
|--------|-------------|-------------|--------------|
| `healthy` | All systems functioning optimally | 90-100 | Normal operations |
| `degraded` | Some performance issues | 70-89 | Monitor closely |
| `impaired` | Significant connectivity problems | 50-69 | Investigation required |
| `failed` | Connection or authentication failure | 0-49 | Immediate action needed |

---

## 💡 Best Practices

### System Monitoring Strategy

1. **Regular Health Checks**: Monitor cluster health at least every 15 minutes
2. **Performance Baselines**: Establish normal operating parameters
3. **Proactive Alerting**: Set up alerts for degraded performance
4. **Capacity Planning**: Monitor growth trends for resource planning

### Performance Optimization

1. **Resource Monitoring**: Track CPU, memory, and disk usage trends
2. **Queue Management**: Monitor queue usage to prevent bottlenecks
3. **Network Optimization**: Optimize agent communication patterns
4. **Storage Management**: Implement appropriate data retention policies

### Troubleshooting Approach

1. **Start with Cluster Health**: Get overall system status first
2. **Drill Down to Nodes**: Identify specific problematic nodes
3. **Service Analysis**: Check individual service statistics
4. **Log Investigation**: Search logs for specific error patterns

---

## 🔧 Troubleshooting

### Common Issues

#### Cluster Health Degraded
```json
{
  "cluster_status": "yellow",
  "health_score": 65,
  "issues": ["High CPU usage on master node", "Sync delays detected"]
}
```

**Solutions**:
- Check resource usage on master node
- Investigate network connectivity between nodes
- Review cluster configuration

#### High Queue Usage
```json
{
  "queue_statistics": {
    "receive_queue": {
      "usage_percent": 85.4,
      "status": "warning"
    }
  }
}
```

**Solutions**:
- Scale processing capacity
- Optimize rule performance
- Check for resource bottlenecks

#### Service Connectivity Issues
```json
{
  "connection_validation": {
    "overall_status": "impaired",
    "indexer_connectivity": {
      "status": "fail",
      "error": "Connection timeout"
    }
  }
}
```

**Solutions**:
- Verify service status and restart if needed
- Check network connectivity and firewall rules
- Validate credentials and certificates

---

**Next**: See [Compliance & Reporting API](compliance-reporting.md) for compliance management tools.