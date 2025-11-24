# Agent Management API

Complete reference for Wazuh agent management and monitoring tools. These tools provide comprehensive visibility into agent status, health, configuration, and running processes across your infrastructure.

## Overview

The agent management tools offer six main capabilities:
- **Agent Discovery**: List and filter agents by various criteria
- **Health Monitoring**: Check agent connectivity and operational status
- **Configuration Management**: View agent configurations and settings
- **Process Monitoring**: Monitor running processes on agents
- **Network Monitoring**: Track open ports and network connections
- **Operational Intelligence**: Real-time agent status and performance

---

## 🖥️ get_wazuh_agents

Retrieve comprehensive information about Wazuh agents with flexible filtering options.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `agent_id` | string | `null` | No | Specific agent ID to query (3-8 alphanumeric characters) |
| `status` | string | `null` | No | Filter by agent status |
| `limit` | integer | `100` | No | Maximum number of agents to retrieve (1-1000) |

### Agent Status Values

| Status | Description | Typical Use Case |
|--------|-------------|------------------|
| `active` | Agent is connected and sending data | Normal operations |
| `disconnected` | Agent is not currently connected | Troubleshooting connectivity |
| `never_connected` | Agent registered but never connected | Initial setup verification |
| `pending` | Agent registration pending approval | New agent deployment |

### Usage Examples

#### List All Active Agents
```
Ask Claude: "Show me all active Wazuh agents"
```

This queries:
- `status`: "active"
- `limit`: 100 (default)

#### Get Specific Agent Details
```
Ask Claude: "Get details for agent 001"
```

This queries:
- `agent_id`: "001"

#### Find Disconnected Agents
```
Ask Claude: "Show me all disconnected agents"
```

This queries:
- `status`: "disconnected"

#### List First 50 Agents
```
Ask Claude: "List the first 50 agents in the system"
```

This queries:
- `limit`: 50

### Response Format

```json
{
  "agents": [
    {
      "id": "001",
      "name": "web-server-01",
      "ip": "192.168.1.100",
      "status": "active",
      "last_keep_alive": "2024-01-01T14:58:30Z",
      "os": {
        "platform": "ubuntu",
        "version": "20.04",
        "arch": "x86_64"
      },
      "version": "4.8.0",
      "manager": "wazuh-manager-01",
      "group": ["default", "web-servers"],
      "node_name": "worker-01",
      "register_date": "2024-01-01T10:00:00Z",
      "configuration_hash": "ab12cd34ef56",
      "merged_sum": "98765432",
      "config_sum": "12345678"
    }
  ],
  "total_agents": 156,
  "summary": {
    "active": 142,
    "disconnected": 12,
    "never_connected": 2,
    "pending": 0
  },
  "metadata": {
    "query_time": "2024-01-01T15:00:00Z",
    "api_source": "wazuh_server"
  }
}
```

### Agent Information Fields

| Field | Description | Example |
|-------|-------------|---------|
| `id` | Unique agent identifier | "001", "web-01" |
| `name` | Agent hostname | "web-server-01" |
| `ip` | Agent IP address | "192.168.1.100" |
| `status` | Current connection status | "active", "disconnected" |
| `last_keep_alive` | Last communication timestamp | "2024-01-01T14:58:30Z" |
| `os.platform` | Operating system | "ubuntu", "windows", "centos" |
| `version` | Wazuh agent version | "4.8.0" |
| `group` | Agent groups | ["default", "web-servers"] |

---

## ✅ get_wazuh_running_agents

Get a quick list of currently active and running Wazuh agents.

### Parameters

None - returns all active agents.

### Usage Examples

#### Quick Status Check
```
Ask Claude: "Show me all running agents"
```

#### Operational Overview
```
Ask Claude: "Which agents are currently online?"
```

### Response Format

```json
{
  "running_agents": [
    {
      "id": "001",
      "name": "web-server-01",
      "ip": "192.168.1.100",
      "last_keep_alive": "2024-01-01T14:58:30Z",
      "uptime": "72h 15m",
      "status": "active"
    },
    {
      "id": "003",
      "name": "db-server-01",
      "ip": "192.168.1.103",
      "last_keep_alive": "2024-01-01T14:58:45Z",
      "uptime": "168h 22m",
      "status": "active"
    }
  ],
  "summary": {
    "total_running": 142,
    "average_uptime": "96h 30m",
    "oldest_uptime": "720h 15m",
    "newest_connection": "2h 15m"
  }
}
```

---

## 🏥 check_agent_health

Perform comprehensive health check on a specific Wazuh agent.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `agent_id` | string | - | **Yes** | ID of the agent to check (3-8 alphanumeric characters) |

### Usage Examples

#### Basic Health Check
```
Ask Claude: "Check the health of agent 001"
```

#### Troubleshooting
```
Ask Claude: "Is agent web-01 healthy?"
```

### Response Format

```json
{
  "agent_health": {
    "agent_id": "001",
    "agent_name": "web-server-01",
    "overall_status": "healthy",
    "health_score": 95,
    "checks": {
      "connectivity": {
        "status": "pass",
        "last_seen": "2024-01-01T14:58:30Z",
        "latency_ms": 12
      },
      "version_compatibility": {
        "status": "pass",
        "agent_version": "4.8.0",
        "manager_version": "4.8.0",
        "compatible": true
      },
      "configuration": {
        "status": "pass",
        "config_hash": "ab12cd34ef56",
        "last_updated": "2024-01-01T10:00:00Z"
      },
      "performance": {
        "status": "warning",
        "cpu_usage": 85,
        "memory_usage": 67,
        "disk_usage": 42
      },
      "log_collection": {
        "status": "pass",
        "events_per_second": 15.2,
        "queue_usage": 12
      }
    },
    "recommendations": [
      "Monitor CPU usage - currently at 85%",
      "Consider increasing log buffer size"
    ]
  }
}
```

### Health Check Categories

| Category | Description | Status Values |
|----------|-------------|---------------|
| `connectivity` | Network connection status | pass, fail |
| `version_compatibility` | Agent/manager version compatibility | pass, warning, fail |
| `configuration` | Configuration sync status | pass, warning, fail |
| `performance` | System resource usage | pass, warning, critical |
| `log_collection` | Log processing performance | pass, warning, fail |

---

## ⚙️ get_agent_configuration

Retrieve detailed configuration information for a specific Wazuh agent.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `agent_id` | string | - | **Yes** | ID of the agent |

### Usage Examples

#### View Agent Configuration
```
Ask Claude: "Show me the configuration for agent 001"
```

#### Configuration Audit
```
Ask Claude: "What is the current configuration of agent web-01?"
```

### Response Format

```json
{
  "agent_configuration": {
    "agent_id": "001",
    "agent_name": "web-server-01",
    "configuration": {
      "client": {
        "server": [
          {
            "address": "192.168.1.10",
            "port": 1514,
            "protocol": "tcp"
          }
        ],
        "config-profile": "ubuntu, ubuntu20, ubuntu20.04",
        "notify_time": 10,
        "time-reconnect": 60
      },
      "rootcheck": {
        "disabled": "no",
        "check_files": "yes",
        "check_trojans": "yes",
        "check_dev": "yes",
        "check_sys": "yes",
        "check_pids": "yes",
        "check_ports": "yes",
        "check_if": "yes"
      },
      "sca": {
        "enabled": "yes",
        "scan_on_start": "yes",
        "interval": "12h",
        "skip_nfs": "yes"
      },
      "wodle": [
        {
          "name": "cis-cat",
          "disabled": "yes"
        },
        {
          "name": "osquery",
          "disabled": "yes"
        },
        {
          "name": "syscollector",
          "disabled": "no",
          "interval": "1h",
          "scan_on_start": "yes"
        }
      ],
      "localfile": [
        {
          "log_format": "syslog",
          "location": "/var/log/auth.log"
        },
        {
          "log_format": "syslog",
          "location": "/var/log/syslog"
        },
        {
          "log_format": "apache",
          "location": "/var/log/apache2/access.log"
        }
      ]
    },
    "metadata": {
      "config_hash": "ab12cd34ef56",
      "last_updated": "2024-01-01T10:00:00Z",
      "merged_sum": "98765432"
    }
  }
}
```

---

## 🔄 get_agent_processes

Monitor running processes on a specific Wazuh agent.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `agent_id` | string | - | **Yes** | ID of the agent |
| `limit` | integer | `100` | No | Maximum number of processes to retrieve |

### Usage Examples

#### List Agent Processes
```
Ask Claude: "Show me running processes on agent 001"
```

#### Security Monitoring
```
Ask Claude: "What processes are running on web-server-01?"
```

### Response Format

```json
{
  "agent_processes": {
    "agent_id": "001",
    "agent_name": "web-server-01",
    "scan_time": "2024-01-01T15:00:00Z",
    "total_processes": 156,
    "processes": [
      {
        "pid": "1",
        "name": "systemd",
        "state": "S",
        "ppid": "0",
        "utime": "15",
        "stime": "25",
        "cmd": "/sbin/init",
        "argvs": "/sbin/init",
        "euser": "root",
        "ruser": "root",
        "suser": "root",
        "egroup": "root",
        "rgroup": "root",
        "sgroup": "root",
        "fgroup": "root",
        "priority": "20",
        "nice": "0",
        "size": "225280",
        "vm_size": "225280",
        "resident": "9472",
        "share": "6784",
        "start_time": "1673308800",
        "pgrp": "1",
        "session": "1",
        "nlwp": "1",
        "tgid": "1",
        "tty": "0"
      }
    ],
    "summary": {
      "by_user": {
        "root": 45,
        "www-data": 12,
        "mysql": 8
      },
      "by_state": {
        "running": 2,
        "sleeping": 148,
        "zombie": 0,
        "stopped": 6
      },
      "resource_usage": {
        "total_memory": "2048000",
        "used_memory": "1456000",
        "memory_percentage": 71.1
      }
    }
  }
}
```

### Process Information Fields

| Field | Description | Example |
|-------|-------------|---------|
| `pid` | Process ID | "1234" |
| `name` | Process name | "apache2" |
| `state` | Process state | "S" (sleeping), "R" (running) |
| `cmd` | Command line | "/usr/sbin/apache2" |
| `euser` | Effective user | "www-data" |
| `size` | Virtual memory size (KB) | "225280" |
| `resident` | Resident memory (KB) | "9472" |

---

## 🌐 get_agent_ports

Monitor open ports and network connections on a specific Wazuh agent.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `agent_id` | string | - | **Yes** | ID of the agent |
| `limit` | integer | `100` | No | Maximum number of ports to retrieve |

### Usage Examples

#### Network Security Audit
```
Ask Claude: "Show me open ports on agent 001"
```

#### Service Discovery
```
Ask Claude: "What services are listening on web-server-01?"
```

### Response Format

```json
{
  "agent_ports": {
    "agent_id": "001",
    "agent_name": "web-server-01",
    "scan_time": "2024-01-01T15:00:00Z",
    "total_ports": 12,
    "ports": [
      {
        "protocol": "tcp",
        "local_ip": "0.0.0.0",
        "local_port": "22",
        "remote_ip": "0.0.0.0",
        "remote_port": "0",
        "tx_queue": "0",
        "rx_queue": "0",
        "inode": "12345",
        "state": "listening",
        "pid": "1234",
        "process": "sshd"
      },
      {
        "protocol": "tcp",
        "local_ip": "0.0.0.0",
        "local_port": "80",
        "remote_ip": "0.0.0.0",
        "remote_port": "0",
        "tx_queue": "0",
        "rx_queue": "0",
        "inode": "67890",
        "state": "listening",
        "pid": "5678",
        "process": "apache2"
      }
    ],
    "summary": {
      "by_protocol": {
        "tcp": 10,
        "udp": 2
      },
      "by_state": {
        "listening": 8,
        "established": 3,
        "time_wait": 1
      },
      "services": {
        "ssh": 1,
        "http": 1,
        "https": 1,
        "mysql": 1
      }
    },
    "security_analysis": {
      "exposed_services": ["ssh", "http", "https"],
      "unusual_ports": [],
      "security_score": 85,
      "recommendations": [
        "Consider restricting SSH access to specific IP ranges",
        "Ensure HTTPS is properly configured with valid certificates"
      ]
    }
  }
}
```

### Port Information Fields

| Field | Description | Security Relevance |
|-------|-------------|-------------------|
| `protocol` | Network protocol | tcp, udp |
| `local_port` | Listening port | 22 (SSH), 80 (HTTP), 443 (HTTPS) |
| `state` | Connection state | listening, established, time_wait |
| `process` | Associated process | sshd, apache2, mysql |
| `pid` | Process ID | Correlation with process monitoring |

---

## 💡 Best Practices

### Agent Monitoring Strategy

1. **Regular Health Checks**: Monitor agent health periodically
2. **Process Monitoring**: Track unusual processes and resource usage
3. **Network Security**: Monitor open ports for security exposure
4. **Configuration Audits**: Verify configurations match security policies

### Performance Optimization

1. **Targeted Queries**: Use agent_id for specific agent monitoring
2. **Appropriate Limits**: Set reasonable limits for large environments
3. **Status Filtering**: Use status filters to focus on problematic agents

### Security Considerations

1. **Access Control**: Ensure proper permissions for agent data access
2. **Sensitive Data**: Process and port information may contain sensitive details
3. **Network Exposure**: Monitor for unexpected open ports

---

## 🔧 Troubleshooting

### Common Issues

#### Agent Not Found
```json
{
  "error": "Agent with ID '999' not found",
  "error_code": "AGENT_NOT_FOUND"
}
```

**Solution**: Verify agent ID exists using `get_wazuh_agents`

#### Agent Disconnected
```json
{
  "error": "Agent '001' is disconnected - cannot retrieve process/port information",
  "error_code": "AGENT_DISCONNECTED"
}
```

**Solution**: Check agent connectivity and restart if necessary

#### Insufficient Permissions
```json
{
  "error": "Insufficient permissions to access agent data",
  "error_code": "ACCESS_DENIED"
}
```

**Solution**: Ensure Wazuh user has proper agent read permissions

### Diagnostic Workflow

1. **Check Agent Status**: Use `get_wazuh_agents` to verify agent exists and is active
2. **Health Assessment**: Use `check_agent_health` for comprehensive status
3. **Detailed Investigation**: Use specific tools (`get_agent_processes`, `get_agent_ports`) for deep analysis
4. **Configuration Review**: Use `get_agent_configuration` for configuration issues

---

**Next**: See [Vulnerability Management API](vulnerabilities.md) for vulnerability scanning tools.