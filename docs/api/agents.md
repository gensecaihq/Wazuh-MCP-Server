# Agents

Tools in the `agents` toolset. All six read from the Wazuh Manager API and do not need the Indexer.

| Tool | Purpose | Manager API endpoint |
|------|---------|----------------------|
| [`get_wazuh_agents`](#get_wazuh_agents) | List agents, optionally filtered | `GET /agents` |
| [`get_wazuh_running_agents`](#get_wazuh_running_agents) | List active agents | `GET /agents?status=active` |
| [`check_agent_health`](#check_agent_health) | Status summary for one agent | `GET /agents` |
| [`get_agent_processes`](#get_agent_processes) | Process inventory for one agent | `GET /syscollector/{agent_id}/processes` |
| [`get_agent_ports`](#get_agent_ports) | Open-port inventory for one agent | `GET /syscollector/{agent_id}/ports` |
| [`get_agent_configuration`](#get_agent_configuration) | Agent group configuration | `GET /agents`, `GET /groups/{group}/configuration` |

Agent IDs are 1 to 5 digits and are zero-padded to three digits (`"3"` becomes `"003"`). Conventions shared by all tools are described in the [tool reference overview](README.md).

---

## get_wazuh_agents

Returns agents from the Manager API, optionally filtered by ID or status.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /agents`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | no | none | Agent ID; sent as `agents_list` |
| `status` | string | no | none | `active`, `disconnected`, `never_connected`, `pending` |
| `limit` | integer | no | `100` | 1 to 1000 |

### Notes

- The Manager API response is returned unchanged: `data.affected_items` holds full agent records (`id`, `name`, `ip`, `status`, `os`, `version`, `lastKeepAlive`, `dateAdd`, `group`, `node_name` and other fields reported by the Manager), and `data.total_affected_items` is the Manager's total.

### Example

Arguments:

```json
{"status": "disconnected"}
```

Result:

```text
Wazuh Agents:
{
  "data": {
    "affected_items": [
      {
        "id": "007",
        "name": "win-ws-07",
        "ip": "10.0.4.37",
        "status": "disconnected",
        "os": {"name": "Microsoft Windows 11 Pro", "version": "10.0.22631", "platform": "windows"},
        "version": "Wazuh v4.14.1",
        "lastKeepAlive": "2026-09-22T17:03:44+00:00",
        "dateAdd": "2026-03-02T10:21:09+00:00",
        "group": ["default", "windows"],
        "node_name": "node01"
      }
    ],
    "total_affected_items": 1,
    "total_failed_items": 0,
    "failed_items": []
  },
  "message": "All selected items were returned",
  "error": 0
}
```

---

## get_wazuh_running_agents

Returns agents whose status is `active`.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /agents?status=active`

### Parameters

None.

### Notes

- No `limit` is sent, so the Manager API's default page size applies. Use `get_wazuh_agents` with `status: "active"` and an explicit `limit` for larger fleets.
- The response has the same shape as `get_wazuh_agents`, under the label `Running Agents:`.

### Example

Arguments:

```json
{}
```

Result (one record shown):

```text
Running Agents:
{
  "data": {
    "affected_items": [
      {
        "id": "001",
        "name": "mail-01",
        "ip": "10.0.1.10",
        "status": "active",
        "os": {"name": "Ubuntu", "version": "22.04.4 LTS", "platform": "ubuntu"},
        "version": "Wazuh v4.14.1",
        "lastKeepAlive": "2026-09-24T09:42:10+00:00",
        "group": ["default", "linux"],
        "node_name": "node01"
      }
    ],
    "total_affected_items": 2,
    "total_failed_items": 0,
    "failed_items": []
  },
  "message": "All selected items were returned",
  "error": 0
}
```

---

## check_agent_health

Returns a status summary for one agent.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /agents` with `agents_list` and a field selection

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | yes | | Agent ID |

### Notes

- `health` is `healthy` when the agent's status is `active` and `unhealthy` for any other status. No other checks are performed.
- An unknown agent ID returns an `isError` result: `Agent <id> not found`.

### Example

Arguments:

```json
{"agent_id": "1"}
```

Result:

```text
Agent Health:
{
  "data": {
    "agent_id": "001",
    "name": "mail-01",
    "status": "active",
    "health": "healthy",
    "ip": "10.0.1.10",
    "os": {"name": "Ubuntu", "version": "22.04.4 LTS", "platform": "ubuntu"},
    "version": "Wazuh v4.14.1",
    "last_keep_alive": "2026-09-24T09:42:10+00:00",
    "date_add": "2026-01-12T08:00:03+00:00",
    "group": ["default", "linux"],
    "node_name": "node01"
  }
}
```

---

## get_agent_processes

Returns the syscollector process inventory for one agent.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /syscollector/{agent_id}/processes`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | yes | | Agent ID |
| `limit` | integer | no | `100` | 1 to 1000 |

### Notes

- Syscollector is a periodic inventory, not a live process list. Each record's `scan.time` shows when it was collected.
- The syscollector module must be enabled on the agent. The Manager API response is returned unchanged.

### Example

Arguments:

```json
{"agent_id": "003", "limit": 2}
```

Result (one record shown):

```text
Agent Processes:
{
  "data": {
    "affected_items": [
      {
        "pid": "2207",
        "name": "nginx",
        "state": "S",
        "ppid": 1,
        "euser": "www-data",
        "cmd": "nginx: worker process",
        "vm_size": 57680,
        "resident": 6104,
        "start_time": 1727100100,
        "scan": {"id": 0, "time": "2026-09-24T09:30:02+00:00"},
        "agent_id": "003"
      }
    ],
    "total_affected_items": 2,
    "total_failed_items": 0,
    "failed_items": []
  },
  "message": "All selected items were returned",
  "error": 0
}
```

---

## get_agent_ports

Returns the syscollector network-port inventory for one agent.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /syscollector/{agent_id}/ports`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | yes | | Agent ID |
| `limit` | integer | no | `100` | 1 to 1000 |

### Notes

- Like processes, ports come from the periodic syscollector inventory. The Manager API response is returned unchanged.

### Example

Arguments:

```json
{"agent_id": "003", "limit": 2}
```

Result (one record shown):

```text
Agent Ports:
{
  "data": {
    "affected_items": [
      {
        "protocol": "tcp",
        "local": {"ip": "0.0.0.0", "port": 22},
        "remote": {"ip": "0.0.0.0", "port": 0},
        "state": "listening",
        "pid": 1123,
        "process": "sshd",
        "tx_queue": 0,
        "rx_queue": 0,
        "inode": 23114,
        "scan": {"id": 0, "time": "2026-09-24T09:30:05+00:00"},
        "agent_id": "003"
      }
    ],
    "total_affected_items": 2,
    "total_failed_items": 0,
    "failed_items": []
  },
  "message": "All selected items were returned",
  "error": 0
}
```

---

## get_agent_configuration

Returns an agent's identity and configuration checksums, plus the shared configuration of its first group.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /agents` (fields `id`, `name`, `group`, `configSum`, `mergedSum`, `status`, `version`) and `GET /groups/{group}/configuration`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | yes | | Agent ID |

### Notes

- Only the first group in the agent's `group` list is read. If that request fails, `group_configuration` is an empty list rather than an error.
- This is the centrally managed group configuration (`agent.conf`), not the agent's local `ossec.conf`.
- An unknown agent ID returns an `isError` result: `Agent <id> not found`.

### Example

Arguments:

```json
{"agent_id": "001"}
```

Result:

```text
Agent Configuration:
{
  "data": {
    "agent": {
      "id": "001",
      "name": "mail-01",
      "status": "active",
      "version": "Wazuh v4.14.1",
      "group": ["default", "linux"],
      "configSum": "ab73af41699f13fdd81903b5f23d8d00",
      "mergedSum": "4a8724b20dee0124ff9656783c490c4e"
    },
    "group_configuration": [
      {
        "filters": {},
        "config": {
          "syscheck": {"frequency": 43200, "directories": ["/etc", "/usr/bin"]},
          "sca": {"enabled": "yes", "interval": "12h"}
        }
      }
    ]
  }
}
```
