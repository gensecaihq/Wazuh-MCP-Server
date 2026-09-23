# System Monitoring

Tools in the `system` toolset that report on the Wazuh Manager, its cluster and its ruleset. All of them read from the Wazuh Manager API and take no parameters (apart from `cluster_id` in multi-cluster mode). The two manager-log tools in the same toolset are documented in [Manager logs](log-management.md).

| Tool | Purpose | Manager API endpoint |
|------|---------|----------------------|
| [`get_wazuh_statistics`](#get_wazuh_statistics) | Hourly alert and event statistics | `GET /manager/stats` |
| [`get_wazuh_weekly_stats`](#get_wazuh_weekly_stats) | Hourly averages per weekday | `GET /manager/stats/weekly` |
| [`get_wazuh_cluster_health`](#get_wazuh_cluster_health) | Cluster node health check | `GET /cluster/healthcheck` |
| [`get_wazuh_cluster_nodes`](#get_wazuh_cluster_nodes) | Cluster node list | `GET /cluster/nodes` |
| [`get_wazuh_rules_summary`](#get_wazuh_rules_summary) | Rule counts by level and group | `GET /rules` (all pages) |
| [`get_wazuh_remoted_stats`](#get_wazuh_remoted_stats) | Agent communication daemon statistics | `GET /manager/stats/remoted` |
| [`get_wazuh_log_collector_stats`](#get_wazuh_log_collector_stats) | Analysis daemon statistics | `GET /manager/stats/analysisd` |
| [`validate_wazuh_connection`](#validate_wazuh_connection) | Manager API reachability and version | `GET /` |
| [`list_wazuh_clusters`](#list_wazuh_clusters) | Configured clusters (multi-cluster mode only) | none |

Except where noted, the Manager API response is returned unchanged under a label line. Conventions shared by all tools are described in the [tool reference overview](README.md).

---

## get_wazuh_statistics

Returns the Manager's hourly statistics: total alerts, events, syscheck and firewall counts, and per-rule alert counts for each hour.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /manager/stats` (no date parameter is sent, so the Manager returns the current day)

### Parameters

None.

### Example

Result (one hour shown):

```text
Wazuh Statistics:
{
  "data": {
    "affected_items": [
      {
        "hour": 9,
        "alerts": [{"sigid": 5763, "level": 10, "times": 3}],
        "totalAlerts": 911,
        "syscheck": 17,
        "firewall": 0,
        "events": 30447
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

## get_wazuh_weekly_stats

Returns the Manager's weekly statistics: for each weekday, the hourly event averages.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /manager/stats/weekly`

### Parameters

None.

### Example

Result (two days shown, hourly arrays trimmed):

```text
Weekly Statistics:
{
  "data": {
    "affected_items": [
      {"Sun": {"hours": [5820, 5611], "interactions": 0}},
      {"Mon": {"hours": [6104, 6230], "interactions": 0}}
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

## get_wazuh_cluster_health

Returns the Wazuh cluster health check: per-node information (name, type, version, IP, active agents) and synchronization status.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /cluster/healthcheck`

### Parameters

None.

### Notes

- Requires Wazuh cluster mode. On a standalone Manager, the Manager API's error is returned as an `isError` result.

### Example

Result (trimmed):

```text
Cluster Health:
{
  "data": {
    "affected_items": [
      {
        "info": {"name": "node01", "type": "master", "version": "4.14.1", "ip": "10.0.0.2", "n_active_agents": 2},
        "status": {"last_keep_alive": "n/a"}
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

## get_wazuh_cluster_nodes

Returns the nodes of the Wazuh cluster with their type, version and IP.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /cluster/nodes`

### Parameters

None.

### Notes

- The response is cached in memory for up to 5 minutes.
- Requires Wazuh cluster mode, as for `get_wazuh_cluster_health`.

### Example

Result:

```text
Cluster Nodes:
{
  "data": {
    "affected_items": [
      {"name": "node01", "type": "master", "version": "4.14.1", "ip": "10.0.0.2"},
      {"name": "node02", "type": "worker", "version": "4.14.1", "ip": "10.0.0.3"}
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

## get_wazuh_rules_summary

Counts the loaded detection rules by level and by group.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /rules`, read page by page (500 rules per request) until every rule has been counted

### Parameters

None.

### Notes

- `total_rules` is the number of rules read; `by_level` maps each rule level to its count; `top_groups` holds the 20 most common groups.
- The summary is cached in memory for up to 5 minutes. It describes the ruleset, not how often rules fire; use the [alert tools](alerts.md) for that.

### Example

Result (from a four-rule test ruleset):

```text
Rules Summary:
{
  "data": {
    "total_rules": 4,
    "by_level": {"3": 1, "5": 1, "7": 1, "10": 1},
    "top_groups": {"syslog": 2, "sshd": 2, "ossec": 1, "syscheck": 1, "windows": 1}
  }
}
```

---

## get_wazuh_remoted_stats

Returns statistics for `wazuh-remoted`, the daemon that receives agent traffic: queue usage, TCP sessions, event and control message counts, discarded messages and bytes sent and received.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /manager/stats/remoted`

### Parameters

None.

### Example

Result:

```text
Remoted Statistics:
{
  "data": {
    "affected_items": [
      {
        "queue_size": 0,
        "total_queue_size": 131072,
        "tcp_sessions": 3,
        "evt_count": 4129011,
        "ctrl_msg_count": 22540,
        "discarded_count": 0,
        "sent_bytes": 118223412,
        "recv_bytes": 1502233891,
        "dequeued_after_close": 0
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

## get_wazuh_log_collector_stats

Returns statistics for `wazuh-analysisd`, the Manager's decoding and rule-matching daemon: events received, decoded (in total and per module), processed and dropped, queue usage, and alerts written. Despite the tool name, these are not agent logcollector statistics.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /manager/stats/analysisd`

### Parameters

None.

### Example

Result (fields trimmed):

```text
Analysisd Statistics:
{
  "data": {
    "affected_items": [
      {
        "total_events_decoded": 4128803,
        "syscheck_events_decoded": 11207,
        "syscollector_events_decoded": 30551,
        "events_processed": 4128803,
        "events_received": 4128830,
        "event_queue_usage": 0.0,
        "alerts_written": 211094,
        "firewall_written": 0,
        "fts_written": 1880,
        "events_dropped": 0
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

## validate_wazuh_connection

Checks that the Manager API is reachable with the configured credentials and returns its root information (API version, hostname, revision).

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /` (not cached)

### Parameters

None.

### Notes

- Only the Manager API is checked, not the Indexer. The server's `/ready` endpoint reports readiness of both.
- A failed connection is reported in the result as `{"status": "failed", "error": "..."}`; it is not an `isError` result.

### Example

Result:

```text
Connection Validation:
{
  "status": "connected",
  "details": {
    "data": {
      "title": "Wazuh API REST",
      "api_version": "4.14.1",
      "revision": "41412",
      "license_name": "GPL 2.0",
      "license_url": "https://github.com/wazuh/wazuh/blob/v4.14.1/LICENSE",
      "hostname": "wazuh-manager",
      "timestamp": "2026-09-24T09:42:30Z"
    },
    "error": 0
  }
}
```

---

## list_wazuh_clusters

Lists the configured Wazuh clusters and the default cluster used when a call has no `cluster_id`. This tool exists only in multi-cluster mode, that is when a clusters file is loaded (see [MULTI_CLUSTER.md](../MULTI_CLUSTER.md)); it is not part of the 55-tool single-cluster catalogue.

- **Scope:** `wazuh:read`
- **Toolset:** `system`
- **Data source:** Server configuration (no Wazuh request)

### Parameters

None. Unlike every other tool, it does not take `cluster_id`.

### Notes

- In multi-cluster mode, every other tool accepts an optional `cluster_id` string. An unknown `cluster_id` is rejected with a JSON-RPC invalid-params error that lists the configured clusters.

### Example

Result:

```text
Configured Wazuh Clusters:
{
  "multi_cluster": true,
  "default_cluster": "prod-eu",
  "clusters": [
    "prod-eu",
    "prod-us"
  ]
}
```
