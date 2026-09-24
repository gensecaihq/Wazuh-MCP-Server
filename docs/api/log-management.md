# Manager Logs

Two tools in the `system` toolset read the Wazuh Manager's own log (`ossec.log`) through the Manager API. They do not search alerts or agent events; for those, use [`search_security_events`](alerts.md#search_security_events) and the other [alert tools](alerts.md).

| Tool | Purpose | Manager API endpoint |
|------|---------|----------------------|
| [`search_wazuh_manager_logs`](#search_wazuh_manager_logs) | Manager log entries containing a search string | `GET /manager/logs?search=...` |
| [`get_wazuh_manager_error_logs`](#get_wazuh_manager_error_logs) | Manager log entries at level `error` | `GET /manager/logs?level=error` |

Each log entry has `timestamp`, `tag` (the daemon or module, e.g. `wazuh-remoted`), `level` and `description`. Both tools return the Manager API response unchanged under a label line. Credentials that appear in log lines (`password=`, `token=`, `Authorization:` and similar) are redacted, as for every tool. Conventions shared by all tools are described in the [tool reference overview](README.md).

---

## search_wazuh_manager_logs

Returns Manager log entries that contain a search string.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /manager/logs` with the `search` parameter

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `query` | string | yes | | Max 500 characters; may not contain `<script`, `javascript:`, `; drop`, `; delete` or `--` |
| `limit` | integer | no | `100` | 1 to 500 (the Manager API's maximum for this endpoint) |

### Notes

- The query is passed as the Manager API's `search` parameter, which returns entries containing the string. It is not the structured `q` filter, so `field=value` expressions are not interpreted as filters.

### Example

Arguments:

```json
{"query": "vulnerability", "limit": 10}
```

Result:

```text
Manager Logs:
{
  "data": {
    "affected_items": [
      {
        "timestamp": "2026-09-24T08:02:55Z",
        "tag": "wazuh-modulesd:vulnerability-scanner",
        "level": "info",
        "description": " Vulnerability scan finished."
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

## get_wazuh_manager_error_logs

Returns Manager log entries whose level is `error`.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /manager/logs` with `level=error`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `limit` | integer | no | `100` | 1 to 500 |

### Notes

- Only level `error` is requested; warnings and critical entries are not included. Use `search_wazuh_manager_logs` to look for other entries.

### Example

Arguments:

```json
{"limit": 10}
```

Result:

```text
Manager Error Logs:
{
  "data": {
    "affected_items": [
      {
        "timestamp": "2026-09-24T09:31:02Z",
        "tag": "wazuh-remoted",
        "level": "error",
        "description": " Agent key already in use: agent ID '007'"
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
