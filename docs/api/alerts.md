# Alerts

Tools in the `alerts` toolset. All five read the `wazuh-alerts-*` index on the Wazuh Indexer; the Manager API has no alerts endpoint. They require `WAZUH_INDEXER_HOST` and return an `isError` result when it is not set.

| Tool | Purpose |
|------|---------|
| [`get_wazuh_alerts`](#get_wazuh_alerts) | Alert documents with filters |
| [`get_wazuh_alert_summary`](#get_wazuh_alert_summary) | Alert counts grouped by one field |
| [`get_alerts_aggregated`](#get_alerts_aggregated) | Complete totals, top rules, levels and agents for a window |
| [`analyze_alert_patterns`](#analyze_alert_patterns) | Rules firing at or above a frequency threshold |
| [`search_security_events`](#search_security_events) | Free-text search plus structured filters |

Conventions shared by all tools (argument formats, errors, compact mode, truncation, GCF) are described in the [tool reference overview](README.md).

---

## get_wazuh_alerts

Returns alert documents, newest first, with optional filters. All filters are combined with AND.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-alerts-*`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `limit` | integer | no | `100` | 1 to 1000. The upper bound is `MAX_ALERTS_PER_QUERY` (default 1000, settable up to 10000) and is advertised as the schema maximum |
| `rule_id` | string | no | none | 1 to 6 digits, exact match on `rule.id` |
| `level` | string | no | none | Minimum rule level: one or two digits with optional `+` (`"10"` and `"10+"` both mean level 10 and above) |
| `agent_id` | string | no | none | Agent ID, exact match on `agent.id` |
| `rule_groups` | array of string | no | none | Up to 20 group names (letters, digits, `.`, `_`, `-`; max 64 chars each). Matches alerts in any of the listed groups |
| `timestamp_start` | string | no | none | ISO 8601 or date math, e.g. `now-24h` |
| `timestamp_end` | string | no | none | ISO 8601 or date math, e.g. `now` |
| `compact` | boolean | no | `true` | Return essential fields only |

### Notes

- Without `timestamp_start`/`timestamp_end` there is no time bound: the tool returns the newest `limit` alerts in the index.
- `total_affected_items` is the true number of matching alerts, not the number returned.
- Compact records keep `timestamp`, `agent` (`id`, `name`), `rule` (`id`, `level`, `description`, `groups`, and `mitre` when present), `srcip` and `dstip` (from `data.*`, when present), `syscheck` (`path`, `event`, when present) and `full_log` (first 300 characters).
- A `_warning` is added when the match count reaches `limit`.

### Example

Arguments:

```json
{"level": "5+", "agent_id": "3", "timestamp_start": "now-24h", "limit": 2}
```

Result (compact, pretty-printed, one record shown):

```text
Wazuh Alerts:
{
  "data": {
    "affected_items": [
      {
        "timestamp": "2026-09-24T09:41:07.512+0000",
        "agent": {"id": "003", "name": "web-01"},
        "rule": {
          "id": "5710",
          "level": 5,
          "description": "sshd: Attempt to login using a non-existent user",
          "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"],
          "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"], "technique": ["Password Guessing"]}
        },
        "srcip": "203.0.113.45",
        "full_log": "Sep 24 09:41:07 web-01 sshd[23114]: Invalid user admin from 203.0.113.45 port 51122"
      }
    ],
    "total_affected_items": 4231,
    "total_failed_items": 0,
    "failed_items": []
  },
  "_warning": "Results may be truncated (4231 items returned, limit was 2). Use more specific filters (time_range, agent_id, rule_id, level) or increase limit for complete results."
}
```

---

## get_wazuh_alert_summary

Counts alerts in a time window, grouped by one field.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-alerts-*`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `time_range` | string | no | `24h` | `1h`, `6h`, `12h`, `1d`, `24h`, `7d`, `30d` |
| `group_by` | string | no | `rule.level` | `rule.level`, `rule.id`, `rule.groups`, `agent.id`, `agent.name` |

### Notes

- Grouping is done in the server over the newest 1,000 alerts in the window. `total_alerts` is the true match count; `alerts_sampled` is the number grouped. When the window holds more than 1,000 alerts, `truncated` is `true` and a `truncation_warning` is included. Use [`get_alerts_aggregated`](#get_alerts_aggregated) for complete counts.
- With `group_by: "rule.groups"`, an alert is counted once in each of its groups.

### Example

Arguments:

```json
{"time_range": "24h", "group_by": "rule.level"}
```

Result:

```text
Alert Summary:
{
  "data": {
    "time_range": "24h",
    "group_by": "rule.level",
    "total_alerts": 4231,
    "alerts_sampled": 3,
    "truncated": true,
    "groups": {"5": 1, "10": 1, "7": 1},
    "truncation_warning": "Grouping reflects the newest 3 of 4231 matching alerts."
  }
}
```

---

## get_alerts_aggregated

Summarizes every alert in a time window using Indexer aggregations. There is no document limit, so the counts are complete. Prefer this tool over `get_wazuh_alerts` or `get_wazuh_alert_summary` when the goal is an overview of a period.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-alerts-*` (aggregation query, no documents returned)

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `timestamp_start` | string | no | `now-24h` | ISO 8601 or date math |
| `timestamp_end` | string | no | `now` | ISO 8601 or date math |
| `top_rules` | integer | no | `50` | 1 to 500 |
| `top_agents` | integer | no | `50` | 1 to 500 |

### Notes

- Returns `total_alerts`, the `top_rules` rule IDs by count (with description and level), up to 20 rule levels in `by_level`, and the `top_agents` agents by count. Agents are bucketed by `agent.name`.
- The result is not wrapped in a `data` object.

### Example

Arguments:

```json
{"timestamp_start": "now-7d", "top_rules": 2, "top_agents": 2}
```

Result:

```text
Aggregated Alerts:
{
  "time_range": {"gte": "now-7d", "lte": "now"},
  "total_alerts": 4231,
  "top_rules": [
    {"rule_id": "5710", "count": 2988, "description": "sshd: Attempt to login using a non-existent user", "level": 5},
    {"rule_id": "550", "count": 611, "description": "Integrity checksum changed.", "level": 7}
  ],
  "by_level": [
    {"level": 5, "count": 3120},
    {"level": 7, "count": 845},
    {"level": 10, "count": 266}
  ],
  "top_agents": [
    {"agent": "web-01", "count": 3301},
    {"agent": "db-01", "count": 930}
  ]
}
```

---

## analyze_alert_patterns

Lists rules that fired at least `min_frequency` times in a time window, most frequent first.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-alerts-*`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `time_range` | string | no | `24h` | `1h`, `6h`, `12h`, `1d`, `24h`, `7d`, `30d` |
| `min_frequency` | integer | no | `5` | 1 to 1000 |

### Notes

- Counts are computed over the newest 1,000 alerts in the window. When more alerts match, `truncated` is `true`, `truncation_warning` is set, and the per-rule counts are lower bounds. `total_alerts` is always the true match count.
- Each pattern reports `rule_id`, `count`, `description` and `level`.

### Example

Arguments:

```json
{"time_range": "24h", "min_frequency": 1}
```

Result (patterns trimmed):

```text
Alert Patterns:
{
  "data": {
    "time_range": "24h",
    "min_frequency": 1,
    "patterns": [
      {"rule_id": "5710", "count": 1, "description": "sshd: Attempt to login using a non-existent user", "level": 5},
      {"rule_id": "5763", "count": 1, "description": "sshd: brute force trying to get access to the system. Non existent user.", "level": 10}
    ],
    "total_patterns": 3,
    "total_alerts": 4231,
    "alerts_analyzed": 3,
    "truncated": true,
    "truncation_warning": "Pattern counts reflect the newest 3 of 4231 matching alerts; frequencies are lower bounds."
  }
}
```

---

## search_security_events

Searches alerts in a time window with a free-text query and optional structured filters. All filters are combined with AND.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-alerts-*`, using an OpenSearch `simple_query_string` query across all alert fields

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `query` | string | yes | | Free text, max 500 characters. See query syntax below |
| `time_range` | string | no | `24h` | `1h`, `6h`, `12h`, `1d`, `24h`, `7d`, `30d` |
| `limit` | integer | no | `100` | 1 to 1000. The upper bound is `MAX_ALERTS_PER_QUERY` (default 1000, settable up to 10000) and is advertised as the schema maximum |
| `rule_id` | string | no | none | 1 to 6 digits, exact match on `rule.id` |
| `agent_id` | string | no | none | Agent ID, exact match on `agent.id` |
| `level` | string | no | none | Minimum rule level, e.g. `"10"` or `"12+"` |
| `srcip` | string | no | none | IPv4 or IPv6, exact match on `data.srcip` |
| `dstip` | string | no | none | IPv4 or IPv6, exact match on `data.dstip` |
| `compact` | boolean | no | `true` | Return essential fields only (same fields as `get_wazuh_alerts`) |

### Query syntax

| Syntax | Meaning |
|--------|---------|
| `sshd failed` | Both terms must match (the default operator is AND) |
| `sshd AND failed` | Same as above; `AND` is translated to `+` |
| `ssh OR rdp` | Either term; `OR` is translated to `\|` |
| `NOT windows` | Exclude the term; `NOT` is translated to `-` |
| `"invalid user"` | Exact phrase. Words inside quotes are not treated as operators |
| `auth*` | Prefix match (trailing wildcard only) |

Not supported: leading wildcards (a leading `*` or `?` is stripped), regular expressions, and `field:value` syntax. Use the structured parameters (`rule_id`, `agent_id`, `level`, `srcip`, `dstip`) for field filters. Malformed query syntax does not raise an error.

### Notes

- Results are sorted newest first. `total_affected_items` is the true match count, and a `_warning` is added when it reaches `limit`.

### Example

Arguments:

```json
{"query": "sshd AND \"invalid user\"", "time_range": "24h", "srcip": "203.0.113.45", "limit": 1}
```

Result (compact, pretty-printed):

```text
Security Events:
{
  "data": {
    "affected_items": [
      {
        "timestamp": "2026-09-24T09:41:07.512+0000",
        "agent": {"id": "003", "name": "web-01"},
        "rule": {
          "id": "5710",
          "level": 5,
          "description": "sshd: Attempt to login using a non-existent user",
          "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"],
          "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"], "technique": ["Password Guessing"]}
        },
        "srcip": "203.0.113.45",
        "full_log": "Sep 24 09:41:07 web-01 sshd[23114]: Invalid user admin from 203.0.113.45 port 51122"
      }
    ],
    "total_affected_items": 4231,
    "total_failed_items": 0,
    "failed_items": []
  },
  "_warning": "Results may be truncated (4231 items returned, limit was 1). Use more specific filters (time_range, agent_id, rule_id, level) or increase limit for complete results."
}
```
