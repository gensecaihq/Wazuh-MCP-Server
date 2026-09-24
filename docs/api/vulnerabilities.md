# Vulnerabilities

Tools in the `vulnerabilities` toolset. All three read the `wazuh-states-vulnerabilities-*` index on the Wazuh Indexer. The Manager API's `/vulnerability` endpoint was removed in Wazuh 4.8.0, so these tools require Wazuh 4.8.0 or later with the vulnerability detection module enabled, and `WAZUH_INDEXER_HOST` configured. Without the Indexer they return an `isError` result.

| Tool | Purpose |
|------|---------|
| [`get_wazuh_vulnerabilities`](#get_wazuh_vulnerabilities) | Vulnerability records with agent and severity filters |
| [`get_wazuh_critical_vulnerabilities`](#get_wazuh_critical_vulnerabilities) | Critical-severity records only |
| [`get_wazuh_vulnerability_summary`](#get_wazuh_vulnerability_summary) | Counts by severity (aggregation) |

Conventions shared by all tools are described in the [tool reference overview](README.md).

---

## get_wazuh_vulnerabilities

Returns vulnerability records, optionally filtered by agent and severity.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-states-vulnerabilities-*`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | no | none | Agent ID, exact match on `agent.id` |
| `severity` | string | no | none | `low`, `medium`, `high`, `critical` (case-insensitive; matched against `vulnerability.severity`) |
| `limit` | integer | no | `100` | 1 to 500 |
| `compact` | boolean | no | `true` | Return essential fields only |

### Notes

- Records are not sorted by severity or date.
- Full records (`compact: false`) contain `id`, `cve`, `severity`, `description`, `reference`, `cvss_score` (CVSS base score), `under_evaluation`, `detected_at`, `published_at`, `agent` (`id`, `name`) and `package` (`name`, `version`, `architecture`).
- Compact records keep `id`, `cve`, `severity`, `description` (first 120 characters), `reference`, `published_at`, `package` (`name`, `version`) and `agent` (`id`, `name`). They omit `cvss_score`, `under_evaluation`, `detected_at` and `package.architecture`.
- A `_warning` is added when the match count reaches `limit`.

### Example

Arguments:

```json
{"severity": "high", "limit": 10, "compact": false}
```

Result:

```text
Vulnerabilities:
{
  "data": {
    "affected_items": [
      {
        "id": "CVE-2024-25062",
        "cve": "CVE-2024-25062",
        "severity": "High",
        "description": "An issue was discovered in libxml2 before 2.11.7 and 2.12.x before 2.12.5.",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-25062",
        "cvss_score": 7.5,
        "under_evaluation": false,
        "detected_at": "2026-09-18T03:14:22.000Z",
        "published_at": "2024-02-04T23:15:08Z",
        "agent": {"id": "005", "name": "db-01"},
        "package": {"name": "libxml2", "version": "2.9.13+dfsg-1ubuntu0.3", "architecture": "amd64"}
      }
    ],
    "total_affected_items": 1,
    "total_failed_items": 0,
    "failed_items": []
  }
}
```

---

## get_wazuh_critical_vulnerabilities

Returns vulnerability records whose severity is `Critical`, across all agents.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-states-vulnerabilities-*`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `limit` | integer | no | `50` | 1 to 500 |
| `compact` | boolean | no | `true` | Return essential fields only |

### Notes

- Equivalent to `get_wazuh_vulnerabilities` with `severity: "critical"` and no agent filter. Record fields and compact behaviour are the same.
- To restrict to one agent, use `get_wazuh_vulnerabilities` with `agent_id` and `severity: "critical"`.

### Example

Arguments:

```json
{"limit": 1}
```

Result (compact, pretty-printed):

```text
Critical Vulnerabilities:
{
  "data": {
    "affected_items": [
      {
        "id": "CVE-2024-5535",
        "severity": "Critical",
        "cve": "CVE-2024-5535",
        "description": "Issue summary: Calling the OpenSSL API function SSL_select_next_proto with an empty supported client protocols buffer ma...",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2024-5535",
        "published_at": "2024-06-27T11:15:00Z",
        "package": {"name": "openssl", "version": "3.0.2-0ubuntu1.10"},
        "agent": {"id": "003", "name": "web-01"}
      }
    ],
    "total_affected_items": 1,
    "total_failed_items": 0,
    "failed_items": []
  },
  "_warning": "Results may be truncated (1 items returned, limit was 1). Use more specific filters (time_range, agent_id, rule_id, level) or increase limit for complete results."
}
```

---

## get_wazuh_vulnerability_summary

Returns vulnerability counts by severity using an Indexer aggregation, so the counts cover every matching record.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-states-vulnerabilities-*` (aggregation query)

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `time_range` | string | no | none | `1d`, `7d`, `30d`. Counts only vulnerabilities whose `vulnerability.detected_at` falls within the window |
| `agent_id` | string | no | none | Counts only vulnerabilities on this agent |

### Notes

- Without `time_range`, the summary covers every vulnerability currently present in the index (all open findings), regardless of when it was detected. With it, only findings first detected inside the window are counted.
- `by_severity` uses the severity values as stored in the index (`Critical`, `High`, `Medium`, `Low`, and any others present). `critical`, `high`, `medium` and `low` repeat those four counts, with `0` when absent.
- `total_vulnerabilities` counts records; `affected_agents` is the number of distinct agent IDs among them.

### Example

Arguments:

```json
{"time_range": "7d"}
```

Result:

```text
Vulnerability Summary:
{
  "data": {
    "total_vulnerabilities": 639,
    "affected_agents": 3,
    "by_severity": {"Medium": 412, "High": 157, "Low": 61, "Critical": 9},
    "critical": 9,
    "high": 157,
    "medium": 412,
    "low": 61
  }
}
```
