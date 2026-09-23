# Security Analysis

Tools in the `analysis` toolset, plus `search_external_context`, which is in its own `web_search` toolset because it is the only tool that sends data outside the Wazuh deployment.

| Tool | Toolset | Purpose | Data source |
|------|---------|---------|-------------|
| [`analyze_security_threat`](#analyze_security_threat) | `analysis` | Alerts that mention an indicator | Indexer |
| [`check_ioc_reputation`](#check_ioc_reputation) | `analysis` | Local sighting count and highest alert level for an indicator | Indexer |
| [`perform_risk_assessment`](#perform_risk_assessment) | `analysis` | Weighted risk score for one agent or the environment | Manager API + Indexer |
| [`get_top_security_threats`](#get_top_security_threats) | `analysis` | Rules ranked by severity, volume and spread | Indexer |
| [`generate_security_report`](#generate_security_report) | `analysis` | Multi-section report for a daily, weekly, monthly or incident window | Manager API + Indexer |
| [`search_external_context`](#search_external_context) | `web_search` | Web search results for an indicator or topic | You.com Search API |

None of these tools queries an external threat-intelligence feed. `analyze_security_threat` and `check_ioc_reputation` reflect only what your own Wazuh deployment has recorded. Conventions shared by all tools are described in the [tool reference overview](README.md).

---

## analyze_security_threat

Searches alert history for an indicator and returns the match count with a sample of matching alerts.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-alerts-*` (free-text search over all alert fields)

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `indicator` | string | yes | | Validated against `indicator_type`: a valid IPv4/IPv6 address, a hex hash of 32 to 128 characters, a domain name, or a URL starting with `http://` or `https://` |
| `indicator_type` | string | no | `ip` | `ip`, `hash`, `domain`, `url` |

### Notes

- The indicator is searched as free text across all alert fields, with no time bound. The newest 100 matches are fetched; `matching_alerts` is the true total and `truncated` is `true` when it exceeds the sample.
- `alerts` contains up to 20 full alert documents (not compacted).
- `indicator_type` controls validation only; it does not restrict which alert fields are searched.

### Example

Arguments:

```json
{"indicator": "203.0.113.45"}
```

Result (one alert shown):

```text
Threat Analysis:
{
  "data": {
    "indicator": "203.0.113.45",
    "type": "ip",
    "matching_alerts": 4231,
    "alerts_sampled": 3,
    "truncated": true,
    "alerts": [
      {
        "timestamp": "2026-09-24T09:41:07.512+0000",
        "id": "1727170867.4512338",
        "agent": {"id": "003", "name": "web-01", "ip": "10.0.2.15"},
        "manager": {"name": "wazuh-manager"},
        "rule": {
          "id": "5710",
          "level": 5,
          "description": "sshd: Attempt to login using a non-existent user",
          "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"],
          "mitre": {"id": ["T1110.001"], "tactic": ["Credential Access"], "technique": ["Password Guessing"]},
          "firedtimes": 14,
          "pci_dss": ["10.2.4", "10.2.5"]
        },
        "decoder": {"name": "sshd", "parent": "sshd"},
        "data": {"srcip": "203.0.113.45", "srcuser": "admin", "srcport": "51122"},
        "full_log": "Sep 24 09:41:07 web-01 sshd[23114]: Invalid user admin from 203.0.113.45 port 51122",
        "location": "/var/log/auth.log"
      }
    ]
  }
}
```

---

## check_ioc_reputation

Counts local alert sightings of an indicator and derives a coarse risk label from the highest alert level seen. This is not an external reputation lookup: zero sightings means "not seen locally", not "known clean".

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-alerts-*` (free-text search over all alert fields)

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `indicator` | string | yes | | Validated against `indicator_type`, as for `analyze_security_threat` |
| `indicator_type` | string | no | `ip` | `ip`, `domain`, `hash`, `url` |

### Notes

- No time bound. `occurrences` is the true match count; `max_alert_level` is taken from the newest 500 matches (`occurrences_sampled`).
- `risk` is `high` when `max_alert_level` is 10 or more, `medium` when it is 5 to 9, and `low` otherwise (including no sightings).

### Example

Arguments:

```json
{"indicator": "203.0.113.45", "indicator_type": "ip"}
```

Result:

```text
IoC Reputation:
{
  "data": {
    "indicator": "203.0.113.45",
    "type": "ip",
    "occurrences": 4231,
    "occurrences_sampled": 3,
    "truncated": true,
    "max_alert_level": 10,
    "risk": "high"
  }
}
```

---

## perform_risk_assessment

Computes a 0 to 100 risk score for one agent, or for the environment, from agent connectivity, vulnerability counts, recent high-severity alerts and SCA scores.

- **Scope:** `wazuh:read`
- **Data source:** Manager API (`GET /agents`, `GET /sca/{agent_id}`) and, when configured, the Indexer (vulnerability summary and alerts)

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | no | none | Agent ID. When set, every data source is scoped to this agent |

### Risk factors

| Factor | Condition | Severity |
|--------|-----------|----------|
| `disconnected_agents` | Any agent in scope whose status is not `active` | high |
| `critical_vulnerabilities` | One or more open Critical vulnerabilities | critical |
| `high_vulnerabilities` | One or more open High vulnerabilities | high |
| `high_severity_alerts` | More than 10 alerts of level 10 or above in the last 24 hours | high |
| `elevated_alert_activity` | 1 to 10 alerts of level 10 or above in the last 24 hours | medium |
| `low_sca_compliance` | Average SCA policy score below 50 | high |
| `moderate_sca_compliance` | Average SCA policy score from 50 to 69 | medium |

### Scoring

- Each factor contributes `weight × min(log2(count + 1), 5)`, with weights critical 30, high 20, medium 10, low 5. SCA factors count as 1. The sum is capped at 100.
- `risk_level` is `critical` at 70 or above, `high` at 50 to 69, `medium` at 25 to 49, and `low` below 25.

### Notes

- The SCA average is taken from the first active agent in scope only (`sca_average_score`).
- Without the Indexer, or if an Indexer query fails, the vulnerability and alert factors are skipped and `vulnerability_summary` / `alert_summary` are `null`. The result is not an error in that case, so a low score can reflect missing data.
- The agent list is requested without a `limit`, so the Manager API's default page size applies.

### Example

Arguments:

```json
{}
```

Result:

```text
Risk Assessment:
{
  "data": {
    "overall_risk_score": 100,
    "risk_level": "critical",
    "total_agents": 3,
    "risk_factors": [
      {"factor": "disconnected_agents", "count": 1, "severity": "high", "details": [{"id": "007", "name": "win-ws-07"}]},
      {"factor": "critical_vulnerabilities", "count": 9, "severity": "critical"},
      {"factor": "high_vulnerabilities", "count": 157, "severity": "high"},
      {"factor": "high_severity_alerts", "count": 4231, "severity": "high"},
      {"factor": "moderate_sca_compliance", "score": 57, "severity": "medium"}
    ],
    "vulnerability_summary": {
      "total_vulnerabilities": 639,
      "affected_agents": 3,
      "by_severity": {"Medium": 412, "High": 157, "Low": 61, "Critical": 9},
      "critical": 9,
      "high": 157,
      "medium": 412,
      "low": 61
    },
    "alert_summary": {"high_severity_alerts_24h": 4231},
    "sca_average_score": 57
  }
}
```

---

## get_top_security_threats

Ranks the rules that fired in a time window by a threat score that weights severity above volume.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-alerts-*`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `limit` | integer | no | `10` | 1 to 50 |
| `time_range` | string | no | `24h` | `1h`, `6h`, `12h`, `1d`, `24h`, `7d`, `30d` |

### Notes

- Computed over the newest 1,000 alerts in the window. When more alerts match, `truncated` is `true` and counts and rankings are lower bounds. `total_alerts` is the true match count.
- `threat_score = 100 × (0.6 × level/15 + 0.25 × min(log2(count + 1), 6)/6 + 0.15 × min(agents, 10)/10)`, rounded down. Threats are sorted by score, then by count.
- Each threat lists up to 20 `source_ips` (from `data.srcip`) and up to 20 `affected_agents`, with `first_seen` and `last_seen` timestamps. `mitre` is `null` when the rule has no MITRE mapping.

### Example

Arguments:

```json
{"limit": 2, "time_range": "24h"}
```

Result (one threat shown):

```text
Top Security Threats:
{
  "data": {
    "time_range": "24h",
    "total_alerts": 4231,
    "total_alerts_analyzed": 3,
    "truncated": true,
    "threats": [
      {
        "rule_id": "5763",
        "description": "sshd: brute force trying to get access to the system. Non existent user.",
        "level": 10,
        "count": 1,
        "threat_score": 45,
        "groups": ["syslog", "sshd", "authentication_failures"],
        "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
        "source_ips": ["203.0.113.45"],
        "affected_agents": [{"id": "003", "name": "web-01"}],
        "first_seen": "2026-09-24T09:40:55.101+0000",
        "last_seen": "2026-09-24T09:40:55.101+0000"
      }
    ],
    "total_unique_rules": 3,
    "truncation_warning": "Threat ranking reflects the newest 3 of 4231 matching alerts; counts and rankings are lower bounds."
  }
}
```

---

## generate_security_report

Builds a structured report whose sections depend on the report type.

- **Scope:** `wazuh:read`
- **Data source:** Manager API (`GET /agents`, `GET /`, `GET /sca/{agent_id}`) and, when configured, the Indexer (alerts, vulnerability summary, top threats)

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `report_type` | string | no | `daily` | `daily`, `weekly`, `monthly`, `incident` |
| `include_recommendations` | boolean | no | `true` | Add a `recommendations` section |

### Sections

| Section | Report types | Content |
|---------|--------------|---------|
| `agents` | all | Total, active and disconnected counts for up to 500 agents |
| `manager` | all | Manager API version and hostname from `GET /` |
| `alerts` | all (Indexer) | True total for the window, and a severity breakdown of the newest 500 alerts: `critical` (level 12+), `high` (10 to 11), `medium` (7 to 9), `low` (below 7) |
| `vulnerabilities` | all (Indexer) | Vulnerability summary for all open findings (not limited to the window) |
| `top_threats` | all (Indexer) | Top 5 entries from `get_top_security_threats` for the window |
| `compliance_summary` | `weekly`, `monthly` | Average SCA score for up to 3 active agents |
| `recommendations` | when `include_recommendations` is true | Actions for critical alerts in the sample, critical vulnerabilities and disconnected agents, or an `info` entry when none apply |

The window is 24 hours for `daily`, 7 days for `weekly`, 30 days for `monthly` and 1 hour for `incident`.

### Notes

- Without the Indexer, the `alerts`, `vulnerabilities` and `top_threats` sections are omitted. A section whose query fails contains `{"error": "..."}` instead of data; the report as a whole still succeeds.

### Example

Arguments:

```json
{"report_type": "daily"}
```

Result (`top_threats` trimmed to one entry):

```text
Security Report:
{
  "data": {
    "report_type": "daily",
    "generated_at": "2026-09-23T19:20:19.274921+00:00",
    "time_range": "24h",
    "sections": {
      "agents": {"total": 3, "active": 2, "disconnected": 1},
      "manager": {"version": "4.14.1", "hostname": "wazuh-manager", "type": null},
      "alerts": {"total": 4231, "sampled": 3, "truncated": true, "by_severity": {"low": 1, "high": 1, "medium": 1}, "time_range": "24h"},
      "vulnerabilities": {
        "total_vulnerabilities": 639,
        "affected_agents": 3,
        "by_severity": {"Medium": 412, "High": 157, "Low": 61, "Critical": 9},
        "critical": 9,
        "high": 157,
        "medium": 412,
        "low": 61
      },
      "top_threats": [
        {
          "rule_id": "5763",
          "description": "sshd: brute force trying to get access to the system. Non existent user.",
          "level": 10,
          "count": 1,
          "threat_score": 45,
          "groups": ["syslog", "sshd", "authentication_failures"],
          "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
          "source_ips": ["203.0.113.45"],
          "affected_agents": [{"id": "003", "name": "web-01"}],
          "first_seen": "2026-09-24T09:40:55.101+0000",
          "last_seen": "2026-09-24T09:40:55.101+0000"
        }
      ],
      "recommendations": [
        {"priority": "critical", "action": "Patch 9 critical vulnerabilities"},
        {"priority": "high", "action": "Investigate 1 disconnected agents"}
      ]
    }
  }
}
```

---

## search_external_context

Queries the You.com Search API for web context on an indicator or security topic. Disabled unless `YDC_API_KEY` is set.

- **Scope:** `wazuh:read`
- **Toolset:** `web_search`
- **Data source:** You.com Search API (`YDC_BASE_URL`, default `https://ydc-index.io`). The query text leaves your network.
- **Annotations:** `openWorldHint: true` (the only tool with this hint)

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `query` | string | yes | | Max 500 characters |
| `count` | integer | no | `5` | 1 to 10 |

### Notes

- Without `YDC_API_KEY`, the tool returns `enabled: false` with an explanatory `message`; this is a normal result, not an error.
- When enabled, the result contains `query`, `enabled: true`, `results` (each with `title`, `url`, `description`, `snippets`) and `search_uuid`. Searches use `safesearch=moderate`.
- The You.com client has its own circuit breaker, so a You.com outage does not affect Wazuh API calls. For air-gapped deployments, exclude the `web_search` toolset.
- Web results are third-party content and should be treated as untrusted data.

### Example

Arguments:

```json
{"query": "CVE-2024-5535"}
```

Result (no `YDC_API_KEY` configured):

```text
External Context:
{
  "data": {
    "query": "CVE-2024-5535",
    "enabled": false,
    "results": [],
    "message": "Set YDC_API_KEY to enable optional You.com web search context."
  }
}
```
