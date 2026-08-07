# Security Analysis API

Reference for Wazuh security analysis and threat intelligence tools. These tools query live Wazuh data (Manager API + Indexer) and perform server-side enrichment including threat scoring, indicator extraction, and risk calculation.

## Overview

Six capabilities:
- **Threat Analysis**: Search alerts for threat indicators (IPs, domains, hashes)
- **IOC Reputation**: Indicator of Compromise lookup against alert history
- **External Context Search**: Opt-in web search (You.com) for context around an indicator or topic
- **Risk Assessment**: Multi-factor risk scoring from agents, vulnerabilities, alerts, and SCA
- **Threat Ranking**: Top threats with source IPs, affected agents, timeline, and composite scores
- **Security Reporting**: Reports differentiated by type (daily/weekly/monthly/incident) with recommendations

> **Note:** Except for `search_external_context` (an opt-in web search enabled via `YDC_API_KEY`), these tools return structured data from the Wazuh APIs and Indexer queries with server-side enrichment — they do not call external threat-intelligence feeds (VirusTotal, AbuseIPDB, etc.) or use AI/ML models. The LLM client can further analyze the returned data.

---

## analyze_security_threat

Search Wazuh alert history for a threat indicator via Elasticsearch.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `indicator` | string | — | **Yes** | Threat indicator (IP, hash, domain, URL) |
| `indicator_type` | string | `"ip"` | No | Type: `ip`, `hash`, `domain`, `url` |

### Response

```json
{
  "data": {
    "indicator": "203.0.113.15",
    "type": "ip",
    "matching_alerts": 12,
    "alerts": [
      {
        "timestamp": "2026-03-31T14:23:00Z",
        "rule": {"id": "5712", "level": 10, "description": "SSH brute force"},
        "agent": {"id": "003", "name": "web-prod-01"},
        "srcip": "203.0.113.15"
      }
    ]
  }
}
```

The `alerts` array contains up to 20 matching alerts (compact format). The LLM can analyze patterns, timelines, and affected assets from this data.

---

## check_ioc_reputation

Check how frequently an indicator appears in Wazuh alert history and the maximum alert severity associated with it.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `indicator` | string | — | **Yes** | IOC to check |
| `indicator_type` | string | `"ip"` | No | Type: `ip`, `domain`, `hash`, `url` |

### Response

```json
{
  "data": {
    "indicator": "198.51.100.15",
    "type": "ip",
    "occurrences": 47,
    "max_alert_level": 12,
    "risk": "high"
  }
}
```

Risk levels: `"high"` (max level >= 10), `"medium"` (>= 5), `"low"` (< 5).

---

## search_external_context

Search the web (via You.com) for additional context around a security topic or indicator.
**Opt-in:** disabled unless `YDC_API_KEY` is set — otherwise it returns `enabled: false` with an
empty result and a hint. Runs behind its own circuit breaker, isolated from the Wazuh API.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `query` | string | — | Yes | Security topic or indicator to search for |
| `count` | integer | `5` | No | Number of results (1–10) |

### Response

```json
{
  "data": {
    "query": "CVE-2026-XXXX exploitation",
    "enabled": true,
    "results": [
      { "title": "…", "url": "https://…", "description": "…", "snippets": ["…"] }
    ],
    "search_uuid": "…"
  }
}
```

---

## perform_risk_assessment

Multi-factor risk assessment combining agent status, vulnerabilities, alert severity, and SCA compliance scores.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `agent_id` | string | `null` | No | Specific agent (null = entire environment) |

### Response

```json
{
  "data": {
    "overall_risk_score": 62,
    "risk_level": "high",
    "total_agents": 15,
    "risk_factors": [
      {"factor": "disconnected_agents", "count": 3, "severity": "high", "details": [{"id": "005", "name": "db-backup"}]},
      {"factor": "critical_vulnerabilities", "count": 8, "severity": "critical"},
      {"factor": "high_severity_alerts", "count": 23, "severity": "high"},
      {"factor": "moderate_sca_compliance", "score": 58, "severity": "medium"}
    ],
    "vulnerability_summary": {"critical": 8, "high": 15, "medium": 42, "low": 12},
    "alert_summary": {"high_severity_alerts_24h": 23},
    "sca_average_score": 58
  }
}
```

**Risk score calculation:** Weighted sum of risk factors: critical=30, high=20, medium=10, low=5 points per factor, with logarithmic diminishing returns on count. Scale: 0-100.

| Score | Level | Interpretation |
|-------|-------|---------------|
| 70-100 | critical | Immediate action required |
| 50-69 | high | Investigate within hours |
| 25-49 | medium | Review within 24 hours |
| 0-24 | low | Routine monitoring |

---

## get_top_security_threats

Top threats ranked by composite score, with source IPs, affected agents, MITRE ATT&CK mapping, and timeline.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `limit` | integer | `10` | No | Number of top threats (1-50) |
| `time_range` | string | `"24h"` | No | Time window |

### Response

```json
{
  "data": {
    "time_range": "24h",
    "total_alerts_analyzed": 1247,
    "threats": [
      {
        "rule_id": "5712",
        "description": "SSHD brute force trying to get access to the system",
        "level": 10,
        "count": 245,
        "threat_score": 87,
        "groups": ["syslog", "sshd", "authentication_failures"],
        "mitre": {"id": ["T1110"], "tactic": ["Credential Access"], "technique": ["Brute Force"]},
        "source_ips": ["198.51.100.10", "203.0.113.25"],
        "affected_agents": [
          {"id": "003", "name": "web-prod-01"},
          {"id": "007", "name": "api-server-02"}
        ],
        "first_seen": "2026-03-31T02:00:00Z",
        "last_seen": "2026-03-31T14:30:00Z"
      }
    ],
    "total_unique_rules": 42
  }
}
```

**Threat score calculation:** `level * 5 * log2(count + 1) * (1 + 0.1 * affected_agents_count)`, capped at 100. Higher scores = more severe, more frequent, more widespread.

---

## generate_security_report

Reports with content that varies by type. Includes alert summaries, vulnerability counts, top threats, and data-driven recommendations.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `report_type` | string | `"daily"` | No | `daily`, `weekly`, `monthly`, `incident` |
| `include_recommendations` | boolean | `true` | No | Include action recommendations |

### Report Type Behavior

| Type | Time Range | Includes SCA | Includes Recommendations | Use Case |
|------|-----------|-------------|--------------------------|----------|
| `daily` | 24h | No | Yes | SOC shift handoff |
| `weekly` | 7d | Yes | Yes | Management briefing |
| `monthly` | 30d | Yes | Yes | Executive summary |
| `incident` | 1h | No | Yes | Active incident triage |

### Response (daily example)

```json
{
  "data": {
    "report_type": "daily",
    "generated_at": "2026-03-31T15:00:00Z",
    "time_range": "24h",
    "sections": {
      "agents": {"total": 15, "active": 12, "disconnected": 3},
      "manager": {"version": "4.14.1", "hostname": "wazuh-mgr"},
      "alerts": {"total": 1247, "by_severity": {"critical": 5, "high": 23, "medium": 89, "low": 1130}, "time_range": "24h"},
      "vulnerabilities": {"critical": 8, "high": 15, "medium": 42, "low": 12, "total_vulnerabilities": 77},
      "top_threats": [
        {"rule_id": "5712", "description": "SSH brute force", "threat_score": 87, "count": 245}
      ],
      "recommendations": [
        {"priority": "critical", "action": "Investigate 5 critical-severity alerts immediately"},
        {"priority": "critical", "action": "Patch 8 critical vulnerabilities"},
        {"priority": "high", "action": "Investigate 3 disconnected agents"}
      ]
    }
  }
}
```

---

## run_compliance_check

SCA-based compliance assessment. Filters SCA policies by framework relevance when framework-specific policies exist.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `framework` | string | `"PCI-DSS"` | No | `PCI-DSS`, `HIPAA`, `SOX`, `GDPR`, `NIST`, `ISO27001` |
| `agent_id` | string | `null` | No | Specific agent (null = sample up to 5 active agents) |

### Response

```json
{
  "data": {
    "framework": "PCI-DSS",
    "overall_score": 62,
    "overall_status": "fail",
    "total_checks": 462,
    "total_pass": 287,
    "total_fail": 175,
    "agents_checked": 2,
    "results": [
      {
        "agent_id": "001",
        "agent_name": "web-prod-01",
        "score": 53,
        "pass": 118,
        "fail": 104,
        "total_checks": 222,
        "policies": [
          {"policy_id": "cis_ubuntu24-04", "name": "CIS Ubuntu 24.04 LTS Benchmark v1.0.0", "score": 49, "pass": 118, "fail": 119}
        ]
      }
    ]
  }
}
```

**Framework filtering:** When Wazuh has framework-specific SCA policies installed (e.g., PCI-DSS policies), those are prioritized. When only generic CIS benchmarks are available, all policies are included since CIS controls map broadly to all frameworks.

**Overall status:** `"pass"` when `overall_score >= 70`, `"fail"` otherwise.

---

## Limitations

These tools provide factual data from Wazuh with server-side enrichment. They do NOT:
- Query external threat intelligence APIs (VirusTotal, AbuseIPDB, Shodan)
- Use AI/ML models for analysis
- Provide geolocation data for IPs
- Generate executive narrative summaries (the LLM client does this)
- Map individual CIS benchmark checks to specific framework requirement numbers

The LLM client (Claude, Ollama, etc.) is expected to interpret the structured data and provide narrative analysis, recommendations, and correlation.
