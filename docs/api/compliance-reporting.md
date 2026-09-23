# Compliance and Reporting

Tools in the `compliance` toolset. They derive compliance-related indicators from Wazuh Security Configuration Assessment (SCA) results, alerts, vulnerability data and agent status.

These tools do not certify compliance. SCA checks measure configuration hardening, which is one input to a controls assessment. The outputs say so explicitly (`disclaimer`, `assessment`, `posture` fields), and none of them emits a pass/fail verdict for a framework as a whole.

| Tool | Purpose | Data source |
|------|---------|-------------|
| [`run_compliance_check`](#run_compliance_check) | SCA hardening coverage for a framework | Manager API (SCA) |
| [`get_iso27001_dashboard`](#get_iso27001_dashboard) | ISO 27001:2022 posture across the mapped Annex A controls | Manager API + Indexer |
| [`get_iso27001_control_detail`](#get_iso27001_control_detail) | Evidence behind one control or domain | Manager API + Indexer |
| [`get_iso27001_gap_analysis`](#get_iso27001_gap_analysis) | Prioritized list of failing or unevidenced controls | Manager API + Indexer |
| [`get_iso27001_alerts`](#get_iso27001_alerts) | Recent alerts mapped to Annex A controls | Indexer |
| [`get_sca_policy_checks`](#get_sca_policy_checks) | Check-level results for one SCA policy on one agent | Manager API (SCA) |

For a multi-section operational report, see [`generate_security_report`](security-analysis.md#generate_security_report). Conventions shared by all tools are described in the [tool reference overview](README.md).

## ISO 27001:2022 control map

The ISO tools cover 14 of the 93 Annex A controls. Each mapped control has one Wazuh data source and a weight used in the dashboard's weighted average. Domain A.7 (Physical) has no mapped controls.

| Control | Title | Data source | Weight | Evidence used |
|---------|-------|-------------|--------|---------------|
| A.5.26 | Response to information security incidents | alerts | 2 | Rule groups `incident`, `syslog` |
| A.6.3 | Information security awareness, education and training | agents | 1 | Active agent count |
| A.8.1 | User endpoint devices | sca | 3 | SCA policies matching `cis`, `workstation`, `desktop`, `endpoint`, `windows`, `linux` |
| A.8.2 | Privileged access rights | alerts | 3 | Rule groups `syscheck`, `rootcheck`, `sudo`, `privilege_escalation` |
| A.8.4 | Access to source code | alerts | 1 | Rule groups `syscheck`, `fim` |
| A.8.5 | Secure authentication | alerts | 3 | Rule groups `authentication_failed`, `authentication_success`, `multiple_authentication_failures` |
| A.8.7 | Protection against malware | alerts | 3 | Rule groups `malware`, `virus`, `rootcheck`, `trojans` |
| A.8.8 | Management of technical vulnerabilities | vulnerabilities | 4 | Vulnerability counts by severity |
| A.8.9 | Configuration management | sca | 3 | SCA policies matching `cis`, `hardening`, `benchmark`, `configuration` |
| A.8.12 | Data leakage prevention | alerts | 2 | Rule groups `syscheck`, `fim`, `data_exfiltration` |
| A.8.15 | Logging | stats | 3 | analysisd events decoded (`GET /manager/stats/analysisd`) |
| A.8.16 | Monitoring activities | alerts | 3 | All alerts |
| A.8.20 | Networks security | alerts | 2 | Rule groups `firewall`, `network`, `ids`, `iptables` |
| A.8.22 | Segregation of networks | agents | 1 | Active agent count |

SCA policy matching is a case-insensitive substring match on the policy ID and name.

---

## run_compliance_check

Reports the share of passing SCA checks in the policies that match a framework, per agent and overall.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /agents` and `GET /sca/{agent_id}`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `framework` | string | no | `PCI-DSS` | `PCI-DSS`, `HIPAA`, `SOX`, `GDPR`, `NIST`, `ISO27001`. Case-insensitive; `PCI` and `PCIDSS` are accepted as `PCI-DSS` |
| `agent_id` | string | no | none | Check only this agent |

### Framework matching

An SCA policy counts toward a framework when its ID or name contains one of these keywords:

| Framework | Keywords |
|-----------|----------|
| PCI-DSS | `pci`, `payment`, `card` |
| HIPAA | `hipaa`, `health` |
| SOX | `sox`, `sarbanes` |
| GDPR | `gdpr`, `privacy`, `data_protection` |
| NIST | `nist`, `800-53`, `cybersecurity` |
| ISO27001 | `iso`, `27001`, `cis`, `hardening`, `benchmark`, `configuration` |

### Notes

- Without `agent_id`, the tool reads up to 10 active agents and checks the SCA results of the first 5. An agent whose SCA request fails is included with no policies. With `agent_id`, a failed SCA request is returned as an error.
- If no matching policy is loaded on any checked agent, the result has `assessment: "not_assessable"` and a `reason`, instead of scoring unrelated benchmarks under the framework's name. Stock Wazuh ships CIS benchmark policies, which match `ISO27001` but not the other frameworks' keywords.
- Otherwise `assessment` is `hardening_coverage`, and `hardening_coverage_pct` is passing checks divided by `total_checks` across the matching policies.

### Example

Arguments:

```json
{"framework": "ISO27001", "agent_id": "001"}
```

Result:

```text
Compliance Check:
{
  "data": {
    "framework": "ISO27001",
    "assessment": "hardening_coverage",
    "hardening_coverage_pct": 51,
    "disclaimer": "Percentage of mapped SCA/CIS configuration checks passing. This is a hardening coverage indicator, NOT a pass/fail compliance certification.",
    "total_checks": 187,
    "total_pass": 96,
    "total_fail": 71,
    "agents_checked": 1,
    "results": [
      {
        "agent_id": "001",
        "agent_name": null,
        "hardening_coverage_pct": 51,
        "pass": 96,
        "fail": 71,
        "total_checks": 187,
        "policies": [
          {"policy_id": "cis_ubuntu22-04", "name": "CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0", "score": 57, "pass": 96, "fail": 71}
        ]
      }
    ]
  }
}
```

With `{"framework": "HIPAA"}` and only CIS policies loaded:

```text
Compliance Check:
{
  "data": {
    "framework": "HIPAA",
    "assessment": "not_assessable",
    "reason": "No SCA/CIS policy matching HIPAA is loaded on the checked agent(s). This tool measures configuration hardening and cannot substitute for a HIPAA controls assessment. Load a framework-specific SCA policy or assess out of band.",
    "agents_checked": 2
  }
}
```

---

## get_iso27001_dashboard

Scores the 14 mapped Annex A controls, aggregates them per domain and overall, and adds a per-device SCA panel.

- **Scope:** `wazuh:read`
- **Data source:** Manager API (`GET /agents`, `GET /sca/{agent_id}`, `GET /manager/stats/analysisd`) and the Indexer (alerts from the last 30 days; vulnerabilities)

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | no | none | Scope every data source to this agent (whatever its status). Without it, active agents fleet-wide |

### How controls are scored

| Data source | Score | Status |
|-------------|-------|--------|
| sca | Passing checks as a percentage of all checks in matching policies, minus a penalty of `(fail_rate - 0.30) × 50` when more than 30% fail. SCA is read for up to 5 agents | `pass` at 75 or above, otherwise `fail`; `no_data` without matching checks |
| alerts | Not scored (`null`). Alert volume is not treated as a compliance measure | `monitoring_active` when matching alerts exist, otherwise `no_data` |
| vulnerabilities | `100 - 15 × critical - 5 × high - medium`, minimum 0. Counts come from up to 500 records per agent | `pass` at 75 or above, otherwise `fail`; `no_data` when the Indexer is not configured or the query fails |
| agents | `min(100, 10 × active agents)` | `active`, or `no_data` with no agents |
| stats | 100 when analysisd has decoded events, otherwise 0 | `active` or `no_data` |

- Domain and overall scores are weighted averages of the scored controls only. `posture` is `strong_where_measured` (75 or above), `moderate_where_measured` (50 to 74), `weak_where_measured` (below 50) or `insufficient_data`.
- Each control has a `confidence` of `high`, `medium`, `low` or `none`, based on the amount of evidence and whether its query succeeded.
- Alert data is limited to the newest 500 alerts from the last 30 days.
- Without the Indexer, alert-based controls report `no_data` and A.8.8 reports `no_data`; the tool still returns a result.

### Example

Arguments:

```json
{}
```

Result (`controls` trimmed to two entries):

```text
ISO 27001 Dashboard:
{
  "data": {
    "framework": "ISO27001:2022",
    "assessment_type": "control_coverage_indicator",
    "disclaimer": "This is a control-coverage indicator, NOT a compliance certification. Only 14 of 93 ISO 27001:2022 Annex A controls are mapped to Wazuh telemetry (A.7 Physical has none). Scores reflect only the mapped, technically measurable controls and must not be read as whole-framework compliance.",
    "controls_mapped": 14,
    "controls_total": 93,
    "coverage_pct_of_framework": 15,
    "overall_weighted_score": 57,
    "posture": "moderate_where_measured",
    "overall_confidence": "medium",
    "scoring": {
      "method": "weighted_average",
      "note": "Weighted by control importance over the MAPPED controls only (A.8.8 vulnerabilities weight=4). Alert-based controls report detection coverage and are not scored on volume. No pass/fail verdict is emitted.",
      "vuln_agents_aggregated": 2,
      "sca_agents_sampled": 2
    },
    "active_agents": 2,
    "vulnerability_summary": {"critical": 2, "high": 2, "medium": 0, "low": 0},
    "domain_summary": {
      "A.5": {"name": "Organizational", "weighted_score": null, "controls_measured": 0, "low_confidence_controls": 0},
      "A.6": {"name": "People", "weighted_score": 20, "controls_measured": 1, "low_confidence_controls": 0},
      "A.7": {"name": "Physical", "weighted_score": null, "controls_measured": 0, "low_confidence_controls": 0},
      "A.8": {"name": "Technological", "weighted_score": 60, "controls_measured": 5, "low_confidence_controls": 0}
    },
    "controls": [
      {"control_id": "A.8.8", "title": "Management of technical vulnerabilities", "domain": "A.8", "data_source": "vulnerabilities", "status": "fail", "score": 60, "weight": 4, "confidence": "high", "evidence_count": 4},
      {"control_id": "A.8.16", "title": "Monitoring activities", "domain": "A.8", "data_source": "alerts", "status": "monitoring_active", "score": null, "weight": 3, "confidence": "low", "evidence_count": 3}
    ],
    "failing_controls": [
      {"control_id": "A.8.8", "title": "Management of technical vulnerabilities", "score": 60, "weight": 4},
      {"control_id": "A.8.1", "title": "User endpoint devices", "score": 47, "weight": 3},
      {"control_id": "A.8.9", "title": "Configuration management", "score": 47, "weight": 3}
    ],
    "no_data_controls": ["A.8.7", "A.8.20"],
    "endpoint_device_panel": {
      "board_summary": "0/2 endpoint device(s) meet the ISO 27001 A.8.1 configuration-hardening baseline (SCA/CIS checks). 2 device(s) need hardening remediation. Critical vulnerabilities outstanding: 2. This reflects configuration hardening only, not full ISO 27001 compliance.",
      "devices": [
        {"agent_id": "001", "device_name": "mail-01", "sca_score": 51, "sca_policies": 1, "sca_status": "fail", "os": "Ubuntu"},
        {"agent_id": "003", "device_name": "web-01", "sca_score": 51, "sca_policies": 1, "sca_status": "fail", "os": "Ubuntu"}
      ],
      "total_devices": 2,
      "compliant_devices": 0,
      "non_compliant_devices": 2
    }
  }
}
```

---

## get_iso27001_control_detail

Returns the Wazuh evidence behind one mapped control, or behind every mapped control in a domain.

- **Scope:** `wazuh:read`
- **Data source:** Depends on the control's data source (see the [control map](#iso-270012022-control-map)): Manager API for SCA, agents and stats; Indexer for alerts and vulnerabilities

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `control_id` | string | yes | | A domain (`A.5`, `A.6`, `A.7`, `A.8`) or one of `A.5.26`, `A.6.3`, `A.8.1`, `A.8.2`, `A.8.4`, `A.8.5`, `A.8.7`, `A.8.8`, `A.8.9`, `A.8.12`, `A.8.15`, `A.8.16`, `A.8.20`, `A.8.22`. Lowercase input such as `a.8.8` is accepted |
| `agent_id` | string | no | none | Scope the evidence to this agent |

### Evidence by data source

| Data source | Evidence returned |
|-------------|-------------------|
| sca | Up to 10 SCA policies for the agent (policies matching the control's keywords, or all policies if none match) with score, pass, fail and total checks |
| alerts | Up to 100 alerts in the control's rule groups (no time bound): `alert_count` (number fetched, so at most 100), `rule_groups_searched`, and up to 20 `recent_alerts` |
| vulnerabilities | Up to 200 vulnerability records for the agent: total, `by_severity`, and up to 20 critical CVEs with package name and version |
| agents | Active agent count and up to 20 agents with OS and last keep-alive |
| stats | Raw analysisd statistics |

### Notes

- For SCA and vulnerability evidence without `agent_id`, the first active agent is used.
- `A.7` is accepted but has no mapped controls, so its `controls` list is empty.
- If one control's query fails, that control's `evidence` is `{"error": "..."}` and the others are still returned. Without the Indexer, vulnerability evidence is a note that the Indexer is not configured.

### Example

Arguments:

```json
{"control_id": "A.8.8"}
```

Result:

```text
ISO 27001 Control Detail [A.8.8]:
{
  "data": {
    "queried_control": "A.8.8",
    "framework": "ISO27001:2022",
    "controls": [
      {
        "control_id": "A.8.8",
        "title": "Management of technical vulnerabilities",
        "data_source": "vulnerabilities",
        "evidence": {
          "agent_id": "001",
          "total_vulnerabilities": 2,
          "by_severity": {"critical": 1, "high": 1},
          "critical_vulnerabilities": [
            {"cve": "CVE-2024-5535", "name": "openssl", "severity": "Critical", "version": "3.0.2-0ubuntu1.10"}
          ]
        }
      }
    ]
  }
}
```

---

## get_iso27001_gap_analysis

Lists mapped controls that are failing or have no evidence, ordered by severity, with a remediation hint for each.

- **Scope:** `wazuh:read`
- **Data source:** The same data as [`get_iso27001_dashboard`](#get_iso27001_dashboard), which it runs internally

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | no | none | Scope the analysis to this agent |

### Notes

- A control with status `no_data` becomes a `no_evidence` gap of severity `high`.
- A control with status `fail` becomes a `failing_checks` gap: severity `critical` when its score is below 40, otherwise `medium`.
- Alert-based controls with `monitoring_active` status are not gaps.

### Example

Arguments:

```json
{}
```

Result (`gaps` trimmed to two entries):

```text
ISO 27001 Gap Analysis:
{
  "data": {
    "framework": "ISO27001:2022",
    "total_gaps": 5,
    "gaps_by_domain": {"A.8": 5},
    "gaps": [
      {
        "control_id": "A.8.7",
        "title": "Protection against malware",
        "domain": "A.8",
        "gap_type": "no_evidence",
        "severity": "high",
        "score": null,
        "recommendation": "No Wazuh data available for this control. Data source expected: alerts. Ensure the relevant Wazuh module is enabled (e.g. SCA, vulnerability scanner, FIM)."
      },
      {
        "control_id": "A.8.8",
        "title": "Management of technical vulnerabilities",
        "domain": "A.8",
        "gap_type": "failing_checks",
        "severity": "medium",
        "score": 60,
        "recommendation": "Score: 60%. Patch critical and high-severity vulnerabilities. Prioritize CVEs with public exploits."
      }
    ],
    "summary": "5 gap(s) identified across ISO 27001:2022 Annex A controls. Critical: 0, High: 2, Medium: 3."
  }
}
```

---

## get_iso27001_alerts

Maps recent alerts to the alert-based Annex A controls by rule group and returns counts with sample alerts.

- **Scope:** `wazuh:read`
- **Data source:** Indexer, `wazuh-alerts-*`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `time_range` | string | no | `24h` | `1h`, `6h`, `12h`, `24h`, `7d`, `30d` |
| `agent_id` | string | no | none | Scope to this agent |

### Notes

- Reads the newest 500 alerts in the window (`total_alerts_fetched`). Counts are per control and an alert can count toward several controls. A.8.16 counts every fetched alert.
- `controls_with_alerts` is sorted by `alert_count` and includes up to 10 `sample_alerts` each; `controls_without_alerts` lists the alert-based controls with no matches.
- If the Indexer query fails, the result is `{"error": "Failed to fetch alerts: ..."}`.

### Example

Arguments:

```json
{"time_range": "24h"}
```

Result (trimmed):

```text
ISO 27001 Alerts:
{
  "data": {
    "framework": "ISO27001:2022",
    "time_range": "24h",
    "total_alerts_fetched": 3,
    "controls_with_alerts": [
      {
        "control_id": "A.8.5",
        "title": "Secure authentication",
        "domain": "A.8",
        "alert_count": 1,
        "sample_alerts": [
          {"timestamp": "2026-09-24T09:41:07.512+0000", "rule_id": "5710", "description": "sshd: Attempt to login using a non-existent user", "level": 5, "agent": "web-01"}
        ]
      }
    ],
    "controls_without_alerts": ["A.8.7", "A.8.20"]
  }
}
```

---

## get_sca_policy_checks

Returns check-level results for one SCA policy on one agent, including rationale and remediation for failed checks. Use it after `run_compliance_check` or the ISO tools to see why a policy scores low.

- **Scope:** `wazuh:read`
- **Data source:** Manager API, `GET /sca/{agent_id}/checks/{policy_id}`

### Parameters

| Name | Type | Required | Default | Constraints |
|------|------|----------|---------|-------------|
| `agent_id` | string | yes | | Agent ID |
| `policy_id` | string | yes | | SCA policy ID, e.g. `cis_ubuntu22-04`. Letters, digits, `.`, `_`, `-`; max 64 characters |

### Notes

- `score` is passed checks as a percentage of passed plus failed checks; `not applicable` checks are counted separately and excluded from the score.
- `failed_checks` (with `description`, `rationale`, `remediation`) and `passed_checks` are each capped at 50 entries.
- No `limit` is sent, so the Manager API's default page size applies to the checks read.

### Example

Arguments:

```json
{"agent_id": "001", "policy_id": "cis_ubuntu22-04"}
```

Result:

```text
SCA Policy Checks [cis_ubuntu22-04]:
{
  "data": {
    "agent_id": "001",
    "policy_id": "cis_ubuntu22-04",
    "total_checks": 3,
    "passed": 1,
    "failed": 1,
    "not_applicable": 1,
    "score": 50,
    "failed_checks": [
      {
        "id": 28500,
        "title": "Ensure mounting of cramfs filesystems is disabled.",
        "description": "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems.",
        "rationale": "Removing support for unneeded filesystem types reduces the local attack surface of the system.",
        "remediation": "Edit or create a file in the /etc/modprobe.d/ directory ending in .conf with 'install cramfs /bin/false'.",
        "result": "failed"
      }
    ],
    "passed_checks": [
      {"id": 28501, "title": "Ensure /tmp is a separate partition.", "result": "passed"}
    ]
  }
}
```

## Guided prompt

The server also provides an `iso27001_assessment` prompt that walks through the dashboard, domain drill-down, gap analysis and recommendations. Its arguments are `scope` (`full`, `technological` or `specific_control`), `control_id` and `agent_id`, all optional.

ISO 27001 tooling was contributed by [@andrzej-piotrowski-pl](https://github.com/andrzej-piotrowski-pl) (#74).
