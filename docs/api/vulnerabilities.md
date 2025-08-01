# Vulnerability Management API

Complete reference for Wazuh vulnerability assessment and management tools. These tools provide comprehensive vulnerability scanning, critical threat identification, and vulnerability trend analysis across your infrastructure.

## Overview

The vulnerability management tools offer three main capabilities:
- **Vulnerability Discovery**: Comprehensive scanning across all monitored systems
- **Critical Threat Assessment**: Identification and prioritization of high-risk vulnerabilities
- **Trend Analysis**: Statistical analysis and tracking of vulnerability patterns over time

---

## 🛡️ get_wazuh_vulnerabilities

Retrieve comprehensive vulnerability information from Wazuh with flexible filtering options.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `agent_id` | string | `null` | No | Filter by specific agent ID (3-8 alphanumeric characters) |
| `severity` | string | `null` | No | Filter by severity level |
| `limit` | integer | `100` | No | Maximum number of vulnerabilities to retrieve (1-500) |

### Severity Levels

| Severity | CVSS Range | Priority | Typical Action |
|----------|------------|----------|----------------|
| `critical` | 9.0-10.0 | Immediate | Emergency patching within 24-48 hours |
| `high` | 7.0-8.9 | High | Patch within 7-14 days |
| `medium` | 4.0-6.9 | Medium | Patch within 30-60 days |
| `low` | 0.1-3.9 | Low | Patch during maintenance windows |
| `informational` | 0.0 | Informational | Monitor, no immediate action required |

### Usage Examples

#### All Vulnerabilities Overview
```
Ask Claude: "Show me all vulnerabilities in the system"
```

This queries:
- `limit`: 100 (default)
- Returns vulnerabilities across all agents

#### Agent-Specific Vulnerability Scan
```
Ask Claude: "Get vulnerabilities for agent 001"
```

This queries:
- `agent_id`: "001"
- `limit`: 100 (default)

#### Critical Vulnerabilities Only
```
Ask Claude: "Show me only critical vulnerabilities"
```

This queries:
- `severity`: "critical"
- `limit`: 100 (default)

#### Large Environment Scan
```
Ask Claude: "List the first 200 vulnerabilities ordered by severity"
```

This queries:
- `limit`: 200
- Results ordered by severity (critical first)

### Response Format

```json
{
  "vulnerabilities": [
    {
      "id": "CVE-2024-0001",
      "title": "Remote Code Execution in Apache HTTP Server",
      "severity": "critical",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "published_date": "2024-01-15T10:00:00Z",
      "modified_date": "2024-01-16T14:30:00Z",
      "affected_package": {
        "name": "apache2",
        "version": "2.4.41-4ubuntu3.14",
        "architecture": "amd64"
      },
      "agent": {
        "id": "001",
        "name": "web-server-01",
        "ip": "192.168.1.100"
      },
      "description": "A buffer overflow vulnerability in mod_rewrite allows remote attackers to execute arbitrary code via crafted HTTP requests.",
      "references": [
        "https://httpd.apache.org/security/vulnerabilities_24.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"
      ],
      "solution": {
        "type": "VendorFix",
        "description": "Upgrade to Apache HTTP Server 2.4.58 or later",
        "fixed_version": "2.4.58"
      },
      "exploit_available": true,
      "detection_method": "version_check",
      "first_found": "2024-01-16T09:15:00Z",
      "status": "open"
    }
  ],
  "summary": {
    "total_vulnerabilities": 156,
    "by_severity": {
      "critical": 12,
      "high": 34,
      "medium": 78,
      "low": 32,
      "informational": 0
    },
    "by_status": {
      "open": 140,
      "fixed": 12,
      "mitigated": 4
    },
    "agents_affected": 45,
    "oldest_vulnerability": "2023-11-15T08:30:00Z",
    "newest_vulnerability": "2024-01-16T09:15:00Z"
  },
  "metadata": {
    "scan_time": "2024-01-16T15:00:00Z",
    "api_source": "wazuh_indexer",
    "query_time_ms": 342
  }
}
```

### Vulnerability Information Fields

| Field | Description | Security Relevance |
|-------|-------------|-------------------|
| `cvss_score` | Common Vulnerability Scoring System score | Risk prioritization (0.0-10.0) |
| `severity` | Human-readable severity level | Immediate action priority |
| `exploit_available` | Whether public exploits exist | Increased risk indicator |
| `affected_package` | Software package details | Target for patching |
| `solution.fixed_version` | Version that fixes the vulnerability | Upgrade target |
| `status` | Current vulnerability status | Remediation tracking |

---

## 🚨 get_wazuh_critical_vulnerabilities

Retrieve only critical vulnerabilities requiring immediate attention.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `limit` | integer | `50` | No | Maximum number of critical vulnerabilities to retrieve (1-100) |

### Usage Examples

#### Emergency Response
```
Ask Claude: "Show me all critical vulnerabilities that need immediate attention"
```

#### Executive Dashboard
```
Ask Claude: "What are the top 10 most critical security issues?"
```

This queries:
- `limit`: 10
- Only vulnerabilities with CVSS >= 9.0

### Response Format

```json
{
  "critical_vulnerabilities": [
    {
      "id": "CVE-2024-0001",
      "title": "Remote Code Execution in Apache HTTP Server",
      "cvss_score": 9.8,
      "severity": "critical",
      "exploit_available": true,
      "exploit_maturity": "functional",
      "affected_agents": [
        {
          "id": "001",
          "name": "web-server-01",
          "exposure": "internet_facing"
        },
        {
          "id": "003", 
          "name": "web-server-02",
          "exposure": "internal_network"
        }
      ],
      "business_impact": {
        "confidentiality": "high",
        "integrity": "high", 
        "availability": "high",
        "business_risk": "critical"
      },
      "remediation": {
        "urgency": "immediate",
        "timeline": "24_hours",
        "difficulty": "low",
        "downtime_required": true
      },
      "threat_intelligence": {
        "exploitation_likelihood": "very_high",
        "trending": true,
        "active_campaigns": 3
      },
      "first_found": "2024-01-16T09:15:00Z",
      "age_days": 1
    }
  ],
  "emergency_summary": {
    "total_critical": 12,
    "internet_facing": 8,
    "with_exploits": 9,
    "trending_threats": 4,
    "average_age_days": 15.2,
    "oldest_critical": "2023-12-01T10:00:00Z"
  },
  "remediation_timeline": {
    "immediate_action_required": 5,
    "patch_within_24h": 3,
    "patch_within_48h": 2,
    "patch_within_week": 2
  }
}
```

### Critical Vulnerability Indicators

| Indicator | Description | Action Required |
|-----------|-------------|-----------------|
| `exploit_available: true` | Public exploits exist | Immediate patching |
| `trending: true` | Currently being exploited in the wild | Emergency response |
| `internet_facing` | Exposed to external networks | Highest priority |
| `active_campaigns > 0` | Active attack campaigns detected | Incident response |

---

## 📊 get_wazuh_vulnerability_summary

Generate statistical summary and trends for vulnerability management reporting.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `time_range` | string | `"7d"` | No | Time range for trend analysis: 1d, 7d, 30d, 90d |

### Time Range Options

| Range | Description | Use Case |
|-------|-------------|----------|
| `1d` | Last 24 hours | Daily security briefings |
| `7d` | Last week | Weekly security reports |
| `30d` | Last month | Monthly compliance reports |
| `90d` | Last quarter | Quarterly security reviews |

### Usage Examples

#### Weekly Security Report
```
Ask Claude: "Give me a vulnerability summary for the last week"
```

This queries:
- `time_range`: "7d"
- Includes trend analysis and new discoveries

#### Monthly Compliance Report
```
Ask Claude: "Generate a monthly vulnerability trend report"
```

This queries:
- `time_range`: "30d"
- Focus on compliance metrics and remediation progress

#### Quarterly Security Review
```
Ask Claude: "Show me vulnerability trends for the last quarter"
```

This queries:
- `time_range`: "90d"
- Comprehensive trend analysis

### Response Format

```json
{
  "vulnerability_summary": {
    "time_range": "7d",
    "report_generated": "2024-01-16T15:00:00Z",
    "period_start": "2024-01-09T15:00:00Z",
    "period_end": "2024-01-16T15:00:00Z",
    "total_vulnerabilities": 156,
    "severity_breakdown": {
      "critical": {
        "count": 12,
        "percentage": 7.69,
        "trend": "increasing",
        "change_from_previous": "+3"
      },
      "high": {
        "count": 34,
        "percentage": 21.79,
        "trend": "stable",
        "change_from_previous": "-1"
      },
      "medium": {
        "count": 78,
        "percentage": 50.00,
        "trend": "decreasing",
        "change_from_previous": "-5"
      },
      "low": {
        "count": 32,
        "percentage": 20.51,
        "trend": "stable",
        "change_from_previous": "+1"
      }
    },
    "remediation_metrics": {
      "vulnerabilities_fixed": 23,
      "mean_time_to_fix": "12.5_days",
      "median_time_to_fix": "8_days",
      "fix_rate_percentage": 14.74,
      "sla_compliance": {
        "critical_24h": 83.33,
        "high_7d": 76.47,
        "medium_30d": 91.03
      }
    },
    "discovery_metrics": {
      "new_vulnerabilities": 18,
      "new_critical": 3,
      "new_high": 7,
      "discovery_rate_daily": 2.57,
      "top_affected_packages": [
        {
          "package": "openssl",
          "vulnerabilities": 5,
          "severity_max": "high"
        },
        {
          "package": "apache2", 
          "vulnerabilities": 3,
          "severity_max": "critical"
        }
      ]
    },
    "agent_exposure": {
      "agents_with_vulnerabilities": 45,
      "most_vulnerable_agents": [
        {
          "agent_id": "001",
          "agent_name": "web-server-01",
          "vulnerability_count": 23,
          "critical_count": 4
        },
        {
          "agent_id": "015",
          "agent_name": "db-server-03",
          "vulnerability_count": 19,
          "critical_count": 2
        }
      ],
      "vulnerability_density": 3.47
    },
    "compliance_indicators": {
      "pci_dss_compliance": 78.5,
      "hipaa_compliance": 82.1,
      "nist_compliance": 75.3,
      "overall_security_score": 78.6
    },
    "trending_threats": [
      {
        "cve_id": "CVE-2024-0001",
        "title": "Apache RCE",
        "trend_score": 95,
        "exploitation_increase": "300%"
      }
    ]
  }
}
```

### Key Metrics Explained

| Metric | Description | Target Value |
|--------|-------------|--------------|
| `fix_rate_percentage` | Percentage of vulnerabilities remediated | >15% monthly |
| `mean_time_to_fix` | Average time to remediate vulnerabilities | <14 days |
| `sla_compliance.critical_24h` | % of critical vulns fixed in 24h | >90% |
| `vulnerability_density` | Average vulnerabilities per agent | <5 per system |
| `overall_security_score` | Composite security posture score | >80% |

---

## 💡 Best Practices

### Vulnerability Management Strategy

1. **Prioritization Framework**: Use CVSS scores combined with business context
2. **Regular Scanning**: Implement continuous vulnerability assessment
3. **SLA Enforcement**: Maintain strict remediation timelines for critical issues
4. **Trend Monitoring**: Track vulnerability trends to identify systemic issues

### Performance Optimization

1. **Targeted Scanning**: Use agent_id filters for specific system analysis
2. **Appropriate Limits**: Balance comprehensiveness with query performance
3. **Time-Based Analysis**: Use appropriate time ranges for trend analysis

### Security Considerations

1. **Access Control**: Ensure proper permissions for vulnerability data access
2. **Information Security**: Vulnerability data is highly sensitive
3. **Remediation Tracking**: Maintain audit trails for all remediation activities
4. **Third-Party Intelligence**: Correlate with external threat feeds

---

## 🔧 Troubleshooting

### Common Issues

#### No Vulnerabilities Returned
```json
{
  "vulnerabilities": [],
  "error_context": "No vulnerability scanner configured or no scans completed"
}
```

**Solutions**:
- Verify vulnerability scanning is enabled in Wazuh configuration
- Check if vulnerability feeds are properly configured
- Ensure agents have vulnerability scanning modules active

#### Agent Not Found
```json
{
  "error": "Agent with ID '999' not found or has no vulnerability data",
  "error_code": "AGENT_NOT_FOUND"
}
```

**Solution**: Verify agent ID exists using `get_wazuh_agents`

#### Indexer Connection Issues
```json
{
  "error": "Cannot connect to Wazuh Indexer for vulnerability data",
  "error_code": "INDEXER_UNAVAILABLE"
}
```

**Solution**: Check Wazuh Indexer connectivity and credentials

### Data Quality Issues

1. **Outdated Vulnerability Data**: Ensure vulnerability feeds are regularly updated
2. **Missing Package Information**: Verify system inventory scanning is active
3. **Incomplete CVSS Data**: Some vulnerabilities may lack complete scoring information

### Performance Tips

1. **Batch Processing**: Use reasonable limits for large environments
2. **Filtering Strategy**: Use severity filters to focus on actionable items
3. **Caching**: Results are cached for 5 minutes to improve performance

---

**Next**: See [Security Analysis API](security-analysis.md) for threat analysis tools.