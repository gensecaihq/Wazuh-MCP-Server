# Security Analysis API

Complete reference for Wazuh AI-powered security analysis and threat intelligence tools. These tools provide advanced threat detection, risk assessment, pattern analysis, and comprehensive security reporting capabilities.

## Overview

The security analysis tools offer six main capabilities:
- **Threat Intelligence**: AI-powered analysis of security indicators (IPs, domains, hashes)
- **Risk Assessment**: Comprehensive security posture evaluation
- **Pattern Analysis**: Machine learning-based alert pattern detection
- **IOC Reputation**: Indicator of Compromise verification against multiple sources
- **Threat Ranking**: Identification and prioritization of top security threats
- **Security Reporting**: Automated generation of comprehensive security reports

---

## 🧠 analyze_security_threat

Perform AI-powered analysis of security threat indicators using machine learning and threat intelligence feeds.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `indicator` | string | - | **Yes** | The threat indicator to analyze |
| `indicator_type` | string | `"ip"` | No | Type of indicator to analyze |

### Indicator Types

| Type | Description | Examples | Analysis Focus |
|------|-------------|----------|----------------|
| `ip` | IP addresses | 192.168.1.100, 10.0.0.1 | Geolocation, reputation, network behavior |
| `domain` | Domain names | malicious.com, suspicious.org | DNS analysis, reputation, categorization |
| `hash` | File hashes | SHA256, MD5, SHA1 hashes | Malware analysis, file reputation |
| `url` | URLs | http://suspicious.com/path | URL categorization, threat classification |

### Usage Examples

#### IP Address Analysis
```
Ask Claude: "Analyze the security threat for IP address 203.0.113.15"
```

This queries:
- `indicator`: "203.0.113.15"
- `indicator_type`: "ip"

#### Domain Reputation Check
```
Ask Claude: "Analyze security threat for domain suspicious-site.com"
```

This queries:
- `indicator`: "suspicious-site.com"
- `indicator_type`: "domain"

#### File Hash Analysis
```
Ask Claude: "Analyze this file hash: a1b2c3d4e5f6..."
```

This queries:
- `indicator`: "a1b2c3d4e5f6..."
- `indicator_type`: "hash"

### Response Format

```json
{
  "threat_analysis": {
    "indicator": "203.0.113.15",
    "indicator_type": "ip",
    "analysis_timestamp": "2024-01-16T15:00:00Z",
    "threat_score": 85,
    "threat_level": "high",
    "confidence": 92,
    "summary": "High-risk IP address associated with multiple malicious activities",
    "details": {
      "geolocation": {
        "country": "Unknown",
        "region": "Unknown",
        "city": "Unknown",
        "isp": "Tor Network",
        "organization": "Anonymous Proxy"
      },
      "reputation_sources": [
        {
          "source": "VirusTotal",
          "verdict": "malicious",
          "score": 8,
          "last_analysis": "2024-01-16T12:00:00Z"
        },
        {
          "source": "AbuseIPDB",
          "verdict": "malicious",
          "abuse_confidence": 89,
          "last_reported": "2024-01-15T18:30:00Z"
        },
        {
          "source": "Shodan",
          "open_ports": [22, 80, 443, 8080],
          "services": ["ssh", "http", "https", "http-proxy"]
        }
      ],
      "threat_intelligence": {
        "known_campaigns": [
          "APT29 Infrastructure",
          "Cobalt Strike C2"
        ],
        "malware_families": [
          "Emotet",
          "TrickBot"
        ],
        "attack_types": [
          "Command and Control",
          "Data Exfiltration",
          "Lateral Movement"
        ]
      },
      "behavioral_analysis": {
        "connection_patterns": "High frequency, short duration connections",
        "traffic_anomalies": "Encrypted C2 traffic patterns detected",
        "temporal_patterns": "Active during off-hours (2-6 AM UTC)"
      }
    },
    "recommendations": [
      "Immediately block this IP address across all network security devices",
      "Review all historical connections to this IP for potential compromise",
      "Scan any systems that communicated with this IP for malware",
      "Implement enhanced monitoring for similar IP patterns"
    ],
    "related_indicators": [
      {
        "indicator": "malicious-domain.com",
        "type": "domain",
        "relationship": "resolves_to"
      },
      {
        "indicator": "198.51.100.25",
        "type": "ip",
        "relationship": "same_campaign"
      }
    ]
  }
}
```

### Threat Score Interpretation

| Score Range | Threat Level | Typical Action | Response Time |
|-------------|--------------|----------------|---------------|
| 90-100 | Critical | Block immediately, incident response | <1 hour |
| 70-89 | High | Block, investigate thoroughly | <4 hours |
| 50-69 | Medium | Monitor closely, limited blocking | <24 hours |
| 30-49 | Low | Log and monitor | <7 days |
| 0-29 | Informational | Baseline monitoring | Routine |

---

## ⚠️ perform_risk_assessment

Conduct comprehensive security risk assessment for specific agents or the entire environment.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `agent_id` | string | `null` | No | Specific agent to assess (if null, assesses entire environment) |

### Usage Examples

#### Environment-Wide Risk Assessment
```
Ask Claude: "Perform a comprehensive risk assessment of our security environment"
```

This queries:
- `agent_id`: null
- Assesses entire Wazuh-monitored infrastructure

#### Agent-Specific Risk Assessment
```
Ask Claude: "Assess the security risk for agent web-server-01"
```

This queries:
- `agent_id`: "001"
- Focuses on specific system assessment

### Response Format

```json
{
  "risk_assessment": {
    "scope": "environment",
    "assessment_timestamp": "2024-01-16T15:00:00Z",
    "overall_risk_score": 72,
    "risk_level": "medium_high",
    "confidence": 88,
    "executive_summary": "Environment shows elevated risk due to unpatched critical vulnerabilities and suspicious network activity",
    "risk_categories": {
      "vulnerability_risk": {
        "score": 85,
        "level": "high",
        "critical_vulns": 12,
        "high_vulns": 34,
        "unpatched_days_avg": 18.5,
        "internet_facing_vulns": 8
      },
      "threat_exposure": {
        "score": 68,
        "level": "medium_high",
        "active_threats": 5,
        "suspicious_connections": 23,
        "malware_detections": 2,
        "c2_communications": 1
      },
      "configuration_risk": {
        "score": 45,
        "level": "medium",
        "misconfigurations": 15,
        "weak_passwords": 3,
        "unnecessary_services": 8,
        "missing_patches": 42
      },
      "compliance_risk": {
        "score": 35,
        "level": "low_medium",
        "pci_dss_gaps": 2,
        "hipaa_gaps": 1,
        "nist_gaps": 5,
        "audit_findings": 8
      }
    },
    "critical_findings": [
      {
        "finding_id": "CRIT-001",
        "category": "vulnerability",
        "severity": "critical",
        "title": "Internet-facing Apache server with RCE vulnerability",
        "description": "CVE-2024-0001 affects 3 internet-facing web servers",
        "risk_score": 95,
        "affected_agents": ["001", "003", "007"],
        "remediation": "Immediate patching required within 24 hours"
      },
      {
        "finding_id": "CRIT-002", 
        "category": "threat",
        "severity": "high",
        "title": "Active C2 communication detected",
        "description": "Agent 005 communicating with known malicious IP",
        "risk_score": 88,
        "affected_agents": ["005"],
        "remediation": "Isolate system and perform forensic analysis"
      }
    ],
    "risk_trends": {
      "7_day_trend": "increasing",
      "30_day_trend": "stable",
      "risk_velocity": "+12 points/week",
      "improvement_areas": [
        "Vulnerability management",
        "Network segmentation",
        "Endpoint protection"
      ]
    },
    "mitigation_priorities": [
      {
        "priority": 1,
        "action": "Patch critical vulnerabilities on internet-facing systems",
        "impact": "High",
        "effort": "Medium", 
        "timeline": "24-48 hours"
      },
      {
        "priority": 2,
        "action": "Investigate and remediate C2 communication",
        "impact": "High",
        "effort": "High",
        "timeline": "Immediate"
      },
      {
        "priority": 3,
        "action": "Implement network segmentation for high-risk systems",
        "impact": "Medium",
        "effort": "High",
        "timeline": "1-2 weeks"
      }
    ]
  }
}
```

---

## 🔍 analyze_alert_patterns

Use machine learning to identify patterns, trends, and anomalies in security alerts.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `time_range` | string | `"24h"` | No | Time range for pattern analysis |
| `min_frequency` | integer | `5` | No | Minimum frequency for pattern detection |

### Usage Examples

#### Daily Pattern Analysis
```
Ask Claude: "Analyze security alert patterns from the last 24 hours"
```

#### Weekly Anomaly Detection
```
Ask Claude: "Find unusual alert patterns from the past week with minimum 10 occurrences"
```

This queries:
- `time_range`: "7d"
- `min_frequency`: 10

### Response Format

```json
{
  "pattern_analysis": {
    "analysis_period": "24h",
    "analysis_timestamp": "2024-01-16T15:00:00Z",
    "total_alerts_analyzed": 1247,
    "patterns_detected": 8,
    "anomalies_found": 3,
    "confidence_score": 87,
    "detected_patterns": [
      {
        "pattern_id": "PATTERN-001",
        "pattern_type": "temporal_clustering",
        "confidence": 94,
        "frequency": 45,
        "severity": "high",
        "title": "SSH Brute Force Attack Waves",
        "description": "Coordinated SSH login attempts occurring in 15-minute intervals",
        "details": {
          "time_windows": ["02:00-03:00 UTC", "14:00-15:00 UTC"],
          "affected_agents": ["001", "003", "005", "007"],
          "source_ips": ["198.51.100.10", "203.0.113.25"],
          "attack_vector": "SSH brute force",
          "success_rate": "0%",
          "total_attempts": 2340
        },
        "ml_analysis": {
          "pattern_strength": 0.89,
          "likelihood_coordinated": 0.95,
          "campaign_indicators": [
            "Synchronized timing",
            "Common source networks",
            "Similar credential patterns"
          ]
        },
        "recommendations": [
          "Implement rate limiting on SSH service",
          "Block source IP ranges",
          "Enable fail2ban or similar protection"
        ]
      },
      {
        "pattern_id": "PATTERN-002",
        "pattern_type": "behavioral_anomaly",
        "confidence": 82,
        "frequency": 23,
        "severity": "medium",
        "title": "Unusual File Access Patterns",
        "description": "Abnormal file access times and locations detected",
        "details": {
          "affected_agents": ["009"],
          "file_patterns": ["/etc/passwd", "/etc/shadow", "/home/*/.ssh/*"],
          "access_times": ["03:45 UTC", "04:12 UTC", "04:33 UTC"],
          "user_accounts": ["backup", "maintenance"],
          "anomaly_score": 78
        },
        "recommendations": [
          "Review user account activities",
          "Implement file integrity monitoring",
          "Check for privilege escalation"
        ]
      }
    ],
    "anomalies": [
      {
        "anomaly_id": "ANOM-001",
        "type": "volume_spike",
        "severity": "high",
        "description": "300% increase in authentication failures",
        "time_period": "14:00-15:00 UTC",
        "baseline": 15,
        "observed": 67,
        "deviation_score": 3.4
      }
    ],
    "trending_indicators": {
      "increasing_threats": [
        "SSH brute force attacks",
        "Web application scanning"
      ],
      "decreasing_threats": [
        "Malware detections",
        "DDoS attempts"
      ],
      "emerging_patterns": [
        "Off-hours administrative access",
        "Unusual network reconnaissance"
      ]
    }
  }
}
```

---

## 🔍 check_ioc_reputation

Check reputation of Indicators of Compromise (IoCs) against multiple threat intelligence sources.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `indicator` | string | - | **Yes** | The IoC to check |
| `indicator_type` | string | `"ip"` | No | Type of indicator |

### Usage Examples

#### IP Reputation Check
```
Ask Claude: "Check the reputation of IP address 198.51.100.15"
```

#### Domain Reputation Check
```
Ask Claude: "Check reputation for domain malicious.example.com"
```

### Response Format

```json
{
  "ioc_reputation": {
    "indicator": "198.51.100.15",
    "indicator_type": "ip",
    "check_timestamp": "2024-01-16T15:00:00Z",
    "overall_verdict": "malicious",
    "confidence": 95,
    "reputation_score": 15,
    "source_consensus": {
      "malicious": 8,
      "suspicious": 2,
      "clean": 1,
      "unknown": 2
    },
    "detailed_results": [
      {
        "source": "VirusTotal",
        "verdict": "malicious",
        "detection_ratio": "8/89",
        "last_analysis": "2024-01-16T12:00:00Z",
        "categories": ["malware", "c2"]
      },
      {
        "source": "AbuseIPDB",
        "verdict": "malicious",
        "abuse_confidence": 89,
        "reports_count": 156,
        "last_reported": "2024-01-15T22:15:00Z"
      }
    ],
    "threat_context": {
      "known_campaigns": ["APT29", "Cobalt Strike"],
      "malware_families": ["Emotet", "TrickBot"],
      "first_seen": "2023-11-15T10:30:00Z",
      "last_seen": "2024-01-16T14:45:00Z"
    },
    "recommendations": [
      "Block indicator immediately",
      "Search for related indicators",
      "Review historical connections"
    ]
  }
}
```

---

## 🎯 get_top_security_threats

Identify and rank the most significant security threats based on alert frequency, severity, and impact.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `limit` | integer | `10` | No | Number of top threats to retrieve |
| `time_range` | string | `"24h"` | No | Time range for threat analysis |

### Usage Examples

#### Security Dashboard
```
Ask Claude: "Show me the top 5 security threats in the last 24 hours"
```

#### Weekly Threat Intelligence
```
Ask Claude: "What are the top 15 security threats from this week?"
```

### Response Format

```json
{
  "top_security_threats": {
    "analysis_period": "24h",
    "threats_analyzed": 1247,
    "ranking_timestamp": "2024-01-16T15:00:00Z",
    "ranking_criteria": ["frequency", "severity", "impact", "trend"],
    "threats": [
      {
        "rank": 1,
        "threat_id": "THREAT-001",
        "threat_name": "SSH Brute Force Campaign",
        "threat_score": 92,
        "severity": "high",
        "frequency": 245,
        "affected_systems": 12,
        "description": "Coordinated SSH brute force attacks targeting multiple servers",
        "indicators": {
          "source_ips": ["198.51.100.10", "203.0.113.25"],
          "target_ports": [22],
          "attack_patterns": ["credential_stuffing", "dictionary_attack"]
        },
        "impact_assessment": {
          "confidentiality": "medium",
          "integrity": "low", 
          "availability": "high",
          "business_impact": "medium"
        },
        "timeline": {
          "first_detected": "2024-01-16T02:00:00Z",
          "peak_activity": "2024-01-16T14:30:00Z",
          "current_status": "ongoing"
        },
        "mitigation_status": {
          "blocking_active": true,
          "rate_limiting": true,
          "monitoring_enhanced": true
        }
      }
    ]
  }
}
```

---

## 📋 generate_security_report

Generate comprehensive security reports for various stakeholders and timeframes.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `report_type` | string | `"daily"` | No | Type of security report to generate |
| `include_recommendations` | boolean | `true` | No | Include security recommendations |

### Report Types

| Type | Description | Audience | Contents |
|------|-------------|----------|----------|
| `daily` | Daily security briefing | Security team | Current threats, new alerts, urgent actions |
| `weekly` | Weekly summary report | Management | Trends, metrics, major incidents |
| `monthly` | Monthly comprehensive report | Executives | Strategic overview, compliance, investments |
| `incident` | Incident-specific report | All stakeholders | Detailed incident analysis and response |

### Usage Examples

#### Daily Security Briefing
```
Ask Claude: "Generate a daily security report with recommendations"
```

#### Executive Monthly Report
```
Ask Claude: "Create a monthly security report for executive review"
```

### Response Format

```json
{
  "security_report": {
    "report_type": "daily",
    "report_date": "2024-01-16",
    "generated_timestamp": "2024-01-16T15:00:00Z",
    "report_period": "2024-01-15T15:00:00Z to 2024-01-16T15:00:00Z",
    "executive_summary": {
      "overall_security_status": "elevated",
      "key_findings": [
        "12 critical vulnerabilities require immediate attention",
        "Active SSH brute force campaign detected and mitigated",
        "Network segmentation improvements needed"
      ],
      "threat_level": "medium_high",
      "recommendations_count": 8
    },
    "threat_landscape": {
      "total_alerts": 1247,
      "critical_alerts": 23,
      "high_priority_alerts": 89,
      "new_threats_detected": 3,
      "blocked_attacks": 156,
      "trend_analysis": "Increasing attack volume, stable threat sophistication"
    },
    "vulnerability_status": {
      "critical_vulnerabilities": 12,
      "new_vulnerabilities": 5,
      "patched_vulnerabilities": 8,
      "overdue_patches": 15,
      "compliance_score": 78.5
    },
    "incident_summary": {
      "new_incidents": 2,
      "ongoing_incidents": 1,
      "resolved_incidents": 3,
      "mean_resolution_time": "4.2 hours"
    },
    "recommendations": [
      {
        "priority": "critical",
        "category": "vulnerability_management",
        "title": "Patch Critical Apache RCE Vulnerability",
        "description": "CVE-2024-0001 affects 3 internet-facing servers",
        "timeline": "Within 24 hours",
        "effort": "Medium"
      }
    ],
    "metrics": {
      "security_score": 72,
      "compliance_percentage": 85.3,
      "mean_time_to_detect": "12 minutes",
      "mean_time_to_respond": "35 minutes"
    }
  }
}
```

---

## 💡 Best Practices

### Threat Analysis Strategy

1. **Multi-Source Validation**: Use multiple threat intelligence sources for verification
2. **Context Awareness**: Consider business context when assessing threats
3. **Automated Response**: Implement automated blocking for confirmed threats
4. **Historical Analysis**: Track threat evolution over time

### Risk Assessment Approach

1. **Regular Assessments**: Conduct risk assessments at least monthly
2. **Agent-Specific Focus**: Perform detailed assessments on critical systems
3. **Trend Monitoring**: Track risk score changes over time
4. **Mitigation Tracking**: Monitor effectiveness of implemented controls

### Pattern Analysis Optimization

1. **Appropriate Time Windows**: Match analysis periods to threat types
2. **Frequency Thresholds**: Set meaningful minimum frequencies
3. **False Positive Management**: Tune patterns to reduce noise
4. **Continuous Learning**: Regularly update pattern detection algorithms

---

## 🔧 Troubleshooting

### Common Issues

#### AI Analysis Unavailable
```json
{
  "error": "AI analysis service unavailable - using basic reputation only",
  "error_code": "AI_SERVICE_DOWN"
}
```

**Solution**: Basic reputation checking continues; AI features temporarily limited

#### External API Limits
```json
{
  "error": "External threat intelligence API rate limit exceeded",
  "error_code": "RATE_LIMIT_EXCEEDED"
}
```

**Solution**: Results may be cached or limited to available sources

#### Insufficient Data
```json
{
  "error": "Insufficient historical data for pattern analysis",
  "error_code": "INSUFFICIENT_DATA"
}
```

**Solution**: Increase time range or reduce minimum frequency thresholds

---

**Next**: See [System Monitoring API](system-monitoring.md) for infrastructure monitoring tools.