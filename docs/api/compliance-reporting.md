# Compliance & Reporting API

Complete reference for Wazuh compliance checking and security reporting tools. These tools provide comprehensive compliance assessment against major frameworks and automated generation of security reports for various stakeholders.

## Overview

The compliance and reporting tools offer two main capabilities:
- **Compliance Assessment**: Automated evaluation against security frameworks (PCI-DSS, HIPAA, SOX, GDPR, NIST)
- **Security Reporting**: Comprehensive security report generation for different audiences and timeframes

---

## 📋 run_compliance_check

Perform automated compliance assessment against established security frameworks and regulations.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `framework` | string | `"PCI-DSS"` | No | Compliance framework to evaluate against |
| `agent_id` | string | `null` | No | Specific agent to assess (if null, assesses entire environment) |

### Supported Frameworks

| Framework | Description | Key Requirements | Target Industries |
|-----------|-------------|------------------|-------------------|
| `PCI-DSS` | Payment Card Industry Data Security Standard | Card data protection, network security | E-commerce, retail, finance |
| `HIPAA` | Health Insurance Portability and Accountability Act | PHI protection, access controls | Healthcare, insurance |
| `SOX` | Sarbanes-Oxley Act | Financial reporting controls, audit trails | Public companies |
| `GDPR` | General Data Protection Regulation | Personal data protection, privacy rights | EU organizations |
| `NIST` | NIST Cybersecurity Framework | Identify, protect, detect, respond, recover | Government, critical infrastructure |
| `ISO27001` | Information Security Management | ISMS implementation, risk management | All industries |
| `FISMA` | Federal Information Security Management Act | Federal information systems security | US government agencies |

### Usage Examples

#### PCI-DSS Compliance Assessment
```
Ask Claude: "Run a PCI-DSS compliance check for the entire environment"
```

This queries:
- `framework`: "PCI-DSS"
- `agent_id`: null (entire environment)

#### HIPAA Compliance for Specific System
```
Ask Claude: "Check HIPAA compliance for agent web-server-01"
```

This queries:
- `framework`: "HIPAA"
- `agent_id`: "001"

#### NIST Framework Assessment
```
Ask Claude: "Evaluate our environment against NIST cybersecurity framework"
```

This queries:
- `framework`: "NIST"
- `agent_id`: null

### Response Format

```json
{
  "compliance_assessment": {
    "framework": "PCI-DSS",
    "version": "4.0",
    "assessment_scope": "environment",
    "assessment_timestamp": "2024-01-16T15:00:00Z",
    "overall_compliance": {
      "score": 78.5,
      "status": "partially_compliant",
      "confidence": 92,
      "requirements_met": 47,
      "requirements_total": 60,
      "compliance_percentage": 78.33
    },
    "requirement_categories": {
      "network_security": {
        "category_id": "1",
        "title": "Install and maintain network security controls",
        "score": 85,
        "status": "compliant",
        "requirements_met": 8,
        "requirements_total": 9,
        "critical_gaps": 0
      },
      "account_data_protection": {
        "category_id": "2",
        "title": "Apply secure configurations to all system components",
        "score": 72,
        "status": "partially_compliant",
        "requirements_met": 13,
        "requirements_total": 18,
        "critical_gaps": 2
      },
      "cardholder_data_protection": {
        "category_id": "3",
        "title": "Protect stored account data",
        "score": 65,
        "status": "partially_compliant",
        "requirements_met": 7,
        "requirements_total": 11,
        "critical_gaps": 1
      }
    },
    "detailed_findings": [
      {
        "finding_id": "PCI-3.2.1",
        "requirement": "3.2.1 Do not store sensitive authentication data after authorization",
        "status": "non_compliant",
        "severity": "critical",
        "risk_score": 95,
        "description": "Sensitive authentication data found in log files",
        "affected_systems": [
          {
            "agent_id": "001",
            "agent_name": "web-server-01",
            "evidence": [
              "CVV codes detected in application logs",
              "Full magnetic stripe data in debug logs"
            ]
          }
        ],
        "remediation": {
          "priority": "immediate",
          "timeline": "24-48 hours",
          "actions": [
            "Remove sensitive data from all log files",
            "Implement data masking for logging",
            "Update application code to prevent logging sensitive data",
            "Conduct thorough data inventory"
          ],
          "estimated_effort": "high"
        }
      },
      {
        "finding_id": "PCI-11.2.1",
        "requirement": "11.2.1 Perform quarterly internal vulnerability scans",
        "status": "compliant",
        "severity": "low",
        "risk_score": 25,
        "description": "Regular vulnerability scanning is active and current",
        "evidence": [
          "Last scan: 2024-01-15T10:00:00Z",
          "Scan frequency: Weekly",
          "Critical vulnerabilities: 0"
        ],
        "recommendations": [
          "Continue current scanning schedule",
          "Consider increasing scan frequency for critical systems"
        ]
      }
    ],
    "risk_assessment": {
      "overall_risk": "medium_high",
      "risk_factors": [
        {
          "factor": "sensitive_data_exposure",
          "risk_level": "critical",
          "impact": "severe",
          "likelihood": "high"
        },
        {
          "factor": "access_control_gaps",
          "risk_level": "high",
          "impact": "moderate",
          "likelihood": "medium"
        }
      ],
      "business_impact": {
        "regulatory_fines": "potential",
        "reputation_damage": "high",
        "business_disruption": "moderate",
        "financial_impact": "$50K - $500K"
      }
    },
    "remediation_roadmap": {
      "immediate_actions": [
        {
          "action": "Remove sensitive data from logs",
          "timeline": "24 hours",
          "priority": "critical",
          "owner": "Security Team"
        }
      ],
      "short_term": [
        {
          "action": "Implement comprehensive access logging",
          "timeline": "2 weeks",
          "priority": "high",
          "owner": "IT Operations"
        }
      ],
      "long_term": [
        {
          "action": "Deploy network segmentation",
          "timeline": "3 months",
          "priority": "medium",
          "owner": "Network Team"
        }
      ]
    },
    "compliance_trends": {
      "previous_assessment": {
        "date": "2023-12-16T15:00:00Z",
        "score": 72.1,
        "trend": "improving"
      },
      "score_change": "+6.4",
      "areas_improved": [
        "Network security controls",
        "Vulnerability management"
      ],
      "areas_declined": [
        "Data protection measures"
      ]
    }
  }
}
```

### Compliance Status Levels

| Status | Score Range | Description | Action Required |
|--------|-------------|-------------|-----------------|
| `compliant` | 90-100 | Meets all requirements | Maintain current controls |
| `mostly_compliant` | 80-89 | Minor gaps only | Address remaining issues |
| `partially_compliant` | 60-79 | Significant gaps exist | Remediation plan required |
| `non_compliant` | 0-59 | Major compliance failures | Immediate action required |

### Framework-Specific Insights

#### PCI-DSS Key Areas
- **Data Protection**: Encryption, tokenization, key management
- **Network Security**: Firewalls, network segmentation, secure protocols
- **Access Control**: Authentication, authorization, principle of least privilege
- **Monitoring**: Logging, monitoring, incident response

#### HIPAA Key Areas
- **Administrative Safeguards**: Security officer, training, access management
- **Physical Safeguards**: Facility access, workstation security, device controls
- **Technical Safeguards**: Access control, audit controls, integrity, encryption

#### NIST Framework Functions
- **Identify**: Asset management, risk assessment, governance
- **Protect**: Access control, data security, protective technology
- **Detect**: Anomaly detection, continuous monitoring
- **Respond**: Response planning, communications, analysis
- **Recover**: Recovery planning, improvements, communications

---

## 📊 generate_security_report

Generate comprehensive security reports tailored for different audiences and use cases.

### Parameters

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `report_type` | string | `"daily"` | No | Type of security report to generate |
| `include_recommendations` | boolean | `true` | No | Include actionable security recommendations |

### Report Types

| Type | Description | Audience | Frequency | Key Contents |
|------|-------------|----------|-----------|--------------|
| `daily` | Daily security briefing | Security team | Daily | Current threats, urgent actions, new alerts |
| `weekly` | Weekly summary report | Management | Weekly | Trends, metrics, major incidents, KPIs |
| `monthly` | Monthly comprehensive report | Executives | Monthly | Strategic overview, compliance status, ROI |
| `quarterly` | Quarterly strategic review | Board/Executives | Quarterly | Risk posture, compliance trends, investments |
| `incident` | Incident-specific report | All stakeholders | Ad-hoc | Detailed incident analysis, lessons learned |
| `compliance` | Compliance assessment report | Auditors/Executives | Quarterly | Framework adherence, gaps, remediation |
| `executive` | Executive dashboard summary | C-level | Weekly/Monthly | High-level metrics, business impact, decisions |

### Usage Examples

#### Daily Security Briefing
```
Ask Claude: "Generate a daily security report with recommendations"
```

This queries:
- `report_type`: "daily"
- `include_recommendations`: true

#### Executive Monthly Summary
```
Ask Claude: "Create a monthly executive security report"
```

This queries:
- `report_type`: "monthly"
- `include_recommendations`: true

#### Compliance Report
```
Ask Claude: "Generate a compliance-focused security report"
```

This queries:
- `report_type`: "compliance"
- `include_recommendations`: true

### Response Format

```json
{
  "security_report": {
    "report_metadata": {
      "report_type": "monthly",
      "report_title": "Monthly Security Posture Report - January 2024",
      "generated_timestamp": "2024-01-31T15:00:00Z",
      "report_period": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-31T23:59:59Z",
        "duration_days": 31
      },
      "audience": "executive",
      "classification": "confidential"
    },
    "executive_summary": {
      "overall_security_posture": "good",
      "security_score": 82,
      "trend": "improving",
      "key_achievements": [
        "95% reduction in critical vulnerabilities",
        "Successful SOC 2 Type II certification",
        "Zero security incidents with business impact"
      ],
      "major_concerns": [
        "Increasing sophisticated phishing attempts",
        "Cloud security configuration gaps",
        "Third-party vendor risk exposure"
      ],
      "business_impact": {
        "security_incidents": 0,
        "downtime_prevented": "12 hours",
        "estimated_loss_avoided": "$125,000",
        "compliance_status": "maintained"
      }
    },
    "threat_landscape_analysis": {
      "threat_summary": {
        "total_threats_detected": 15678,
        "critical_threats": 23,
        "threats_blocked": 15234,
        "success_rate": 97.2,
        "emerging_threats": 8
      },
      "attack_vectors": [
        {
          "vector": "email_phishing",
          "incidents": 234,
          "trend": "increasing",
          "success_rate": 2.1,
          "impact": "medium"
        },
        {
          "vector": "web_application_attacks",
          "incidents": 156,
          "trend": "stable",
          "success_rate": 0.0,
          "impact": "low"
        }
      ],
      "geographic_threat_distribution": {
        "top_source_countries": [
          {"country": "Unknown/TOR", "percentage": 34.2},
          {"country": "China", "percentage": 23.1},
          {"country": "Russia", "percentage": 18.7}
        ]
      },
      "threat_intelligence_insights": [
        "APT29 targeting financial services sector",
        "New ransomware variant detected in similar organizations",
        "Supply chain attacks increasing 300% year-over-year"
      ]
    },
    "vulnerability_management": {
      "vulnerability_summary": {
        "total_vulnerabilities": 156,
        "critical": 2,
        "high": 23,
        "medium": 89,
        "low": 42,
        "patching_sla_compliance": 94.2
      },
      "remediation_metrics": {
        "mean_time_to_patch": "8.5 days",
        "critical_patch_sla": "24 hours",
        "high_patch_sla": "7 days",
        "vulnerabilities_fixed": 78,
        "overdue_patches": 3
      },
      "top_vulnerability_categories": [
        {
          "category": "web_application",
          "count": 45,
          "trend": "decreasing"
        },
        {
          "category": "operating_system",
          "count": 67,
          "trend": "stable"
        }
      ]
    },
    "compliance_status": {
      "frameworks_assessed": [
        {
          "framework": "PCI-DSS",
          "score": 89.2,
          "status": "compliant",
          "last_assessment": "2024-01-15T10:00:00Z",
          "next_assessment": "2024-04-15T10:00:00Z"
        },
        {
          "framework": "SOC 2 Type II",
          "score": 95.8,
          "status": "certified",
          "certification_date": "2024-01-20T15:00:00Z",
          "expiry_date": "2025-01-20T15:00:00Z"
        }
      ],
      "audit_findings": {
        "total_findings": 8,
        "critical": 0,
        "high": 2,
        "medium": 4,
        "low": 2,
        "findings_resolved": 6
      }
    },
    "security_metrics": {
      "detection_metrics": {
        "mean_time_to_detect": "8.5 minutes",
        "mean_time_to_respond": "25 minutes",
        "mean_time_to_recover": "2.3 hours",
        "false_positive_rate": 3.2
      },
      "operational_metrics": {
        "security_events_processed": 2847293,
        "alerts_generated": 15678,
        "incidents_created": 23,
        "incidents_resolved": 23,
        "system_availability": 99.97
      },
      "team_performance": {
        "security_analyst_efficiency": 87,
        "automation_rate": 65,
        "training_completion": 95,
        "certification_compliance": 100
      }
    },
    "risk_assessment": {
      "overall_risk_score": 35,
      "risk_level": "low_medium",
      "risk_categories": {
        "cyber_threats": {
          "score": 25,
          "trend": "improving"
        },
        "compliance_risk": {
          "score": 15,
          "trend": "stable"
        },
        "operational_risk": {
          "score": 30,
          "trend": "improving"
        }
      },
      "top_risks": [
        {
          "risk": "Third-party vendor security",
          "score": 65,
          "mitigation": "Enhanced vendor assessment program"
        },
        {
          "risk": "Cloud misconfiguration",
          "score": 45,
          "mitigation": "Automated cloud security posture management"
        }
      ]
    },
    "financial_analysis": {
      "security_investments": {
        "total_budget": "$2,500,000",
        "spent_ytd": "$520,000",
        "budget_utilization": 20.8,
        "roi_estimate": "450%"
      },
      "cost_avoidance": {
        "incidents_prevented": 156,
        "estimated_savings": "$1,250,000",
        "downtime_avoided_hours": 48,
        "reputation_protection": "high"
      },
      "upcoming_investments": [
        {
          "project": "Zero Trust Architecture",
          "budget": "$750,000",
          "timeline": "Q2-Q4 2024",
          "expected_roi": "300%"
        }
      ]
    },
    "recommendations": [
      {
        "category": "strategic",
        "priority": "high",
        "title": "Implement Zero Trust Network Architecture",
        "description": "Deploy comprehensive zero trust security model to address evolving threat landscape",
        "business_justification": "Reduce breach risk by 60%, improve compliance posture",
        "timeline": "6 months",
        "budget_required": "$750,000",
        "expected_roi": "300%"
      },
      {
        "category": "operational",
        "priority": "medium",
        "title": "Enhance Third-Party Risk Management",
        "description": "Implement continuous vendor security monitoring and assessment",
        "business_justification": "Mitigate supply chain risks, ensure vendor compliance",
        "timeline": "3 months",
        "budget_required": "$150,000",
        "expected_roi": "200%"
      }
    ],
    "next_steps": {
      "immediate_actions": [
        "Review and approve zero trust architecture proposal",
        "Initiate third-party risk assessment program",
        "Schedule quarterly board security briefing"
      ],
      "upcoming_milestones": [
        {
          "milestone": "Q1 Security Assessment",
          "date": "2024-03-31",
          "description": "Comprehensive security posture review"
        },
        {
          "milestone": "SOC 2 Type II Renewal",
          "date": "2024-12-20",
          "description": "Annual certification renewal process"
        }
      ]
    },
    "appendices": {
      "detailed_metrics": "Available upon request",
      "technical_findings": "Available upon request",
      "vendor_assessments": "Available upon request",
      "compliance_evidence": "Available upon request"
    }
  }
}
```

### Report Customization Options

#### Daily Report Focus Areas
- **Immediate Threats**: Current active threats requiring attention
- **Alert Summary**: New alerts and their priorities
- **System Health**: Infrastructure status and performance
- **Action Items**: Specific tasks for security team

#### Weekly Report Focus Areas
- **Trend Analysis**: Week-over-week security metrics
- **Incident Review**: Detailed analysis of security incidents
- **Performance Metrics**: KPIs and operational effectiveness
- **Resource Utilization**: Team and tool performance

#### Monthly Report Focus Areas
- **Strategic Overview**: High-level security posture assessment
- **Compliance Status**: Framework adherence and audit results
- **ROI Analysis**: Security investment effectiveness
- **Risk Assessment**: Current risk landscape and mitigation

#### Executive Report Elements
- **Business Impact**: Security's effect on business operations
- **Financial Metrics**: Budget utilization and cost avoidance
- **Strategic Recommendations**: High-level security investments
- **Compliance Assurance**: Regulatory requirement adherence

---

## 💡 Best Practices

### Compliance Management Strategy

1. **Continuous Monitoring**: Implement ongoing compliance assessment
2. **Framework Mapping**: Map controls across multiple frameworks
3. **Risk-Based Approach**: Prioritize based on business risk
4. **Evidence Collection**: Maintain comprehensive audit trails

### Reporting Best Practices

1. **Audience Alignment**: Tailor content to audience needs and technical level
2. **Actionable Insights**: Focus on recommendations that drive improvement
3. **Trend Analysis**: Show progress over time with historical context
4. **Visual Elements**: Use charts and graphs for complex data (when supported)

### Compliance Optimization

1. **Control Harmonization**: Implement controls that satisfy multiple frameworks
2. **Automation Integration**: Use automated tools for continuous compliance
3. **Regular Assessment**: Conduct assessments quarterly or semi-annually
4. **Gap Remediation**: Prioritize compliance gaps by business impact

---

## 🔧 Troubleshooting

### Common Issues

#### Insufficient Compliance Data
```json
{
  "error": "Insufficient data for comprehensive compliance assessment",
  "error_code": "INSUFFICIENT_DATA",
  "recommendations": ["Enable additional logging", "Deploy missing monitoring tools"]
}
```

**Solution**: Ensure all required monitoring and logging components are active

#### Framework Not Supported
```json
{
  "error": "Compliance framework 'CUSTOM-FRAMEWORK' not supported",
  "error_code": "UNSUPPORTED_FRAMEWORK",
  "supported_frameworks": ["PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST"]
}
```

**Solution**: Use one of the supported frameworks or contact support for custom framework development

#### Report Generation Timeout
```json
{
  "error": "Report generation timeout - dataset too large",
  "error_code": "TIMEOUT",
  "suggestions": ["Reduce report scope", "Use agent-specific filtering"]
}
```

**Solution**: Narrow report scope or generate reports for specific time periods/agents

### Performance Optimization

1. **Scoped Assessments**: Use agent-specific assessments for large environments
2. **Incremental Reports**: Generate reports for specific time periods
3. **Caching Strategy**: Leverage cached compliance data when appropriate
4. **Parallel Processing**: Enable concurrent assessment of multiple frameworks

---

**Next**: See [Log Management API](log-management.md) for log analysis and search tools.