"""Compliance analysis for various security frameworks."""

from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, Counter
import sys
import os

# Clean imports within the package
from wazuh_mcp_server.config import ComplianceFramework
from wazuh_mcp_server.utils.logging import get_logger

logger = get_logger(__name__)


class ComplianceStatus(Enum):
    """Compliance status levels."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


@dataclass
class ComplianceRequirement:
    """Individual compliance requirement."""
    id: str
    title: str
    description: str
    framework: ComplianceFramework
    status: ComplianceStatus
    score: float  # 0-100
    evidence: List[str]
    gaps: List[str]
    recommendations: List[str]


@dataclass
class ComplianceReport:
    """Comprehensive compliance assessment report."""
    framework: ComplianceFramework
    overall_score: float
    status: ComplianceStatus
    requirements: List[ComplianceRequirement]
    summary: Dict[str, Any]
    recommendations: List[str]
    timestamp: datetime


class ComplianceAnalyzer:
    """Comprehensive compliance analysis engine."""
    
    def __init__(self, client_manager=None):
        self.logger = get_logger(__name__)
        self.client_manager = client_manager
        self.framework_requirements = self._initialize_requirements()
    
    def _initialize_requirements(self) -> Dict[ComplianceFramework, List[Dict[str, Any]]]:
        """Initialize compliance requirements for each framework."""
        return {
            ComplianceFramework.PCI_DSS: self._get_pci_dss_requirements(),
            ComplianceFramework.HIPAA: self._get_hipaa_requirements(),
            ComplianceFramework.GDPR: self._get_gdpr_requirements(),
            ComplianceFramework.NIST: self._get_nist_requirements(),
            ComplianceFramework.ISO27001: self._get_iso27001_requirements(),
        }
    
    def assess_compliance(
        self,
        framework: ComplianceFramework,
        alerts: List[Dict[str, Any]],
        agents: List[Dict[str, Any]],
        vulnerabilities: Optional[List[Dict[str, Any]]] = None
    ) -> ComplianceReport:
        """Perform comprehensive compliance assessment."""
        
        requirements = self.framework_requirements.get(framework, [])
        assessed_requirements = []
        
        for req_template in requirements:
            requirement = self._assess_requirement(
                req_template, alerts, agents, vulnerabilities
            )
            assessed_requirements.append(requirement)
        
        # Calculate overall score and status
        overall_score = self._calculate_overall_score(assessed_requirements)
        overall_status = self._determine_overall_status(overall_score)
        
        # Generate summary and recommendations
        summary = self._generate_summary(assessed_requirements)
        recommendations = self._generate_framework_recommendations(framework, assessed_requirements)
        
        return ComplianceReport(
            framework=framework,
            overall_score=overall_score,
            status=overall_status,
            requirements=assessed_requirements,
            summary=summary,
            recommendations=recommendations,
            timestamp=datetime.utcnow()
        )
    
    def _assess_requirement(
        self,
        req_template: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        agents: List[Dict[str, Any]],
        vulnerabilities: Optional[List[Dict[str, Any]]]
    ) -> ComplianceRequirement:
        """Assess individual compliance requirement."""
        
        req_id = req_template["id"]
        assessment_method = req_template.get("assessment_method", "default")
        
        if assessment_method == "alert_analysis":
            return self._assess_via_alerts(req_template, alerts)
        elif assessment_method == "agent_analysis":
            return self._assess_via_agents(req_template, agents)
        elif assessment_method == "vulnerability_analysis":
            return self._assess_via_vulnerabilities(req_template, vulnerabilities or [])
        elif assessment_method == "combined_analysis":
            return self._assess_combined(req_template, alerts, agents, vulnerabilities or [])
        else:
            return self._assess_default(req_template)
    
    def _assess_via_alerts(self, req_template: Dict[str, Any], alerts: List[Dict[str, Any]]) -> ComplianceRequirement:
        """Assess requirement based on alert analysis."""
        req_id = req_template["id"]
        criteria = req_template.get("criteria", {})
        
        evidence = []
        gaps = []
        score = 0
        
        # Analyze alerts based on criteria
        if "forbidden_rules" in criteria:
            forbidden_count = 0
            for alert in alerts:
                rule_id = alert.get("rule", {}).get("id")
                if rule_id in criteria["forbidden_rules"]:
                    forbidden_count += 1
                    gaps.append(f"Detected forbidden activity: Rule {rule_id}")
            
            if forbidden_count == 0:
                score += 40
                evidence.append("No forbidden activities detected")
            else:
                gaps.append(f"{forbidden_count} instances of forbidden activities")
        
        if "required_monitoring" in criteria:
            monitoring_rules = criteria["required_monitoring"]
            detected_rules = set()
            
            for alert in alerts:
                rule_id = alert.get("rule", {}).get("id")
                if rule_id in monitoring_rules:
                    detected_rules.add(rule_id)
            
            coverage = len(detected_rules) / len(monitoring_rules) if monitoring_rules else 1.0
            score += coverage * 60
            
            if coverage > 0.8:
                evidence.append(f"Good monitoring coverage: {coverage:.1%}")
            else:
                gaps.append(f"Insufficient monitoring coverage: {coverage:.1%}")
        
        # Determine status
        if score >= 90:
            status = ComplianceStatus.COMPLIANT
        elif score >= 70:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceRequirement(
            id=req_id,
            title=req_template["title"],
            description=req_template["description"],
            framework=req_template["framework"],
            status=status,
            score=min(score, 100),
            evidence=evidence,
            gaps=gaps,
            recommendations=req_template.get("recommendations", [])
        )
    
    def _assess_via_agents(self, req_template: Dict[str, Any], agents: List[Dict[str, Any]]) -> ComplianceRequirement:
        """Assess requirement based on agent analysis."""
        req_id = req_template["id"]
        criteria = req_template.get("criteria", {})
        
        evidence = []
        gaps = []
        score = 0
        
        if not agents:
            return ComplianceRequirement(
                id=req_id,
                title=req_template["title"],
                description=req_template["description"],
                framework=req_template["framework"],
                status=ComplianceStatus.UNKNOWN,
                score=0,
                evidence=[],
                gaps=["No agent data available"],
                recommendations=req_template.get("recommendations", [])
            )
        
        # Analyze agent health and coverage
        active_agents = [a for a in agents if a.get("status") == "active"]
        coverage = len(active_agents) / len(agents) if agents else 0
        
        if coverage >= 0.95:
            score += 50
            evidence.append(f"Excellent agent coverage: {coverage:.1%}")
        elif coverage >= 0.8:
            score += 30
            evidence.append(f"Good agent coverage: {coverage:.1%}")
        else:
            score += 10
            gaps.append(f"Poor agent coverage: {coverage:.1%}")
        
        # Check for required agent configurations
        if "required_os_coverage" in criteria:
            required_os = set(criteria["required_os_coverage"])
            detected_os = set()
            
            for agent in agents:
                os_platform = agent.get("os", {}).get("platform", "").lower()
                if os_platform:
                    detected_os.add(os_platform)
            
            os_coverage = len(detected_os.intersection(required_os)) / len(required_os) if required_os else 1.0
            score += os_coverage * 50
            
            if os_coverage == 1.0:
                evidence.append("All required OS platforms covered")
            else:
                missing_os = required_os - detected_os
                gaps.append(f"Missing OS coverage: {', '.join(missing_os)}")
        
        # Determine status
        if score >= 90:
            status = ComplianceStatus.COMPLIANT
        elif score >= 70:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceRequirement(
            id=req_id,
            title=req_template["title"],
            description=req_template["description"],
            framework=req_template["framework"],
            status=status,
            score=min(score, 100),
            evidence=evidence,
            gaps=gaps,
            recommendations=req_template.get("recommendations", [])
        )
    
    def _assess_via_vulnerabilities(self, req_template: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]) -> ComplianceRequirement:
        """Assess requirement based on vulnerability analysis."""
        req_id = req_template["id"]
        criteria = req_template.get("criteria", {})
        
        evidence = []
        gaps = []
        score = 100  # Start with full score, deduct for issues
        
        if not vulnerabilities:
            evidence.append("No vulnerabilities detected")
            return ComplianceRequirement(
                id=req_id,
                title=req_template["title"],
                description=req_template["description"],
                framework=req_template["framework"],
                status=ComplianceStatus.COMPLIANT,
                score=score,
                evidence=evidence,
                gaps=gaps,
                recommendations=req_template.get("recommendations", [])
            )
        
        # Analyze vulnerability severity distribution
        severity_count = Counter()
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown").lower()
            severity_count[severity] += 1
        
        # Deduct points based on severity
        critical_vulns = severity_count.get("critical", 0)
        high_vulns = severity_count.get("high", 0)
        medium_vulns = severity_count.get("medium", 0)
        
        score -= critical_vulns * 20  # 20 points per critical
        score -= high_vulns * 10     # 10 points per high
        score -= medium_vulns * 5    # 5 points per medium
        
        score = max(score, 0)
        
        if critical_vulns > 0:
            gaps.append(f"{critical_vulns} critical vulnerabilities found")
        if high_vulns > 0:
            gaps.append(f"{high_vulns} high severity vulnerabilities found")
        
        if score >= 90:
            status = ComplianceStatus.COMPLIANT
            evidence.append("Vulnerability levels within acceptable limits")
        elif score >= 70:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceRequirement(
            id=req_id,
            title=req_template["title"],
            description=req_template["description"],
            framework=req_template["framework"],
            status=status,
            score=score,
            evidence=evidence,
            gaps=gaps,
            recommendations=req_template.get("recommendations", [])
        )
    
    def _assess_combined(
        self,
        req_template: Dict[str, Any],
        alerts: List[Dict[str, Any]],
        agents: List[Dict[str, Any]],
        vulnerabilities: List[Dict[str, Any]]
    ) -> ComplianceRequirement:
        """Assess requirement using combined analysis."""
        # This is a simplified combined assessment
        # In practice, this would be more sophisticated
        
        alert_req = self._assess_via_alerts(req_template, alerts)
        agent_req = self._assess_via_agents(req_template, agents)
        vuln_req = self._assess_via_vulnerabilities(req_template, vulnerabilities)
        
        # Weighted average
        combined_score = (alert_req.score * 0.4) + (agent_req.score * 0.3) + (vuln_req.score * 0.3)
        
        # Combine evidence and gaps
        evidence = alert_req.evidence + agent_req.evidence + vuln_req.evidence
        gaps = alert_req.gaps + agent_req.gaps + vuln_req.gaps
        
        # Determine worst status
        statuses = [alert_req.status, agent_req.status, vuln_req.status]
        if ComplianceStatus.NON_COMPLIANT in statuses:
            status = ComplianceStatus.NON_COMPLIANT
        elif ComplianceStatus.PARTIALLY_COMPLIANT in statuses:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            status = ComplianceStatus.COMPLIANT
        
        return ComplianceRequirement(
            id=req_template["id"],
            title=req_template["title"],
            description=req_template["description"],
            framework=req_template["framework"],
            status=status,
            score=combined_score,
            evidence=evidence,
            gaps=gaps,
            recommendations=req_template.get("recommendations", [])
        )
    
    def _assess_default(self, req_template: Dict[str, Any]) -> ComplianceRequirement:
        """Default assessment when no specific method is available."""
        return ComplianceRequirement(
            id=req_template["id"],
            title=req_template["title"],
            description=req_template["description"],
            framework=req_template["framework"],
            status=ComplianceStatus.NOT_APPLICABLE,
            score=0,
            evidence=[],
            gaps=["Assessment method not implemented"],
            recommendations=req_template.get("recommendations", [])
        )
    
    def _calculate_overall_score(self, requirements: List[ComplianceRequirement]) -> float:
        """Calculate overall compliance score."""
        if not requirements:
            return 0.0
        
        total_score = sum(req.score for req in requirements)
        return round(total_score / len(requirements), 2)
    
    def _determine_overall_status(self, score: float) -> ComplianceStatus:
        """Determine overall compliance status."""
        if score >= 90:
            return ComplianceStatus.COMPLIANT
        elif score >= 70:
            return ComplianceStatus.PARTIALLY_COMPLIANT
        else:
            return ComplianceStatus.NON_COMPLIANT
    
    def _generate_summary(self, requirements: List[ComplianceRequirement]) -> Dict[str, Any]:
        """Generate compliance summary statistics."""
        status_count = Counter(req.status for req in requirements)
        
        return {
            "total_requirements": len(requirements),
            "compliant": status_count[ComplianceStatus.COMPLIANT],
            "partially_compliant": status_count[ComplianceStatus.PARTIALLY_COMPLIANT],
            "non_compliant": status_count[ComplianceStatus.NON_COMPLIANT],
            "not_applicable": status_count[ComplianceStatus.NOT_APPLICABLE],
            "unknown": status_count[ComplianceStatus.UNKNOWN],
            "compliance_percentage": round(
                (status_count[ComplianceStatus.COMPLIANT] / len(requirements) * 100) if requirements else 0, 1
            )
        }
    
    def _generate_framework_recommendations(
        self,
        framework: ComplianceFramework,
        requirements: List[ComplianceRequirement]
    ) -> List[str]:
        """Generate framework-specific recommendations."""
        recommendations = []
        
        # Add recommendations from non-compliant requirements
        for req in requirements:
            if req.status in [ComplianceStatus.NON_COMPLIANT, ComplianceStatus.PARTIALLY_COMPLIANT]:
                recommendations.extend(req.recommendations)
        
        # Add framework-specific general recommendations
        if framework == ComplianceFramework.PCI_DSS:
            recommendations.extend([
                "Implement network segmentation for cardholder data environment",
                "Regularly update and patch systems handling cardholder data",
                "Implement strong access controls and authentication"
            ])
        elif framework == ComplianceFramework.HIPAA:
            recommendations.extend([
                "Implement comprehensive data encryption for PHI",
                "Establish audit trails for all PHI access",
                "Conduct regular risk assessments"
            ])
        elif framework == ComplianceFramework.GDPR:
            recommendations.extend([
                "Implement data protection by design and by default",
                "Establish procedures for data subject rights",
                "Conduct privacy impact assessments"
            ])
        
        return list(set(recommendations))  # Remove duplicates
    
    # Framework-specific requirements definitions
    def _get_pci_dss_requirements(self) -> List[Dict[str, Any]]:
        """Get PCI DSS compliance requirements."""
        return [
            {
                "id": "PCI-1.1",
                "title": "Firewall Configuration Standards",
                "description": "Install and maintain a firewall configuration to protect cardholder data",
                "framework": ComplianceFramework.PCI_DSS,
                "assessment_method": "alert_analysis",
                "criteria": {
                    "required_monitoring": ["5710", "5711", "5712"],  # Firewall rules
                    "forbidden_rules": ["17151", "17152"]  # Firewall bypass attempts
                },
                "recommendations": [
                    "Review firewall rules quarterly",
                    "Document all firewall changes"
                ]
            },
            {
                "id": "PCI-2.1",
                "title": "Default Passwords and Security Parameters",
                "description": "Change vendor-supplied defaults for system passwords and security parameters",
                "framework": ComplianceFramework.PCI_DSS,
                "assessment_method": "alert_analysis",
                "criteria": {
                    "forbidden_rules": ["5710", "5503"]  # Default password usage
                },
                "recommendations": [
                    "Change all default passwords",
                    "Remove default accounts"
                ]
            },
            {
                "id": "PCI-10.1",
                "title": "Audit Trail Implementation",
                "description": "Implement audit trails to link all access to system components",
                "framework": ComplianceFramework.PCI_DSS,
                "assessment_method": "agent_analysis",
                "criteria": {
                    "required_os_coverage": ["windows", "linux"]
                },
                "recommendations": [
                    "Enable comprehensive logging",
                    "Implement log correlation"
                ]
            },
            {
                "id": "PCI-11.2",
                "title": "Vulnerability Scanning",
                "description": "Run internal and external network vulnerability scans regularly",
                "framework": ComplianceFramework.PCI_DSS,
                "assessment_method": "vulnerability_analysis",
                "criteria": {},
                "recommendations": [
                    "Perform quarterly vulnerability scans",
                    "Remediate high-risk vulnerabilities promptly"
                ]
            }
        ]
    
    def _get_hipaa_requirements(self) -> List[Dict[str, Any]]:
        """Get HIPAA compliance requirements."""
        return [
            {
                "id": "HIPAA-164.308",
                "title": "Administrative Safeguards",
                "description": "Implement administrative safeguards for PHI",
                "framework": ComplianceFramework.HIPAA,
                "assessment_method": "combined_analysis",
                "criteria": {},
                "recommendations": [
                    "Designate security officer",
                    "Implement workforce training"
                ]
            },
            {
                "id": "HIPAA-164.310",
                "title": "Physical Safeguards",
                "description": "Implement physical safeguards for PHI systems",
                "framework": ComplianceFramework.HIPAA,
                "assessment_method": "agent_analysis",
                "criteria": {},
                "recommendations": [
                    "Implement physical access controls",
                    "Secure workstation use procedures"
                ]
            },
            {
                "id": "HIPAA-164.312",
                "title": "Technical Safeguards",
                "description": "Implement technical safeguards for PHI",
                "framework": ComplianceFramework.HIPAA,
                "assessment_method": "alert_analysis",
                "criteria": {
                    "required_monitoring": ["5715", "5716"],  # Access control rules
                    "forbidden_rules": ["5720", "5721"]  # Unauthorized access
                },
                "recommendations": [
                    "Implement access controls",
                    "Enable audit controls",
                    "Encrypt PHI data"
                ]
            }
        ]
    
    def _get_gdpr_requirements(self) -> List[Dict[str, Any]]:
        """Get GDPR compliance requirements."""
        return [
            {
                "id": "GDPR-25",
                "title": "Data Protection by Design and Default",
                "description": "Implement data protection by design and by default",
                "framework": ComplianceFramework.GDPR,
                "assessment_method": "combined_analysis",
                "criteria": {},
                "recommendations": [
                    "Implement privacy by design",
                    "Minimize data collection"
                ]
            },
            {
                "id": "GDPR-32",
                "title": "Security of Processing",
                "description": "Implement appropriate security measures for personal data",
                "framework": ComplianceFramework.GDPR,
                "assessment_method": "vulnerability_analysis",
                "criteria": {},
                "recommendations": [
                    "Implement encryption",
                    "Ensure data integrity",
                    "Test security measures regularly"
                ]
            }
        ]
    
    def _get_nist_requirements(self) -> List[Dict[str, Any]]:
        """Get NIST Cybersecurity Framework requirements."""
        return [
            {
                "id": "NIST-ID.AM",
                "title": "Asset Management",
                "description": "Identify and manage assets",
                "framework": ComplianceFramework.NIST,
                "assessment_method": "agent_analysis",
                "criteria": {},
                "recommendations": [
                    "Maintain asset inventory",
                    "Classify information systems"
                ]
            },
            {
                "id": "NIST-PR.AC",
                "title": "Access Control",
                "description": "Limit access to assets and facilities",
                "framework": ComplianceFramework.NIST,
                "assessment_method": "alert_analysis",
                "criteria": {
                    "required_monitoring": ["5715", "5716"],
                    "forbidden_rules": ["5720", "5721"]
                },
                "recommendations": [
                    "Implement least privilege",
                    "Use multi-factor authentication"
                ]
            },
            {
                "id": "NIST-DE.CM",
                "title": "Security Continuous Monitoring",
                "description": "Monitor security events continuously",
                "framework": ComplianceFramework.NIST,
                "assessment_method": "combined_analysis",
                "criteria": {},
                "recommendations": [
                    "Implement continuous monitoring",
                    "Establish baseline operations"
                ]
            }
        ]
    
    def _get_iso27001_requirements(self) -> List[Dict[str, Any]]:
        """Get ISO 27001 compliance requirements."""
        return [
            {
                "id": "ISO-A.9.1",
                "title": "Access Control Policy",
                "description": "Establish access control policy",
                "framework": ComplianceFramework.ISO27001,
                "assessment_method": "alert_analysis",
                "criteria": {
                    "required_monitoring": ["5715", "5716"],
                    "forbidden_rules": ["5720", "5721"]
                },
                "recommendations": [
                    "Document access control policy",
                    "Review access rights regularly"
                ]
            },
            {
                "id": "ISO-A.12.6",
                "title": "Management of Technical Vulnerabilities",
                "description": "Manage technical vulnerabilities",
                "framework": ComplianceFramework.ISO27001,
                "assessment_method": "vulnerability_analysis",
                "criteria": {},
                "recommendations": [
                    "Implement vulnerability management process",
                    "Apply security patches promptly"
                ]
            }
        ]
    
    # Async methods required by FastMCP server
    
    async def run_compliance_check(self, framework: str = "PCI-DSS", agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Run compliance check against security frameworks."""
        try:
            # Map string to ComplianceFramework enum
            framework_map = {
                "PCI-DSS": ComplianceFramework.PCI_DSS,
                "HIPAA": ComplianceFramework.HIPAA,
                "SOX": ComplianceFramework.SOX,
                "GDPR": ComplianceFramework.GDPR,
                "NIST": ComplianceFramework.NIST,
                "ISO27001": ComplianceFramework.ISO27001
            }
            
            framework_enum = framework_map.get(framework, ComplianceFramework.PCI_DSS)
            
            if not self.client_manager:
                return {
                    "framework": framework,
                    "agent_id": agent_id,
                    "error": "No client manager available",
                    "status": "error"
                }
            
            # Get requirements for the framework
            requirements = self.framework_requirements.get(framework_enum, [])
            
            if not requirements:
                return {
                    "framework": framework,
                    "agent_id": agent_id,
                    "error": f"No requirements defined for framework {framework}",
                    "status": "error"
                }
            
            # Collect data for compliance assessment
            alerts_data = await self.client_manager.get_alerts(
                agent_id=agent_id,
                limit=5000
            ) if agent_id else await self.client_manager.get_alerts(limit=5000)
            
            agents_data = await self.client_manager.get_agents()
            vulns_data = await self.client_manager.search_vulnerabilities(limit=1000)
            
            alerts = alerts_data.get('data', {}).get('affected_items', [])
            agents = agents_data.get('data', {}).get('affected_items', [])
            vulnerabilities = vulns_data.get('data', {}).get('affected_items', [])
            
            # Assess each requirement
            assessed_requirements = []
            total_score = 0
            
            for req in requirements:
                assessment = self._assess_requirement(req, alerts, agents, vulnerabilities, agent_id)
                assessed_requirements.append(assessment)
                total_score += assessment["score"]
            
            # Calculate overall compliance
            overall_score = total_score / len(requirements) if requirements else 0
            compliance_status = self._determine_compliance_status(overall_score)
            
            # Generate recommendations
            recommendations = []
            for req in assessed_requirements:
                if req["status"] != "compliant":
                    recommendations.extend(req.get("recommendations", []))
            
            return {
                "framework": framework,
                "agent_id": agent_id,
                "overall_score": round(overall_score, 2),
                "status": compliance_status,
                "requirements": assessed_requirements,
                "recommendations": list(set(recommendations)),  # Remove duplicates
                "summary": {
                    "total_requirements": len(requirements),
                    "compliant": len([r for r in assessed_requirements if r["status"] == "compliant"]),
                    "non_compliant": len([r for r in assessed_requirements if r["status"] == "non_compliant"]),
                    "partially_compliant": len([r for r in assessed_requirements if r["status"] == "partially_compliant"])
                },
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error running compliance check: {e}")
            return {
                "framework": framework,
                "agent_id": agent_id,
                "error": str(e),
                "status": "error"
            }
    
    def _assess_requirement(self, req: Dict[str, Any], alerts: List[Dict[str, Any]], 
                          agents: List[Dict[str, Any]], vulnerabilities: List[Dict[str, Any]],
                          agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Assess a single compliance requirement."""
        try:
            method = req.get("assessment_method", "combined_analysis")
            criteria = req.get("criteria", {})
            
            if method == "alert_analysis":
                score, status, evidence = self._assess_alert_based(alerts, criteria)
            elif method == "agent_analysis":
                score, status, evidence = self._assess_agent_based(agents, criteria, agent_id)
            elif method == "vulnerability_analysis":
                score, status, evidence = self._assess_vulnerability_based(vulnerabilities, criteria)
            else:  # combined_analysis
                score, status, evidence = self._assess_combined(alerts, agents, vulnerabilities, criteria)
            
            return {
                "id": req["id"],
                "title": req["title"],
                "description": req["description"],
                "score": score,
                "status": status,
                "evidence": evidence,
                "recommendations": req.get("recommendations", [])
            }
            
        except Exception as e:
            self.logger.error(f"Error assessing requirement {req.get('id', 'unknown')}: {e}")
            return {
                "id": req.get("id", "unknown"),
                "title": req.get("title", "Unknown"),
                "description": req.get("description", "Unknown"),
                "score": 0,
                "status": "unknown",
                "evidence": [f"Error: {str(e)}"],
                "recommendations": req.get("recommendations", [])
            }
    
    def _assess_alert_based(self, alerts: List[Dict[str, Any]], criteria: Dict[str, Any]) -> tuple:
        """Assess compliance based on alert patterns."""
        required_monitoring = criteria.get("required_monitoring", [])
        forbidden_rules = criteria.get("forbidden_rules", [])
        
        evidence = []
        score = 100  # Start with perfect score
        
        # Check for required monitoring
        if required_monitoring:
            found_rules = set()
            for alert in alerts:
                rule_id = str(alert.get('rule', {}).get('id', ''))
                if rule_id in required_monitoring:
                    found_rules.add(rule_id)
            
            missing_rules = set(required_monitoring) - found_rules
            if missing_rules:
                score -= (len(missing_rules) / len(required_monitoring)) * 50
                evidence.append(f"Missing monitoring for rules: {list(missing_rules)}")
            else:
                evidence.append(f"All required monitoring rules present: {required_monitoring}")
        
        # Check for forbidden patterns
        if forbidden_rules:
            found_forbidden = []
            for alert in alerts:
                rule_id = str(alert.get('rule', {}).get('id', ''))
                if rule_id in forbidden_rules:
                    found_forbidden.append(rule_id)
            
            if found_forbidden:
                score -= len(found_forbidden) * 10  # -10 per forbidden rule violation
                evidence.append(f"Forbidden rule violations found: {found_forbidden}")
        
        # Determine status
        if score >= 90:
            status = "compliant"
        elif score >= 60:
            status = "partially_compliant"
        else:
            status = "non_compliant"
        
        return max(0, score), status, evidence
    
    def _assess_agent_based(self, agents: List[Dict[str, Any]], criteria: Dict[str, Any], 
                          agent_id: Optional[str] = None) -> tuple:
        """Assess compliance based on agent status."""
        if agent_id:
            relevant_agents = [a for a in agents if a.get('id') == agent_id]
        else:
            relevant_agents = agents
        
        if not relevant_agents:
            return 0, "unknown", ["No agents found for assessment"]
        
        active_agents = len([a for a in relevant_agents if a.get('status') == 'active'])
        total_agents = len(relevant_agents)
        
        score = (active_agents / total_agents) * 100 if total_agents > 0 else 0
        
        evidence = [
            f"Active agents: {active_agents}/{total_agents}",
            f"Agent availability: {score:.1f}%"
        ]
        
        if score >= 95:
            status = "compliant"
        elif score >= 80:
            status = "partially_compliant"
        else:
            status = "non_compliant"
        
        return score, status, evidence
    
    def _assess_vulnerability_based(self, vulnerabilities: List[Dict[str, Any]], criteria: Dict[str, Any]) -> tuple:
        """Assess compliance based on vulnerability management."""
        if not vulnerabilities:
            return 100, "compliant", ["No vulnerabilities found"]
        
        critical_vulns = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'critical'])
        high_vulns = len([v for v in vulnerabilities if v.get('severity', '').lower() == 'high'])
        total_vulns = len(vulnerabilities)
        
        # Score based on vulnerability severity distribution
        score = 100
        if critical_vulns > 0:
            score -= critical_vulns * 20  # -20 per critical vulnerability
        if high_vulns > 0:
            score -= high_vulns * 5   # -5 per high vulnerability
        
        score = max(0, score)
        
        evidence = [
            f"Total vulnerabilities: {total_vulns}",
            f"Critical vulnerabilities: {critical_vulns}",
            f"High vulnerabilities: {high_vulns}"
        ]
        
        if score >= 90:
            status = "compliant"
        elif score >= 70:
            status = "partially_compliant"
        else:
            status = "non_compliant"
        
        return score, status, evidence
    
    def _assess_combined(self, alerts: List[Dict[str, Any]], agents: List[Dict[str, Any]], 
                       vulnerabilities: List[Dict[str, Any]], criteria: Dict[str, Any]) -> tuple:
        """Assess compliance using combined analysis of all data sources."""
        # Weighted assessment of all components
        alert_score, _, alert_evidence = self._assess_alert_based(alerts, criteria)
        agent_score, _, agent_evidence = self._assess_agent_based(agents, criteria)
        vuln_score, _, vuln_evidence = self._assess_vulnerability_based(vulnerabilities, criteria)
        
        # Weighted average (alerts 40%, agents 30%, vulnerabilities 30%)
        combined_score = (alert_score * 0.4) + (agent_score * 0.3) + (vuln_score * 0.3)
        
        evidence = alert_evidence + agent_evidence + vuln_evidence
        
        if combined_score >= 85:
            status = "compliant"
        elif combined_score >= 65:
            status = "partially_compliant"
        else:
            status = "non_compliant"
        
        return combined_score, status, evidence
    
    def _determine_compliance_status(self, overall_score: float) -> str:
        """Determine overall compliance status based on score."""
        if overall_score >= 90:
            return "compliant"
        elif overall_score >= 70:
            return "partially_compliant"
        else:
            return "non_compliant"