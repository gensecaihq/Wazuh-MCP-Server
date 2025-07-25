"""Vulnerability analysis tools for Wazuh MCP Server."""

from typing import Any, Dict, List
import mcp.types as types
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re

from .base import BaseTool
from ..utils import validate_vulnerability_summary_query, validate_critical_vulnerabilities_query


class VulnerabilityTools(BaseTool):
    """Tools for Wazuh vulnerability analysis and management."""
    
    @property
    def tool_definitions(self) -> List[types.Tool]:
        """Return vulnerability-related tool definitions."""
        return [
            types.Tool(
                name="get_wazuh_vulnerability_summary",
                description="Get comprehensive vulnerability assessment across infrastructure with risk scoring",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "severity_filter": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Filter by severity levels",
                            "default": ["critical", "high", "medium", "low"]
                        },
                        "include_remediation": {
                            "type": "boolean",
                            "description": "Include remediation recommendations",
                            "default": True
                        },
                        "agent_filter": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Filter by specific agent IDs (optional)"
                        },
                        "package_filter": {
                            "type": "string",
                            "description": "Filter by package name pattern (optional)"
                        }
                    }
                }
            ),
            types.Tool(
                name="get_wazuh_critical_vulnerabilities",
                description="Get critical vulnerabilities with exploit intelligence and priority scoring",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "include_exploit_data": {
                            "type": "boolean",
                            "description": "Include exploit availability and CVSS data",
                            "default": True
                        },
                        "priority_threshold": {
                            "type": "number",
                            "description": "Minimum priority score (0-100)",
                            "default": 70,
                            "minimum": 0,
                            "maximum": 100
                        },
                        "time_range_days": {
                            "type": "integer",
                            "description": "Look for vulnerabilities discovered in last N days",
                            "default": 30,
                            "minimum": 1,
                            "maximum": 365
                        },
                        "include_trending": {
                            "type": "boolean",
                            "description": "Include trending vulnerability analysis",
                            "default": True
                        }
                    }
                }
            )
        ]
    
    def get_handler_mapping(self) -> Dict[str, callable]:
        """Return mapping of tool names to handler methods."""
        return {
            "get_wazuh_vulnerability_summary": self.handle_vulnerability_summary,
            "get_wazuh_critical_vulnerabilities": self.handle_critical_vulnerabilities
        }
    
    async def handle_vulnerability_summary(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle comprehensive vulnerability summary request."""
        try:
            # Validate input
            validated_args = validate_vulnerability_summary_query(arguments)
            
            severity_filter = validated_args.get("severity_filter", ["critical", "high", "medium", "low"])
            include_remediation = validated_args.get("include_remediation", True)
            agent_filter = validated_args.get("agent_filter")
            package_filter = validated_args.get("package_filter")
            
            # Get vulnerability data from multiple sources
            vuln_data = await self._get_comprehensive_vulnerability_data(
                severity_filter, agent_filter, package_filter
            )
            
            # Generate comprehensive summary
            summary = {
                "overview": self._generate_vulnerability_overview(vuln_data),
                "risk_assessment": self._assess_infrastructure_risk(vuln_data),
                "distribution": self._analyze_vulnerability_distribution(vuln_data),
                "affected_systems": self._analyze_affected_systems(vuln_data),
                "package_analysis": self._analyze_vulnerable_packages(vuln_data),
                "timeline_analysis": self._analyze_vulnerability_timeline(vuln_data)
            }
            
            if include_remediation:
                summary["remediation"] = self._generate_remediation_recommendations(vuln_data)
            
            # Add compliance impact
            summary["compliance_impact"] = self._assess_compliance_impact(vuln_data)
            
            return self._format_response(summary, metadata={
                "source": "wazuh_vulnerability_detector",
                "analysis_type": "comprehensive_vulnerability_summary",
                "filters_applied": {
                    "severity": severity_filter,
                    "agents": len(agent_filter) if agent_filter else "all",
                    "package_pattern": package_filter or "all"
                }
            })
            
        except Exception as e:
            self.logger.error(f"Error in vulnerability summary: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_vulnerability_summary"})
    
    async def handle_critical_vulnerabilities(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle critical vulnerabilities with exploit intelligence."""
        try:
            # Validate input
            validated_args = validate_critical_vulnerabilities_query(arguments)
            
            include_exploit_data = validated_args.get("include_exploit_data", True)
            priority_threshold = validated_args.get("priority_threshold", 70)
            time_range_days = validated_args.get("time_range_days", 30)
            include_trending = validated_args.get("include_trending", True)
            
            # Get critical vulnerability data
            critical_vulns = await self._get_critical_vulnerabilities(
                priority_threshold, time_range_days
            )
            
            # Enrich with exploit intelligence
            enriched_vulns = []
            for vuln in critical_vulns:
                enriched = await self._enrich_with_exploit_data(vuln, include_exploit_data)
                enriched_vulns.append(enriched)
            
            # Sort by priority score
            enriched_vulns.sort(key=lambda x: x.get("priority_score", 0), reverse=True)
            
            # Generate analysis
            analysis = {
                "summary": {
                    "total_critical": len(enriched_vulns),
                    "with_exploits": sum(1 for v in enriched_vulns if v.get("exploit_available", False)),
                    "recently_discovered": sum(1 for v in enriched_vulns if v.get("days_since_discovery", 0) <= 7),
                    "average_priority": sum(v.get("priority_score", 0) for v in enriched_vulns) / len(enriched_vulns) if enriched_vulns else 0
                },
                "critical_vulnerabilities": enriched_vulns[:20],  # Top 20 by priority
                "exploit_intelligence": self._analyze_exploit_landscape(enriched_vulns),
                "attack_vectors": self._analyze_attack_vectors(enriched_vulns),
                "immediate_actions": self._generate_immediate_actions(enriched_vulns)
            }
            
            if include_trending:
                analysis["trending_analysis"] = self._analyze_vulnerability_trends(enriched_vulns)
            
            return self._format_response(analysis, metadata={
                "source": "wazuh_vulnerability_detector",
                "analysis_type": "critical_vulnerability_analysis",
                "priority_threshold": priority_threshold,
                "time_range_days": time_range_days
            })
            
        except Exception as e:
            self.logger.error(f"Error in critical vulnerabilities analysis: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_critical_vulnerabilities"})
    
    # Helper methods for vulnerability analysis
    async def _get_comprehensive_vulnerability_data(self, severity_filter: List[str], 
                                                   agent_filter: List[str] = None,
                                                   package_filter: str = None) -> List[Dict[str, Any]]:
        """Get comprehensive vulnerability data from Wazuh."""
        vulnerabilities = []
        
        # Get vulnerability data from vulnerability detector
        vuln_response = await self.api_client.get_vulnerabilities(
            severity=severity_filter,
            agent_ids=agent_filter
        )
        
        raw_vulns = vuln_response.get("data", {}).get("affected_items", [])
        
        for vuln in raw_vulns:
            # Apply package filter if specified
            if package_filter:
                package_name = vuln.get("name", "")
                if not re.search(package_filter, package_name, re.IGNORECASE):
                    continue
            
            # Enrich vulnerability data
            enriched_vuln = {
                **vuln,
                "risk_score": self._calculate_risk_score(vuln),
                "business_impact": self._assess_business_impact(vuln),
                "remediation_complexity": self._assess_remediation_complexity(vuln)
            }
            vulnerabilities.append(enriched_vuln)
        
        return vulnerabilities
    
    async def _get_critical_vulnerabilities(self, priority_threshold: float, 
                                          time_range_days: int) -> List[Dict[str, Any]]:
        """Get critical vulnerabilities based on priority threshold."""
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=time_range_days)
        
        # Get vulnerability data
        vuln_response = await self.api_client.get_vulnerabilities(
            severity=["critical", "high"],
            date_from=start_date.strftime("%Y-%m-%d"),
            date_to=end_date.strftime("%Y-%m-%d")
        )
        
        vulnerabilities = vuln_response.get("data", {}).get("affected_items", [])
        
        # Filter by priority threshold and enrich
        critical_vulns = []
        for vuln in vulnerabilities:
            priority_score = self._calculate_priority_score(vuln)
            if priority_score >= priority_threshold:
                vuln["priority_score"] = priority_score
                vuln["days_since_discovery"] = self._calculate_days_since_discovery(vuln)
                critical_vulns.append(vuln)
        
        return critical_vulns
    
    async def _enrich_with_exploit_data(self, vuln: Dict[str, Any], 
                                      include_exploit_data: bool) -> Dict[str, Any]:
        """Enrich vulnerability with exploit intelligence."""
        if not include_exploit_data:
            return vuln
        
        cve_id = vuln.get("cve")
        if not cve_id:
            return vuln
        
        # Mock exploit data (in real implementation, this would query external APIs)
        exploit_data = self._get_mock_exploit_data(cve_id)
        
        return {
            **vuln,
            "exploit_available": exploit_data.get("exploit_available", False),
            "exploit_maturity": exploit_data.get("maturity", "unknown"),
            "exploit_complexity": exploit_data.get("complexity", "unknown"),
            "public_exploits": exploit_data.get("public_exploits", 0),
            "cvss_score": exploit_data.get("cvss_score", 0.0),
            "threat_intelligence": exploit_data.get("threat_intel", {})
        }
    
    def _calculate_risk_score(self, vuln: Dict[str, Any]) -> int:
        """Calculate comprehensive risk score for vulnerability."""
        base_score = 0
        
        # Severity scoring
        severity = vuln.get("severity", "").lower()
        severity_scores = {"critical": 40, "high": 30, "medium": 20, "low": 10}
        base_score += severity_scores.get(severity, 5)
        
        # CVSS scoring
        cvss = vuln.get("cvss", {})
        if isinstance(cvss, dict):
            cvss_score = cvss.get("cvss3", {}).get("score", 0)
            base_score += min(int(cvss_score * 6), 30)
        
        # Asset criticality (would come from asset inventory)
        agent_id = vuln.get("agent", {}).get("id", "")
        if agent_id in getattr(self.config, 'critical_agents', []):
            base_score += 20
        
        # Package criticality
        package_name = vuln.get("name", "").lower()
        critical_packages = ["kernel", "openssl", "openssh", "apache", "nginx"]
        if any(pkg in package_name for pkg in critical_packages):
            base_score += 10
        
        return min(base_score, 100)
    
    def _assess_business_impact(self, vuln: Dict[str, Any]) -> str:
        """Assess business impact of vulnerability."""
        risk_score = self._calculate_risk_score(vuln)
        
        if risk_score >= 80:
            return "critical"
        elif risk_score >= 60:
            return "high"
        elif risk_score >= 40:
            return "medium"
        else:
            return "low"
    
    def _assess_remediation_complexity(self, vuln: Dict[str, Any]) -> str:
        """Assess complexity of remediation."""
        package_name = vuln.get("name", "").lower()
        
        # Kernel updates are typically complex
        if "kernel" in package_name:
            return "high"
        
        # System libraries are medium complexity
        system_libs = ["glibc", "openssl", "zlib", "curl"]
        if any(lib in package_name for lib in system_libs):
            return "medium"
        
        # Application packages are typically low complexity
        return "low"
    
    def _calculate_priority_score(self, vuln: Dict[str, Any]) -> float:
        """Calculate priority score for vulnerability triage."""
        score = 0.0
        
        # Base CVSS score (0-40 points)
        cvss = vuln.get("cvss", {})
        if isinstance(cvss, dict):
            cvss_score = cvss.get("cvss3", {}).get("score", 0)
            score += cvss_score * 4
        
        # Exploit availability (0-30 points)
        if vuln.get("exploit_available", False):
            score += 30
        
        # Age factor (0-20 points) - newer vulnerabilities get higher scores
        days_old = vuln.get("days_since_discovery", 365)
        if days_old <= 7:
            score += 20
        elif days_old <= 30:
            score += 15
        elif days_old <= 90:
            score += 10
        
        # Asset criticality (0-10 points)
        agent_id = vuln.get("agent", {}).get("id", "")
        if agent_id in getattr(self.config, 'critical_agents', []):
            score += 10
        
        return min(score, 100.0)
    
    def _calculate_days_since_discovery(self, vuln: Dict[str, Any]) -> int:
        """Calculate days since vulnerability discovery."""
        published_date = vuln.get("published", "")
        if not published_date:
            return 365  # Default to old if unknown
        
        try:
            pub_date = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
            return (datetime.utcnow() - pub_date.replace(tzinfo=None)).days
        except:
            return 365
    
    def _get_mock_exploit_data(self, cve_id: str) -> Dict[str, Any]:
        """Get mock exploit data (replace with real threat intel APIs)."""
        # This would integrate with external threat intelligence APIs
        # For now, providing mock data based on CVE patterns
        
        mock_data = {
            "exploit_available": False,
            "maturity": "unknown",
            "complexity": "unknown",
            "public_exploits": 0,
            "cvss_score": 0.0,
            "threat_intel": {}
        }
        
        # Mock some patterns for demonstration
        if "2023" in cve_id or "2024" in cve_id:
            mock_data["exploit_available"] = True
            mock_data["maturity"] = "proof-of-concept"
            mock_data["public_exploits"] = 2
            mock_data["cvss_score"] = 7.5
        
        return mock_data
    
    def _generate_vulnerability_overview(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate vulnerability overview statistics."""
        if not vulns:
            return {"total": 0, "message": "No vulnerabilities found"}
        
        severity_counts = Counter(v.get("severity", "unknown").lower() for v in vulns)
        risk_scores = [self._calculate_risk_score(v) for v in vulns]
        
        return {
            "total_vulnerabilities": len(vulns),
            "severity_distribution": dict(severity_counts),
            "risk_metrics": {
                "average_risk_score": sum(risk_scores) / len(risk_scores),
                "highest_risk_score": max(risk_scores),
                "critical_risk_count": sum(1 for score in risk_scores if score >= 80)
            },
            "business_impact_distribution": Counter(
                self._assess_business_impact(v) for v in vulns
            )
        }
    
    def _assess_infrastructure_risk(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall infrastructure risk."""
        if not vulns:
            return {"level": "low", "score": 0}
        
        risk_scores = [self._calculate_risk_score(v) for v in vulns]
        avg_risk = sum(risk_scores) / len(risk_scores)
        critical_count = sum(1 for score in risk_scores if score >= 80)
        
        # Calculate infrastructure risk level
        if critical_count > 10 or avg_risk > 70:
            level = "critical"
        elif critical_count > 5 or avg_risk > 50:
            level = "high"
        elif critical_count > 0 or avg_risk > 30:
            level = "medium"
        else:
            level = "low"
        
        return {
            "level": level,
            "score": int(avg_risk),
            "critical_vulnerabilities": critical_count,
            "recommendations": self._get_risk_recommendations(level, critical_count)
        }
    
    def _analyze_vulnerability_distribution(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze how vulnerabilities are distributed."""
        agent_counts = Counter(v.get("agent", {}).get("id", "unknown") for v in vulns)
        package_counts = Counter(v.get("name", "unknown") for v in vulns)
        
        return {
            "by_agent": dict(agent_counts.most_common(10)),
            "by_package": dict(package_counts.most_common(10)),
            "most_affected_agent": agent_counts.most_common(1)[0] if agent_counts else None,
            "most_vulnerable_package": package_counts.most_common(1)[0] if package_counts else None
        }
    
    def _analyze_affected_systems(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze which systems are most affected."""
        systems = defaultdict(list)
        
        for vuln in vulns:
            agent_info = vuln.get("agent", {})
            agent_id = agent_info.get("id", "unknown")
            agent_name = agent_info.get("name", agent_id)
            
            systems[agent_id].append({
                "vulnerability": vuln.get("cve", vuln.get("name", "unknown")),
                "severity": vuln.get("severity", "unknown"),
                "risk_score": self._calculate_risk_score(vuln)
            })
        
        # Calculate system risk scores
        system_risks = {}
        for agent_id, agent_vulns in systems.items():
            avg_risk = sum(v["risk_score"] for v in agent_vulns) / len(agent_vulns)
            system_risks[agent_id] = {
                "vulnerability_count": len(agent_vulns),
                "average_risk_score": avg_risk,
                "critical_count": sum(1 for v in agent_vulns if v["risk_score"] >= 80)
            }
        
        # Sort by risk
        sorted_systems = sorted(
            system_risks.items(),
            key=lambda x: (x[1]["critical_count"], x[1]["average_risk_score"]),
            reverse=True
        )
        
        return {
            "total_affected_systems": len(systems),
            "highest_risk_systems": dict(sorted_systems[:10]),
            "systems_needing_immediate_attention": len([
                s for s in system_risks.values() if s["critical_count"] > 0
            ])
        }
    
    def _analyze_vulnerable_packages(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze vulnerable packages and versions."""
        package_analysis = defaultdict(lambda: {
            "versions": set(),
            "severities": set(),
            "agents_affected": set(),
            "total_vulns": 0
        })
        
        for vuln in vulns:
            package_name = vuln.get("name", "unknown")
            version = vuln.get("version", "unknown")
            severity = vuln.get("severity", "unknown")
            agent_id = vuln.get("agent", {}).get("id", "unknown")
            
            pkg_data = package_analysis[package_name]
            pkg_data["versions"].add(version)
            pkg_data["severities"].add(severity)
            pkg_data["agents_affected"].add(agent_id)
            pkg_data["total_vulns"] += 1
        
        # Convert sets to lists for JSON serialization
        for pkg_data in package_analysis.values():
            pkg_data["versions"] = list(pkg_data["versions"])
            pkg_data["severities"] = list(pkg_data["severities"])
            pkg_data["agents_affected"] = list(pkg_data["agents_affected"])
        
        # Sort by impact
        sorted_packages = sorted(
            package_analysis.items(),
            key=lambda x: (x[1]["total_vulns"], len(x[1]["agents_affected"])),
            reverse=True
        )
        
        return {
            "total_unique_packages": len(package_analysis),
            "most_problematic_packages": dict(sorted_packages[:10]),
            "widespread_packages": [
                pkg for pkg, data in package_analysis.items()
                if len(data["agents_affected"]) > 1
            ]
        }
    
    def _analyze_vulnerability_timeline(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze vulnerability discovery timeline."""
        timeline = defaultdict(int)
        
        for vuln in vulns:
            published_date = vuln.get("published", "")
            if published_date:
                try:
                    pub_date = datetime.fromisoformat(published_date.replace("Z", "+00:00"))
                    month_key = pub_date.strftime("%Y-%m")
                    timeline[month_key] += 1
                except:
                    timeline["unknown"] += 1
            else:
                timeline["unknown"] += 1
        
        # Find recent surge
        sorted_timeline = sorted(timeline.items())
        recent_surge = False
        if len(sorted_timeline) >= 2:
            latest = sorted_timeline[-1][1]
            previous = sorted_timeline[-2][1]
            if latest > previous * 1.5:
                recent_surge = True
        
        return {
            "monthly_distribution": dict(timeline),
            "recent_surge_detected": recent_surge,
            "peak_month": max(timeline.items(), key=lambda x: x[1]) if timeline else None
        }
    
    def _generate_remediation_recommendations(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate remediation recommendations."""
        recommendations = {
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": [],
            "patching_strategy": {}
        }
        
        # Analyze for immediate actions
        critical_vulns = [v for v in vulns if self._calculate_risk_score(v) >= 80]
        if critical_vulns:
            recommendations["immediate_actions"].append({
                "action": "Patch critical vulnerabilities immediately",
                "count": len(critical_vulns),
                "timeline": "24-48 hours"
            })
        
        # Package-based recommendations
        package_counts = Counter(v.get("name", "") for v in vulns)
        for package, count in package_counts.most_common(5):
            if count > 1:
                recommendations["short_term_actions"].append({
                    "action": f"Update {package} package across all systems",
                    "affected_systems": count,
                    "timeline": "1-2 weeks"
                })
        
        # Long-term recommendations
        recommendations["long_term_actions"] = [
            "Implement automated vulnerability scanning",
            "Establish regular patching cycles",
            "Deploy vulnerability management system",
            "Create incident response procedures"
        ]
        
        return recommendations
    
    def _assess_compliance_impact(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess compliance impact of vulnerabilities."""
        high_risk_vulns = [v for v in vulns if self._calculate_risk_score(v) >= 60]
        
        compliance_risks = {
            "PCI_DSS": len([v for v in high_risk_vulns if self._affects_pci_compliance(v)]),
            "HIPAA": len([v for v in high_risk_vulns if self._affects_hipaa_compliance(v)]),
            "SOX": len([v for v in high_risk_vulns if self._affects_sox_compliance(v)]),
            "GDPR": len([v for v in high_risk_vulns if self._affects_gdpr_compliance(v)])
        }
        
        return {
            "compliance_risks": compliance_risks,
            "high_risk_vulnerabilities": len(high_risk_vulns),
            "remediation_urgency": "high" if any(compliance_risks.values()) else "medium"
        }
    
    def _get_risk_recommendations(self, level: str, critical_count: int) -> List[str]:
        """Get risk-based recommendations."""
        if level == "critical":
            return [
                "Implement emergency patching procedures",
                "Consider isolating critical systems",
                "Activate incident response team",
                "Schedule immediate vulnerability assessment"
            ]
        elif level == "high":
            return [
                "Prioritize critical vulnerability patching",
                "Increase monitoring frequency",
                "Review security controls"
            ]
        else:
            return [
                "Continue regular patching schedule",
                "Monitor for new vulnerabilities"
            ]
    
    def _analyze_exploit_landscape(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze exploit landscape for critical vulnerabilities."""
        with_exploits = [v for v in vulns if v.get("exploit_available", False)]
        
        exploit_maturity = Counter(v.get("exploit_maturity", "unknown") for v in with_exploits)
        exploit_complexity = Counter(v.get("exploit_complexity", "unknown") for v in with_exploits)
        
        return {
            "total_with_exploits": len(with_exploits),
            "exploit_maturity_distribution": dict(exploit_maturity),
            "exploit_complexity_distribution": dict(exploit_complexity),
            "weaponized_exploits": len([v for v in with_exploits if v.get("exploit_maturity") == "weaponized"])
        }
    
    def _analyze_attack_vectors(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze potential attack vectors."""
        vectors = {
            "network": 0,
            "local": 0,
            "physical": 0,
            "adjacent_network": 0
        }
        
        for vuln in vulns:
            cvss = vuln.get("cvss", {})
            if isinstance(cvss, dict):
                vector = cvss.get("cvss3", {}).get("attackVector", "").lower()
                if "network" in vector:
                    vectors["network"] += 1
                elif "local" in vector:
                    vectors["local"] += 1
                elif "physical" in vector:
                    vectors["physical"] += 1
                elif "adjacent" in vector:
                    vectors["adjacent_network"] += 1
        
        return vectors
    
    def _generate_immediate_actions(self, vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate immediate action items."""
        actions = []
        
        # Top 5 highest priority vulnerabilities
        top_vulns = sorted(vulns, key=lambda x: x.get("priority_score", 0), reverse=True)[:5]
        
        for vuln in top_vulns:
            actions.append({
                "vulnerability": vuln.get("cve", vuln.get("name", "unknown")),
                "priority_score": vuln.get("priority_score", 0),
                "action": f"Patch {vuln.get('name', 'package')} immediately",
                "affected_systems": [vuln.get("agent", {}).get("id", "unknown")],
                "timeline": "24 hours" if vuln.get("priority_score", 0) > 90 else "48-72 hours"
            })
        
        return actions
    
    def _analyze_vulnerability_trends(self, vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze vulnerability trends."""
        # Group by discovery date
        monthly_counts = defaultdict(int)
        for vuln in vulns:
            days_old = vuln.get("days_since_discovery", 365)
            if days_old <= 30:
                monthly_counts["last_30_days"] += 1
            elif days_old <= 60:
                monthly_counts["30_60_days"] += 1
            elif days_old <= 90:
                monthly_counts["60_90_days"] += 1
            else:
                monthly_counts["older"] += 1
        
        # Determine trend
        recent = monthly_counts["last_30_days"]
        older = monthly_counts["30_60_days"]
        
        if recent > older * 1.5:
            trend = "increasing"
        elif recent < older * 0.5:
            trend = "decreasing"
        else:
            trend = "stable"
        
        return {
            "distribution": dict(monthly_counts),
            "trend": trend,
            "recent_discoveries": recent
        }
    
    # Mock compliance check methods
    def _affects_pci_compliance(self, vuln: Dict[str, Any]) -> bool:
        """Check if vulnerability affects PCI DSS compliance."""
        # Mock implementation - would check against actual compliance requirements
        package_name = vuln.get("name", "").lower()
        return any(pkg in package_name for pkg in ["apache", "nginx", "mysql", "postgresql"])
    
    def _affects_hipaa_compliance(self, vuln: Dict[str, Any]) -> bool:
        """Check if vulnerability affects HIPAA compliance."""
        # Mock implementation
        severity = vuln.get("severity", "").lower()
        return severity in ["critical", "high"]
    
    def _affects_sox_compliance(self, vuln: Dict[str, Any]) -> bool:
        """Check if vulnerability affects SOX compliance."""
        # Mock implementation
        return self._calculate_risk_score(vuln) >= 70
    
    def _affects_gdpr_compliance(self, vuln: Dict[str, Any]) -> bool:
        """Check if vulnerability affects GDPR compliance."""
        # Mock implementation
        return vuln.get("exploit_available", False)