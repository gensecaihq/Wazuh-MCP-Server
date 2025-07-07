"""
Wazuh MCP Server API - Programmatic Interface
===========================================

This module provides a high-level API for integrating Wazuh MCP Server
into other Python applications without requiring the MCP protocol.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timedelta

from .config import WazuhConfig, ComplianceFramework, ThreatCategory
from .api.wazuh_client_manager import WazuhClientManager
from .analyzers import SecurityAnalyzer, ComplianceAnalyzer
from .utils import setup_logging, ValidationError
from .__version__ import __version__


class WazuhAPIClient:
    """
    High-level API client for Wazuh operations.
    
    This class provides a simplified interface for common Wazuh operations
    without requiring the MCP protocol layer.
    
    Example:
        ```python
        from wazuh_mcp_server import WazuhAPIClient, WazuhConfig
        
        # Configure connection
        config = WazuhConfig.from_env()
        
        # Create client
        client = WazuhAPIClient(config)
        
        # Initialize connection
        await client.initialize()
        
        # Get recent alerts
        alerts = await client.get_alerts(limit=100)
        
        # Analyze threats
        threat_analysis = await client.analyze_threats()
        
        # Check compliance
        compliance_report = await client.check_compliance("pci_dss")
        
        # Clean up
        await client.close()
        ```
    """
    
    def __init__(self, config: Optional[WazuhConfig] = None, logger: Optional[logging.Logger] = None):
        """
        Initialize the Wazuh API client.
        
        Args:
            config: Wazuh configuration. If None, will load from environment.
            logger: Custom logger. If None, will create a default logger.
        """
        self.config = config or WazuhConfig.from_env()
        self.logger = logger or setup_logging(
            log_level=self.config.log_level,
            logger_name="wazuh_api_client"
        )
        
        # Initialize components
        self.api_client = WazuhClientManager(self.config)
        self.security_analyzer = SecurityAnalyzer()
        self.compliance_analyzer = ComplianceAnalyzer()
        
        self._initialized = False
        
        self.logger.info(f"Wazuh API Client v{__version__} initialized")
    
    async def initialize(self) -> Dict[str, Any]:
        """
        Initialize connections and detect Wazuh version.
        
        Returns:
            Dictionary containing initialization status and server info.
        """
        try:
            self.logger.info("Initializing Wazuh API connections...")
            
            # Initialize API client
            await self.api_client.initialize()
            
            # Test connections
            server_info = await self.api_client.get_server_info()
            
            self._initialized = True
            self.logger.info("Wazuh API Client initialized successfully")
            
            return {
                "status": "success",
                "server_info": server_info,
                "client_version": __version__,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to initialize Wazuh API Client: {e}")
            raise
    
    async def get_alerts(
        self,
        limit: int = 100,
        level: Optional[str] = None,
        time_range: Optional[int] = None,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        search_params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Retrieve Wazuh alerts.
        
        Args:
            limit: Maximum number of alerts to retrieve (1-10000)
            level: Alert severity level filter
            time_range: Time range in seconds from now
            agent_id: Specific agent ID to filter by
            rule_id: Specific rule ID to filter by
            search_params: Additional search parameters
            
        Returns:
            Dictionary containing alerts and metadata
        """
        self._ensure_initialized()
        
        try:
            self.logger.debug(f"Fetching alerts: limit={limit}, level={level}, time_range={time_range}")
            
            data = await self.api_client.get_alerts(
                limit=limit,
                level=level,
                time_range=time_range,
                agent_id=agent_id,
                rule_id=rule_id,
                **search_params or {}
            )
            
            # Add metadata
            result = {
                "alerts": data.get("data", {}).get("affected_items", []),
                "total_items": data.get("data", {}).get("total_affected_items", 0),
                "query_info": {
                    "limit": limit,
                    "level": level,
                    "time_range": time_range,
                    "agent_id": agent_id,
                    "rule_id": rule_id
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Retrieved {len(result['alerts'])} alerts")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get alerts: {e}")
            raise
    
    async def get_agents(
        self,
        status: Optional[str] = None,
        platform: Optional[str] = None,
        version: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Retrieve Wazuh agents.
        
        Args:
            status: Agent status filter (active, disconnected, etc.)
            platform: Platform filter (linux, windows, etc.)
            version: Agent version filter
            limit: Maximum number of agents to retrieve
            
        Returns:
            Dictionary containing agents and metadata
        """
        self._ensure_initialized()
        
        try:
            self.logger.debug(f"Fetching agents: status={status}, platform={platform}")
            
            data = await self.api_client.get_agents(
                status=status,
                platform=platform,
                version=version,
                limit=limit
            )
            
            agents = data.get("data", {}).get("affected_items", [])
            
            # Add health assessment for each agent
            for agent in agents:
                agent["health_assessment"] = self._assess_agent_health(agent)
            
            result = {
                "agents": agents,
                "total_items": data.get("data", {}).get("total_affected_items", 0),
                "summary": self._generate_agents_summary(agents),
                "timestamp": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Retrieved {len(agents)} agents")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get agents: {e}")
            raise
    
    async def analyze_threats(
        self,
        time_range: int = 3600,
        category: Optional[str] = None,
        include_patterns: bool = True,
        include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """
        Perform comprehensive threat analysis.
        
        Args:
            time_range: Time range in seconds for analysis
            category: Specific threat category to focus on
            include_patterns: Include attack pattern analysis
            include_recommendations: Include security recommendations
            
        Returns:
            Dictionary containing threat analysis results
        """
        self._ensure_initialized()
        
        try:
            self.logger.info(f"Performing threat analysis for {time_range} seconds")
            
            # Get alerts for analysis
            alerts_data = await self.get_alerts(limit=1000, time_range=time_range)
            alerts = alerts_data["alerts"]
            
            # Perform risk assessment
            risk_assessment = self.security_analyzer.calculate_comprehensive_risk_score(
                alerts, time_window_hours=time_range // 3600
            )
            
            analysis = {
                "risk_assessment": {
                    "overall_score": risk_assessment.overall_score,
                    "risk_level": risk_assessment.risk_level.value,
                    "confidence": risk_assessment.confidence,
                    "factors": [
                        {
                            "name": factor.name,
                            "score": factor.score,
                            "weight": factor.weight,
                            "description": factor.description
                        }
                        for factor in risk_assessment.factors
                    ]
                },
                "alert_summary": {
                    "total_alerts": len(alerts),
                    "time_range_seconds": time_range,
                    "category_filter": category
                },
                "timestamp": risk_assessment.timestamp.isoformat()
            }
            
            # Add recommendations if requested
            if include_recommendations:
                analysis["recommendations"] = risk_assessment.recommendations
            
            # Add attack patterns if requested
            if include_patterns:
                analysis["attack_patterns"] = self.security_analyzer.identify_attack_patterns(alerts)
            
            self.logger.info(f"Threat analysis completed: risk_level={risk_assessment.risk_level.value}")
            return analysis
            
        except Exception as e:
            self.logger.error(f"Failed to analyze threats: {e}")
            raise
    
    async def check_compliance(
        self,
        framework: Union[str, ComplianceFramework],
        include_evidence: bool = True,
        include_recommendations: bool = True
    ) -> Dict[str, Any]:
        """
        Perform compliance assessment.
        
        Args:
            framework: Compliance framework (pci_dss, hipaa, gdpr, nist, iso27001)
            include_evidence: Include supporting evidence
            include_recommendations: Include remediation recommendations
            
        Returns:
            Dictionary containing compliance assessment results
        """
        self._ensure_initialized()
        
        try:
            # Convert string to enum if needed
            if isinstance(framework, str):
                framework_map = {
                    "pci_dss": ComplianceFramework.PCI_DSS,
                    "hipaa": ComplianceFramework.HIPAA,
                    "gdpr": ComplianceFramework.GDPR,
                    "nist": ComplianceFramework.NIST,
                    "iso27001": ComplianceFramework.ISO27001
                }
                framework = framework_map.get(framework.lower(), ComplianceFramework.PCI_DSS)
            
            self.logger.info(f"Performing {framework.value} compliance assessment")
            
            # Gather data for compliance assessment
            alerts_data = await self.get_alerts(limit=1000)
            alerts = alerts_data["alerts"]
            
            agents_data = await self.get_agents()
            agents = agents_data["agents"]
            
            # Get vulnerabilities for a sample of agents
            vulnerabilities = []
            active_agents = [a for a in agents if a.get("status") == "active"][:5]
            
            for agent in active_agents:
                try:
                    vuln_data = await self.api_client.get_vulnerabilities(agent["id"])
                    vulnerabilities.extend(vuln_data.get("data", {}).get("affected_items", []))
                except Exception as e:
                    self.logger.warning(f"Failed to get vulnerabilities for agent {agent['id']}: {e}")
            
            # Perform compliance assessment
            report = self.compliance_analyzer.assess_compliance(
                framework, alerts, agents, vulnerabilities
            )
            
            result = {
                "framework": framework.value,
                "overall_score": report.overall_score,
                "status": report.status.value,
                "summary": report.summary,
                "timestamp": report.timestamp.isoformat()
            }
            
            if include_evidence:
                result["evidence"] = {
                    "alerts_analyzed": len(alerts),
                    "agents_analyzed": len(agents),
                    "vulnerabilities_analyzed": len(vulnerabilities),
                    "controls": [
                        {
                            "id": control.control_id,
                            "name": control.name,
                            "status": control.status.value,
                            "score": control.score,
                            "description": control.description
                        }
                        for control in report.controls
                    ]
                }
            
            if include_recommendations:
                result["recommendations"] = report.recommendations
            
            self.logger.info(f"Compliance assessment completed: {framework.value} = {report.overall_score:.1f}%")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to check compliance: {e}")
            raise
    
    async def get_vulnerabilities(
        self,
        agent_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Retrieve vulnerability information.
        
        Args:
            agent_id: Specific agent ID to get vulnerabilities for
            severity: Severity filter (low, medium, high, critical)
            limit: Maximum number of vulnerabilities to retrieve
            
        Returns:
            Dictionary containing vulnerability data
        """
        self._ensure_initialized()
        
        try:
            if agent_id:
                data = await self.api_client.get_vulnerabilities(agent_id)
                vulnerabilities = data.get("data", {}).get("affected_items", [])
            else:
                # Get vulnerabilities for all active agents
                agents_data = await self.get_agents(status="active", limit=10)
                vulnerabilities = []
                
                for agent in agents_data["agents"]:
                    try:
                        vuln_data = await self.api_client.get_vulnerabilities(agent["id"])
                        agent_vulns = vuln_data.get("data", {}).get("affected_items", [])
                        # Add agent info to each vulnerability
                        for vuln in agent_vulns:
                            vuln["agent_info"] = {
                                "id": agent["id"],
                                "name": agent.get("name", ""),
                                "ip": agent.get("ip", "")
                            }
                        vulnerabilities.extend(agent_vulns)
                    except Exception as e:
                        self.logger.warning(f"Failed to get vulnerabilities for agent {agent['id']}: {e}")
                        continue
            
            # Filter by severity if specified
            if severity:
                vulnerabilities = [v for v in vulnerabilities if v.get("severity", "").lower() == severity.lower()]
            
            # Limit results
            vulnerabilities = vulnerabilities[:limit]
            
            result = {
                "vulnerabilities": vulnerabilities,
                "total_items": len(vulnerabilities),
                "summary": self._generate_vulnerability_summary(vulnerabilities),
                "query_info": {
                    "agent_id": agent_id,
                    "severity": severity,
                    "limit": limit
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
            self.logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities")
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get vulnerabilities: {e}")
            raise
    
    async def get_security_events(
        self,
        event_type: Optional[str] = None,
        time_range: int = 3600,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        Get recent security events with analysis.
        
        Args:
            event_type: Type of events to retrieve
            time_range: Time range in seconds
            limit: Maximum number of events
            
        Returns:
            Dictionary containing security events and analysis
        """
        self._ensure_initialized()
        
        try:
            # Get recent alerts as security events
            alerts_data = await self.get_alerts(
                limit=limit,
                time_range=time_range
            )
            
            events = alerts_data["alerts"]
            
            # Analyze events for patterns
            patterns = self.security_analyzer.identify_attack_patterns(events)
            
            result = {
                "events": events,
                "total_events": len(events),
                "patterns_detected": patterns,
                "time_range_seconds": time_range,
                "analysis": {
                    "most_common_rules": self._get_most_common_rules(events),
                    "affected_agents": self._get_affected_agents(events),
                    "severity_distribution": self._get_severity_distribution(events)
                },
                "timestamp": datetime.utcnow().isoformat()
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Failed to get security events: {e}")
            raise
    
    async def close(self):
        """Close connections and cleanup resources."""
        try:
            if hasattr(self.api_client, 'close'):
                await self.api_client.close()
            self.logger.info("Wazuh API Client connections closed")
        except Exception as e:
            self.logger.error(f"Error closing connections: {e}")
    
    def _ensure_initialized(self):
        """Ensure the client is initialized."""
        if not self._initialized:
            raise RuntimeError("Client not initialized. Call initialize() first.")
    
    def _assess_agent_health(self, agent: Dict[str, Any]) -> Dict[str, Any]:
        """Assess individual agent health."""
        status = agent.get("status", "unknown")
        last_keep_alive = agent.get("lastKeepAlive")
        version = agent.get("version")
        
        health_score = 100
        issues = []
        
        if status != "active":
            health_score -= 50
            issues.append(f"Agent status is {status}")
        
        if last_keep_alive:
            try:
                from datetime import datetime
                import dateutil.parser
                last_seen = dateutil.parser.parse(last_keep_alive)
                time_diff = datetime.utcnow() - last_seen.replace(tzinfo=None)
                if time_diff.total_seconds() > 300:  # 5 minutes
                    health_score -= 30
                    issues.append("Agent last seen more than 5 minutes ago")
            except Exception:
                pass
        
        return {
            "score": max(0, health_score),
            "status": "healthy" if health_score > 80 else "warning" if health_score > 50 else "critical",
            "issues": issues
        }
    
    def _generate_agents_summary(self, agents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for agents."""
        total = len(agents)
        active = sum(1 for a in agents if a.get("status") == "active")
        disconnected = sum(1 for a in agents if a.get("status") == "disconnected")
        
        platforms = {}
        for agent in agents:
            platform = agent.get("os", {}).get("platform", "unknown")
            platforms[platform] = platforms.get(platform, 0) + 1
        
        return {
            "total_agents": total,
            "active": active,
            "disconnected": disconnected,
            "platform_distribution": platforms,
            "health_summary": {
                "healthy": sum(1 for a in agents if self._assess_agent_health(a)["score"] > 80),
                "warning": sum(1 for a in agents if 50 < self._assess_agent_health(a)["score"] <= 80),
                "critical": sum(1 for a in agents if self._assess_agent_health(a)["score"] <= 50)
            }
        }
    
    def _generate_vulnerability_summary(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary statistics for vulnerabilities."""
        total = len(vulnerabilities)
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Get top CVEs
        cve_counts = {}
        for vuln in vulnerabilities:
            cve = vuln.get("cve", "")
            if cve:
                cve_counts[cve] = cve_counts.get(cve, 0) + 1
        
        top_cves = sorted(cve_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        return {
            "total_vulnerabilities": total,
            "severity_distribution": severity_counts,
            "top_cves": [{"cve": cve, "count": count} for cve, count in top_cves],
            "critical_count": severity_counts.get("critical", 0),
            "high_count": severity_counts.get("high", 0)
        }
    
    def _get_most_common_rules(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get most frequently triggered rules."""
        rule_counts = {}
        for event in events:
            rule_id = event.get("rule", {}).get("id")
            rule_description = event.get("rule", {}).get("description", "")
            if rule_id:
                key = f"{rule_id}: {rule_description}"
                rule_counts[key] = rule_counts.get(key, 0) + 1
        
        return [
            {"rule": rule, "count": count}
            for rule, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
    
    def _get_affected_agents(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Get agents most affected by events."""
        agent_counts = {}
        for event in events:
            agent_id = event.get("agent", {}).get("id")
            agent_name = event.get("agent", {}).get("name", "")
            if agent_id:
                key = f"{agent_id}: {agent_name}"
                agent_counts[key] = agent_counts.get(key, 0) + 1
        
        return [
            {"agent": agent, "event_count": count}
            for agent, count in sorted(agent_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        ]
    
    def _get_severity_distribution(self, events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of event severities."""
        severity_counts = {}
        for event in events:
            level = event.get("rule", {}).get("level", 0)
            if level >= 12:
                severity = "critical"
            elif level >= 7:
                severity = "high"
            elif level >= 4:
                severity = "medium"
            else:
                severity = "low"
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return severity_counts


# Convenience function for quick setup
async def create_client(config: Optional[WazuhConfig] = None) -> WazuhAPIClient:
    """
    Create and initialize a Wazuh API client.
    
    Args:
        config: Wazuh configuration. If None, loads from environment.
        
    Returns:
        Initialized WazuhAPIClient instance
    """
    client = WazuhAPIClient(config)
    await client.initialize()
    return client


# Export main classes and functions
__all__ = [
    "WazuhAPIClient",
    "create_client",
    "WazuhConfig",
    "ComplianceFramework",
    "ThreatCategory"
]
