"""Agent monitoring and management tools for Wazuh MCP Server."""

from typing import Any, Dict, List
import mcp.types as types
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from .base import BaseTool
from ..utils import validate_running_agents_query, validate_rules_summary_query


class AgentTools(BaseTool):
    """Tools for Wazuh agent monitoring, health checking, and management."""
    
    @property
    def tool_definitions(self) -> List[types.Tool]:
        """Return agent-related tool definitions."""
        return [
            types.Tool(
                name="get_wazuh_running_agents",
                description="Get comprehensive real-time agent health monitoring with performance metrics",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "include_performance": {
                            "type": "boolean",
                            "description": "Include detailed performance metrics",
                            "default": True
                        },
                        "health_threshold": {
                            "type": "number",
                            "description": "Health score threshold (0-100) for filtering",
                            "default": 0,
                            "minimum": 0,
                            "maximum": 100
                        },
                        "include_inactive": {
                            "type": "boolean",
                            "description": "Include inactive/disconnected agents",
                            "default": False
                        },
                        "group_filter": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Filter by agent groups (optional)"
                        },
                        "os_filter": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Filter by operating system (optional)"
                        }
                    }
                }
            ),
            types.Tool(
                name="get_wazuh_rules_summary",
                description="Get comprehensive rule effectiveness and coverage analysis with performance insights",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "include_effectiveness": {
                            "type": "boolean",
                            "description": "Include rule effectiveness analysis",
                            "default": True
                        },
                        "time_range_hours": {
                            "type": "integer",
                            "description": "Time range in hours for analysis",
                            "default": 24,
                            "minimum": 1,
                            "maximum": 168
                        },
                        "rule_level_filter": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "Filter by rule levels (1-15)",
                            "default": []
                        },
                        "include_coverage_gaps": {
                            "type": "boolean",
                            "description": "Analyze coverage gaps and recommendations",
                            "default": True
                        },
                        "group_by": {
                            "type": "string",
                            "description": "Group analysis by category",
                            "enum": ["level", "category", "source", "compliance"],
                            "default": "category"
                        }
                    }
                }
            )
        ]
    
    def get_handler_mapping(self) -> Dict[str, callable]:
        """Return mapping of tool names to handler methods."""
        return {
            "get_wazuh_running_agents": self.handle_running_agents,
            "get_wazuh_rules_summary": self.handle_rules_summary
        }
    
    async def handle_running_agents(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle running agents monitoring request."""
        try:
            # Validate input
            validated_args = validate_running_agents_query(arguments)
            
            include_performance = validated_args.get("include_performance", True)
            health_threshold = validated_args.get("health_threshold", 0)
            include_inactive = validated_args.get("include_inactive", False)
            group_filter = validated_args.get("group_filter")
            os_filter = validated_args.get("os_filter")
            
            # Get agent data
            agents_data = await self._get_comprehensive_agent_data(
                include_inactive, group_filter, os_filter
            )
            
            # Calculate health scores and filter
            agents_with_health = []
            for agent in agents_data:
                health_score = self._calculate_agent_health_score(agent)
                agent["health_score"] = health_score
                agent["health_status"] = self._get_health_status(health_score)
                
                if health_score >= health_threshold:
                    agents_with_health.append(agent)
            
            # Generate comprehensive analysis
            analysis = {
                "overview": self._generate_agents_overview(agents_with_health),
                "health_distribution": self._analyze_health_distribution(agents_with_health),
                "connectivity_status": self._analyze_connectivity(agents_with_health),
                "os_distribution": self._analyze_os_distribution(agents_with_health),
                "group_analysis": self._analyze_agent_groups(agents_with_health),
                "alerts": self._generate_health_alerts(agents_with_health)
            }
            
            if include_performance:
                analysis["performance_metrics"] = await self._get_performance_metrics(agents_with_health)
            
            # Add recommendations
            analysis["recommendations"] = self._generate_agent_recommendations(analysis)
            
            return self._format_response(analysis, metadata={
                "source": "wazuh_agents",
                "analysis_type": "comprehensive_agent_monitoring",
                "filters_applied": {
                    "health_threshold": health_threshold,
                    "include_inactive": include_inactive,
                    "groups": group_filter or "all",
                    "os_types": os_filter or "all"
                }
            })
            
        except Exception as e:
            self.logger.error(f"Error in running agents analysis: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_running_agents"})
    
    async def handle_rules_summary(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle rules summary and effectiveness analysis."""
        try:
            # Validate input
            validated_args = validate_rules_summary_query(arguments)
            
            include_effectiveness = validated_args.get("include_effectiveness", True)
            time_range_hours = validated_args.get("time_range_hours", 24)
            rule_level_filter = validated_args.get("rule_level_filter", [])
            include_coverage_gaps = validated_args.get("include_coverage_gaps", True)
            group_by = validated_args.get("group_by", "category")
            
            # Get rules and alert data
            rules_data = await self._get_comprehensive_rules_data(rule_level_filter)
            
            if include_effectiveness:
                effectiveness_data = await self._analyze_rule_effectiveness(
                    rules_data, time_range_hours
                )
            else:
                effectiveness_data = {}
            
            # Generate comprehensive analysis
            analysis = {
                "overview": self._generate_rules_overview(rules_data),
                "distribution": self._analyze_rules_distribution(rules_data, group_by),
                "compliance_mapping": self._analyze_compliance_coverage(rules_data),
                "performance_analysis": self._analyze_rule_performance(rules_data)
            }
            
            if include_effectiveness:
                analysis["effectiveness"] = effectiveness_data
            
            if include_coverage_gaps:
                analysis["coverage_gaps"] = await self._analyze_coverage_gaps(rules_data)
            
            # Add actionable recommendations
            analysis["recommendations"] = self._generate_rules_recommendations(analysis)
            
            return self._format_response(analysis, metadata={
                "source": "wazuh_rules",
                "analysis_type": "comprehensive_rules_analysis",
                "time_range_hours": time_range_hours,
                "group_by": group_by
            })
            
        except Exception as e:
            self.logger.error(f"Error in rules summary analysis: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_rules_summary"})
    
    # Helper methods for agent monitoring
    async def _get_comprehensive_agent_data(self, include_inactive: bool, 
                                          group_filter: List[str] = None,
                                          os_filter: List[str] = None) -> List[Dict[str, Any]]:
        """Get comprehensive agent data from Wazuh."""
        # Get basic agent information
        agents_response = await self.api_client.get_agents(
            status="all" if include_inactive else "active"
        )
        
        agents = agents_response.get("data", {}).get("affected_items", [])
        
        # Apply filters
        filtered_agents = []
        for agent in agents:
            # Group filter
            if group_filter:
                agent_groups = agent.get("group", [])
                if not any(group in agent_groups for group in group_filter):
                    continue
            
            # OS filter
            if os_filter:
                agent_os = agent.get("os", {}).get("platform", "").lower()
                if not any(os_type.lower() in agent_os for os_type in os_filter):
                    continue
            
            # Enrich agent data
            enriched_agent = await self._enrich_agent_data(agent)
            filtered_agents.append(enriched_agent)
        
        return filtered_agents
    
    async def _enrich_agent_data(self, agent: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich agent data with additional metrics."""
        agent_id = agent.get("id")
        
        # Get additional agent information
        try:
            # Agent stats
            stats_response = await self.api_client.get_agent_stats(agent_id)
            agent_stats = stats_response.get("data", {})
            
            # Recent alerts for this agent
            alerts_response = await self.api_client.get_alerts(
                agent_id=agent_id,
                limit=100,
                time_range=3600  # Last hour
            )
            recent_alerts = alerts_response.get("data", {}).get("affected_items", [])
            
            return {
                **agent,
                "stats": agent_stats,
                "recent_alerts_count": len(recent_alerts),
                "recent_alerts": recent_alerts[:5],  # Last 5 alerts
                "last_alert_time": recent_alerts[0].get("timestamp") if recent_alerts else None,
                "enrichment_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.warning(f"Could not enrich agent {agent_id}: {str(e)}")
            return {
                **agent,
                "stats": {},
                "recent_alerts_count": 0,
                "recent_alerts": [],
                "enrichment_error": str(e)
            }
    
    def _calculate_agent_health_score(self, agent: Dict[str, Any]) -> int:
        """Calculate comprehensive health score for agent (0-100)."""
        score = 0
        
        # Connection status (40 points)
        status = agent.get("status", "").lower()
        if status == "active":
            score += 40
        elif status == "pending":
            score += 20
        elif status == "never_connected":
            score += 0
        else:  # disconnected
            score += 10
        
        # Last keep alive (20 points)
        last_keep_alive = agent.get("lastKeepAlive")
        if last_keep_alive:
            try:
                last_time = datetime.fromisoformat(last_keep_alive.replace("Z", "+00:00"))
                minutes_ago = (datetime.utcnow() - last_time.replace(tzinfo=None)).total_seconds() / 60
                
                if minutes_ago <= 5:
                    score += 20
                elif minutes_ago <= 15:
                    score += 15
                elif minutes_ago <= 60:
                    score += 10
                else:
                    score += 0
            except:
                score += 5  # Partial credit for having timestamp
        
        # Recent alerts activity (20 points)
        alerts_count = agent.get("recent_alerts_count", 0)
        if alerts_count > 0:
            # Active monitoring is good, but not too many alerts
            if alerts_count <= 10:
                score += 20
            elif alerts_count <= 50:
                score += 15
            else:
                score += 10  # Too many alerts might indicate issues
        else:
            score += 10  # No alerts could be good or bad
        
        # Agent configuration (10 points)
        if agent.get("group"):
            score += 5
        if agent.get("version"):
            score += 5
        
        # OS information completeness (10 points)
        os_info = agent.get("os", {})
        if os_info.get("platform"):
            score += 3
        if os_info.get("version"):
            score += 3
        if os_info.get("name"):
            score += 4
        
        return min(score, 100)
    
    def _get_health_status(self, health_score: int) -> str:
        """Get health status label from score."""
        if health_score >= 80:
            return "excellent"
        elif health_score >= 60:
            return "good"
        elif health_score >= 40:
            return "fair"
        elif health_score >= 20:
            return "poor"
        else:
            return "critical"
    
    def _generate_agents_overview(self, agents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate overview statistics for agents."""
        if not agents:
            return {"total": 0, "message": "No agents found"}
        
        status_counts = Counter(agent.get("status", "unknown") for agent in agents)
        health_scores = [agent.get("health_score", 0) for agent in agents]
        os_counts = Counter(
            agent.get("os", {}).get("platform", "unknown") for agent in agents
        )
        
        return {
            "total_agents": len(agents),
            "status_distribution": dict(status_counts),
            "health_metrics": {
                "average_health_score": sum(health_scores) / len(health_scores),
                "healthy_agents": sum(1 for score in health_scores if score >= 80),
                "agents_needing_attention": sum(1 for score in health_scores if score < 60)
            },
            "os_distribution": dict(os_counts.most_common()),
            "recent_activity": {
                "agents_with_recent_alerts": sum(
                    1 for agent in agents if agent.get("recent_alerts_count", 0) > 0
                ),
                "total_recent_alerts": sum(
                    agent.get("recent_alerts_count", 0) for agent in agents
                )
            }
        }
    
    def _analyze_health_distribution(self, agents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze distribution of agent health scores."""
        health_statuses = Counter(agent.get("health_status", "unknown") for agent in agents)
        
        # Group agents by health score ranges
        score_ranges = {
            "90-100": 0,
            "80-89": 0,
            "70-79": 0,
            "60-69": 0,
            "50-59": 0,
            "0-49": 0
        }
        
        for agent in agents:
            score = agent.get("health_score", 0)
            if score >= 90:
                score_ranges["90-100"] += 1
            elif score >= 80:
                score_ranges["80-89"] += 1
            elif score >= 70:
                score_ranges["70-79"] += 1
            elif score >= 60:
                score_ranges["60-69"] += 1
            elif score >= 50:
                score_ranges["50-59"] += 1
            else:
                score_ranges["0-49"] += 1
        
        return {
            "by_status": dict(health_statuses),
            "by_score_range": score_ranges,
            "critical_agents": [
                {
                    "id": agent.get("id"),
                    "name": agent.get("name"),
                    "health_score": agent.get("health_score"),
                    "status": agent.get("status"),
                    "issues": self._identify_agent_issues(agent)
                }
                for agent in agents if agent.get("health_score", 0) < 40
            ]
        }
    
    def _analyze_connectivity(self, agents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze agent connectivity patterns."""
        connectivity_issues = []
        last_contact_analysis = {"within_hour": 0, "within_day": 0, "older": 0}
        
        for agent in agents:
            last_keep_alive = agent.get("lastKeepAlive")
            if last_keep_alive:
                try:
                    last_time = datetime.fromisoformat(last_keep_alive.replace("Z", "+00:00"))
                    hours_ago = (datetime.utcnow() - last_time.replace(tzinfo=None)).total_seconds() / 3600
                    
                    if hours_ago <= 1:
                        last_contact_analysis["within_hour"] += 1
                    elif hours_ago <= 24:
                        last_contact_analysis["within_day"] += 1
                    else:
                        last_contact_analysis["older"] += 1
                        
                    # Flag connectivity issues
                    if hours_ago > 24 and agent.get("status") == "active":
                        connectivity_issues.append({
                            "agent_id": agent.get("id"),
                            "agent_name": agent.get("name"),
                            "last_contact": last_keep_alive,
                            "hours_since_contact": round(hours_ago, 2)
                        })
                except:
                    last_contact_analysis["older"] += 1
        
        return {
            "last_contact_distribution": last_contact_analysis,
            "connectivity_issues": connectivity_issues,
            "connectivity_health": "good" if len(connectivity_issues) == 0 else "needs_attention"
        }
    
    def _analyze_os_distribution(self, agents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze operating system distribution."""
        os_details = defaultdict(lambda: {"count": 0, "versions": set(), "agents": []})
        
        for agent in agents:
            os_info = agent.get("os", {})
            platform = os_info.get("platform", "unknown")
            version = os_info.get("version", "unknown")
            
            os_details[platform]["count"] += 1
            os_details[platform]["versions"].add(version)
            os_details[platform]["agents"].append({
                "id": agent.get("id"),
                "name": agent.get("name"),
                "version": version
            })
        
        # Convert sets to lists for JSON serialization
        for platform_data in os_details.values():
            platform_data["versions"] = list(platform_data["versions"])
            platform_data["unique_versions"] = len(platform_data["versions"])
        
        return {
            "platforms": dict(os_details),
            "diversity_score": len(os_details),
            "version_fragmentation": {
                platform: data["unique_versions"] 
                for platform, data in os_details.items()
            }
        }
    
    def _analyze_agent_groups(self, agents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze agent group distribution and health."""
        group_analysis = defaultdict(lambda: {
            "agents": [],
            "health_scores": [],
            "status_distribution": Counter()
        })
        
        for agent in agents:
            groups = agent.get("group", ["default"])
            for group in groups:
                group_data = group_analysis[group]
                group_data["agents"].append(agent.get("id"))
                group_data["health_scores"].append(agent.get("health_score", 0))
                group_data["status_distribution"][agent.get("status", "unknown")] += 1
        
        # Calculate group health metrics
        group_health = {}
        for group, data in group_analysis.items():
            health_scores = data["health_scores"]
            group_health[group] = {
                "agent_count": len(data["agents"]),
                "average_health": sum(health_scores) / len(health_scores) if health_scores else 0,
                "status_distribution": dict(data["status_distribution"]),
                "health_rating": self._get_health_status(
                    sum(health_scores) / len(health_scores) if health_scores else 0
                )
            }
        
        return {
            "groups": group_health,
            "total_groups": len(group_analysis),
            "healthiest_group": max(group_health.items(), key=lambda x: x[1]["average_health"])[0] if group_health else None,
            "groups_needing_attention": [
                group for group, data in group_health.items() 
                if data["average_health"] < 60
            ]
        }
    
    def _generate_health_alerts(self, agents: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate health alerts for agents."""
        alerts = []
        
        # Critical health agents
        critical_agents = [a for a in agents if a.get("health_score", 0) < 40]
        if critical_agents:
            alerts.append({
                "level": "critical",
                "type": "poor_health",
                "message": f"{len(critical_agents)} agents have critical health scores",
                "affected_agents": [a.get("id") for a in critical_agents],
                "recommendation": "Investigate connectivity and configuration issues"
            })
        
        # Disconnected agents
        disconnected = [a for a in agents if a.get("status") == "disconnected"]
        if disconnected:
            alerts.append({
                "level": "warning",
                "type": "disconnected",
                "message": f"{len(disconnected)} agents are disconnected",
                "affected_agents": [a.get("id") for a in disconnected],
                "recommendation": "Check network connectivity and agent services"
            })
        
        # High alert volume
        high_alert_agents = [a for a in agents if a.get("recent_alerts_count", 0) > 50]
        if high_alert_agents:
            alerts.append({
                "level": "warning",
                "type": "high_alert_volume",
                "message": f"{len(high_alert_agents)} agents have unusually high alert volume",
                "affected_agents": [a.get("id") for a in high_alert_agents],
                "recommendation": "Review alert configuration and investigate potential issues"
            })
        
        return alerts
    
    async def _get_performance_metrics(self, agents: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get performance metrics for agents."""
        performance_data = {
            "response_times": [],
            "memory_usage": [],
            "cpu_usage": [],
            "network_metrics": []
        }
        
        for agent in agents:
            stats = agent.get("stats", {})
            
            # Mock performance data (would come from actual agent stats)
            if stats:
                performance_data["response_times"].append({
                    "agent_id": agent.get("id"),
                    "response_time_ms": stats.get("response_time", 100)
                })
                performance_data["memory_usage"].append({
                    "agent_id": agent.get("id"),
                    "memory_mb": stats.get("memory_usage", 50)
                })
        
        return {
            "summary": {
                "total_agents_with_metrics": len([a for a in agents if a.get("stats")]),
                "average_response_time": sum(
                    m["response_time_ms"] for m in performance_data["response_times"]
                ) / len(performance_data["response_times"]) if performance_data["response_times"] else 0
            },
            "details": performance_data
        }
    
    def _generate_agent_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on agent analysis."""
        recommendations = []
        
        overview = analysis.get("overview", {})
        health_metrics = overview.get("health_metrics", {})
        
        # Health-based recommendations
        if health_metrics.get("agents_needing_attention", 0) > 0:
            recommendations.append(
                f"Address {health_metrics['agents_needing_attention']} agents with poor health scores"
            )
        
        # Connectivity recommendations
        connectivity = analysis.get("connectivity_status", {})
        if connectivity.get("connectivity_issues", []):
            recommendations.append("Investigate connectivity issues with flagged agents")
        
        # Group recommendations
        group_analysis = analysis.get("group_analysis", {})
        problematic_groups = group_analysis.get("groups_needing_attention", [])
        if problematic_groups:
            recommendations.append(f"Review configuration for groups: {', '.join(problematic_groups)}")
        
        # OS diversity recommendations
        os_dist = analysis.get("os_distribution", {})
        if os_dist.get("diversity_score", 0) > 5:
            recommendations.append("Consider standardizing OS versions for easier management")
        
        return recommendations
    
    # Helper methods for rules analysis
    async def _get_comprehensive_rules_data(self, level_filter: List[int] = None) -> List[Dict[str, Any]]:
        """Get comprehensive rules data from Wazuh."""
        # Get rules information
        rules_response = await self.api_client.get_rules()
        rules = rules_response.get("data", {}).get("affected_items", [])
        
        # Apply level filter
        if level_filter:
            rules = [rule for rule in rules if rule.get("level", 0) in level_filter]
        
        # Enrich rules with additional metadata
        enriched_rules = []
        for rule in rules:
            enriched_rule = {
                **rule,
                "effectiveness_score": self._calculate_rule_effectiveness(rule),
                "compliance_mappings": self._get_rule_compliance_mappings(rule),
                "category": self._categorize_rule(rule)
            }
            enriched_rules.append(enriched_rule)
        
        return enriched_rules
    
    async def _analyze_rule_effectiveness(self, rules: List[Dict[str, Any]], 
                                        time_range_hours: int) -> Dict[str, Any]:
        """Analyze rule effectiveness based on alert patterns."""
        effectiveness_data = {
            "active_rules": [],
            "inactive_rules": [],
            "top_performing_rules": [],
            "underperforming_rules": []
        }
        
        # Get alerts for the time range
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        alerts_response = await self.api_client.get_alerts(
            limit=10000,
            time_range=time_range_hours * 3600
        )
        alerts = alerts_response.get("data", {}).get("affected_items", [])
        
        # Analyze rule usage
        rule_usage = Counter(alert.get("rule", {}).get("id") for alert in alerts)
        
        for rule in rules:
            rule_id = rule.get("id")
            alert_count = rule_usage.get(rule_id, 0)
            
            rule_analysis = {
                "rule_id": rule_id,
                "description": rule.get("description", ""),
                "level": rule.get("level", 0),
                "alerts_generated": alert_count,
                "effectiveness_score": rule.get("effectiveness_score", 0)
            }
            
            if alert_count > 0:
                effectiveness_data["active_rules"].append(rule_analysis)
                if alert_count > 10:  # High activity
                    effectiveness_data["top_performing_rules"].append(rule_analysis)
            else:
                effectiveness_data["inactive_rules"].append(rule_analysis)
                if rule.get("level", 0) >= 10:  # High level but no alerts
                    effectiveness_data["underperforming_rules"].append(rule_analysis)
        
        return effectiveness_data
    
    def _calculate_rule_effectiveness(self, rule: Dict[str, Any]) -> int:
        """Calculate effectiveness score for a rule (0-100)."""
        score = 0
        
        # Level scoring (0-30 points)
        level = rule.get("level", 0)
        score += min(level * 2, 30)
        
        # Groups and categories (0-20 points)
        groups = rule.get("groups", [])
        if groups:
            score += 10
            # Bonus for important categories
            important_groups = ["authentication", "firewall", "intrusion_detection", "malware"]
            if any(group in important_groups for group in groups):
                score += 10
        
        # Description quality (0-20 points)
        description = rule.get("description", "")
        if description:
            score += 10
            if len(description) > 50:  # Detailed description
                score += 10
        
        # Compliance mappings (0-15 points)
        if rule.get("pci_dss"):
            score += 5
        if rule.get("hipaa"):
            score += 5
        if rule.get("gdpr"):
            score += 5
        
        # Rule complexity (0-15 points)
        if rule.get("regex"):
            score += 5
        if rule.get("decoded_as"):
            score += 5
        if rule.get("if_sid"):
            score += 5
        
        return min(score, 100)
    
    def _get_rule_compliance_mappings(self, rule: Dict[str, Any]) -> List[str]:
        """Get compliance framework mappings for rule."""
        mappings = []
        
        if rule.get("pci_dss"):
            mappings.append("PCI_DSS")
        if rule.get("hipaa"):
            mappings.append("HIPAA")
        if rule.get("gdpr"):
            mappings.append("GDPR")
        if rule.get("tsc"):
            mappings.append("TSC")
        if rule.get("nist_800_53"):
            mappings.append("NIST_800_53")
        
        return mappings
    
    def _categorize_rule(self, rule: Dict[str, Any]) -> str:
        """Categorize rule based on groups and description."""
        groups = rule.get("groups", [])
        description = rule.get("description", "").lower()
        
        # Category mapping
        if any("authentication" in group for group in groups) or "login" in description:
            return "authentication"
        elif any("firewall" in group for group in groups) or "firewall" in description:
            return "network_security"
        elif any("intrusion" in group for group in groups) or "intrusion" in description:
            return "intrusion_detection"
        elif any("malware" in group for group in groups) or "malware" in description:
            return "malware_detection"
        elif any("compliance" in group for group in groups):
            return "compliance"
        elif any("web" in group for group in groups) or "web" in description:
            return "web_security"
        elif any("system" in group for group in groups) or "system" in description:
            return "system_monitoring"
        else:
            return "general"
    
    def _generate_rules_overview(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate overview statistics for rules."""
        if not rules:
            return {"total": 0, "message": "No rules found"}
        
        level_dist = Counter(rule.get("level", 0) for rule in rules)
        category_dist = Counter(rule.get("category", "unknown") for rule in rules)
        effectiveness_scores = [rule.get("effectiveness_score", 0) for rule in rules]
        
        return {
            "total_rules": len(rules),
            "level_distribution": dict(level_dist),
            "category_distribution": dict(category_dist),
            "effectiveness_metrics": {
                "average_effectiveness": sum(effectiveness_scores) / len(effectiveness_scores),
                "high_effectiveness_rules": sum(1 for score in effectiveness_scores if score >= 80),
                "low_effectiveness_rules": sum(1 for score in effectiveness_scores if score < 40)
            },
            "compliance_coverage": {
                framework: sum(1 for rule in rules if framework in rule.get("compliance_mappings", []))
                for framework in ["PCI_DSS", "HIPAA", "GDPR", "NIST_800_53"]
            }
        }
    
    def _analyze_rules_distribution(self, rules: List[Dict[str, Any]], group_by: str) -> Dict[str, Any]:
        """Analyze rules distribution by specified grouping."""
        distribution = defaultdict(list)
        
        for rule in rules:
            if group_by == "level":
                key = rule.get("level", 0)
            elif group_by == "category":
                key = rule.get("category", "unknown")
            elif group_by == "source":
                key = rule.get("filename", "unknown")
            elif group_by == "compliance":
                mappings = rule.get("compliance_mappings", [])
                key = mappings[0] if mappings else "none"
            else:
                key = "all"
            
            distribution[key].append(rule)
        
        # Generate statistics for each group
        group_stats = {}
        for key, group_rules in distribution.items():
            effectiveness_scores = [r.get("effectiveness_score", 0) for r in group_rules]
            group_stats[str(key)] = {
                "count": len(group_rules),
                "average_effectiveness": sum(effectiveness_scores) / len(effectiveness_scores) if effectiveness_scores else 0,
                "level_range": {
                    "min": min(r.get("level", 0) for r in group_rules),
                    "max": max(r.get("level", 0) for r in group_rules)
                } if group_rules else {"min": 0, "max": 0}
            }
        
        return {
            "grouped_by": group_by,
            "groups": group_stats,
            "total_groups": len(distribution)
        }
    
    def _analyze_compliance_coverage(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze compliance framework coverage."""
        frameworks = ["PCI_DSS", "HIPAA", "GDPR", "NIST_800_53", "TSC"]
        coverage = {}
        
        for framework in frameworks:
            framework_rules = [
                rule for rule in rules 
                if framework in rule.get("compliance_mappings", [])
            ]
            
            coverage[framework] = {
                "total_rules": len(framework_rules),
                "coverage_percentage": (len(framework_rules) / len(rules)) * 100 if rules else 0,
                "high_level_rules": len([r for r in framework_rules if r.get("level", 0) >= 10]),
                "categories_covered": len(set(r.get("category") for r in framework_rules))
            }
        
        return coverage
    
    def _analyze_rule_performance(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze rule performance characteristics."""
        # Group rules by performance characteristics
        high_performance = [r for r in rules if r.get("effectiveness_score", 0) >= 80]
        medium_performance = [r for r in rules if 40 <= r.get("effectiveness_score", 0) < 80]
        low_performance = [r for r in rules if r.get("effectiveness_score", 0) < 40]
        
        return {
            "performance_tiers": {
                "high": {
                    "count": len(high_performance),
                    "percentage": (len(high_performance) / len(rules)) * 100 if rules else 0
                },
                "medium": {
                    "count": len(medium_performance),
                    "percentage": (len(medium_performance) / len(rules)) * 100 if rules else 0
                },
                "low": {
                    "count": len(low_performance),
                    "percentage": (len(low_performance) / len(rules)) * 100 if rules else 0
                }
            },
            "optimization_candidates": [
                {
                    "rule_id": rule.get("id"),
                    "description": rule.get("description", ""),
                    "current_score": rule.get("effectiveness_score", 0),
                    "level": rule.get("level", 0)
                }
                for rule in low_performance[:10]  # Top 10 candidates for optimization
            ]
        }
    
    async def _analyze_coverage_gaps(self, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze potential coverage gaps in rule set."""
        gaps = {
            "category_gaps": [],
            "compliance_gaps": [],
            "level_gaps": [],
            "recommendations": []
        }
        
        # Analyze category coverage
        categories = set(rule.get("category") for rule in rules)
        expected_categories = {
            "authentication", "network_security", "intrusion_detection",
            "malware_detection", "web_security", "system_monitoring", "compliance"
        }
        missing_categories = expected_categories - categories
        
        if missing_categories:
            gaps["category_gaps"] = list(missing_categories)
            gaps["recommendations"].append(
                f"Consider adding rules for missing categories: {', '.join(missing_categories)}"
            )
        
        # Analyze level distribution gaps
        level_dist = Counter(rule.get("level", 0) for rule in rules)
        if not any(level >= 12 for level in level_dist.keys()):
            gaps["level_gaps"].append("No critical level rules (12+)")
            gaps["recommendations"].append("Add critical level rules for high-priority threats")
        
        # Analyze compliance gaps
        frameworks = ["PCI_DSS", "HIPAA", "GDPR"]
        for framework in frameworks:
            framework_rules = [
                r for r in rules if framework in r.get("compliance_mappings", [])
            ]
            coverage_percent = (len(framework_rules) / len(rules)) * 100 if rules else 0
            
            if coverage_percent < 20:  # Less than 20% coverage
                gaps["compliance_gaps"].append(f"Low {framework} coverage ({coverage_percent:.1f}%)")
                gaps["recommendations"].append(f"Increase {framework} compliance rule coverage")
        
        return gaps
    
    def _generate_rules_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on rules analysis."""
        recommendations = []
        
        overview = analysis.get("overview", {})
        effectiveness = overview.get("effectiveness_metrics", {})
        
        # Effectiveness recommendations
        if effectiveness.get("low_effectiveness_rules", 0) > 0:
            recommendations.append(
                f"Review and optimize {effectiveness['low_effectiveness_rules']} low-effectiveness rules"
            )
        
        # Coverage recommendations
        coverage_gaps = analysis.get("coverage_gaps", {})
        if coverage_gaps.get("category_gaps"):
            recommendations.append("Add rules for missing security categories")
        
        # Performance recommendations
        performance = analysis.get("performance_analysis", {})
        optimization_candidates = performance.get("optimization_candidates", [])
        if optimization_candidates:
            recommendations.append(f"Optimize {len(optimization_candidates)} underperforming rules")
        
        # Compliance recommendations
        compliance = analysis.get("compliance_mapping", {})
        low_coverage_frameworks = [
            framework for framework, data in compliance.items()
            if data.get("coverage_percentage", 0) < 50
        ]
        if low_coverage_frameworks:
            recommendations.append(
                f"Improve compliance coverage for: {', '.join(low_coverage_frameworks)}"
            )
        
        return recommendations
    
    def _identify_agent_issues(self, agent: Dict[str, Any]) -> List[str]:
        """Identify specific issues with an agent."""
        issues = []
        
        # Status issues
        if agent.get("status") == "disconnected":
            issues.append("Agent disconnected")
        elif agent.get("status") == "never_connected":
            issues.append("Agent never connected")
        
        # Connectivity issues
        last_keep_alive = agent.get("lastKeepAlive")
        if last_keep_alive:
            try:
                last_time = datetime.fromisoformat(last_keep_alive.replace("Z", "+00:00"))
                hours_ago = (datetime.utcnow() - last_time.replace(tzinfo=None)).total_seconds() / 3600
                if hours_ago > 24:
                    issues.append(f"No contact for {int(hours_ago)} hours")
            except:
                issues.append("Invalid last keep alive timestamp")
        
        # Alert volume issues
        alert_count = agent.get("recent_alerts_count", 0)
        if alert_count > 100:
            issues.append("Unusually high alert volume")
        elif alert_count == 0:
            issues.append("No recent alerts (possible monitoring gap)")
        
        # Configuration issues
        if not agent.get("group"):
            issues.append("No group assignment")
        
        return issues