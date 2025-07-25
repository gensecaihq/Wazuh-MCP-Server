"""Alert-related tools for Wazuh MCP Server."""

from typing import Any, Dict, List
import mcp.types as types

from .base import BaseTool
from ..utils import validate_alert_query, validate_alert_summary_query


class AlertTools(BaseTool):
    """Tools for handling Wazuh alerts and alert analysis."""
    
    @property
    def tool_definitions(self) -> List[types.Tool]:
        """Return alert-related tool definitions."""
        return [
            types.Tool(
                name="get_alerts",
                description="Retrieve Wazuh alerts with advanced filtering and validation",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of alerts to retrieve",
                            "default": 100,
                            "minimum": 1,
                            "maximum": 10000
                        },
                        "level": {
                            "type": "integer",
                            "description": "Minimum alert level (1-15)",
                            "minimum": 1,
                            "maximum": 15
                        },
                        "time_range": {
                            "type": "integer",
                            "description": "Time range in seconds (e.g., 3600 for last hour)",
                            "minimum": 300,
                            "maximum": 86400
                        },
                        "agent_id": {
                            "type": "string",
                            "description": "Filter alerts by specific agent ID"
                        }
                    }
                }
            ),
            types.Tool(
                name="alert_summary",
                description="Generate comprehensive alert summary with statistics and trends",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "time_range": {
                            "type": "integer",
                            "description": "Time range in seconds for analysis",
                            "default": 3600,
                            "minimum": 300,
                            "maximum": 86400
                        },
                        "group_by": {
                            "type": "string",
                            "description": "Group alerts by field",
                            "enum": ["rule_id", "agent_id", "level", "location"],
                            "default": "level"
                        },
                        "include_trends": {
                            "type": "boolean",
                            "description": "Include trend analysis",
                            "default": True
                        }
                    }
                }
            )
        ]
    
    def get_handler_mapping(self) -> Dict[str, callable]:
        """Return mapping of tool names to handler methods."""
        return {
            "get_alerts": self.handle_get_alerts,
            "alert_summary": self.handle_alert_summary
        }
    
    async def handle_get_alerts(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get_alerts tool call."""
        try:
            # Validate input
            validated_args = validate_alert_query(arguments)
            
            # Get alerts from API
            response = await self.api_client.get_alerts(
                limit=validated_args.get("limit", 100),
                level=validated_args.get("level"),
                time_range=validated_args.get("time_range"),
                agent_id=validated_args.get("agent_id")
            )
            
            # Format response
            alerts = response.get("data", {}).get("affected_items", [])
            
            # Add enrichment information
            enriched_alerts = []
            for alert in alerts:
                enriched_alert = {
                    **alert,
                    "enrichment": {
                        "risk_score": self._calculate_risk_score(alert),
                        "severity_label": self._get_severity_label(alert.get("rule", {}).get("level", 0)),
                        "category": self._categorize_alert(alert)
                    }
                }
                enriched_alerts.append(enriched_alert)
            
            return self._format_response({
                "alerts": enriched_alerts,
                "total_count": len(enriched_alerts),
                "query_params": validated_args
            }, metadata={
                "source": "wazuh_api",
                "enrichment_enabled": True
            })
            
        except Exception as e:
            self.logger.error(f"Error retrieving alerts: {str(e)}")
            return self._format_error_response(e, {"operation": "get_alerts"})
    
    async def handle_alert_summary(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle alert_summary tool call."""
        try:
            # Validate input
            validated_args = validate_alert_summary_query(arguments)
            
            # Get alerts for analysis
            response = await self.api_client.get_alerts(
                limit=10000,  # Get larger dataset for analysis
                time_range=validated_args.get("time_range", 3600)
            )
            
            alerts = response.get("data", {}).get("affected_items", [])
            
            # Generate summary statistics
            summary = self._generate_alert_summary(
                alerts, 
                group_by=validated_args.get("group_by", "level"),
                include_trends=validated_args.get("include_trends", True)
            )
            
            return self._format_response(summary, metadata={
                "analysis_period": validated_args.get("time_range", 3600),
                "total_alerts_analyzed": len(alerts)
            })
            
        except Exception as e:
            self.logger.error(f"Error generating alert summary: {str(e)}")
            return self._format_error_response(e, {"operation": "alert_summary"})
    
    def _calculate_risk_score(self, alert: Dict[str, Any]) -> int:
        """Calculate risk score for an alert."""
        level = alert.get("rule", {}).get("level", 0)
        base_score = min(level * 10, 100)
        
        # Adjust based on agent criticality
        agent_id = alert.get("agent", {}).get("id")
        if agent_id in getattr(self.config, 'critical_agents', []):
            base_score = min(base_score * 1.5, 100)
        
        return int(base_score)
    
    def _get_severity_label(self, level: int) -> str:
        """Get severity label for alert level."""
        if level >= 12:
            return "critical"
        elif level >= 8:
            return "high"
        elif level >= 4:
            return "medium"
        else:
            return "low"
    
    def _categorize_alert(self, alert: Dict[str, Any]) -> str:
        """Categorize alert based on rule information."""
        rule = alert.get("rule", {})
        groups = rule.get("groups", [])
        
        if any("authentication" in group.lower() for group in groups):
            return "authentication"
        elif any("intrusion" in group.lower() for group in groups):
            return "intrusion"
        elif any("malware" in group.lower() for group in groups):
            return "malware"
        elif any("compliance" in group.lower() for group in groups):
            return "compliance"
        else:
            return "general"
    
    def _generate_alert_summary(self, alerts: List[Dict[str, Any]], 
                               group_by: str, include_trends: bool) -> Dict[str, Any]:
        """Generate comprehensive alert summary."""
        from collections import defaultdict
        from datetime import datetime, timedelta
        
        # Group alerts
        grouped = defaultdict(list)
        for alert in alerts:
            if group_by == "level":
                key = alert.get("rule", {}).get("level", 0)
            elif group_by == "rule_id":
                key = alert.get("rule", {}).get("id", "unknown")
            elif group_by == "agent_id":
                key = alert.get("agent", {}).get("id", "unknown")
            elif group_by == "location":
                key = alert.get("location", "unknown")
            else:
                key = "all"
            
            grouped[key].append(alert)
        
        # Generate summary
        summary = {
            "total_alerts": len(alerts),
            "grouped_stats": {
                str(key): {
                    "count": len(group_alerts),
                    "percentage": round(len(group_alerts) / len(alerts) * 100, 2) if alerts else 0
                }
                for key, group_alerts in grouped.items()
            },
            "severity_distribution": self._get_severity_distribution(alerts),
            "top_rules": self._get_top_rules(alerts),
            "top_agents": self._get_top_agents(alerts)
        }
        
        if include_trends:
            summary["trends"] = self._calculate_trends(alerts)
        
        return summary
    
    def _get_severity_distribution(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get distribution of alerts by severity."""
        distribution = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for alert in alerts:
            level = alert.get("rule", {}).get("level", 0)
            severity = self._get_severity_label(level)
            distribution[severity] += 1
        
        return distribution
    
    def _get_top_rules(self, alerts: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top rules by alert count."""
        from collections import Counter
        
        rule_counts = Counter()
        for alert in alerts:
            rule_id = alert.get("rule", {}).get("id", "unknown")
            rule_description = alert.get("rule", {}).get("description", "")
            rule_counts[(rule_id, rule_description)] += 1
        
        return [
            {"rule_id": rule_info[0], "description": rule_info[1], "count": count}
            for rule_info, count in rule_counts.most_common(limit)
        ]
    
    def _get_top_agents(self, alerts: List[Dict[str, Any]], limit: int = 10) -> List[Dict[str, Any]]:
        """Get top agents by alert count."""
        from collections import Counter
        
        agent_counts = Counter()
        for alert in alerts:
            agent_id = alert.get("agent", {}).get("id", "unknown")
            agent_name = alert.get("agent", {}).get("name", "")
            agent_counts[(agent_id, agent_name)] += 1
        
        return [
            {"agent_id": agent_info[0], "name": agent_info[1], "count": count}
            for agent_info, count in agent_counts.most_common(limit)
        ]
    
    def _calculate_trends(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate alert trends over time."""
        from collections import defaultdict
        from datetime import datetime
        
        # Group alerts by hour
        hourly_counts = defaultdict(int)
        for alert in alerts:
            timestamp = alert.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                hour_key = dt.strftime("%H:00")
                hourly_counts[hour_key] += 1
            except (ValueError, AttributeError):
                continue
        
        # Calculate trend direction
        counts = list(hourly_counts.values())
        if len(counts) >= 2:
            recent_avg = sum(counts[-3:]) / min(3, len(counts))
            earlier_avg = sum(counts[:-3]) / max(1, len(counts) - 3) if len(counts) > 3 else 0
            
            if recent_avg > earlier_avg * 1.2:
                trend = "increasing"
            elif recent_avg < earlier_avg * 0.8:
                trend = "decreasing"
            else:
                trend = "stable"
        else:
            trend = "insufficient_data"
        
        return {
            "hourly_distribution": dict(hourly_counts),
            "trend_direction": trend,
            "peak_hour": max(hourly_counts.items(), key=lambda x: x[1])[0] if hourly_counts else None
        }