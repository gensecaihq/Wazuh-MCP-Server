"""Statistics and monitoring tools for Wazuh MCP Server."""

from typing import Any, Dict, List
import mcp.types as types
from datetime import datetime, timedelta
from collections import defaultdict, Counter

from .base import BaseTool
from ..utils import validate_time_range, validate_agent_id


class StatisticsTools(BaseTool):
    """Tools for Wazuh statistics, monitoring, and advanced analytics."""
    
    @property
    def tool_definitions(self) -> List[types.Tool]:
        """Return statistics-related tool definitions."""
        return [
            types.Tool(
                name="get_wazuh_alert_summary",
                description="Get comprehensive alert statistics with trend detection and anomaly analysis",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "time_range": {
                            "type": "integer",
                            "description": "Time range in seconds (e.g., 3600 for last hour)",
                            "default": 3600,
                            "minimum": 300,
                            "maximum": 604800
                        },
                        "include_anomalies": {
                            "type": "boolean",
                            "description": "Include anomaly detection in analysis",
                            "default": True
                        },
                        "include_predictions": {
                            "type": "boolean",
                            "description": "Include trend predictions",
                            "default": False
                        }
                    }
                }
            ),
            types.Tool(
                name="get_wazuh_weekly_stats",
                description="Get weekly statistics with anomaly detection and pattern analysis",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "weeks": {
                            "type": "integer",
                            "description": "Number of weeks to analyze",
                            "default": 1,
                            "minimum": 1,
                            "maximum": 4
                        },
                        "compare_previous": {
                            "type": "boolean",
                            "description": "Compare with previous period",
                            "default": True
                        }
                    }
                }
            ),
            types.Tool(
                name="get_wazuh_remoted_stats",
                description="Get remote daemon statistics and communication health metrics",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "include_performance": {
                            "type": "boolean",
                            "description": "Include performance metrics",
                            "default": True
                        }
                    }
                }
            ),
            types.Tool(
                name="get_wazuh_log_collector_stats",
                description="Get log collector statistics with coverage and performance analysis",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "agent_id": {
                            "type": "string",
                            "description": "Specific agent ID (optional)"
                        },
                        "include_file_analysis": {
                            "type": "boolean",
                            "description": "Include per-file statistics",
                            "default": True
                        }
                    }
                }
            )
        ]
    
    def get_handler_mapping(self) -> Dict[str, callable]:
        """Return mapping of tool names to handler methods."""
        return {
            "get_wazuh_alert_summary": self.handle_alert_summary_advanced,
            "get_wazuh_weekly_stats": self.handle_weekly_stats,
            "get_wazuh_remoted_stats": self.handle_remoted_stats,
            "get_wazuh_log_collector_stats": self.handle_log_collector_stats
        }
    
    async def handle_alert_summary_advanced(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle advanced alert summary with trend detection."""
        try:
            time_range = arguments.get("time_range", 3600)
            include_anomalies = arguments.get("include_anomalies", True)
            include_predictions = arguments.get("include_predictions", False)
            
            # Get alerts for analysis
            response = await self.api_client.get_alerts(
                limit=10000,
                time_range=time_range
            )
            
            alerts = response.get("data", {}).get("affected_items", [])
            
            # Generate comprehensive summary
            summary = {
                "overview": {
                    "total_alerts": len(alerts),
                    "time_range_seconds": time_range,
                    "analysis_timestamp": datetime.utcnow().isoformat()
                },
                "statistics": self._calculate_alert_statistics(alerts),
                "patterns": self._detect_alert_patterns(alerts),
                "top_indicators": self._get_top_indicators(alerts)
            }
            
            if include_anomalies:
                summary["anomalies"] = self._detect_anomalies(alerts)
            
            if include_predictions:
                summary["predictions"] = self._generate_predictions(alerts)
            
            return self._format_response(summary, metadata={
                "source": "wazuh_api",
                "analysis_type": "advanced_alert_summary"
            })
            
        except Exception as e:
            self.logger.error(f"Error in advanced alert summary: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_alert_summary"})
    
    async def handle_weekly_stats(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle weekly statistics with anomaly detection."""
        try:
            weeks = arguments.get("weeks", 1)
            compare_previous = arguments.get("compare_previous", True)
            
            # Calculate time ranges
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(weeks=weeks)
            
            # Get statistics from API
            stats_response = await self.api_client.get_manager_stats(
                date_from=start_time.strftime("%Y-%m-%d"),
                date_to=end_time.strftime("%Y-%m-%d")
            )
            
            weekly_stats = {
                "period": {
                    "weeks": weeks,
                    "start_date": start_time.isoformat(),
                    "end_date": end_time.isoformat()
                },
                "alerts": self._analyze_weekly_alerts(stats_response),
                "events": self._analyze_weekly_events(stats_response),
                "performance": self._analyze_weekly_performance(stats_response)
            }
            
            if compare_previous:
                # Get previous period for comparison
                prev_end = start_time
                prev_start = prev_end - timedelta(weeks=weeks)
                
                prev_response = await self.api_client.get_manager_stats(
                    date_from=prev_start.strftime("%Y-%m-%d"),
                    date_to=prev_end.strftime("%Y-%m-%d")
                )
                
                weekly_stats["comparison"] = self._compare_periods(stats_response, prev_response)
            
            # Detect anomalies in weekly patterns
            weekly_stats["anomalies"] = self._detect_weekly_anomalies(stats_response)
            
            return self._format_response(weekly_stats, metadata={
                "analysis_type": "weekly_statistics"
            })
            
        except Exception as e:
            self.logger.error(f"Error in weekly stats: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_weekly_stats"})
    
    async def handle_remoted_stats(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle remote daemon statistics."""
        try:
            include_performance = arguments.get("include_performance", True)
            
            # Get remoted stats
            stats_response = await self.api_client.get_remoted_stats()
            
            remoted_stats = {
                "daemon_status": self._get_daemon_status(stats_response),
                "connection_stats": self._analyze_connections(stats_response),
                "message_stats": self._analyze_message_flow(stats_response),
                "queue_stats": self._analyze_queues(stats_response)
            }
            
            if include_performance:
                remoted_stats["performance"] = self._analyze_remoted_performance(stats_response)
            
            # Add health assessment
            remoted_stats["health_assessment"] = self._assess_remoted_health(remoted_stats)
            
            return self._format_response(remoted_stats, metadata={
                "source": "wazuh_remoted",
                "analysis_type": "daemon_statistics"
            })
            
        except Exception as e:
            self.logger.error(f"Error in remoted stats: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_remoted_stats"})
    
    async def handle_log_collector_stats(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle log collector statistics."""
        try:
            agent_id = arguments.get("agent_id")
            include_file_analysis = arguments.get("include_file_analysis", True)
            
            if agent_id:
                # Get stats for specific agent
                stats_response = await self.api_client.get_agent_stats(
                    agent_id=agent_id,
                    component="logcollector"
                )
            else:
                # Get global log collector stats
                stats_response = await self.api_client.get_manager_stats(
                    component="logcollector"
                )
            
            collector_stats = {
                "overview": self._get_collector_overview(stats_response),
                "coverage": self._analyze_log_coverage(stats_response),
                "performance": self._analyze_collector_performance(stats_response)
            }
            
            if include_file_analysis:
                collector_stats["file_analysis"] = self._analyze_monitored_files(stats_response)
            
            # Add recommendations
            collector_stats["recommendations"] = self._generate_collector_recommendations(collector_stats)
            
            return self._format_response(collector_stats, metadata={
                "source": "wazuh_logcollector",
                "agent_id": agent_id,
                "analysis_type": "log_collector_statistics"
            })
            
        except Exception as e:
            self.logger.error(f"Error in log collector stats: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_log_collector_stats"})
    
    # Helper methods for alert summary
    def _calculate_alert_statistics(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate comprehensive alert statistics."""
        if not alerts:
            return {"message": "No alerts to analyze"}
        
        # Time-based analysis
        timestamps = []
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert.get("timestamp", "").replace("Z", "+00:00"))
                timestamps.append(ts)
            except:
                continue
        
        if timestamps:
            time_stats = {
                "earliest_alert": min(timestamps).isoformat(),
                "latest_alert": max(timestamps).isoformat(),
                "alert_rate_per_hour": len(alerts) / ((max(timestamps) - min(timestamps)).total_seconds() / 3600) if len(timestamps) > 1 else 0
            }
        else:
            time_stats = {}
        
        # Level distribution
        level_dist = Counter(alert.get("rule", {}).get("level", 0) for alert in alerts)
        
        # Agent distribution
        agent_dist = Counter(alert.get("agent", {}).get("id", "unknown") for alert in alerts)
        
        return {
            "time_statistics": time_stats,
            "level_distribution": dict(level_dist),
            "agent_distribution": dict(agent_dist.most_common(10)),
            "unique_rules": len(set(alert.get("rule", {}).get("id") for alert in alerts)),
            "unique_agents": len(agent_dist)
        }
    
    def _detect_alert_patterns(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Detect patterns in alerts."""
        patterns = {
            "temporal_patterns": [],
            "rule_patterns": [],
            "agent_patterns": []
        }
        
        # Temporal pattern detection
        hourly_dist = defaultdict(int)
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert.get("timestamp", "").replace("Z", "+00:00"))
                hourly_dist[ts.hour] += 1
            except:
                continue
        
        if hourly_dist:
            peak_hour = max(hourly_dist.items(), key=lambda x: x[1])
            patterns["temporal_patterns"].append({
                "type": "peak_hour",
                "hour": peak_hour[0],
                "count": peak_hour[1],
                "percentage": round(peak_hour[1] / len(alerts) * 100, 2)
            })
        
        # Rule pattern detection
        rule_sequences = self._detect_rule_sequences(alerts)
        if rule_sequences:
            patterns["rule_patterns"] = rule_sequences[:5]  # Top 5 sequences
        
        return patterns
    
    def _detect_anomalies(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalies in alert data."""
        anomalies = []
        
        # Detect unusual alert spikes
        hourly_counts = defaultdict(int)
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert.get("timestamp", "").replace("Z", "+00:00"))
                hour_key = ts.strftime("%Y-%m-%d %H:00")
                hourly_counts[hour_key] += 1
            except:
                continue
        
        if hourly_counts:
            counts = list(hourly_counts.values())
            avg_count = sum(counts) / len(counts)
            std_dev = (sum((x - avg_count) ** 2 for x in counts) / len(counts)) ** 0.5
            
            for hour, count in hourly_counts.items():
                if count > avg_count + (2 * std_dev):  # 2 standard deviations
                    anomalies.append({
                        "type": "alert_spike",
                        "timestamp": hour,
                        "count": count,
                        "severity": "high" if count > avg_count + (3 * std_dev) else "medium",
                        "deviation": round((count - avg_count) / std_dev, 2)
                    })
        
        return anomalies
    
    def _get_top_indicators(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get top security indicators from alerts."""
        indicators = {
            "top_source_ips": [],
            "top_destination_ips": [],
            "top_users": [],
            "top_processes": []
        }
        
        # Extract indicators from alert data
        source_ips = Counter()
        dest_ips = Counter()
        users = Counter()
        processes = Counter()
        
        for alert in alerts:
            data = alert.get("data", {})
            
            if "srcip" in data:
                source_ips[data["srcip"]] += 1
            if "dstip" in data:
                dest_ips[data["dstip"]] += 1
            if "srcuser" in data:
                users[data["srcuser"]] += 1
            if "process" in data:
                processes[data["process"]] += 1
        
        indicators["top_source_ips"] = [
            {"ip": ip, "count": count} for ip, count in source_ips.most_common(5)
        ]
        indicators["top_destination_ips"] = [
            {"ip": ip, "count": count} for ip, count in dest_ips.most_common(5)
        ]
        indicators["top_users"] = [
            {"user": user, "count": count} for user, count in users.most_common(5)
        ]
        indicators["top_processes"] = [
            {"process": proc, "count": count} for proc, count in processes.most_common(5)
        ]
        
        return indicators
    
    def _generate_predictions(self, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate simple trend predictions."""
        # Simple linear trend prediction
        hourly_counts = defaultdict(int)
        for alert in alerts:
            try:
                ts = datetime.fromisoformat(alert.get("timestamp", "").replace("Z", "+00:00"))
                hour_key = ts.hour
                hourly_counts[hour_key] += 1
            except:
                continue
        
        if len(hourly_counts) >= 3:
            counts = list(hourly_counts.values())
            trend = "increasing" if counts[-1] > counts[0] else "decreasing"
            avg_rate = sum(counts) / len(counts)
            
            return {
                "trend_direction": trend,
                "predicted_next_hour": int(avg_rate * 1.1 if trend == "increasing" else avg_rate * 0.9),
                "confidence": "low"  # Simple prediction
            }
        
        return {"message": "Insufficient data for predictions"}
    
    # Helper methods for other statistics
    def _detect_rule_sequences(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect common rule sequences."""
        # Group alerts by agent and sort by time
        agent_alerts = defaultdict(list)
        for alert in alerts:
            agent_id = alert.get("agent", {}).get("id")
            if agent_id:
                agent_alerts[agent_id].append(alert)
        
        # Find common sequences
        sequences = Counter()
        for agent_id, agent_alert_list in agent_alerts.items():
            # Sort by timestamp
            sorted_alerts = sorted(agent_alert_list, key=lambda x: x.get("timestamp", ""))
            
            # Look for 2-rule sequences
            for i in range(len(sorted_alerts) - 1):
                rule1 = sorted_alerts[i].get("rule", {}).get("id")
                rule2 = sorted_alerts[i + 1].get("rule", {}).get("id")
                if rule1 and rule2:
                    sequences[(rule1, rule2)] += 1
        
        return [
            {
                "sequence": list(seq),
                "count": count,
                "description": f"Rule {seq[0]} followed by {seq[1]}"
            }
            for seq, count in sequences.most_common(5)
        ]
    
    def _analyze_weekly_alerts(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze weekly alert statistics."""
        # This would parse the actual response structure
        return {
            "total_alerts": stats_response.get("data", {}).get("total_alerts", 0),
            "daily_average": stats_response.get("data", {}).get("daily_average", 0),
            "peak_day": stats_response.get("data", {}).get("peak_day", "unknown")
        }
    
    def _analyze_weekly_events(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze weekly event statistics."""
        return {
            "total_events": stats_response.get("data", {}).get("total_events", 0),
            "events_per_second": stats_response.get("data", {}).get("eps", 0)
        }
    
    def _analyze_weekly_performance(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze weekly performance metrics."""
        return {
            "average_processing_time": stats_response.get("data", {}).get("avg_processing_time", 0),
            "peak_memory_usage": stats_response.get("data", {}).get("peak_memory", 0)
        }
    
    def _compare_periods(self, current: Dict[str, Any], previous: Dict[str, Any]) -> Dict[str, Any]:
        """Compare two time periods."""
        current_alerts = current.get("data", {}).get("total_alerts", 0)
        previous_alerts = previous.get("data", {}).get("total_alerts", 0)
        
        if previous_alerts > 0:
            change_percent = ((current_alerts - previous_alerts) / previous_alerts) * 100
        else:
            change_percent = 100 if current_alerts > 0 else 0
        
        return {
            "alert_change_percent": round(change_percent, 2),
            "trend": "increasing" if change_percent > 0 else "decreasing"
        }
    
    def _detect_weekly_anomalies(self, stats_response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in weekly patterns."""
        anomalies = []
        
        # Check for unusual patterns in the data
        daily_stats = stats_response.get("data", {}).get("daily_stats", [])
        if daily_stats:
            avg_daily = sum(day.get("alerts", 0) for day in daily_stats) / len(daily_stats)
            for day in daily_stats:
                if day.get("alerts", 0) > avg_daily * 2:
                    anomalies.append({
                        "type": "daily_spike",
                        "date": day.get("date"),
                        "value": day.get("alerts"),
                        "severity": "high"
                    })
        
        return anomalies
    
    def _get_daemon_status(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Get remote daemon status."""
        return {
            "status": "active",  # Would come from actual response
            "uptime_seconds": stats_response.get("data", {}).get("uptime", 0),
            "last_restart": stats_response.get("data", {}).get("last_restart", "unknown")
        }
    
    def _analyze_connections(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze connection statistics."""
        return {
            "active_connections": stats_response.get("data", {}).get("active_connections", 0),
            "total_connections": stats_response.get("data", {}).get("total_connections", 0),
            "failed_connections": stats_response.get("data", {}).get("failed_connections", 0)
        }
    
    def _analyze_message_flow(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze message flow statistics."""
        return {
            "messages_received": stats_response.get("data", {}).get("messages_received", 0),
            "messages_sent": stats_response.get("data", {}).get("messages_sent", 0),
            "messages_per_second": stats_response.get("data", {}).get("mps", 0)
        }
    
    def _analyze_queues(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze queue statistics."""
        return {
            "queue_size": stats_response.get("data", {}).get("queue_size", 0),
            "queue_usage_percent": stats_response.get("data", {}).get("queue_usage", 0)
        }
    
    def _analyze_remoted_performance(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze remoted performance metrics."""
        return {
            "cpu_usage_percent": stats_response.get("data", {}).get("cpu_usage", 0),
            "memory_usage_mb": stats_response.get("data", {}).get("memory_usage", 0),
            "network_bandwidth_mbps": stats_response.get("data", {}).get("bandwidth", 0)
        }
    
    def _assess_remoted_health(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall health of remote daemon."""
        issues = []
        
        # Check connection health
        conn_stats = stats.get("connection_stats", {})
        if conn_stats.get("failed_connections", 0) > conn_stats.get("total_connections", 1) * 0.1:
            issues.append("High connection failure rate")
        
        # Check queue health
        queue_stats = stats.get("queue_stats", {})
        if queue_stats.get("queue_usage_percent", 0) > 80:
            issues.append("Queue usage critical")
        
        return {
            "status": "healthy" if not issues else "degraded",
            "issues": issues,
            "score": 100 - (len(issues) * 25)  # Simple scoring
        }
    
    def _get_collector_overview(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Get log collector overview."""
        return {
            "total_files_monitored": stats_response.get("data", {}).get("files_monitored", 0),
            "total_bytes_read": stats_response.get("data", {}).get("bytes_read", 0),
            "lines_processed": stats_response.get("data", {}).get("lines_processed", 0)
        }
    
    def _analyze_log_coverage(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze log coverage statistics."""
        return {
            "coverage_percent": stats_response.get("data", {}).get("coverage", 0),
            "monitored_paths": stats_response.get("data", {}).get("monitored_paths", []),
            "missing_paths": stats_response.get("data", {}).get("missing_paths", [])
        }
    
    def _analyze_collector_performance(self, stats_response: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze collector performance."""
        return {
            "read_rate_mb_per_sec": stats_response.get("data", {}).get("read_rate", 0),
            "processing_delay_ms": stats_response.get("data", {}).get("processing_delay", 0)
        }
    
    def _analyze_monitored_files(self, stats_response: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze individual monitored files."""
        files = stats_response.get("data", {}).get("files", [])
        return [
            {
                "path": f.get("path"),
                "size_mb": f.get("size", 0) / 1024 / 1024,
                "lines_read": f.get("lines_read", 0),
                "last_read": f.get("last_read", "unknown")
            }
            for f in files[:10]  # Top 10 files
        ]
    
    def _generate_collector_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """Generate recommendations for log collector."""
        recommendations = []
        
        coverage = stats.get("coverage", {}).get("coverage_percent", 100)
        if coverage < 80:
            recommendations.append("Increase log coverage - currently below 80%")
        
        perf = stats.get("performance", {})
        if perf.get("processing_delay_ms", 0) > 1000:
            recommendations.append("High processing delay detected - consider optimization")
        
        return recommendations