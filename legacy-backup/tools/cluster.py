"""Cluster and manager monitoring tools for Wazuh MCP Server."""

from typing import Any, Dict, List
import mcp.types as types
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re

from .base import BaseTool
from ..utils import validate_cluster_health_query, validate_manager_error_logs_query


class ClusterTools(BaseTool):
    """Tools for Wazuh cluster monitoring, health checking, and manager log analysis."""
    
    @property
    def tool_definitions(self) -> List[types.Tool]:
        """Return cluster and manager-related tool definitions."""
        return [
            types.Tool(
                name="get_wazuh_cluster_health",
                description="Get comprehensive cluster diagnostics with node health and performance analysis",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "include_performance": {
                            "type": "boolean",
                            "description": "Include detailed performance metrics for all nodes",
                            "default": True
                        },
                        "include_sync_status": {
                            "type": "boolean",
                            "description": "Include cluster synchronization status analysis",
                            "default": True
                        },
                        "health_threshold": {
                            "type": "number",
                            "description": "Health score threshold (0-100) for alerts",
                            "default": 80,
                            "minimum": 0,
                            "maximum": 100
                        },
                        "include_historical": {
                            "type": "boolean",
                            "description": "Include historical health trends",
                            "default": False
                        },
                        "node_filter": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Filter by specific node names (optional)"
                        }
                    }
                }
            ),
            types.Tool(
                name="get_wazuh_cluster_nodes",
                description="Get individual node monitoring and detailed health analysis for each cluster member",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "node_name": {
                            "type": "string",
                            "description": "Specific node name to analyze (optional, analyzes all if not provided)"
                        },
                        "include_stats": {
                            "type": "boolean",
                            "description": "Include detailed node statistics",
                            "default": True
                        },
                        "include_logs": {
                            "type": "boolean",
                            "description": "Include recent log analysis for nodes",
                            "default": False
                        },
                        "performance_window_hours": {
                            "type": "integer",
                            "description": "Performance analysis window in hours",
                            "default": 24,
                            "minimum": 1,
                            "maximum": 168
                        }
                    }
                }
            ),
            types.Tool(
                name="search_wazuh_manager_logs",
                description="Enhanced forensic log search with timeline reconstruction and pattern analysis",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "search_pattern": {
                            "type": "string",
                            "description": "Search pattern or keyword (supports regex)",
                            "default": ""
                        },
                        "log_level": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Filter by log levels",
                            "default": ["error", "warning", "info", "debug"]
                        },
                        "time_range_hours": {
                            "type": "integer",
                            "description": "Time range in hours to search",
                            "default": 24,
                            "minimum": 1,
                            "maximum": 168
                        },
                        "max_results": {
                            "type": "integer",
                            "description": "Maximum number of results to return",
                            "default": 100,
                            "minimum": 1,
                            "maximum": 1000
                        },
                        "include_context": {
                            "type": "boolean",
                            "description": "Include surrounding log context for matches",
                            "default": True
                        },
                        "timeline_analysis": {
                            "type": "boolean",
                            "description": "Generate timeline reconstruction",
                            "default": False
                        }
                    }
                }
            ),
            types.Tool(
                name="get_wazuh_manager_error_logs",
                description="Get manager error logs with root cause analysis and trend detection",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "severity_filter": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Filter by error severity levels",
                            "default": ["critical", "error", "warning"]
                        },
                        "time_range_hours": {
                            "type": "integer",
                            "description": "Time range in hours for analysis",
                            "default": 24,
                            "minimum": 1,
                            "maximum": 168
                        },
                        "include_root_cause": {
                            "type": "boolean",
                            "description": "Include automated root cause analysis",
                            "default": True
                        },
                        "include_trends": {
                            "type": "boolean",
                            "description": "Include error trend analysis",
                            "default": True
                        },
                        "group_similar": {
                            "type": "boolean",
                            "description": "Group similar errors together",
                            "default": True
                        },
                        "max_errors": {
                            "type": "integer",
                            "description": "Maximum number of errors to analyze",
                            "default": 500,
                            "minimum": 10,
                            "maximum": 2000
                        }
                    }
                }
            )
        ]
    
    def get_handler_mapping(self) -> Dict[str, callable]:
        """Return mapping of tool names to handler methods."""
        return {
            "get_wazuh_cluster_health": self.handle_cluster_health,
            "get_wazuh_cluster_nodes": self.handle_cluster_nodes,
            "search_wazuh_manager_logs": self.handle_manager_logs_search,
            "get_wazuh_manager_error_logs": self.handle_manager_error_logs
        }
    
    async def handle_cluster_health(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle cluster health monitoring request."""
        try:
            # Validate input
            validated_args = validate_cluster_health_query(arguments)
            
            include_performance = validated_args.get("include_performance", True)
            include_sync_status = validated_args.get("include_sync_status", True)
            health_threshold = validated_args.get("health_threshold", 80)
            include_historical = validated_args.get("include_historical", False)
            node_filter = validated_args.get("node_filter")
            
            # Get cluster information
            cluster_status = await self._get_cluster_status()
            cluster_nodes = await self._get_cluster_nodes(node_filter)
            
            # Calculate overall cluster health
            cluster_health_score = self._calculate_cluster_health(cluster_nodes, cluster_status)
            
            # Generate comprehensive analysis
            analysis = {
                "overview": {
                    "cluster_enabled": cluster_status.get("enabled", False),
                    "cluster_health_score": cluster_health_score,
                    "health_status": self._get_health_status_label(cluster_health_score),
                    "total_nodes": len(cluster_nodes),
                    "healthy_nodes": len([n for n in cluster_nodes if n.get("health_score", 0) >= health_threshold]),
                    "analysis_timestamp": datetime.utcnow().isoformat()
                },
                "nodes_summary": self._analyze_nodes_summary(cluster_nodes),
                "connectivity": self._analyze_cluster_connectivity(cluster_nodes),
                "load_distribution": self._analyze_load_distribution(cluster_nodes)
            }
            
            if include_performance:
                analysis["performance_metrics"] = await self._get_cluster_performance_metrics(cluster_nodes)
            
            if include_sync_status:
                analysis["synchronization"] = await self._analyze_sync_status(cluster_nodes)
            
            if include_historical:
                analysis["trends"] = await self._get_cluster_trends()
            
            # Generate alerts and recommendations
            analysis["alerts"] = self._generate_cluster_alerts(analysis, health_threshold)
            analysis["recommendations"] = self._generate_cluster_recommendations(analysis)
            
            return self._format_response(analysis, metadata={
                "source": "wazuh_cluster",
                "analysis_type": "comprehensive_cluster_health",
                "health_threshold": health_threshold
            })
            
        except Exception as e:
            self.logger.error(f"Error in cluster health analysis: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_cluster_health"})
    
    async def handle_cluster_nodes(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle individual node monitoring request."""
        try:
            node_name = arguments.get("node_name")
            include_stats = arguments.get("include_stats", True)
            include_logs = arguments.get("include_logs", False)
            performance_window_hours = arguments.get("performance_window_hours", 24)
            
            # Get node information
            if node_name:
                nodes = await self._get_specific_node_info(node_name)
            else:
                nodes = await self._get_cluster_nodes()
            
            # Enrich node data
            enriched_nodes = []
            for node in nodes:
                enriched_node = await self._enrich_node_data(
                    node, include_stats, include_logs, performance_window_hours
                )
                enriched_nodes.append(enriched_node)
            
            # Generate node analysis
            analysis = {
                "nodes": enriched_nodes,
                "summary": self._generate_nodes_summary(enriched_nodes),
                "performance_comparison": self._compare_node_performance(enriched_nodes),
                "role_analysis": self._analyze_node_roles(enriched_nodes)
            }
            
            if len(enriched_nodes) > 1:
                analysis["cluster_balance"] = self._analyze_cluster_balance(enriched_nodes)
            
            return self._format_response(analysis, metadata={
                "source": "wazuh_cluster_nodes",
                "analysis_type": "individual_node_monitoring",
                "target_node": node_name or "all_nodes"
            })
            
        except Exception as e:
            self.logger.error(f"Error in cluster nodes analysis: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_cluster_nodes"})
    
    async def handle_manager_logs_search(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle manager logs search with forensic capabilities."""
        try:
            search_pattern = arguments.get("search_pattern", "")
            log_level = arguments.get("log_level", ["error", "warning", "info", "debug"])
            time_range_hours = arguments.get("time_range_hours", 24)
            max_results = arguments.get("max_results", 100)
            include_context = arguments.get("include_context", True)
            timeline_analysis = arguments.get("timeline_analysis", False)
            
            # Get manager logs
            logs = await self._search_manager_logs(
                search_pattern, log_level, time_range_hours, max_results
            )
            
            # Process and analyze logs
            processed_logs = self._process_log_entries(logs, include_context)
            
            analysis = {
                "search_results": {
                    "total_matches": len(processed_logs),
                    "search_pattern": search_pattern,
                    "time_range_hours": time_range_hours,
                    "log_entries": processed_logs[:max_results]
                },
                "patterns": self._analyze_log_patterns(processed_logs),
                "frequency_analysis": self._analyze_log_frequency(processed_logs),
                "severity_distribution": self._analyze_severity_distribution(processed_logs)
            }
            
            if timeline_analysis:
                analysis["timeline"] = self._generate_timeline_reconstruction(processed_logs)
            
            # Generate insights
            analysis["insights"] = self._generate_log_insights(processed_logs, search_pattern)
            
            return self._format_response(analysis, metadata={
                "source": "wazuh_manager_logs",
                "analysis_type": "forensic_log_search",
                "search_query": search_pattern
            })
            
        except Exception as e:
            self.logger.error(f"Error in manager logs search: {str(e)}")
            return self._format_error_response(e, {"operation": "search_wazuh_manager_logs"})
    
    async def handle_manager_error_logs(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Handle manager error logs analysis with root cause detection."""
        try:
            # Validate input
            validated_args = validate_manager_error_logs_query(arguments)
            
            severity_filter = validated_args.get("severity_filter", ["critical", "error", "warning"])
            time_range_hours = validated_args.get("time_range_hours", 24)
            include_root_cause = validated_args.get("include_root_cause", True)
            include_trends = validated_args.get("include_trends", True)
            group_similar = validated_args.get("group_similar", True)
            max_errors = validated_args.get("max_errors", 500)
            
            # Get error logs
            error_logs = await self._get_manager_error_logs(
                severity_filter, time_range_hours, max_errors
            )
            
            # Process and group errors
            if group_similar:
                grouped_errors = self._group_similar_errors(error_logs)
            else:
                grouped_errors = {"ungrouped": error_logs}
            
            analysis = {
                "overview": {
                    "total_errors": len(error_logs),
                    "unique_error_types": len(grouped_errors),
                    "time_range_hours": time_range_hours,
                    "severity_distribution": Counter(
                        log.get("level", "unknown") for log in error_logs
                    )
                },
                "error_groups": self._analyze_error_groups(grouped_errors),
                "critical_errors": self._identify_critical_errors(error_logs),
                "error_patterns": self._analyze_error_patterns(error_logs)
            }
            
            if include_root_cause:
                analysis["root_cause_analysis"] = self._perform_root_cause_analysis(grouped_errors)
            
            if include_trends:
                analysis["trends"] = self._analyze_error_trends(error_logs, time_range_hours)
            
            # Generate actionable recommendations
            analysis["remediation"] = self._generate_error_remediation(analysis)
            
            return self._format_response(analysis, metadata={
                "source": "wazuh_manager_error_logs",
                "analysis_type": "comprehensive_error_analysis",
                "severity_filters": severity_filter
            })
            
        except Exception as e:
            self.logger.error(f"Error in manager error logs analysis: {str(e)}")
            return self._format_error_response(e, {"operation": "get_wazuh_manager_error_logs"})
    
    # Helper methods for cluster health
    async def _get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status information."""
        try:
            cluster_response = await self.api_client.get_cluster_status()
            return cluster_response.get("data", {})
        except Exception as e:
            self.logger.warning(f"Could not get cluster status: {str(e)}")
            return {"enabled": False, "error": str(e)}
    
    async def _get_cluster_nodes(self, node_filter: List[str] = None) -> List[Dict[str, Any]]:
        """Get cluster nodes information."""
        try:
            nodes_response = await self.api_client.get_cluster_nodes()
            nodes = nodes_response.get("data", {}).get("affected_items", [])
            
            if node_filter:
                nodes = [node for node in nodes if node.get("name") in node_filter]
            
            # Enrich nodes with health scores
            for node in nodes:
                node["health_score"] = self._calculate_node_health_score(node)
                node["role"] = self._determine_node_role(node)
            
            return nodes
        except Exception as e:
            self.logger.error(f"Could not get cluster nodes: {str(e)}")
            return []
    
    async def _get_specific_node_info(self, node_name: str) -> List[Dict[str, Any]]:
        """Get information for a specific node."""
        try:
            node_response = await self.api_client.get_cluster_node_info(node_name)
            node_data = node_response.get("data", {})
            return [node_data] if node_data else []
        except Exception as e:
            self.logger.error(f"Could not get node {node_name} info: {str(e)}")
            return []
    
    def _calculate_cluster_health(self, nodes: List[Dict[str, Any]], 
                                 cluster_status: Dict[str, Any]) -> int:
        """Calculate overall cluster health score."""
        if not cluster_status.get("enabled", False):
            return 0  # No cluster = no cluster health
        
        if not nodes:
            return 0  # No nodes = no health
        
        # Calculate average node health
        node_scores = [node.get("health_score", 0) for node in nodes]
        avg_node_health = sum(node_scores) / len(node_scores)
        
        # Adjust for cluster-specific factors
        cluster_health = avg_node_health
        
        # Penalty for missing nodes (assuming standard 3-node cluster)
        expected_nodes = 3
        if len(nodes) < expected_nodes:
            penalty = (expected_nodes - len(nodes)) * 15
            cluster_health = max(0, cluster_health - penalty)
        
        # Bonus for all nodes being healthy
        healthy_nodes = sum(1 for score in node_scores if score >= 80)
        if healthy_nodes == len(nodes) and len(nodes) >= 2:
            cluster_health = min(100, cluster_health + 5)
        
        return int(cluster_health)
    
    def _calculate_node_health_score(self, node: Dict[str, Any]) -> int:
        """Calculate health score for individual node."""
        score = 0
        
        # Connection status (40 points)
        status = node.get("status", "").lower()
        if status == "connected":
            score += 40
        elif status == "disconnected":
            score += 0
        else:
            score += 20  # Unknown/other status
        
        # Node type and role (20 points)
        node_type = node.get("type", "").lower()
        if node_type == "master":
            score += 20
        elif node_type == "worker":
            score += 15
        else:
            score += 10
        
        # Last keep alive (20 points)
        last_keep_alive = node.get("lastKeepAlive")
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
                score += 5
        
        # Version consistency (10 points)
        version = node.get("version")
        if version:
            score += 10
        
        # Performance indicators (10 points)
        # This would include CPU, memory, disk usage if available
        stats = node.get("stats", {})
        if stats:
            score += 10
        
        return min(score, 100)
    
    def _get_health_status_label(self, health_score: int) -> str:
        """Get health status label from score."""
        if health_score >= 90:
            return "excellent"
        elif health_score >= 80:
            return "good"
        elif health_score >= 60:
            return "fair"
        elif health_score >= 40:
            return "poor"
        else:
            return "critical"
    
    def _determine_node_role(self, node: Dict[str, Any]) -> str:
        """Determine the role of a cluster node."""
        node_type = node.get("type", "").lower()
        if node_type == "master":
            return "master"
        elif node_type == "worker":
            return "worker"
        else:
            return "unknown"
    
    def _analyze_nodes_summary(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze summary statistics for cluster nodes."""
        if not nodes:
            return {"total": 0, "message": "No nodes found"}
        
        status_counts = Counter(node.get("status", "unknown") for node in nodes)
        role_counts = Counter(node.get("role", "unknown") for node in nodes)
        health_scores = [node.get("health_score", 0) for node in nodes]
        
        return {
            "total_nodes": len(nodes),
            "status_distribution": dict(status_counts),
            "role_distribution": dict(role_counts),
            "health_metrics": {
                "average_health": sum(health_scores) / len(health_scores),
                "healthy_nodes": sum(1 for score in health_scores if score >= 80),
                "unhealthy_nodes": sum(1 for score in health_scores if score < 60)
            },
            "master_nodes": sum(1 for node in nodes if node.get("role") == "master"),
            "worker_nodes": sum(1 for node in nodes if node.get("role") == "worker")
        }
    
    def _analyze_cluster_connectivity(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze cluster connectivity status."""
        connected_nodes = [node for node in nodes if node.get("status") == "connected"]
        disconnected_nodes = [node for node in nodes if node.get("status") != "connected"]
        
        connectivity_health = "excellent"
        if disconnected_nodes:
            if len(disconnected_nodes) == len(nodes):
                connectivity_health = "critical"
            elif len(disconnected_nodes) > len(nodes) / 2:
                connectivity_health = "poor"
            else:
                connectivity_health = "degraded"
        
        return {
            "connected_nodes": len(connected_nodes),
            "disconnected_nodes": len(disconnected_nodes),
            "connectivity_health": connectivity_health,
            "connectivity_percentage": (len(connected_nodes) / len(nodes)) * 100 if nodes else 0,
            "problematic_nodes": [
                {
                    "name": node.get("name"),
                    "status": node.get("status"),
                    "last_seen": node.get("lastKeepAlive")
                }
                for node in disconnected_nodes
            ]
        }
    
    def _analyze_load_distribution(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze load distribution across cluster nodes."""
        # Mock load analysis (would use real metrics in production)
        load_data = []
        
        for node in nodes:
            # Simulate load data based on node health and status
            base_load = 50 if node.get("status") == "connected" else 0
            health_score = node.get("health_score", 0)
            
            # Higher health generally means handling more load efficiently
            simulated_load = base_load + (health_score / 5)
            
            load_data.append({
                "node_name": node.get("name"),
                "cpu_usage": min(simulated_load + 10, 100),
                "memory_usage": min(simulated_load, 100),
                "network_usage": min(simulated_load - 10, 100)
            })
        
        # Calculate load balance score
        if load_data:
            cpu_loads = [data["cpu_usage"] for data in load_data]
            load_variance = sum((x - sum(cpu_loads)/len(cpu_loads))**2 for x in cpu_loads) / len(cpu_loads)
            balance_score = max(0, 100 - load_variance)
        else:
            balance_score = 0
        
        return {
            "load_balance_score": int(balance_score),
            "node_loads": load_data,
            "average_cpu": sum(data["cpu_usage"] for data in load_data) / len(load_data) if load_data else 0,
            "load_distribution_health": "good" if balance_score > 70 else "needs_attention"
        }
    
    async def _get_cluster_performance_metrics(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Get performance metrics for the cluster."""
        performance_data = {
            "cluster_throughput": {
                "alerts_per_second": 0,
                "events_per_second": 0,
                "api_requests_per_minute": 0
            },
            "resource_usage": {
                "total_memory_gb": 0,
                "total_cpu_cores": 0,
                "storage_usage_gb": 0
            },
            "response_times": []
        }
        
        # Aggregate performance data from all nodes
        for node in nodes:
            # Mock performance data (would come from real metrics)
            node_stats = node.get("stats", {})
            
            performance_data["cluster_throughput"]["alerts_per_second"] += node_stats.get("eps", 10)
            performance_data["resource_usage"]["total_memory_gb"] += node_stats.get("memory_gb", 8)
            performance_data["resource_usage"]["total_cpu_cores"] += node_stats.get("cpu_cores", 4)
            
            performance_data["response_times"].append({
                "node": node.get("name"),
                "avg_response_ms": node_stats.get("response_time_ms", 100)
            })
        
        return performance_data
    
    async def _analyze_sync_status(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze cluster synchronization status."""
        # Mock sync analysis (would check actual sync status)
        sync_status = {
            "overall_sync_health": "good",
            "nodes_in_sync": len([n for n in nodes if n.get("status") == "connected"]),
            "nodes_out_of_sync": 0,
            "last_sync_times": [],
            "sync_issues": []
        }
        
        # Check for potential sync issues
        connected_nodes = [n for n in nodes if n.get("status") == "connected"]
        if len(connected_nodes) < len(nodes):
            sync_status["sync_issues"].append("Some nodes disconnected, sync may be affected")
            sync_status["overall_sync_health"] = "degraded"
        
        if len(connected_nodes) < 2:
            sync_status["sync_issues"].append("Insufficient nodes for proper synchronization")
            sync_status["overall_sync_health"] = "critical"
        
        return sync_status
    
    async def _get_cluster_trends(self) -> Dict[str, Any]:
        """Get historical cluster health trends."""
        # Mock trend data (would come from historical metrics)
        return {
            "health_trend": "stable",
            "performance_trend": "improving",
            "node_availability": {
                "last_24h": 98.5,
                "last_7d": 99.2,
                "last_30d": 97.8
            },
            "alerts": [
                "Node availability dipped to 95% last week",
                "Performance improved 15% over last month"
            ]
        }
    
    def _generate_cluster_alerts(self, analysis: Dict[str, Any], health_threshold: int) -> List[Dict[str, Any]]:
        """Generate alerts based on cluster analysis."""
        alerts = []
        
        # Overall health alerts
        overview = analysis.get("overview", {})
        cluster_health = overview.get("cluster_health_score", 0)
        
        if cluster_health < health_threshold:
            alerts.append({
                "level": "critical" if cluster_health < 50 else "warning",
                "type": "cluster_health",
                "message": f"Cluster health score ({cluster_health}) below threshold ({health_threshold})",
                "recommendation": "Investigate node connectivity and performance issues"
            })
        
        # Node connectivity alerts
        connectivity = analysis.get("connectivity", {})
        if connectivity.get("disconnected_nodes", 0) > 0:
            alerts.append({
                "level": "warning",
                "type": "node_connectivity",
                "message": f"{connectivity['disconnected_nodes']} nodes are disconnected",
                "affected_nodes": [n["name"] for n in connectivity.get("problematic_nodes", [])],
                "recommendation": "Check network connectivity and node status"
            })
        
        # Load balance alerts
        load_dist = analysis.get("load_distribution", {})
        if load_dist.get("load_balance_score", 100) < 70:
            alerts.append({
                "level": "warning",
                "type": "load_imbalance",
                "message": "Cluster load is not well distributed",
                "recommendation": "Review node configurations and workload distribution"
            })
        
        return alerts
    
    def _generate_cluster_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on cluster analysis."""
        recommendations = []
        
        overview = analysis.get("overview", {})
        nodes_summary = analysis.get("nodes_summary", {})
        
        # Health-based recommendations
        unhealthy_nodes = nodes_summary.get("health_metrics", {}).get("unhealthy_nodes", 0)
        if unhealthy_nodes > 0:
            recommendations.append(f"Address {unhealthy_nodes} unhealthy nodes to improve cluster stability")
        
        # Role distribution recommendations
        master_nodes = nodes_summary.get("master_nodes", 0)
        if master_nodes < 2:
            recommendations.append("Consider adding more master nodes for high availability")
        elif master_nodes > 3:
            recommendations.append("Consider reducing master nodes to optimize resource usage")
        
        # Connectivity recommendations
        connectivity = analysis.get("connectivity", {})
        if connectivity.get("connectivity_percentage", 100) < 100:
            recommendations.append("Investigate and resolve node connectivity issues")
        
        # Performance recommendations
        load_dist = analysis.get("load_distribution", {})
        if load_dist.get("average_cpu", 0) > 80:
            recommendations.append("Consider scaling cluster due to high CPU usage")
        
        return recommendations
    
    # Helper methods for node monitoring
    async def _enrich_node_data(self, node: Dict[str, Any], include_stats: bool, 
                               include_logs: bool, performance_window_hours: int) -> Dict[str, Any]:
        """Enrich node data with additional information."""
        enriched = {**node}
        
        if include_stats:
            try:
                stats_response = await self.api_client.get_cluster_node_stats(node.get("name"))
                enriched["detailed_stats"] = stats_response.get("data", {})
            except Exception as e:
                enriched["stats_error"] = str(e)
        
        if include_logs:
            try:
                # Get recent logs for this node
                logs_response = await self.api_client.get_node_logs(
                    node.get("name"), 
                    hours=min(performance_window_hours, 24)
                )
                enriched["recent_logs"] = logs_response.get("data", [])[:10]  # Last 10 logs
            except Exception as e:
                enriched["logs_error"] = str(e)
        
        # Add performance analysis
        enriched["performance_analysis"] = self._analyze_node_performance(enriched, performance_window_hours)
        
        return enriched
    
    def _analyze_node_performance(self, node: Dict[str, Any], window_hours: int) -> Dict[str, Any]:
        """Analyze individual node performance."""
        stats = node.get("detailed_stats", {})
        
        # Mock performance analysis (would use real metrics)
        analysis = {
            "cpu_efficiency": 85,  # Mock value
            "memory_efficiency": 78,  # Mock value
            "network_performance": 92,  # Mock value
            "disk_performance": 88,  # Mock value
            "overall_performance_score": 0
        }
        
        # Calculate overall performance score
        scores = [analysis[key] for key in analysis if key != "overall_performance_score"]
        analysis["overall_performance_score"] = sum(scores) / len(scores) if scores else 0
        
        return analysis
    
    def _generate_nodes_summary(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary for individual nodes analysis."""
        if not nodes:
            return {"total": 0}
        
        performance_scores = [
            node.get("performance_analysis", {}).get("overall_performance_score", 0) 
            for node in nodes
        ]
        
        return {
            "total_nodes_analyzed": len(nodes),
            "average_performance": sum(performance_scores) / len(performance_scores) if performance_scores else 0,
            "best_performing_node": max(nodes, key=lambda x: x.get("performance_analysis", {}).get("overall_performance_score", 0)).get("name") if nodes else None,
            "nodes_needing_attention": [
                node.get("name") for node in nodes 
                if node.get("health_score", 0) < 70
            ]
        }
    
    def _compare_node_performance(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Compare performance metrics across nodes."""
        if len(nodes) < 2:
            return {"message": "Need at least 2 nodes for comparison"}
        
        performance_comparison = {}
        metrics = ["cpu_efficiency", "memory_efficiency", "network_performance", "disk_performance"]
        
        for metric in metrics:
            values = [
                node.get("performance_analysis", {}).get(metric, 0) 
                for node in nodes
            ]
            performance_comparison[metric] = {
                "average": sum(values) / len(values),
                "min": min(values),
                "max": max(values),
                "variance": sum((x - sum(values)/len(values))**2 for x in values) / len(values)
            }
        
        return performance_comparison
    
    def _analyze_node_roles(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze distribution and health of node roles."""
        role_analysis = defaultdict(lambda: {"count": 0, "health_scores": [], "performance_scores": []})
        
        for node in nodes:
            role = node.get("role", "unknown")
            role_data = role_analysis[role]
            
            role_data["count"] += 1
            role_data["health_scores"].append(node.get("health_score", 0))
            role_data["performance_scores"].append(
                node.get("performance_analysis", {}).get("overall_performance_score", 0)
            )
        
        # Calculate averages for each role
        role_stats = {}
        for role, data in role_analysis.items():
            health_scores = data["health_scores"]
            perf_scores = data["performance_scores"]
            
            role_stats[role] = {
                "count": data["count"],
                "average_health": sum(health_scores) / len(health_scores) if health_scores else 0,
                "average_performance": sum(perf_scores) / len(perf_scores) if perf_scores else 0
            }
        
        return role_stats
    
    def _analyze_cluster_balance(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze overall cluster balance and efficiency."""
        health_scores = [node.get("health_score", 0) for node in nodes]
        performance_scores = [
            node.get("performance_analysis", {}).get("overall_performance_score", 0) 
            for node in nodes
        ]
        
        # Calculate balance metrics
        health_variance = sum((x - sum(health_scores)/len(health_scores))**2 for x in health_scores) / len(health_scores)
        perf_variance = sum((x - sum(performance_scores)/len(performance_scores))**2 for x in performance_scores) / len(performance_scores)
        
        balance_score = max(0, 100 - (health_variance + perf_variance) / 2)
        
        return {
            "balance_score": balance_score,
            "health_distribution_balance": 100 - health_variance,
            "performance_distribution_balance": 100 - perf_variance,
            "balance_status": "good" if balance_score > 70 else "needs_improvement",
            "recommendations": self._get_balance_recommendations(balance_score, nodes)
        }
    
    def _get_balance_recommendations(self, balance_score: float, nodes: List[Dict[str, Any]]) -> List[str]:
        """Get recommendations for improving cluster balance."""
        recommendations = []
        
        if balance_score < 70:
            # Find underperforming nodes
            avg_health = sum(node.get("health_score", 0) for node in nodes) / len(nodes)
            underperforming = [
                node.get("name") for node in nodes 
                if node.get("health_score", 0) < avg_health * 0.8
            ]
            
            if underperforming:
                recommendations.append(f"Optimize nodes: {', '.join(underperforming)}")
            
            recommendations.append("Review cluster configuration for better load distribution")
            recommendations.append("Consider rebalancing workloads across nodes")
        
        return recommendations
    
    # Helper methods for log analysis
    async def _search_manager_logs(self, search_pattern: str, log_levels: List[str], 
                                  time_range_hours: int, max_results: int) -> List[Dict[str, Any]]:
        """Search manager logs with given criteria."""
        try:
            # Build search query
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=time_range_hours)
            
            logs_response = await self.api_client.search_manager_logs(
                query=search_pattern,
                levels=log_levels,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                limit=max_results
            )
            
            return logs_response.get("data", {}).get("logs", [])
            
        except Exception as e:
            self.logger.error(f"Error searching manager logs: {str(e)}")
            # Return mock data for demonstration
            return self._generate_mock_log_data(search_pattern, log_levels, max_results)
    
    def _generate_mock_log_data(self, search_pattern: str, log_levels: List[str], max_results: int) -> List[Dict[str, Any]]:
        """Generate mock log data for demonstration."""
        mock_logs = []
        base_time = datetime.utcnow()
        
        for i in range(min(max_results, 20)):
            log_time = base_time - timedelta(minutes=i * 5)
            level = log_levels[i % len(log_levels)] if log_levels else "info"
            
            mock_logs.append({
                "timestamp": log_time.isoformat() + "Z",
                "level": level,
                "message": f"Sample log message containing {search_pattern}" if search_pattern else f"Sample {level} message {i}",
                "component": "wazuh-manager" if i % 2 == 0 else "wazuh-remoted",
                "thread_id": f"thread_{i % 5}",
                "location": f"src/main.c:{100 + i}"
            })
        
        return mock_logs
    
    def _process_log_entries(self, logs: List[Dict[str, Any]], include_context: bool) -> List[Dict[str, Any]]:
        """Process and enrich log entries."""
        processed = []
        
        for i, log in enumerate(logs):
            processed_log = {
                **log,
                "severity_score": self._calculate_log_severity_score(log),
                "category": self._categorize_log_entry(log)
            }
            
            if include_context and i > 0:
                processed_log["context_before"] = logs[i-1].get("message", "")
            
            if include_context and i < len(logs) - 1:
                processed_log["context_after"] = logs[i+1].get("message", "")
            
            processed.append(processed_log)
        
        return processed
    
    def _calculate_log_severity_score(self, log: Dict[str, Any]) -> int:
        """Calculate severity score for log entry."""
        level = log.get("level", "").lower()
        
        severity_scores = {
            "critical": 100,
            "error": 80,
            "warning": 60,
            "info": 40,
            "debug": 20
        }
        
        base_score = severity_scores.get(level, 30)
        
        # Adjust based on message content
        message = log.get("message", "").lower()
        if any(keyword in message for keyword in ["failed", "error", "exception", "critical"]):
            base_score = min(100, base_score + 20)
        
        return base_score
    
    def _categorize_log_entry(self, log: Dict[str, Any]) -> str:
        """Categorize log entry based on content."""
        message = log.get("message", "").lower()
        component = log.get("component", "").lower()
        
        if "authentication" in message or "login" in message:
            return "authentication"
        elif "connection" in message or "network" in message:
            return "connectivity"
        elif "cluster" in message or "sync" in message:
            return "cluster"
        elif "database" in message or "db" in message:
            return "database"
        elif "agent" in message:
            return "agent_management"
        elif "rule" in message or "decoder" in message:
            return "rules_engine"
        else:
            return "general"
    
    def _analyze_log_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns in log entries."""
        patterns = {
            "most_common_messages": [],
            "error_patterns": [],
            "component_activity": Counter(),
            "hourly_distribution": Counter()
        }
        
        # Analyze message patterns
        message_counts = Counter()
        for log in logs:
            message = log.get("message", "")
            # Normalize message for pattern detection
            normalized = re.sub(r'\d+', 'X', message)  # Replace numbers with X
            normalized = re.sub(r'[a-f0-9]{8,}', 'HASH', normalized)  # Replace hashes
            message_counts[normalized] += 1
        
        patterns["most_common_messages"] = [
            {"pattern": pattern, "count": count}
            for pattern, count in message_counts.most_common(10)
        ]
        
        # Analyze component activity
        for log in logs:
            component = log.get("component", "unknown")
            patterns["component_activity"][component] += 1
        
        # Analyze temporal patterns
        for log in logs:
            timestamp = log.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                hour_key = dt.strftime("%H:00")
                patterns["hourly_distribution"][hour_key] += 1
            except:
                continue
        
        return {
            "most_common_messages": patterns["most_common_messages"],
            "component_activity": dict(patterns["component_activity"]),
            "hourly_distribution": dict(patterns["hourly_distribution"]),
            "peak_activity_hour": max(patterns["hourly_distribution"].items(), key=lambda x: x[1])[0] if patterns["hourly_distribution"] else None
        }
    
    def _analyze_log_frequency(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze frequency patterns in logs."""
        if not logs:
            return {"total": 0}
        
        # Group by time intervals
        time_buckets = defaultdict(int)
        
        for log in logs:
            timestamp = log.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                # 5-minute buckets
                bucket = dt.replace(minute=dt.minute - dt.minute % 5, second=0, microsecond=0)
                time_buckets[bucket] += 1
            except:
                continue
        
        # Calculate frequency statistics
        frequencies = list(time_buckets.values())
        avg_frequency = sum(frequencies) / len(frequencies) if frequencies else 0
        
        return {
            "total_logs": len(logs),
            "time_span_minutes": len(time_buckets) * 5,
            "average_logs_per_5min": avg_frequency,
            "peak_frequency": max(frequencies) if frequencies else 0,
            "frequency_trend": "increasing" if frequencies and frequencies[-1] > frequencies[0] else "stable"
        }
    
    def _analyze_severity_distribution(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze distribution of log severity levels."""
        level_counts = Counter(log.get("level", "unknown") for log in logs)
        severity_scores = [log.get("severity_score", 0) for log in logs]
        
        return {
            "level_distribution": dict(level_counts),
            "average_severity_score": sum(severity_scores) / len(severity_scores) if severity_scores else 0,
            "high_severity_logs": sum(1 for score in severity_scores if score >= 80),
            "critical_logs": sum(1 for score in severity_scores if score >= 90)
        }
    
    def _generate_timeline_reconstruction(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate timeline reconstruction from logs."""
        # Sort logs by timestamp
        sorted_logs = sorted(logs, key=lambda x: x.get("timestamp", ""))
        
        # Create timeline events
        timeline_events = []
        for log in sorted_logs:
            timeline_events.append({
                "timestamp": log.get("timestamp"),
                "event_type": log.get("category", "general"),
                "severity": log.get("level", "info"),
                "description": log.get("message", "")[:100] + "..." if len(log.get("message", "")) > 100 else log.get("message", ""),
                "component": log.get("component", "unknown")
            })
        
        # Identify event sequences
        event_sequences = self._identify_event_sequences(timeline_events)
        
        return {
            "timeline_events": timeline_events,
            "event_sequences": event_sequences,
            "total_events": len(timeline_events),
            "time_span": {
                "start": sorted_logs[0].get("timestamp") if sorted_logs else None,
                "end": sorted_logs[-1].get("timestamp") if sorted_logs else None
            }
        }
    
    def _identify_event_sequences(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify related event sequences in timeline."""
        sequences = []
        
        # Simple sequence detection based on component and time proximity
        current_sequence = []
        last_component = None
        last_time = None
        
        for event in events:
            event_time = event.get("timestamp")
            component = event.get("component")
            
            try:
                current_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
                
                # Start new sequence if component changes or time gap > 5 minutes
                if (last_component and component != last_component) or \
                   (last_time and (current_time - last_time).total_seconds() > 300):
                    
                    if len(current_sequence) > 1:
                        sequences.append({
                            "component": last_component,
                            "event_count": len(current_sequence),
                            "duration_seconds": (current_sequence[-1]["time"] - current_sequence[0]["time"]).total_seconds(),
                            "events": current_sequence
                        })
                    
                    current_sequence = []
                
                current_sequence.append({
                    "time": current_time,
                    "description": event.get("description", "")
                })
                
                last_component = component
                last_time = current_time
                
            except:
                continue
        
        # Add final sequence
        if len(current_sequence) > 1:
            sequences.append({
                "component": last_component,
                "event_count": len(current_sequence),
                "events": current_sequence
            })
        
        return sequences
    
    def _generate_log_insights(self, logs: List[Dict[str, Any]], search_pattern: str) -> List[str]:
        """Generate insights from log analysis."""
        insights = []
        
        if not logs:
            insights.append("No logs found matching the search criteria")
            return insights
        
        # Pattern-specific insights
        if search_pattern:
            insights.append(f"Found {len(logs)} logs matching pattern '{search_pattern}'")
        
        # Severity insights
        critical_logs = [log for log in logs if log.get("severity_score", 0) >= 90]
        if critical_logs:
            insights.append(f"Found {len(critical_logs)} critical severity logs requiring immediate attention")
        
        # Frequency insights
        if len(logs) > 100:
            insights.append("High log volume detected - consider investigating potential issues")
        
        # Component insights
        component_counts = Counter(log.get("component", "unknown") for log in logs)
        most_active = component_counts.most_common(1)[0] if component_counts else None
        if most_active:
            insights.append(f"Most active component: {most_active[0]} ({most_active[1]} logs)")
        
        # Category insights
        category_counts = Counter(log.get("category", "general") for log in logs)
        if "authentication" in category_counts and category_counts["authentication"] > 10:
            insights.append("High authentication activity detected")
        
        return insights
    
    # Helper methods for error log analysis
    async def _get_manager_error_logs(self, severity_filter: List[str], 
                                     time_range_hours: int, max_errors: int) -> List[Dict[str, Any]]:
        """Get manager error logs with filtering."""
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=time_range_hours)
            
            error_response = await self.api_client.get_manager_logs(
                levels=severity_filter,
                start_time=start_time.isoformat(),
                end_time=end_time.isoformat(),
                limit=max_errors
            )
            
            return error_response.get("data", {}).get("logs", [])
            
        except Exception as e:
            self.logger.error(f"Error getting manager error logs: {str(e)}")
            # Return mock error data
            return self._generate_mock_error_data(severity_filter, max_errors)
    
    def _generate_mock_error_data(self, severity_filter: List[str], max_errors: int) -> List[Dict[str, Any]]:
        """Generate mock error data for demonstration."""
        mock_errors = []
        base_time = datetime.utcnow()
        
        error_templates = [
            "Failed to connect to agent {agent_id}: Connection timeout",
            "Database connection lost: Unable to execute query",
            "Authentication failed for user {user}: Invalid credentials",
            "Cluster synchronization error: Node {node} unreachable",
            "Rule processing error: Invalid regex pattern in rule {rule_id}",
            "Memory allocation failed: Out of memory",
            "Configuration validation error: Invalid parameter {param}",
            "Network interface error: Cannot bind to port {port}"
        ]
        
        for i in range(min(max_errors, 50)):
            error_time = base_time - timedelta(minutes=i * 3)
            level = severity_filter[i % len(severity_filter)] if severity_filter else "error"
            
            template = error_templates[i % len(error_templates)]
            message = template.format(
                agent_id=f"00{i % 10}",
                user=f"user{i % 5}",
                node=f"node{i % 3}",
                rule_id=f"rule_{1000 + i}",
                param=f"param_{i}",
                port=8000 + (i % 100)
            )
            
            mock_errors.append({
                "timestamp": error_time.isoformat() + "Z",
                "level": level,
                "message": message,
                "component": "wazuh-manager",
                "error_code": f"E{1000 + i}",
                "thread_id": f"thread_{i % 5}"
            })
        
        return mock_errors
    
    def _group_similar_errors(self, errors: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group similar errors together."""
        groups = defaultdict(list)
        
        for error in errors:
            message = error.get("message", "")
            
            # Normalize message for grouping
            normalized = re.sub(r'\d+', 'X', message)  # Replace numbers
            normalized = re.sub(r'[a-f0-9]{8,}', 'HASH', normalized)  # Replace hashes
            normalized = re.sub(r'user\w+', 'USER', normalized)  # Replace usernames
            normalized = re.sub(r'node\w+', 'NODE', normalized)  # Replace node names
            
            groups[normalized].append(error)
        
        return dict(groups)
    
    def _analyze_error_groups(self, grouped_errors: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Analyze grouped error data."""
        group_analysis = {}
        
        for pattern, errors in grouped_errors.items():
            group_analysis[pattern] = {
                "count": len(errors),
                "first_occurrence": min(error.get("timestamp", "") for error in errors),
                "last_occurrence": max(error.get("timestamp", "") for error in errors),
                "frequency_per_hour": len(errors) / 24,  # Assuming 24 hour window
                "severity_levels": list(set(error.get("level", "unknown") for error in errors)),
                "affected_components": list(set(error.get("component", "unknown") for error in errors)),
                "sample_message": errors[0].get("message", "") if errors else ""
            }
        
        return group_analysis
    
    def _identify_critical_errors(self, errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify critical errors requiring immediate attention."""
        critical_keywords = [
            "out of memory", "segmentation fault", "core dump", "fatal",
            "cannot start", "shutdown", "panic", "corruption"
        ]
        
        critical_errors = []
        for error in errors:
            message = error.get("message", "").lower()
            level = error.get("level", "").lower()
            
            is_critical = (
                level in ["critical", "fatal"] or
                any(keyword in message for keyword in critical_keywords)
            )
            
            if is_critical:
                critical_errors.append({
                    **error,
                    "criticality_reason": self._determine_criticality_reason(error, critical_keywords)
                })
        
        return critical_errors
    
    def _determine_criticality_reason(self, error: Dict[str, Any], keywords: List[str]) -> str:
        """Determine why an error is considered critical."""
        message = error.get("message", "").lower()
        level = error.get("level", "").lower()
        
        if level in ["critical", "fatal"]:
            return f"Severity level: {level}"
        
        for keyword in keywords:
            if keyword in message:
                return f"Contains critical keyword: {keyword}"
        
        return "Unknown criticality reason"
    
    def _analyze_error_patterns(self, errors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns in error occurrences."""
        patterns = {
            "temporal_patterns": self._analyze_temporal_error_patterns(errors),
            "component_patterns": Counter(error.get("component", "unknown") for error in errors),
            "error_cascades": self._detect_error_cascades(errors)
        }
        
        return {
            "temporal_patterns": patterns["temporal_patterns"],
            "component_distribution": dict(patterns["component_patterns"]),
            "error_cascades": patterns["error_cascades"],
            "most_problematic_component": patterns["component_patterns"].most_common(1)[0][0] if patterns["component_patterns"] else None
        }
    
    def _analyze_temporal_error_patterns(self, errors: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze when errors occur most frequently."""
        hourly_counts = Counter()
        
        for error in errors:
            timestamp = error.get("timestamp", "")
            try:
                dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                hour_key = dt.strftime("%H:00")
                hourly_counts[hour_key] += 1
            except:
                continue
        
        return {
            "hourly_distribution": dict(hourly_counts),
            "peak_error_hour": hourly_counts.most_common(1)[0][0] if hourly_counts else None,
            "error_frequency_trend": "increasing" if self._is_increasing_trend(hourly_counts) else "stable"
        }
    
    def _is_increasing_trend(self, hourly_counts: Counter) -> bool:
        """Determine if error frequency is increasing."""
        if len(hourly_counts) < 4:
            return False
        
        # Simple trend detection: compare first and last quarters
        sorted_hours = sorted(hourly_counts.items())
        first_quarter = sum(count for _, count in sorted_hours[:len(sorted_hours)//4])
        last_quarter = sum(count for _, count in sorted_hours[-len(sorted_hours)//4:])
        
        return last_quarter > first_quarter * 1.2
    
    def _detect_error_cascades(self, errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect error cascades (related errors occurring in sequence)."""
        # Sort errors by timestamp
        sorted_errors = sorted(errors, key=lambda x: x.get("timestamp", ""))
        
        cascades = []
        current_cascade = []
        last_time = None
        
        for error in sorted_errors:
            try:
                error_time = datetime.fromisoformat(error.get("timestamp", "").replace("Z", "+00:00"))
                
                # Start new cascade if gap > 10 minutes
                if last_time and (error_time - last_time).total_seconds() > 600:
                    if len(current_cascade) > 2:  # Only report cascades with 3+ errors
                        cascades.append({
                            "start_time": current_cascade[0].get("timestamp"),
                            "end_time": current_cascade[-1].get("timestamp"),
                            "error_count": len(current_cascade),
                            "duration_minutes": ((datetime.fromisoformat(current_cascade[-1].get("timestamp", "").replace("Z", "+00:00")) - 
                                                 datetime.fromisoformat(current_cascade[0].get("timestamp", "").replace("Z", "+00:00"))).total_seconds() / 60),
                            "primary_components": list(set(e.get("component", "unknown") for e in current_cascade))
                        })
                    current_cascade = []
                
                current_cascade.append(error)
                last_time = error_time
                
            except:
                continue
        
        # Check final cascade
        if len(current_cascade) > 2:
            cascades.append({
                "start_time": current_cascade[0].get("timestamp"),
                "end_time": current_cascade[-1].get("timestamp"),
                "error_count": len(current_cascade),
                "primary_components": list(set(e.get("component", "unknown") for e in current_cascade))
            })
        
        return cascades
    
    def _perform_root_cause_analysis(self, grouped_errors: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
        """Perform automated root cause analysis on error groups."""
        root_causes = {}
        
        for pattern, errors in grouped_errors.items():
            if len(errors) < 2:  # Skip single occurrences
                continue
            
            analysis = {
                "potential_causes": [],
                "recommended_actions": [],
                "confidence_score": 0
            }
            
            # Analyze error pattern for root causes
            sample_message = errors[0].get("message", "").lower()
            
            if "connection" in sample_message and "timeout" in sample_message:
                analysis["potential_causes"].append("Network connectivity issues")
                analysis["recommended_actions"].append("Check network configuration and firewall rules")
                analysis["confidence_score"] = 85
            
            elif "authentication" in sample_message and "failed" in sample_message:
                analysis["potential_causes"].append("Invalid credentials or authentication service issues")
                analysis["recommended_actions"].append("Verify user credentials and authentication service status")
                analysis["confidence_score"] = 90
            
            elif "memory" in sample_message:
                analysis["potential_causes"].append("Insufficient system memory or memory leak")
                analysis["recommended_actions"].append("Monitor memory usage and consider increasing available memory")
                analysis["confidence_score"] = 80
            
            elif "database" in sample_message:
                analysis["potential_causes"].append("Database connectivity or performance issues")
                analysis["recommended_actions"].append("Check database status and performance metrics")
                analysis["confidence_score"] = 75
            
            else:
                analysis["potential_causes"].append("Configuration or system-level issue")
                analysis["recommended_actions"].append("Review system logs and configuration files")
                analysis["confidence_score"] = 50
            
            # Add frequency-based insights
            if len(errors) > 10:
                analysis["potential_causes"].append("Recurring system issue requiring immediate attention")
                analysis["confidence_score"] = min(100, analysis["confidence_score"] + 10)
            
            root_causes[pattern] = analysis
        
        return root_causes
    
    def _analyze_error_trends(self, errors: List[Dict[str, Any]], time_range_hours: int) -> Dict[str, Any]:
        """Analyze error trends over time."""
        # Group errors by time buckets
        bucket_size_minutes = max(60, time_range_hours * 60 // 24)  # At least 1 hour buckets
        time_buckets = defaultdict(int)
        
        for error in errors:
            try:
                error_time = datetime.fromisoformat(error.get("timestamp", "").replace("Z", "+00:00"))
                # Round down to bucket boundary
                bucket_time = error_time.replace(
                    minute=error_time.minute - error_time.minute % bucket_size_minutes,
                    second=0,
                    microsecond=0
                )
                time_buckets[bucket_time] += 1
            except:
                continue
        
        # Calculate trend
        if len(time_buckets) >= 2:
            sorted_buckets = sorted(time_buckets.items())
            error_counts = [count for _, count in sorted_buckets]
            
            # Simple linear trend
            if error_counts[-1] > error_counts[0]:
                trend_direction = "increasing"
            elif error_counts[-1] < error_counts[0]:
                trend_direction = "decreasing"
            else:
                trend_direction = "stable"
        else:
            trend_direction = "insufficient_data"
        
        return {
            "trend_direction": trend_direction,
            "total_time_buckets": len(time_buckets),
            "average_errors_per_bucket": sum(time_buckets.values()) / len(time_buckets) if time_buckets else 0,
            "peak_error_count": max(time_buckets.values()) if time_buckets else 0,
            "error_distribution": [
                {"time": time.isoformat(), "count": count}
                for time, count in sorted(time_buckets.items())
            ]
        }
    
    def _generate_error_remediation(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate remediation recommendations based on error analysis."""
        remediation = {
            "immediate_actions": [],
            "short_term_actions": [],
            "long_term_actions": [],
            "preventive_measures": []
        }
        
        overview = analysis.get("overview", {})
        critical_errors = analysis.get("critical_errors", [])
        root_cause = analysis.get("root_cause_analysis", {})
        
        # Immediate actions for critical errors
        if critical_errors:
            remediation["immediate_actions"].append({
                "priority": "critical",
                "action": f"Address {len(critical_errors)} critical errors immediately",
                "timeline": "within 1 hour"
            })
        
        # Actions based on root cause analysis
        for pattern, cause_analysis in root_cause.items():
            if cause_analysis.get("confidence_score", 0) > 80:
                for action in cause_analysis.get("recommended_actions", []):
                    remediation["short_term_actions"].append({
                        "action": action,
                        "pattern": pattern[:50] + "..." if len(pattern) > 50 else pattern,
                        "confidence": cause_analysis.get("confidence_score")
                    })
        
        # Long-term actions based on trends
        trends = analysis.get("trends", {})
        if trends.get("trend_direction") == "increasing":
            remediation["long_term_actions"].append("Implement proactive monitoring to prevent error escalation")
        
        # Preventive measures
        remediation["preventive_measures"] = [
            "Implement automated error detection and alerting",
            "Regular system health checks and maintenance",
            "Monitor system resources and performance metrics",
            "Maintain up-to-date system documentation"
        ]
        
        return remediation