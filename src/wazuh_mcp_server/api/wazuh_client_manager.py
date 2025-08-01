"""Wazuh Client Manager for handling both Server and Indexer APIs."""

import re
from typing import Dict, Any, Optional, List
from packaging import version
from datetime import datetime

# Clean absolute imports within the package
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.utils import get_logger
from wazuh_mcp_server.api.wazuh_client import WazuhAPIClient
from wazuh_mcp_server.api.wazuh_indexer_client import WazuhIndexerClient

logger = get_logger(__name__)


class WazuhClientManager:
    """Manages both Wazuh Server API and Indexer API clients."""
    
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.server_client = WazuhAPIClient(config)
        self.indexer_client = None
        self.wazuh_version = None
        
        # Initialize indexer client if configuration is available
        if self._has_indexer_config():
            self.indexer_client = WazuhIndexerClient(config)
        else:
            logger.warning("Indexer configuration not found, some features may be limited")
    
    def _has_indexer_config(self) -> bool:
        """Check if indexer configuration is available."""
        return (
            self.config.indexer_host is not None and
            self.config.indexer_username is not None and
            self.config.indexer_password is not None
        )
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.server_client.__aenter__()
        if self.indexer_client:
            await self.indexer_client.__aenter__()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.server_client.__aexit__(exc_type, exc_val, exc_tb)
        if self.indexer_client:
            await self.indexer_client.__aexit__(exc_type, exc_val, exc_tb)
    
    async def detect_wazuh_version(self) -> Optional[str]:
        """Detect Wazuh version from the server API."""
        try:
            info = await self.server_client._request("GET", "/")
            version_str = info.get("data", {}).get("api_version", "")
            if version_str:
                self.wazuh_version = version_str
                logger.info(f"Detected Wazuh version: {version_str}")
                return version_str
        except Exception as e:
            logger.warning(f"Could not detect Wazuh version: {str(e)}")
        return None
    
    def _is_version_48_or_later(self) -> bool:
        """Check if Wazuh version is 4.8.0 or later."""
        if not self.wazuh_version:
            # If version is not detected, use configuration flag
            return self.config.use_indexer_for_alerts
        
        try:
            # Extract version number (e.g., "v4.8.0" -> "4.8.0")
            version_match = re.search(r'(\d+\.\d+\.\d+)', self.wazuh_version)
            if version_match:
                current_version = version.parse(version_match.group(1))
                min_version = version.parse("4.8.0")
                return current_version >= min_version
        except Exception as e:
            logger.warning(f"Could not parse version {self.wazuh_version}: {str(e)}")
        
        return self.config.use_indexer_for_alerts
    
    def _should_use_indexer_for_alerts(self) -> bool:
        """Determine if Indexer API should be used for alerts."""
        return (
            self.indexer_client is not None and
            self.config.use_indexer_for_alerts and
            self._is_version_48_or_later()
        )
    
    def _should_use_indexer_for_vulnerabilities(self) -> bool:
        """Determine if Indexer API should be used for vulnerabilities."""
        return (
            self.indexer_client is not None and
            self.config.use_indexer_for_vulnerabilities and
            self._is_version_48_or_later()
        )
    
    async def get_alerts(
        self, 
        limit: int = 100, 
        offset: int = 0,
        level: Optional[int] = None, 
        sort: str = "-timestamp",
        time_range: Optional[int] = None,
        agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get alerts using appropriate API (Server or Indexer)."""
        
        if self._should_use_indexer_for_alerts():
            logger.debug("Using Indexer API for alerts")
            return await self.indexer_client.search_alerts(
                limit=limit,
                offset=offset,
                level=level,
                sort=sort,
                time_range=time_range,
                agent_id=agent_id
            )
        else:
            logger.debug("Using Server API for alerts")
            try:
                return await self.server_client.get_alerts(
                    limit=limit,
                    offset=offset,
                    level=level,
                    sort=sort,
                    time_range=time_range,
                    agent_id=agent_id
                )
            except Exception as e:
                # If Server API fails and we have Indexer, try fallback
                if self.indexer_client and "404" in str(e):
                    logger.warning("Server API alerts endpoint not found, falling back to Indexer API")
                    return await self.indexer_client.search_alerts(
                        limit=limit,
                        offset=offset,
                        level=level,
                        sort=sort,
                        time_range=time_range,
                        agent_id=agent_id
                    )
                raise
    
    async def get_agent_vulnerabilities(self, agent_id: str) -> Dict[str, Any]:
        """Get vulnerabilities for an agent using appropriate API."""
        
        if self._should_use_indexer_for_vulnerabilities():
            logger.debug("Using Indexer API for vulnerabilities")
            return await self.indexer_client.search_vulnerabilities(agent_id=agent_id)
        else:
            logger.debug("Using Server API for vulnerabilities")
            try:
                return await self.server_client.get_agent_vulnerabilities(agent_id)
            except Exception as e:
                # If Server API fails and we have Indexer, try fallback
                if self.indexer_client and "404" in str(e):
                    logger.warning("Server API vulnerability endpoint not found, falling back to Indexer API")
                    return await self.indexer_client.search_vulnerabilities(agent_id=agent_id)
                raise
    
    async def search_vulnerabilities(
        self, 
        agent_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        limit: int = 100
    ) -> Dict[str, Any]:
        """Search vulnerabilities using Indexer API."""
        if not self.indexer_client:
            raise ValueError("Indexer client not available for vulnerability search")
        
        return await self.indexer_client.search_vulnerabilities(
            agent_id=agent_id,
            cve_id=cve_id,
            limit=limit
        )
    
    # Delegate other methods to server client
    async def get_agents(self, **kwargs) -> Dict[str, Any]:
        """Get agents from Server API."""
        return await self.server_client.get_agents(**kwargs)
    
    async def get_rules(self, **kwargs) -> Dict[str, Any]:
        """Get rules from Server API."""
        return await self.server_client.get_rules(**kwargs)
    
    async def get_decoders(self, **kwargs) -> Dict[str, Any]:
        """Get decoders from Server API."""
        return await self.server_client.get_decoders(**kwargs)
    
    async def get_agent_stats(self, agent_id: str) -> Dict[str, Any]:
        """Get agent stats from Server API."""
        return await self.server_client.get_agent_stats(agent_id)
    
    async def get_agent_processes(self, agent_id: str) -> Dict[str, Any]:
        """Get agent processes from Server API."""
        return await self.server_client.get_agent_processes(agent_id)
    
    async def get_agent_ports(self, agent_id: str) -> Dict[str, Any]:
        """Get agent ports from Server API."""
        return await self.server_client.get_agent_ports(agent_id)
    
    async def get_wazuh_stats(self, component: str, stat_type: str, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Get Wazuh statistics from Server API."""
        return await self.server_client.get_wazuh_stats(component, stat_type, agent_id)
    
    async def search_wazuh_logs(self, log_source: str, query: str, limit: int = 100, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Search Wazuh logs from Server API."""
        return await self.server_client.search_wazuh_logs(log_source, query, limit, agent_id)
    
    async def get_cluster_info(self) -> Dict[str, Any]:
        """Get cluster info from Server API."""
        return await self.server_client.get_cluster_info()
    
    async def get_cluster_nodes(self) -> Dict[str, Any]:
        """Get cluster nodes from Server API."""
        return await self.server_client.get_cluster_nodes()
    
    async def restart_agent(self, agent_id: str) -> Dict[str, Any]:
        """Restart agent via Server API."""
        return await self.server_client.restart_agent(agent_id)
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check of both APIs."""
        health_data = {
            "server_api": await self.server_client.health_check(),
            "indexer_api": None,
            "overall_status": "healthy",
            "wazuh_version": self.wazuh_version,
            "using_indexer_for_alerts": self._should_use_indexer_for_alerts(),
            "using_indexer_for_vulnerabilities": self._should_use_indexer_for_vulnerabilities()
        }
        
        if self.indexer_client:
            try:
                health_data["indexer_api"] = await self.indexer_client.health_check()
            except Exception as e:
                health_data["indexer_api"] = {"status": "unhealthy", "error": str(e)}
        
        # Determine overall status
        server_healthy = health_data["server_api"]["status"] == "healthy"
        indexer_healthy = (
            health_data["indexer_api"] is None or 
            health_data["indexer_api"]["status"] in ["healthy", "green", "yellow"]
        )
        
        if not server_healthy or (self.indexer_client and not indexer_healthy):
            health_data["overall_status"] = "unhealthy"
        
        return health_data
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get metrics from both clients."""
        metrics = {
            "server_api": self.server_client.get_metrics(),
            "indexer_api": None,
            "configuration": {
                "wazuh_version": self.wazuh_version,
                "indexer_available": self.indexer_client is not None,
                "using_indexer_for_alerts": self._should_use_indexer_for_alerts(),
                "using_indexer_for_vulnerabilities": self._should_use_indexer_for_vulnerabilities()
            }
        }
        
        if self.indexer_client:
            metrics["indexer_api"] = self.indexer_client.get_metrics()
        
        return metrics
    
    # Additional methods required by FastMCP server
    
    async def get_vulnerabilities(self, query_params: Dict[str, Any]) -> Dict[str, Any]:
        """Get vulnerabilities with query parameters."""
        agent_id = query_params.get('agent_id')
        severity = query_params.get('severity')
        limit = query_params.get('limit', 100)
        
        if agent_id:
            return await self.get_agent_vulnerabilities(agent_id)
        else:
            return await self.search_vulnerabilities(severity=severity, limit=limit)
    
    async def get_alert_summary(self, time_range: str = "24h", group_by: str = "rule.level") -> Dict[str, Any]:
        """Get alert summary grouped by specified field."""
        try:
            # Calculate time range
            hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}.get(time_range, 24)
            
            # Get alerts from the specified time range
            alerts_data = await self.get_alerts(
                timestamp_gte=f"now-{hours}h",
                limit=1000
            )
            
            # Summarize alerts by group_by field
            summary = {}
            alerts = alerts_data.get('data', {}).get('affected_items', [])
            
            for alert in alerts:
                key = self._get_nested_value(alert, group_by) or "unknown"
                if key not in summary:
                    summary[key] = {"count": 0, "alerts": []}
                summary[key]["count"] += 1
                summary[key]["alerts"].append(alert)
            
            return {
                "data": {
                    "summary": summary,
                    "total_alerts": len(alerts),
                    "time_range": time_range,
                    "group_by": group_by
                }
            }
        except Exception as e:
            logger.error(f"Error getting alert summary: {e}")
            return {"error": str(e)}
    
    async def get_running_agents(self) -> Dict[str, Any]:
        """Get list of active/running agents."""
        return await self.get_agents(status="active")
    
    async def get_cluster_health(self) -> Dict[str, Any]:
        """Get cluster health information."""
        try:
            cluster_info = await self.get_cluster_info()
            nodes_info = await self.get_cluster_nodes()
            
            return {
                "data": {
                    "cluster_info": cluster_info,
                    "nodes": nodes_info,
                    "status": "healthy" if cluster_info.get("data") else "unknown"
                }
            }
        except Exception as e:
            logger.error(f"Error getting cluster health: {e}")
            return {"error": str(e)}
    
    async def get_rules_summary(self) -> Dict[str, Any]:
        """Get rules summary and effectiveness."""
        try:
            rules_data = await self.get_rules(limit=1000)
            
            # Get recent alerts to analyze rule effectiveness
            alerts_data = await self.get_alerts(limit=1000)
            alerts = alerts_data.get('data', {}).get('affected_items', [])
            
            # Count rule usage
            rule_usage = {}
            for alert in alerts:
                rule_id = alert.get('rule', {}).get('id')
                if rule_id:
                    rule_usage[rule_id] = rule_usage.get(rule_id, 0) + 1
            
            rules = rules_data.get('data', {}).get('affected_items', [])
            for rule in rules:
                rule_id = str(rule.get('id'))
                rule['usage_count'] = rule_usage.get(rule_id, 0)
            
            return {
                "data": {
                    "rules": rules,
                    "total_rules": len(rules),
                    "active_rules": len([r for r in rules if r.get('usage_count', 0) > 0])
                }
            }
        except Exception as e:
            logger.error(f"Error getting rules summary: {e}")
            return {"error": str(e)}
    
    async def get_weekly_stats(self) -> Dict[str, Any]:
        """Get weekly statistics."""
        try:
            # Get alerts from last 7 days
            alerts_data = await self.get_alerts(
                timestamp_gte="now-7d",
                limit=5000
            )
            
            # Get agent stats
            agents_data = await self.get_agents()
            
            alerts = alerts_data.get('data', {}).get('affected_items', [])
            agents = agents_data.get('data', {}).get('affected_items', [])
            
            # Calculate statistics
            active_agents = len([a for a in agents if a.get('status') == 'active'])
            total_alerts = len(alerts)
            critical_alerts = len([a for a in alerts if int(a.get('rule', {}).get('level', 0)) >= 12])
            
            return {
                "data": {
                    "total_alerts": total_alerts,
                    "critical_alerts": critical_alerts,
                    "active_agents": active_agents,
                    "total_agents": len(agents),
                    "period": "7 days"
                }
            }
        except Exception as e:
            logger.error(f"Error getting weekly stats: {e}")
            return {"error": str(e)}
    
    async def search_manager_logs(self, query: str, limit: int = 100) -> Dict[str, Any]:
        """Search manager logs."""
        return await self.search_wazuh_logs("manager", query, limit)
    
    async def get_critical_vulnerabilities(self, limit: int = 50) -> Dict[str, Any]:
        """Get critical vulnerabilities."""
        return await self.search_vulnerabilities(severity="critical", limit=limit)
    
    async def get_vulnerability_summary(self, time_range: str = "7d") -> Dict[str, Any]:
        """Get vulnerability summary."""
        try:
            vulns_data = await self.search_vulnerabilities(limit=1000)
            vulnerabilities = vulns_data.get('data', {}).get('affected_items', [])
            
            # Summarize by severity
            severity_count = {}
            for vuln in vulnerabilities:
                severity = vuln.get('severity', 'unknown')
                severity_count[severity] = severity_count.get(severity, 0) + 1
            
            return {
                "data": {
                    "summary": severity_count,
                    "total_vulnerabilities": len(vulnerabilities),
                    "time_range": time_range
                }
            }
        except Exception as e:
            logger.error(f"Error getting vulnerability summary: {e}")
            return {"error": str(e)}
    
    async def get_remoted_stats(self) -> Dict[str, Any]:
        """Get remoted daemon statistics."""
        return await self.get_wazuh_stats("remoted", "stats")
    
    async def get_log_collector_stats(self) -> Dict[str, Any]:
        """Get log collector statistics."""
        return await self.get_wazuh_stats("logcollector", "stats")
    
    async def get_manager_error_logs(self, limit: int = 100) -> Dict[str, Any]:
        """Get manager error logs."""
        return await self.search_wazuh_logs("manager", "ERROR", limit)
    
    async def check_agent_health(self, agent_id: str) -> Dict[str, Any]:
        """Check agent health status."""
        try:
            agent_data = await self.get_agents(agents_list=[agent_id])
            agents = agent_data.get('data', {}).get('affected_items', [])
            
            if not agents:
                return {"error": f"Agent {agent_id} not found"}
            
            agent = agents[0]
            status = agent.get('status', 'unknown')
            last_keep_alive = agent.get('lastKeepAlive')
            
            health_status = "healthy" if status == "active" else "unhealthy"
            
            return {
                "data": {
                    "agent_id": agent_id,
                    "status": status,
                    "health": health_status,
                    "last_keep_alive": last_keep_alive,
                    "details": agent
                }
            }
        except Exception as e:
            logger.error(f"Error checking agent health: {e}")
            return {"error": str(e)}
    
    async def get_wazuh_statistics(self) -> Dict[str, Any]:
        """Get comprehensive Wazuh statistics."""
        try:
            # Get various statistics
            agents_data = await self.get_agents()
            alerts_data = await self.get_alerts(limit=1000)
            cluster_info = await self.get_cluster_info()
            
            agents = agents_data.get('data', {}).get('affected_items', [])
            alerts = alerts_data.get('data', {}).get('affected_items', [])
            
            stats = {
                "agents": {
                    "total": len(agents),
                    "active": len([a for a in agents if a.get('status') == 'active']),
                    "disconnected": len([a for a in agents if a.get('status') == 'disconnected'])
                },
                "alerts": {
                    "total": len(alerts),
                    "critical": len([a for a in alerts if int(a.get('rule', {}).get('level', 0)) >= 12])
                },
                "cluster": cluster_info.get('data', {})
            }
            
            return {"data": stats}
        except Exception as e:
            logger.error(f"Error getting Wazuh statistics: {e}")
            return {"error": str(e)}
    
    async def search_security_events(self, query: str, time_range: str = "24h", limit: int = 100) -> Dict[str, Any]:
        """Search for security events."""
        try:
            hours = {"1h": 1, "6h": 6, "24h": 24, "7d": 168}.get(time_range, 24)
            
            # Search in alerts
            alerts_data = await self.get_alerts(
                query=query,
                timestamp_gte=f"now-{hours}h",
                limit=limit
            )
            
            return alerts_data
        except Exception as e:
            logger.error(f"Error searching security events: {e}")
            return {"error": str(e)}
    
    async def get_agent_configuration(self, agent_id: str) -> Dict[str, Any]:
        """Get agent configuration."""
        try:
            # Use the server client to get agent configuration
            return await self.server_client.get_agent_config(agent_id)
        except Exception as e:
            logger.error(f"Error getting agent configuration: {e}")
            return {"error": str(e)}
    
    async def validate_connection(self) -> Dict[str, Any]:
        """Validate connection to Wazuh server."""
        try:
            # Test server connection
            health_result = await self.health_check()
            
            # Test basic API call
            info_result = await self.server_client.get("/")
            
            return {
                "data": {
                    "status": "connected",
                    "server_health": health_result,
                    "api_info": info_result,
                    "timestamp": datetime.now().isoformat()
                }
            }
        except Exception as e:
            logger.error(f"Connection validation failed: {e}")
            return {
                "error": str(e),
                "status": "disconnected",
                "timestamp": datetime.now().isoformat()
            }
    
    def _get_nested_value(self, data: Dict[str, Any], key_path: str) -> Any:
        """Get nested value from dictionary using dot notation."""
        keys = key_path.split('.')
        value = data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return None
        return value