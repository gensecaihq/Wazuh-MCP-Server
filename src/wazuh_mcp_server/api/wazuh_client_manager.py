"""Wazuh Client Manager for handling both Server and Indexer APIs."""

import re
from typing import Dict, Any, Optional, List
from packaging import version

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
        except Exception:
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
        except Exception:
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
            except Exception:
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