"""Simplified Wazuh API client for core functionality."""

import asyncio
import json
from typing import Dict, Any, Optional
import httpx

from wazuh_mcp_server.config import WazuhConfig


class WazuhClient:
    """Simplified Wazuh API client."""
    
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.token: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None
    
    async def initialize(self):
        """Initialize the HTTP client and authenticate."""
        self.client = httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.request_timeout_seconds
        )
        await self._authenticate()
    
    async def _authenticate(self):
        """Authenticate with Wazuh API."""
        auth_url = f"{self.config.base_url}/security/user/authenticate"
        
        response = await self.client.post(
            auth_url,
            auth=(self.config.wazuh_user, self.config.wazuh_pass)
        )
        response.raise_for_status()
        
        data = response.json()
        self.token = data["data"]["token"]
    
    async def get_alerts(self, **params) -> Dict[str, Any]:
        """Get alerts from Wazuh."""
        return await self._request("GET", "/alerts", params=params)
    
    async def get_agents(self, **params) -> Dict[str, Any]:
        """Get agents from Wazuh."""
        return await self._request("GET", "/agents", params=params)
    
    async def get_vulnerabilities(self, **params) -> Dict[str, Any]:
        """Get vulnerabilities from Wazuh."""
        return await self._request("GET", "/vulnerability", params=params)
    
    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status."""
        return await self._request("GET", "/cluster/status")
    
    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to Wazuh API."""
        if not self.token:
            await self._authenticate()
        
        url = f"{self.config.base_url}{endpoint}"
        headers = {"Authorization": f"Bearer {self.token}"}
        
        response = await self.client.request(method, url, headers=headers, **kwargs)
        response.raise_for_status()
        
        return response.json()
    
    async def close(self):
        """Close the HTTP client."""
        if self.client:
            await self.client.aclose()