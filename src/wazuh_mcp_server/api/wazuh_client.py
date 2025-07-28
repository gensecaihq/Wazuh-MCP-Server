"""Wazuh API client optimized for Wazuh 4.8+ to 4.12+ compatibility with latest features."""

import asyncio
import json
import time
from typing import Dict, Any, Optional
import httpx

from wazuh_mcp_server.config import WazuhConfig


class WazuhClient:
    """Simplified Wazuh API client with rate limiting."""
    
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.token: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None
        # Rate limiting
        self._rate_limiter = asyncio.Semaphore(config.max_connections)
        self._request_times = []
        self._max_requests_per_minute = getattr(config, 'max_requests_per_minute', 100)
        self._rate_limit_enabled = True
    
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
        
        try:
            response = await self.client.post(
                auth_url,
                auth=(self.config.wazuh_user, self.config.wazuh_pass)
            )
            response.raise_for_status()
            
            data = response.json()
            if "data" not in data or "token" not in data["data"]:
                raise ValueError("Invalid authentication response from Wazuh API")
            
            self.token = data["data"]["token"]
            print(f"✅ Authenticated with Wazuh server at {self.config.wazuh_host}")
            
        except httpx.ConnectError:
            raise ConnectionError(f"Cannot connect to Wazuh server at {self.config.wazuh_host}:{self.config.wazuh_port}")
        except httpx.TimeoutException:
            raise ConnectionError(f"Connection timeout to Wazuh server at {self.config.wazuh_host}")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                raise ValueError("Invalid Wazuh credentials. Check WAZUH_USER and WAZUH_PASS")
            elif e.response.status_code == 403:
                raise ValueError("Wazuh user does not have sufficient permissions")
            else:
                raise ValueError(f"Wazuh API error: {e.response.status_code} - {e.response.text}")
    
    async def get_alerts(self, **params) -> Dict[str, Any]:
        """Get alerts from Wazuh."""
        return await self._request("GET", "/alerts", params=params)
    
    async def get_agents(self, **params) -> Dict[str, Any]:
        """Get agents from Wazuh."""
        return await self._request("GET", "/agents", params=params)
    
    async def get_vulnerabilities(self, **params) -> Dict[str, Any]:
        """Get vulnerabilities from Wazuh Indexer (4.8+ uses centralized vulnerability detection, 4.12+ includes package conditions and CTI data)."""
        # Note: /vulnerability endpoint was deprecated in 4.7.0 and removed in 4.8.0
        # 4.12+ includes package condition fields and CTI references
        return await self._request("GET", "/vulnerability/agents", params=params)
    
    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status."""
        return await self._request("GET", "/cluster/status")
    
    async def search_logs(self, **params) -> Dict[str, Any]:
        """Search logs with advanced filtering capabilities."""
        return await self._request("GET", "/manager/logs", params=params)
    
    async def get_incidents(self, **params) -> Dict[str, Any]:
        """Get security incidents."""
        return await self._request("GET", "/security/incidents", params=params)
    
    async def create_incident(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new security incident."""
        return await self._request("POST", "/security/incidents", json=data)
    
    async def update_incident(self, incident_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update an existing security incident."""
        return await self._request("PUT", f"/security/incidents/{incident_id}", json=data)
    
    async def get_rules(self, **params) -> Dict[str, Any]:
        """Get Wazuh detection rules."""
        return await self._request("GET", "/rules", params=params)
    
    async def get_rule_info(self, rule_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific rule."""
        return await self._request("GET", f"/rules/{rule_id}")
    
    async def get_decoders(self, **params) -> Dict[str, Any]:
        """Get Wazuh log decoders."""
        return await self._request("GET", "/decoders", params=params)
    
    async def execute_active_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute active response command on agents (4.8+ removed 'custom' parameter)."""
        # Note: 'custom' parameter was removed in Wazuh 4.8.0
        # Ensure data dict doesn't contain deprecated 'custom' parameter
        if 'custom' in data:
            data = {k: v for k, v in data.items() if k != 'custom'}
        return await self._request("PUT", "/active-response", json=data)
    
    async def get_active_response_commands(self, **params) -> Dict[str, Any]:
        """Get available active response commands."""
        return await self._request("GET", "/manager/configuration", params={"section": "active-response"})
    
    async def get_cdb_lists(self, **params) -> Dict[str, Any]:
        """Get CDB lists."""
        return await self._request("GET", "/lists", params=params)
    
    async def get_cdb_list_content(self, filename: str) -> Dict[str, Any]:
        """Get specific CDB list content."""
        return await self._request("GET", f"/lists/{filename}")
    
    async def get_fim_events(self, **params) -> Dict[str, Any]:
        """Get File Integrity Monitoring events."""
        return await self._request("GET", "/syscheck", params=params)
    
    async def get_syscollector_info(self, agent_id: str, **params) -> Dict[str, Any]:
        """Get system inventory information from agent."""
        return await self._request("GET", f"/syscollector/{agent_id}", params=params)
    
    async def get_manager_stats(self, **params) -> Dict[str, Any]:
        """Get manager statistics."""
        return await self._request("GET", "/manager/stats", params=params)
    
    async def get_manager_version_check(self) -> Dict[str, Any]:
        """Check for new Wazuh releases (4.8+ feature)."""
        return await self._request("GET", "/manager/version/check")
    
    async def get_cti_data(self, cve_id: str) -> Dict[str, Any]:
        """Get Cyber Threat Intelligence data for CVE (4.12+ feature)."""
        return await self._request("GET", f"/vulnerability/cti/{cve_id}")
    
    async def get_vulnerability_details(self, vuln_id: str, **params) -> Dict[str, Any]:
        """Get detailed vulnerability information including CTI references (4.12+ enhanced)."""
        return await self._request("GET", f"/vulnerability/{vuln_id}", params=params)
    
    async def get_agent_stats(self, agent_id: str, component: str = "logcollector") -> Dict[str, Any]:
        """Get agent component statistics."""
        return await self._request("GET", f"/agents/{agent_id}/stats/{component}")
    
    async def _rate_limit_check(self):
        """Check and enforce rate limiting."""
        current_time = time.time()
        
        # Remove requests older than 1 minute
        self._request_times = [t for t in self._request_times if current_time - t < 60]
        
        # Check if we're hitting the rate limit
        if len(self._request_times) >= self._max_requests_per_minute:
            # Calculate how long to wait before the oldest request expires
            oldest_request_time = self._request_times[0]
            sleep_time = 60 - (current_time - oldest_request_time)
            
            if sleep_time > 0:
                print(f"⚠️ Rate limit reached ({self._max_requests_per_minute}/min). Waiting {sleep_time:.1f}s...")
                await asyncio.sleep(sleep_time)
                
                # Clean up expired requests after waiting
                current_time = time.time()
                self._request_times = [t for t in self._request_times if current_time - t < 60]
        
        # Record this request time
        self._request_times.append(current_time)

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to Wazuh API with rate limiting."""
        # Apply rate limiting
        async with self._rate_limiter:
            await self._rate_limit_check()
            
            if not self.token:
                await self._authenticate()
            
            url = f"{self.config.base_url}{endpoint}"
            headers = {"Authorization": f"Bearer {self.token}"}
            
            try:
                response = await self.client.request(method, url, headers=headers, **kwargs)
                response.raise_for_status()
                
                data = response.json()
                
                # Validate response structure
                if "data" not in data:
                    raise ValueError(f"Invalid response structure from Wazuh API: {endpoint}")
                
                return data
                
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 401:
                    # Token might be expired, try to re-authenticate
                    self.token = None
                    await self._authenticate()
                    # Retry the request once
                    headers = {"Authorization": f"Bearer {self.token}"}
                    response = await self.client.request(method, url, headers=headers, **kwargs)
                    response.raise_for_status()
                    return response.json()
                else:
                    raise ValueError(f"Wazuh API request failed: {e.response.status_code} - {e.response.text}")
            except httpx.ConnectError:
                raise ConnectionError(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
            except httpx.TimeoutException:
                raise ConnectionError(f"Request timeout to Wazuh server")
    
    async def close(self):
        """Close the HTTP client."""
        if self.client:
            await self.client.aclose()