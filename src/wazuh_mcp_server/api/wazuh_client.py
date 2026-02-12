"""Wazuh API client optimized for Wazuh 4.8.0 to 4.14.1 compatibility with latest features."""

import asyncio
import json
import time
from collections import deque
from functools import lru_cache
from typing import Dict, Any, Optional, Tuple
import httpx
import logging

from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.resilience import (
    CircuitBreaker,
    CircuitBreakerConfig,
    RetryConfig
)
from wazuh_mcp_server.api.wazuh_indexer import (
    WazuhIndexerClient,
    IndexerNotConfiguredError
)

logger = logging.getLogger(__name__)


class WazuhClient:
    """Simplified Wazuh API client with rate limiting, circuit breaker, and retry logic."""

    def __init__(self, config: WazuhConfig):
        self.config = config
        self.token: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None
        # Rate limiting with O(1) deque operations
        self._rate_limiter = asyncio.Semaphore(config.max_connections)
        self._request_times: deque = deque(maxlen=200)  # Pre-sized deque for efficiency
        self._max_requests_per_minute = getattr(config, 'max_requests_per_minute', 100)
        self._rate_limit_enabled = True
        # Response caching for static data
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._cache_ttl = 300  # 5 minutes for static data

        # Circuit breaker for API resilience
        circuit_config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=Exception
        )
        self._circuit_breaker = CircuitBreaker(circuit_config)

        # Initialize Wazuh Indexer client if configured (required for Wazuh 4.8.0+)
        self._indexer_client: Optional[WazuhIndexerClient] = None
        if config.wazuh_indexer_host:
            self._indexer_client = WazuhIndexerClient(
                host=config.wazuh_indexer_host,
                port=config.wazuh_indexer_port,
                username=config.wazuh_indexer_user,
                password=config.wazuh_indexer_pass,
                verify_ssl=config.verify_ssl,
                timeout=config.request_timeout_seconds
            )
            logger.info(f"WazuhIndexerClient configured for {config.wazuh_indexer_host}:{config.wazuh_indexer_port}")
        else:
            logger.warning(
                "Wazuh Indexer not configured. Vulnerability tools will not work with Wazuh 4.8.0+. "
                "Set WAZUH_INDEXER_HOST to enable vulnerability queries."
            )

        logger.info("WazuhClient initialized with circuit breaker and retry logic")
    
    async def initialize(self):
        """Initialize the HTTP client and authenticate."""
        self.client = httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.request_timeout_seconds
        )
        await self._authenticate()

        # Initialize indexer client if configured
        if self._indexer_client:
            try:
                await self._indexer_client.initialize()
                logger.info("Wazuh Indexer client initialized successfully")
            except Exception as e:
                logger.warning(f"Wazuh Indexer initialization failed: {e}")
    
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
            logger.info(f"Authenticated with Wazuh server at {self.config.wazuh_host}")
            
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
        """
        Get vulnerabilities from Wazuh Indexer (4.8.0+ required).

        Note: The /vulnerability API endpoint was deprecated in Wazuh 4.7.0
        and removed in 4.8.0. Vulnerability data must be queried from the
        Wazuh Indexer using the wazuh-states-vulnerabilities-* index.

        Args:
            agent_id: Filter by agent ID
            severity: Filter by severity (critical, high, medium, low)
            limit: Maximum number of results (default: 100)

        Returns:
            Vulnerability data from the indexer

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        agent_id = params.get("agent_id")
        severity = params.get("severity")
        limit = params.get("limit", 100)

        return await self._indexer_client.get_vulnerabilities(
            agent_id=agent_id,
            severity=severity,
            limit=limit
        )
    
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
    
    async def _get_cached(self, cache_key: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Get data from cache or fetch from API.

        Args:
            cache_key: Unique cache key for this request
            endpoint: API endpoint
            **kwargs: Additional request parameters

        Returns:
            Cached or fresh API response
        """
        from wazuh_mcp_server.monitoring import record_cache_access
        current_time = time.time()

        # Check cache
        if cache_key in self._cache:
            cached_time, cached_data = self._cache[cache_key]
            if current_time - cached_time < self._cache_ttl:
                record_cache_access("wazuh_api", hit=True)
                return cached_data

        record_cache_access("wazuh_api", hit=False)

        # Fetch from API
        result = await self._request("GET", endpoint, **kwargs)

        # Cache the result
        self._cache[cache_key] = (current_time, result)

        return result

    async def get_rules(self, **params) -> Dict[str, Any]:
        """Get Wazuh detection rules (cached for 5 minutes)."""
        # Use caching for rules as they rarely change
        cache_key = f"rules:{hash(frozenset(params.items()) if params else 'all')}"
        return await self._get_cached(cache_key, "/rules", params=params)
    
    async def get_rule_info(self, rule_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific rule."""
        return await self._request("GET", f"/rules/{rule_id}")
    
    async def get_decoders(self, **params) -> Dict[str, Any]:
        """Get Wazuh log decoders (cached for 5 minutes)."""
        # Use caching for decoders as they rarely change
        cache_key = f"decoders:{hash(frozenset(params.items()) if params else 'all')}"
        return await self._get_cached(cache_key, "/decoders", params=params)
    
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
        """
        Get Cyber Threat Intelligence data for CVE (4.8.0+ via Indexer).

        Note: CTI data is now stored in the Wazuh Indexer.

        Args:
            cve_id: CVE ID to look up (e.g., "CVE-2021-44228")

        Returns:
            Vulnerability data for the specific CVE

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        return await self._indexer_client.get_vulnerabilities(cve_id=cve_id, limit=100)

    async def get_vulnerability_details(self, vuln_id: str, **params) -> Dict[str, Any]:
        """
        Get detailed vulnerability information (4.8.0+ via Indexer).

        Note: Vulnerability details are now stored in the Wazuh Indexer.

        Args:
            vuln_id: Vulnerability/CVE ID

        Returns:
            Detailed vulnerability information

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        return await self._indexer_client.get_vulnerabilities(cve_id=vuln_id, limit=1)
    
    async def get_agent_stats(self, agent_id: str, component: str = "logcollector") -> Dict[str, Any]:
        """Get agent component statistics."""
        return await self._request("GET", f"/agents/{agent_id}/stats/{component}")
    
    async def _rate_limit_check(self) -> None:
        """Check and enforce rate limiting using efficient O(1) deque operations."""
        current_time = time.time()

        # Remove requests older than 1 minute from front of deque (O(1) per removal)
        while self._request_times and current_time - self._request_times[0] >= 60:
            self._request_times.popleft()

        # Check if we're hitting the rate limit
        if len(self._request_times) >= self._max_requests_per_minute:
            # Calculate how long to wait before the oldest request expires
            oldest_request_time = self._request_times[0]
            sleep_time = 60 - (current_time - oldest_request_time)

            if sleep_time > 0:
                logger.warning(f"Rate limit reached ({self._max_requests_per_minute}/min). Waiting {sleep_time:.1f}s...")
                await asyncio.sleep(sleep_time)

                # Clean up expired requests after waiting
                current_time = time.time()
                while self._request_times and current_time - self._request_times[0] >= 60:
                    self._request_times.popleft()

        # Record this request time (O(1) append)
        self._request_times.append(current_time)

    async def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make authenticated request to Wazuh API with rate limiting, circuit breaker, and retry logic."""
        # Apply rate limiting
        async with self._rate_limiter:
            await self._rate_limit_check()

            # Apply circuit breaker and retry logic
            return await self._request_with_resilience(method, endpoint, **kwargs)

    @RetryConfig.WAZUH_API_RETRY
    async def _request_with_resilience(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute request with circuit breaker and retry logic."""
        return await self._circuit_breaker._call(self._execute_request, method, endpoint, **kwargs)

    async def _execute_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute the actual HTTP request to Wazuh API."""
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
                logger.error(f"Wazuh API request failed: {e.response.status_code} - {e.response.text}")
                raise ValueError(f"Wazuh API request failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError as e:
            logger.error(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
            raise ConnectionError(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
        except httpx.TimeoutException as e:
            logger.error(f"Request timeout to Wazuh server")
            raise ConnectionError(f"Request timeout to Wazuh server")
    
    async def get_manager_info(self) -> Dict[str, Any]:
        """Get Wazuh manager information (cached for 5 minutes)."""
        cache_key = "manager_info"
        return await self._get_cached(cache_key, "/")

    async def get_alert_summary(self, time_range: str, group_by: str) -> Dict[str, Any]:
        """Get alert summary grouped by field."""
        params = {"time_range": time_range, "group_by": group_by}
        return await self._request("GET", "/alerts/summary", params=params)

    async def analyze_alert_patterns(self, time_range: str, min_frequency: int) -> Dict[str, Any]:
        """Analyze alert patterns."""
        params = {"time_range": time_range, "min_frequency": min_frequency}
        return await self._request("GET", "/alerts/patterns", params=params)

    async def search_security_events(self, query: str, time_range: str, limit: int) -> Dict[str, Any]:
        """Search security events."""
        params = {"q": query, "time_range": time_range, "limit": limit}
        return await self._request("GET", "/security/events", params=params)

    async def get_running_agents(self) -> Dict[str, Any]:
        """Get running agents."""
        return await self._request("GET", "/agents", params={"status": "active"})

    async def check_agent_health(self, agent_id: str) -> Dict[str, Any]:
        """Check agent health."""
        return await self._request("GET", f"/agents/{agent_id}/health")

    async def get_agent_processes(self, agent_id: str, limit: int) -> Dict[str, Any]:
        """Get agent processes."""
        return await self._request("GET", f"/syscollector/{agent_id}/processes", params={"limit": limit})

    async def get_agent_ports(self, agent_id: str, limit: int) -> Dict[str, Any]:
        """Get agent ports."""
        return await self._request("GET", f"/syscollector/{agent_id}/ports", params={"limit": limit})

    async def get_agent_configuration(self, agent_id: str) -> Dict[str, Any]:
        """Get agent configuration."""
        return await self._request("GET", f"/agents/{agent_id}/config")

    async def get_critical_vulnerabilities(self, limit: int) -> Dict[str, Any]:
        """
        Get critical vulnerabilities from Wazuh Indexer (4.8.0+ required).

        Args:
            limit: Maximum number of results

        Returns:
            Critical vulnerability data from the indexer

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        return await self._indexer_client.get_critical_vulnerabilities(limit=limit)

    async def get_vulnerability_summary(self, time_range: str) -> Dict[str, Any]:
        """
        Get vulnerability summary statistics from Wazuh Indexer (4.8.0+ required).

        Args:
            time_range: Time range for the summary (currently not used, returns all current vulnerabilities)

        Returns:
            Vulnerability summary with counts by severity

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()

        return await self._indexer_client.get_vulnerability_summary()

    async def analyze_security_threat(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Analyze security threat."""
        data = {"indicator": indicator, "type": indicator_type}
        return await self._request("POST", "/security/threat/analyze", json=data)

    async def check_ioc_reputation(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Check IoC reputation."""
        params = {"indicator": indicator, "type": indicator_type}
        return await self._request("GET", "/security/ioc/reputation", params=params)

    async def perform_risk_assessment(self, agent_id: str = None) -> Dict[str, Any]:
        """Perform risk assessment."""
        endpoint = f"/security/risk/{agent_id}" if agent_id else "/security/risk"
        return await self._request("GET", endpoint)

    async def get_top_security_threats(self, limit: int, time_range: str) -> Dict[str, Any]:
        """Get top security threats."""
        params = {"limit": limit, "time_range": time_range}
        return await self._request("GET", "/security/threats/top", params=params)

    async def generate_security_report(self, report_type: str, include_recommendations: bool) -> Dict[str, Any]:
        """Generate security report."""
        data = {"type": report_type, "include_recommendations": include_recommendations}
        return await self._request("POST", "/security/reports/generate", json=data)

    async def run_compliance_check(self, framework: str, agent_id: str = None) -> Dict[str, Any]:
        """Run compliance check."""
        data = {"framework": framework}
        if agent_id:
            data["agent_id"] = agent_id
        return await self._request("POST", "/security/compliance/check", json=data)

    async def get_wazuh_statistics(self) -> Dict[str, Any]:
        """Get Wazuh statistics."""
        return await self._request("GET", "/manager/stats/all")

    async def get_weekly_stats(self) -> Dict[str, Any]:
        """Get weekly statistics."""
        return await self._request("GET", "/manager/stats/weekly")

    async def get_cluster_health(self) -> Dict[str, Any]:
        """Get cluster health."""
        return await self._request("GET", "/cluster/health")

    async def get_cluster_nodes(self) -> Dict[str, Any]:
        """Get cluster nodes (cached for 2 minutes)."""
        cache_key = "cluster_nodes"
        return await self._get_cached(cache_key, "/cluster/nodes")

    async def get_rules_summary(self) -> Dict[str, Any]:
        """Get rules summary (cached for 5 minutes)."""
        cache_key = "rules_summary"
        return await self._get_cached(cache_key, "/rules/summary")

    async def get_remoted_stats(self) -> Dict[str, Any]:
        """Get remoted statistics."""
        return await self._request("GET", "/manager/stats/remoted")

    async def get_log_collector_stats(self) -> Dict[str, Any]:
        """Get log collector statistics."""
        return await self._request("GET", "/manager/stats/logcollector")

    async def search_manager_logs(self, query: str, limit: int) -> Dict[str, Any]:
        """Search manager logs."""
        params = {"q": query, "limit": limit}
        return await self._request("GET", "/manager/logs", params=params)

    async def get_manager_error_logs(self, limit: int) -> Dict[str, Any]:
        """Get manager error logs."""
        params = {"level": "error", "limit": limit}
        return await self._request("GET", "/manager/logs", params=params)

    async def validate_connection(self) -> Dict[str, Any]:
        """Validate Wazuh connection."""
        try:
            result = await self._request("GET", "/")
            return {"status": "connected", "details": result}
        except Exception as e:
            return {"status": "failed", "error": str(e)}
    
    async def close(self):
        """Close the HTTP client and indexer client."""
        if self.client:
            await self.client.aclose()
        if self._indexer_client:
            await self._indexer_client.close()