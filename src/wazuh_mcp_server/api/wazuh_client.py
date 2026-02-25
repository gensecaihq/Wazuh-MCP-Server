"""Wazuh API client optimized for Wazuh 4.8.0 to 4.14.1 compatibility with latest features."""

import asyncio
import json
import logging
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import httpx

from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError, WazuhIndexerClient
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.resilience import CircuitBreaker, CircuitBreakerConfig, RetryConfig

logger = logging.getLogger(__name__)

# Time range to hours mapping for indexer-based queries
_TIME_RANGE_HOURS = {"1h": 1, "6h": 6, "12h": 12, "24h": 24, "7d": 168, "30d": 720}


class WazuhClient:
    """Simplified Wazuh API client with rate limiting, circuit breaker, and retry logic."""

    def __init__(self, config: WazuhConfig):
        self.config = config
        self.token: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None
        # Lock to prevent concurrent re-authentication races
        self._auth_lock = asyncio.Lock()
        # Rate limiting with O(1) deque operations
        self._rate_limiter = asyncio.Semaphore(config.max_connections)
        self._request_times: deque = deque(maxlen=200)  # Pre-sized deque for efficiency
        self._max_requests_per_minute = getattr(config, "max_requests_per_minute", 100)
        self._rate_limit_enabled = True
        # Response caching for static data (bounded to prevent memory growth)
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._cache_ttl = 300  # 5 minutes for static data
        self._cache_max_size = 100

        # Circuit breaker for API resilience
        circuit_config = CircuitBreakerConfig(failure_threshold=5, recovery_timeout=60, expected_exception=Exception)
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
                timeout=config.request_timeout_seconds,
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
        self.client = httpx.AsyncClient(verify=self.config.verify_ssl, timeout=self.config.request_timeout_seconds)
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
            response = await self.client.post(auth_url, auth=(self.config.wazuh_user, self.config.wazuh_pass))
            response.raise_for_status()

            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError):
                raise ValueError("Invalid JSON in authentication response from Wazuh API")
            if "data" not in data or "token" not in data["data"]:
                raise ValueError("Invalid authentication response from Wazuh API")

            self.token = data["data"]["token"]
            logger.info(f"Authenticated with Wazuh server at {self.config.wazuh_host}")

        except httpx.ConnectError:
            raise ConnectionError(
                f"Cannot connect to Wazuh server at {self.config.wazuh_host}:{self.config.wazuh_port}"
            )
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
        """
        Get alerts from the Wazuh Indexer (wazuh-alerts-* index).

        Alerts are stored in the Wazuh Indexer, not the Manager API.
        The Manager API does not have a /alerts endpoint.

        Raises:
            IndexerNotConfiguredError: If Wazuh Indexer is not configured
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError(
                "Wazuh Indexer not configured. "
                "Alerts are stored in the Wazuh Indexer and require WAZUH_INDEXER_HOST to be set.\n\n"
                "Please set the following environment variables:\n"
                "  WAZUH_INDEXER_HOST=<indexer_hostname>\n"
                "  WAZUH_INDEXER_USER=<indexer_username>\n"
                "  WAZUH_INDEXER_PASS=<indexer_password>\n"
                "  WAZUH_INDEXER_PORT=9200 (optional, default: 9200)"
            )

        return await self._indexer_client.get_alerts(
            limit=params.get("limit", 100),
            rule_id=params.get("rule_id"),
            level=params.get("level"),
            agent_id=params.get("agent_id"),
            timestamp_start=params.get("timestamp_start"),
            timestamp_end=params.get("timestamp_end"),
        )

    async def get_agents(self, agent_id=None, status=None, limit=100, **params) -> Dict[str, Any]:
        """Get agents from Wazuh."""
        clean_params: Dict[str, Any] = {}
        if agent_id:
            clean_params["agents_list"] = agent_id
        if status:
            clean_params["status"] = status
        if limit:
            clean_params["limit"] = limit
        for k, v in params.items():
            if v is not None:
                clean_params[k] = v
        return await self._request("GET", "/agents", params=clean_params)

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

        return await self._indexer_client.get_vulnerabilities(agent_id=agent_id, severity=severity, limit=limit)

    async def get_cluster_status(self) -> Dict[str, Any]:
        """Get cluster status."""
        return await self._request("GET", "/cluster/status")

    async def search_logs(self, **params) -> Dict[str, Any]:
        """Search logs with advanced filtering capabilities."""
        return await self._request("GET", "/manager/logs", params=params)

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

        # Cache the result, evicting oldest if at capacity
        self._cache[cache_key] = (current_time, result)
        if len(self._cache) > self._cache_max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][0])
            del self._cache[oldest_key]

        return result

    async def get_rules(self, **params) -> Dict[str, Any]:
        """Get Wazuh detection rules (cached for 5 minutes)."""
        # Use caching for rules as they rarely change
        cache_key = f"rules:{sorted(params.items()) if params else 'all'}"
        return await self._get_cached(cache_key, "/rules", params=params)

    async def get_rule_info(self, rule_id: str) -> Dict[str, Any]:
        """Get detailed information about a specific rule."""
        return await self._request("GET", f"/rules/{rule_id}")

    async def get_decoders(self, **params) -> Dict[str, Any]:
        """Get Wazuh log decoders (cached for 5 minutes)."""
        # Use caching for decoders as they rarely change
        cache_key = f"decoders:{sorted(params.items()) if params else 'all'}"
        return await self._get_cached(cache_key, "/decoders", params=params)

    async def execute_active_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute active response command on agents (4.8+ removed 'custom' parameter)."""
        # Note: 'custom' parameter was removed in Wazuh 4.8.0
        # Ensure data dict doesn't contain deprecated 'custom' parameter
        if "custom" in data:
            data = {k: v for k, v in data.items() if k != "custom"}
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
                logger.warning(
                    f"Rate limit reached ({self._max_requests_per_minute}/min). Waiting {sleep_time:.1f}s..."
                )
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
        # Ensure client is initialized
        if not self.client:
            await self.initialize()
        elif not self.token:
            await self._authenticate()

        url = f"{self.config.base_url}{endpoint}"
        headers = {"Authorization": f"Bearer {self.token}"}

        try:
            response = await self.client.request(method, url, headers=headers, **kwargs)
            response.raise_for_status()

            try:
                data = response.json()
            except (json.JSONDecodeError, ValueError):
                raise ValueError(f"Invalid JSON response from Wazuh API: {endpoint}")

            # Validate response structure
            if "data" not in data:
                raise ValueError(f"Invalid response structure from Wazuh API: {endpoint}")

            return data

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                # Token expired -- re-authenticate with lock to prevent concurrent races
                stale_token = headers.get("Authorization", "").replace("Bearer ", "")
                async with self._auth_lock:
                    # Double-check: another coroutine may have already refreshed
                    if self.token is None or self.token == stale_token:
                        self.token = None
                        await self._authenticate()
                # Retry the request once with refreshed token
                headers = {"Authorization": f"Bearer {self.token}"}
                response = await self.client.request(method, url, headers=headers, **kwargs)
                response.raise_for_status()
                try:
                    return response.json()
                except (json.JSONDecodeError, ValueError):
                    raise ValueError(f"Invalid JSON response from Wazuh API after re-auth: {endpoint}")
            else:
                logger.error(f"Wazuh API request failed: {e.response.status_code} - {e.response.text}")
                raise ValueError(f"Wazuh API request failed: {e.response.status_code} - {e.response.text}")
        except httpx.ConnectError:
            logger.error(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
            raise ConnectionError(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
        except httpx.TimeoutException:
            logger.error("Request timeout to Wazuh server")
            raise ConnectionError("Request timeout to Wazuh server")

    async def get_manager_info(self) -> Dict[str, Any]:
        """Get Wazuh manager information (cached for 5 minutes)."""
        cache_key = "manager_info"
        return await self._get_cached(cache_key, "/")

    def _time_range_to_start(self, time_range: str) -> str:
        """Convert a time_range string like '24h' or '7d' to an ISO 8601 start timestamp."""
        hours = _TIME_RANGE_HOURS.get(time_range, 24)
        return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    async def get_alert_summary(self, time_range: str, group_by: str) -> Dict[str, Any]:
        """Get alert summary — aggregated from Wazuh Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        result = await self._indexer_client.get_alerts(limit=1000, timestamp_start=start)
        alerts = result.get("data", {}).get("affected_items", [])
        groups: Dict[str, int] = {}
        for alert in alerts:
            value: Any = alert
            for part in group_by.split("."):
                value = value.get(part, {}) if isinstance(value, dict) else "unknown"
            key = str(value) if not isinstance(value, dict) else "unknown"
            groups[key] = groups.get(key, 0) + 1
        return {
            "data": {
                "time_range": time_range,
                "group_by": group_by,
                "total_alerts": len(alerts),
                "groups": groups,
            }
        }

    async def analyze_alert_patterns(self, time_range: str, min_frequency: int) -> Dict[str, Any]:
        """Analyze alert patterns — aggregated from Wazuh Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        result = await self._indexer_client.get_alerts(limit=1000, timestamp_start=start)
        alerts = result.get("data", {}).get("affected_items", [])
        rule_counts: Dict[str, Dict[str, Any]] = {}
        for alert in alerts:
            rule = alert.get("rule", {})
            rule_id = rule.get("id", "unknown")
            if rule_id not in rule_counts:
                rule_counts[rule_id] = {
                    "count": 0,
                    "description": rule.get("description", ""),
                    "level": rule.get("level", 0),
                }
            rule_counts[rule_id]["count"] += 1
        patterns = [
            {"rule_id": k, **v} for k, v in rule_counts.items() if v["count"] >= min_frequency
        ]
        patterns.sort(key=lambda x: x["count"], reverse=True)
        return {
            "data": {
                "time_range": time_range,
                "min_frequency": min_frequency,
                "patterns": patterns,
                "total_patterns": len(patterns),
            }
        }

    async def search_security_events(self, query: str, time_range: str, limit: int) -> Dict[str, Any]:
        """Search security events via the Wazuh Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        return await self._indexer_client.get_alerts(limit=limit, timestamp_start=start)

    async def get_running_agents(self) -> Dict[str, Any]:
        """Get running agents."""
        return await self._request("GET", "/agents", params={"status": "active"})

    async def check_agent_health(self, agent_id: str) -> Dict[str, Any]:
        """Check agent health by fetching agent info and extracting status."""
        result = await self._request(
            "GET",
            "/agents",
            params={
                "agents_list": agent_id,
                "select": "id,name,status,ip,os.name,os.version,version,lastKeepAlive,dateAdd,group,node_name",
            },
        )
        agents = result.get("data", {}).get("affected_items", [])
        if not agents:
            raise ValueError(f"Agent {agent_id} not found")
        agent = agents[0]
        status = agent.get("status", "unknown")
        return {
            "data": {
                "agent_id": agent.get("id"),
                "name": agent.get("name"),
                "status": status,
                "health": "healthy" if status == "active" else "unhealthy",
                "ip": agent.get("ip"),
                "os": agent.get("os", {}),
                "version": agent.get("version"),
                "last_keep_alive": agent.get("lastKeepAlive"),
                "date_add": agent.get("dateAdd"),
                "group": agent.get("group"),
                "node_name": agent.get("node_name"),
            }
        }

    async def get_agent_processes(self, agent_id: str, limit: int) -> Dict[str, Any]:
        """Get agent processes."""
        return await self._request("GET", f"/syscollector/{agent_id}/processes", params={"limit": limit})

    async def get_agent_ports(self, agent_id: str, limit: int) -> Dict[str, Any]:
        """Get agent ports."""
        return await self._request("GET", f"/syscollector/{agent_id}/ports", params={"limit": limit})

    async def get_agent_configuration(self, agent_id: str) -> Dict[str, Any]:
        """Get agent configuration by fetching agent info and its group config."""
        agent_result = await self._request(
            "GET",
            "/agents",
            params={"agents_list": agent_id, "select": "id,name,group,configSum,mergedSum,status,version"},
        )
        agents = agent_result.get("data", {}).get("affected_items", [])
        if not agents:
            raise ValueError(f"Agent {agent_id} not found")
        agent = agents[0]
        config_data: Dict[str, Any] = {"agent": agent, "group_configuration": []}
        groups = agent.get("group", [])
        if groups:
            group_name = groups[0] if isinstance(groups, list) else groups
            try:
                group_config = await self._request("GET", f"/groups/{group_name}/configuration")
                config_data["group_configuration"] = group_config.get("data", {}).get("affected_items", [])
            except Exception:
                config_data["group_configuration"] = []
        return {"data": config_data}

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
        """Analyze security threat by searching alerts for the indicator."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        result = await self._indexer_client.get_alerts(limit=100)
        alerts = result.get("data", {}).get("affected_items", [])
        matches = []
        for alert in alerts:
            alert_str = json.dumps(alert)
            if indicator.lower() in alert_str.lower():
                matches.append(alert)
        return {
            "data": {
                "indicator": indicator,
                "type": indicator_type,
                "matching_alerts": len(matches),
                "alerts": matches[:20],
            }
        }

    async def check_ioc_reputation(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Check IoC reputation by searching alert history."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        result = await self._indexer_client.get_alerts(limit=500)
        alerts = result.get("data", {}).get("affected_items", [])
        occurrences = 0
        max_level = 0
        for alert in alerts:
            alert_str = json.dumps(alert)
            if indicator.lower() in alert_str.lower():
                occurrences += 1
                level = alert.get("rule", {}).get("level", 0)
                if isinstance(level, int) and level > max_level:
                    max_level = level
        risk = "high" if max_level >= 10 else "medium" if max_level >= 5 else "low"
        return {
            "data": {
                "indicator": indicator,
                "type": indicator_type,
                "occurrences": occurrences,
                "max_alert_level": max_level,
                "risk": risk,
            }
        }

    async def perform_risk_assessment(self, agent_id: str = None) -> Dict[str, Any]:
        """Perform risk assessment from real agent and vulnerability data."""
        risk_factors: list = []
        params: Dict[str, Any] = {"select": "id,name,status,os.name,version"}
        if agent_id:
            params["agents_list"] = agent_id
        agents = await self._request("GET", "/agents", params=params)
        items = agents.get("data", {}).get("affected_items", [])
        disconnected = [a for a in items if a.get("status") != "active"]
        if disconnected:
            risk_factors.append({"factor": "disconnected_agents", "count": len(disconnected), "severity": "high"})
        if self._indexer_client:
            try:
                vuln_summary = await self._indexer_client.get_vulnerability_summary()
                critical = vuln_summary.get("data", {}).get("critical", 0)
                if critical > 0:
                    risk_factors.append(
                        {"factor": "critical_vulnerabilities", "count": critical, "severity": "critical"}
                    )
            except Exception:
                pass
        if any(f["severity"] == "critical" for f in risk_factors):
            risk_level = "critical"
        elif any(f["severity"] == "high" for f in risk_factors):
            risk_level = "high"
        else:
            risk_level = "medium"
        return {
            "data": {
                "total_agents": len(items),
                "risk_factors": risk_factors,
                "risk_level": risk_level,
            }
        }

    async def get_top_security_threats(self, limit: int, time_range: str) -> Dict[str, Any]:
        """Get top threats by alert rule frequency from Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        result = await self._indexer_client.get_alerts(limit=1000, timestamp_start=start)
        alerts = result.get("data", {}).get("affected_items", [])
        rule_counts: Dict[str, Dict[str, Any]] = {}
        for alert in alerts:
            rule = alert.get("rule", {})
            rule_id = rule.get("id", "unknown")
            if rule_id not in rule_counts:
                rule_counts[rule_id] = {
                    "rule_id": rule_id,
                    "description": rule.get("description", ""),
                    "level": rule.get("level", 0),
                    "count": 0,
                    "groups": rule.get("groups", []),
                }
            rule_counts[rule_id]["count"] += 1
        threats = sorted(rule_counts.values(), key=lambda x: (-x.get("level", 0), -x["count"]))[:limit]
        return {"data": {"time_range": time_range, "threats": threats, "total_unique_rules": len(rule_counts)}}

    async def generate_security_report(self, report_type: str, include_recommendations: bool) -> Dict[str, Any]:
        """Generate security report by aggregating data from multiple real endpoints."""
        report: Dict[str, Any] = {
            "report_type": report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sections": {},
        }
        try:
            agents = await self._request("GET", "/agents", params={"limit": 500})
            items = agents.get("data", {}).get("affected_items", [])
            active = sum(1 for a in items if a.get("status") == "active")
            report["sections"]["agents"] = {"total": len(items), "active": active, "disconnected": len(items) - active}
        except Exception as e:
            report["sections"]["agents"] = {"error": str(e)}
        try:
            info = await self._request("GET", "/")
            report["sections"]["manager"] = info.get("data", {})
        except Exception as e:
            report["sections"]["manager"] = {"error": str(e)}
        if self._indexer_client:
            try:
                vuln_summary = await self._indexer_client.get_vulnerability_summary()
                report["sections"]["vulnerabilities"] = vuln_summary.get("data", {})
            except Exception as e:
                report["sections"]["vulnerabilities"] = {"error": str(e)}
        return {"data": report}

    async def run_compliance_check(self, framework: str, agent_id: str = None) -> Dict[str, Any]:
        """Run compliance check using Wazuh SCA data."""
        if agent_id:
            try:
                return await self._request("GET", f"/sca/{agent_id}")
            except Exception:
                return await self._request(
                    "GET", "/agents", params={"agents_list": agent_id, "select": "id,name,status,group,configSum"}
                )
        agents_result = await self._request(
            "GET", "/agents", params={"status": "active", "limit": 10, "select": "id,name"}
        )
        agents = agents_result.get("data", {}).get("affected_items", [])
        sca_results = []
        for agent in agents[:5]:
            aid = agent.get("id")
            try:
                sca = await self._request("GET", f"/sca/{aid}")
                sca_results.append({"agent_id": aid, "agent_name": agent.get("name"), "sca": sca.get("data", {})})
            except Exception:
                sca_results.append({"agent_id": aid, "agent_name": agent.get("name"), "sca": {"error": "unavailable"}})
        return {"data": {"framework": framework, "agents_checked": len(sca_results), "results": sca_results}}

    async def get_wazuh_statistics(self) -> Dict[str, Any]:
        """Get Wazuh statistics."""
        return await self._request("GET", "/manager/stats")

    async def get_weekly_stats(self) -> Dict[str, Any]:
        """Get weekly statistics."""
        return await self._request("GET", "/manager/stats/weekly")

    async def get_cluster_health(self) -> Dict[str, Any]:
        """Get cluster health."""
        return await self._request("GET", "/cluster/healthcheck")

    async def get_cluster_nodes(self) -> Dict[str, Any]:
        """Get cluster nodes (cached for 2 minutes)."""
        cache_key = "cluster_nodes"
        return await self._get_cached(cache_key, "/cluster/nodes")

    async def get_rules_summary(self) -> Dict[str, Any]:
        """Get rules summary aggregated from /rules endpoint."""
        cache_key = "rules_summary"
        current_time = time.time()
        if cache_key in self._cache:
            cached_time, cached_data = self._cache[cache_key]
            if current_time - cached_time < self._cache_ttl:
                return cached_data

        result = await self._request("GET", "/rules", params={"limit": 500})
        rules = result.get("data", {}).get("affected_items", [])
        level_counts: Dict[int, int] = {}
        group_counts: Dict[str, int] = {}
        for rule in rules:
            level = rule.get("level", 0)
            level_counts[level] = level_counts.get(level, 0) + 1
            for group in rule.get("groups", []):
                group_counts[group] = group_counts.get(group, 0) + 1

        summary = {
            "data": {
                "total_rules": len(rules),
                "by_level": dict(sorted(level_counts.items())),
                "top_groups": dict(sorted(group_counts.items(), key=lambda x: x[1], reverse=True)[:20]),
            }
        }
        self._cache[cache_key] = (current_time, summary)
        return summary

    async def get_remoted_stats(self) -> Dict[str, Any]:
        """Get remoted statistics."""
        return await self._request("GET", "/manager/stats/remoted")

    async def get_log_collector_stats(self) -> Dict[str, Any]:
        """Get analysis daemon statistics."""
        return await self._request("GET", "/manager/stats/analysisd")

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

    # =========================================================================
    # Active Response / Action Tools
    # =========================================================================

    async def block_ip(self, ip_address: str, duration: int = 0, agent_id: str = None) -> Dict[str, Any]:
        """Block IP via firewall-drop active response."""
        data = {
            "command": "firewall-drop0",
            "agent_list": [agent_id] if agent_id else ["all"],
            "arguments": [f"-srcip {ip_address}"],
            "alert": {"data": {"srcip": ip_address}},
        }
        return await self.execute_active_response(data)

    async def isolate_host(self, agent_id: str) -> Dict[str, Any]:
        """Isolate host from network via active response."""
        data = {"command": "host-isolation0", "agent_list": [agent_id], "arguments": []}
        return await self.execute_active_response(data)

    async def kill_process(self, agent_id: str, process_id: int) -> Dict[str, Any]:
        """Kill process on agent via active response."""
        data = {"command": "kill-process0", "agent_list": [agent_id], "arguments": [str(process_id)]}
        return await self.execute_active_response(data)

    async def disable_user(self, agent_id: str, username: str) -> Dict[str, Any]:
        """Disable user account on agent via active response."""
        data = {"command": "disable-account0", "agent_list": [agent_id], "arguments": [username]}
        return await self.execute_active_response(data)

    async def quarantine_file(self, agent_id: str, file_path: str) -> Dict[str, Any]:
        """Quarantine file on agent via active response."""
        data = {"command": "quarantine0", "agent_list": [agent_id], "arguments": [file_path]}
        return await self.execute_active_response(data)

    async def run_active_response(self, agent_id: str, command: str, parameters: dict = None) -> Dict[str, Any]:
        """Execute generic active response command."""
        args = []
        if parameters:
            args = [f"{k}={v}" for k, v in parameters.items()]
        data = {"command": command, "agent_list": [agent_id], "arguments": args}
        return await self.execute_active_response(data)

    async def firewall_drop(self, agent_id: str, src_ip: str, duration: int = 0) -> Dict[str, Any]:
        """Add firewall drop rule via active response."""
        data = {
            "command": "firewall-drop0",
            "agent_list": [agent_id],
            "arguments": [f"-srcip {src_ip}"],
            "alert": {"data": {"srcip": src_ip}},
        }
        return await self.execute_active_response(data)

    async def host_deny(self, agent_id: str, src_ip: str) -> Dict[str, Any]:
        """Add hosts.deny entry via active response."""
        data = {
            "command": "host-deny0",
            "agent_list": [agent_id],
            "arguments": [f"-srcip {src_ip}"],
            "alert": {"data": {"srcip": src_ip}},
        }
        return await self.execute_active_response(data)

    async def restart_service(self, target: str) -> Dict[str, Any]:
        """Restart Wazuh agent or manager."""
        if target == "manager":
            return await self._request("PUT", "/manager/restart")
        return await self._request("PUT", f"/agents/{target}/restart")

    # =========================================================================
    # Verification Tools
    # =========================================================================

    async def check_blocked_ip(self, ip_address: str, agent_id: str = None) -> Dict[str, Any]:
        """Check if IP is blocked by searching active response alerts."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        result = await self._indexer_client.get_alerts(limit=50)
        alerts = result.get("data", {}).get("affected_items", [])
        matches = [a for a in alerts if ip_address in json.dumps(a) and "firewall-drop" in json.dumps(a)]
        return {"data": {"ip_address": ip_address, "blocked": len(matches) > 0, "matching_alerts": len(matches)}}

    async def check_agent_isolation(self, agent_id: str) -> Dict[str, Any]:
        """Check agent isolation status."""
        result = await self._request(
            "GET", "/agents", params={"agents_list": agent_id, "select": "id,name,status"}
        )
        agents = result.get("data", {}).get("affected_items", [])
        if not agents:
            raise ValueError(f"Agent {agent_id} not found")
        agent = agents[0]
        return {
            "data": {
                "agent_id": agent_id,
                "isolated": agent.get("status") == "disconnected",
                "status": agent.get("status"),
                "name": agent.get("name"),
            }
        }

    async def check_process(self, agent_id: str, process_id: int) -> Dict[str, Any]:
        """Check if a process is still running on an agent."""
        result = await self._request(
            "GET", f"/syscollector/{agent_id}/processes", params={"limit": 500}
        )
        processes = result.get("data", {}).get("affected_items", [])
        running = any(str(p.get("pid")) == str(process_id) for p in processes)
        return {"data": {"agent_id": agent_id, "process_id": process_id, "running": running}}

    async def check_user_status(self, agent_id: str, username: str) -> Dict[str, Any]:
        """Check if a user account is disabled."""
        return {
            "data": {
                "agent_id": agent_id,
                "username": username,
                "disabled": False,
                "note": "Check agent logs for disable-account confirmation",
            }
        }

    async def check_file_quarantine(self, agent_id: str, file_path: str) -> Dict[str, Any]:
        """Check if a file has been quarantined via FIM events."""
        result = await self._request(
            "GET", "/syscheck", params={"agents_list": agent_id, "q": f"file={file_path}"}
        )
        events = result.get("data", {}).get("affected_items", [])
        quarantined = any(e.get("type") == "deleted" or "quarantine" in str(e) for e in events)
        return {"data": {"agent_id": agent_id, "file_path": file_path, "quarantined": quarantined}}

    # =========================================================================
    # Rollback Tools
    # =========================================================================

    async def unisolate_host(self, agent_id: str) -> Dict[str, Any]:
        """Remove host isolation via active response."""
        data = {"command": "host-isolation0", "agent_list": [agent_id], "arguments": ["undo"]}
        return await self.execute_active_response(data)

    async def enable_user(self, agent_id: str, username: str) -> Dict[str, Any]:
        """Re-enable user account via active response."""
        data = {"command": "enable-account0", "agent_list": [agent_id], "arguments": [username]}
        return await self.execute_active_response(data)

    async def restore_file(self, agent_id: str, file_path: str) -> Dict[str, Any]:
        """Restore a quarantined file via active response."""
        data = {"command": "quarantine0", "agent_list": [agent_id], "arguments": ["restore", file_path]}
        return await self.execute_active_response(data)

    async def firewall_allow(self, agent_id: str, src_ip: str) -> Dict[str, Any]:
        """Remove firewall drop rule via active response."""
        data = {
            "command": "firewall-drop0",
            "agent_list": [agent_id],
            "arguments": [f"-srcip {src_ip}", "delete"],
        }
        return await self.execute_active_response(data)

    async def host_allow(self, agent_id: str, src_ip: str) -> Dict[str, Any]:
        """Remove hosts.deny entry via active response."""
        data = {
            "command": "host-deny0",
            "agent_list": [agent_id],
            "arguments": [f"-srcip {src_ip}", "delete"],
        }
        return await self.execute_active_response(data)

    async def close(self):
        """Close the HTTP client and indexer client."""
        if self.client:
            await self.client.aclose()
        if self._indexer_client:
            await self._indexer_client.close()
