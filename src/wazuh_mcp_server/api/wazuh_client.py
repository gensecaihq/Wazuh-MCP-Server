"""Wazuh API client optimized for Wazuh 4.8.0 to 4.14.7 compatibility with latest features."""

import asyncio
import ipaddress
import json
import logging
import math
import os
import re
import time
from collections import OrderedDict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

import httpx

from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError, WazuhIndexerClient
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.resilience import CircuitBreaker, CircuitBreakerConfig, RetryConfig

logger = logging.getLogger(__name__)

# Time range to hours mapping for indexer-based queries
_TIME_RANGE_HOURS = {"1h": 1, "6h": 6, "12h": 12, "1d": 24, "24h": 24, "7d": 168, "30d": 720}

YDC_DEFAULT_BASE_URL = "https://ydc-index.io"

# Reporting window for ISO 27001 alert-backed controls (dashboard/gap analysis).
_ISO27001_ALERT_WINDOW_DAYS = 30

# Total ISO 27001:2022 Annex A controls (A.5 Organizational 37 + A.6 People 8 +
# A.7 Physical 14 + A.8 Technological 34). Only a subset is mapped to Wazuh telemetry;
# surfaced alongside controls_mapped so scores are never read as whole-framework compliance.
_ISO27001_TOTAL_ANNEX_A_CONTROLS = 93

# ISO 27001:2022 Annex A control map — links each control to Wazuh data sources
# data_source: "sca" | "alerts" | "vulnerabilities" | "agents" | "stats" | "none"
_ISO27001_CONTROL_MAP: Dict[str, Dict] = {
    "A.5.26": {
        "title": "Response to information security incidents",
        "domain": "A.5",
        "data_source": "alerts",
        "rule_groups": ["incident", "syslog"],
        "sca_keywords": [],
        "weight": 2,
    },
    "A.6.3": {
        "title": "Information security awareness, education and training",
        "domain": "A.6",
        "data_source": "agents",
        "rule_groups": [],
        "sca_keywords": [],
        "weight": 1,
    },
    "A.8.1": {
        "title": "User endpoint devices",
        "domain": "A.8",
        "data_source": "sca",
        "rule_groups": ["syscheck"],
        "sca_keywords": ["cis", "workstation", "desktop", "endpoint", "windows", "linux"],
        "weight": 3,
    },
    "A.8.2": {
        "title": "Privileged access rights",
        "domain": "A.8",
        "data_source": "alerts",
        "rule_groups": ["syscheck", "rootcheck", "sudo", "privilege_escalation"],
        "sca_keywords": [],
        "weight": 3,
    },
    "A.8.4": {
        "title": "Access to source code",
        "domain": "A.8",
        "data_source": "alerts",
        "rule_groups": ["syscheck", "fim"],
        "sca_keywords": [],
        "weight": 1,
    },
    "A.8.5": {
        "title": "Secure authentication",
        "domain": "A.8",
        "data_source": "alerts",
        "rule_groups": ["authentication_failed", "authentication_success", "multiple_authentication_failures"],
        "sca_keywords": ["pam", "ssh", "authentication", "password"],
        "weight": 3,
    },
    "A.8.7": {
        "title": "Protection against malware",
        "domain": "A.8",
        "data_source": "alerts",
        "rule_groups": ["malware", "virus", "rootcheck", "trojans"],
        "sca_keywords": ["antivirus", "malware", "clamav"],
        "weight": 3,
    },
    "A.8.8": {
        "title": "Management of technical vulnerabilities",
        "domain": "A.8",
        "data_source": "vulnerabilities",
        "rule_groups": [],
        "sca_keywords": [],
        "weight": 4,
    },
    "A.8.9": {
        "title": "Configuration management",
        "domain": "A.8",
        "data_source": "sca",
        "rule_groups": [],
        "sca_keywords": ["cis", "hardening", "benchmark", "configuration"],
        "weight": 3,
    },
    "A.8.12": {
        "title": "Data leakage prevention",
        "domain": "A.8",
        "data_source": "alerts",
        "rule_groups": ["syscheck", "fim", "data_exfiltration"],
        "sca_keywords": [],
        "weight": 2,
    },
    "A.8.15": {
        "title": "Logging",
        "domain": "A.8",
        "data_source": "stats",
        "rule_groups": [],
        "sca_keywords": ["audit", "logging", "log", "auditd"],
        "weight": 3,
    },
    "A.8.16": {
        "title": "Monitoring activities",
        "domain": "A.8",
        "data_source": "alerts",
        "rule_groups": [],
        "sca_keywords": [],
        "weight": 3,
    },
    "A.8.20": {
        "title": "Networks security",
        "domain": "A.8",
        "data_source": "alerts",
        "rule_groups": ["firewall", "network", "ids", "iptables"],
        "sca_keywords": ["firewall", "iptables", "network", "nftables"],
        "weight": 2,
    },
    "A.8.22": {
        "title": "Segregation of networks",
        "domain": "A.8",
        "data_source": "agents",
        "rule_groups": [],
        "sca_keywords": [],
        "weight": 1,
    },
}


class WazuhClient:
    """Simplified Wazuh API client with rate limiting, circuit breaker, and retry logic."""

    def __init__(self, config: WazuhConfig):
        self.config = config
        self.token: Optional[str] = None
        self.client: Optional[httpx.AsyncClient] = None
        # Lock to prevent concurrent re-authentication races
        self._auth_lock = asyncio.Lock()
        # Lock to prevent concurrent cold-start initialization races. Without it, N
        # concurrent first requests each call initialize(), which aclose()s and
        # replaces an httpx client another request may be mid-flight on.
        self._init_lock = asyncio.Lock()
        # Rate limiting with O(1) deque operations
        self._rate_limiter = asyncio.Semaphore(config.max_connections)
        self._request_times: deque = deque(maxlen=200)  # Pre-sized deque for efficiency
        self._max_requests_per_minute = getattr(config, "max_requests_per_minute", 100)
        self._rate_limit_enabled = True
        # Response caching for static data (bounded OrderedDict for O(1) eviction)
        self._cache: OrderedDict[str, Tuple[float, Dict[str, Any]]] = OrderedDict()
        self._cache_ttl = 300  # 5 minutes for static data
        self._cache_max_size = 100
        self._youcom_api_key = os.getenv("YDC_API_KEY", "").strip() or None
        self._youcom_base_url = os.getenv("YDC_BASE_URL", YDC_DEFAULT_BASE_URL).rstrip("/")
        self._youcom_verify_ssl = os.getenv("YDC_VERIFY_SSL", "true").strip().lower() == "true"

        # Optional custom active-response commands for unblocking. Stock Wazuh cannot
        # remove a firewall-drop / host-deny block via the API (the API only ever
        # triggers the "add" action; the stock scripts ignore extra_args for add/delete),
        # so the firewall_allow / host_allow rollback tools require an operator-deployed
        # undo script named here. Without one they fail safe rather than re-blocking.
        self._ar_firewall_undo_command = self._normalize_ar_command(os.getenv("WAZUH_AR_FIREWALL_UNDO_COMMAND"))
        self._ar_hostdeny_undo_command = self._normalize_ar_command(os.getenv("WAZUH_AR_HOSTDENY_UNDO_COMMAND"))

        # Protected-target denylist for block_ip: infrastructure whose blocking would be
        # self-inflicted DoS (default gateway, DNS, the Wazuh manager itself). An attacker
        # who can emit a log line on a monitored host could otherwise trick the LLM into
        # "block <critical-ip>". Always includes the manager host; extend via env
        # WAZUH_PROTECTED_IPS (comma-separated IPs / CIDRs). Loopback is always protected.
        self._protected_networks = self._build_protected_networks(os.getenv("WAZUH_PROTECTED_IPS", ""))

        # Circuit breaker for API resilience — only trip on connection/server errors,
        # not on user-input errors (ValueError) which shouldn't degrade the circuit
        circuit_config = CircuitBreakerConfig(
            failure_threshold=5,
            recovery_timeout=60,
            expected_exception=(ConnectionError, httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError),
        )
        self._circuit_breaker = CircuitBreaker(circuit_config)
        # Separate breaker for the optional You.com integration — an external search
        # outage must never open the circuit that gates Wazuh API calls
        self._youcom_circuit_breaker = CircuitBreaker(
            CircuitBreakerConfig(
                failure_threshold=5,
                recovery_timeout=60,
                expected_exception=(ConnectionError, httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError),
            )
        )

        # Initialize Wazuh Indexer client if configured (required for Wazuh 4.8.0+)
        self._indexer_client: Optional[WazuhIndexerClient] = None
        if config.wazuh_indexer_host:
            self._indexer_client = WazuhIndexerClient(
                host=config.wazuh_indexer_host,
                port=config.wazuh_indexer_port,
                username=config.wazuh_indexer_user,
                password=config.wazuh_indexer_pass,
                verify_ssl=getattr(config, "wazuh_indexer_verify_ssl", config.verify_ssl),
                timeout=config.request_timeout_seconds,
                use_ssl=getattr(config, "wazuh_indexer_ssl", True),
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
        # Close existing client to prevent connection pool leak on re-initialization
        if self.client:
            try:
                await self.client.aclose()
            except Exception:
                pass
        self.client = httpx.AsyncClient(
            verify=self.config.verify_ssl,
            timeout=self.config.request_timeout_seconds,
            limits=httpx.Limits(
                max_connections=self.config.max_connections,
                max_keepalive_connections=max(5, self.config.max_connections // 2),
            ),
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
            rule_groups=params.get("rule_groups"),
        )

    async def get_alerts_aggregated(
        self,
        timestamp_start: str = "now-24h",
        timestamp_end: str = "now",
        top_rules: int = 50,
        top_agents: int = 50,
    ) -> Dict[str, Any]:
        """Aggregate alerts over a time range (no document limit) via the indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        return await self._indexer_client.aggregate_alerts(
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
            top_rules=top_rules,
            top_agents=top_agents,
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
                self._cache.move_to_end(cache_key)  # LRU: mark as recently used
                return cached_data

        record_cache_access("wazuh_api", hit=False)

        # Fetch from API
        result = await self._request("GET", endpoint, **kwargs)

        # Cache the result, evicting oldest if at capacity (O(1) eviction)
        self._cache[cache_key] = (current_time, result)
        if len(self._cache) > self._cache_max_size:
            self._cache.popitem(last=False)

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
        # Wazuh 4.x API: agent_list must be passed as query param 'agents_list'
        agents_list = data.pop("agent_list", None)
        params = {}
        if agents_list:
            agent_items = agents_list if isinstance(agents_list, list) else [agents_list]
            # Check if targeting all agents
            if any(str(a).lower() == "all" for a in agent_items):
                # Wazuh 4.x API requires a valid agents_list; use "all" as a special keyword
                # that the API accepts for targeting all agents
                params["agents_list"] = "all"
            else:
                # Filter to numeric agent IDs only
                numeric_agents = [str(a) for a in agent_items if str(a).isdigit()]
                if not numeric_agents:
                    # SAFETY: if the caller supplied targets but none are numeric agent IDs
                    # (e.g. an LLM passed a hostname like "web-01"), we must NOT fall through
                    # with an empty params — Wazuh's active-response controller defaults an
                    # absent agents_list to '*' (ALL agents), which would fan a block/isolate/
                    # kill out to the entire fleet. Refuse instead.
                    raise ValueError(
                        f"No valid numeric agent ID in target(s) {agent_items!r}. "
                        "Active response requires numeric agent IDs (e.g. '001'); "
                        "refusing to dispatch to avoid a fleet-wide action."
                    )
                params["agents_list"] = ",".join(numeric_agents)
        if not params.get("agents_list"):
            # Defense in depth: never send a targeting active-response PUT without an explicit
            # agents_list — an empty/absent list is interpreted as ALL agents by the manager.
            raise ValueError(
                "Active response requires an explicit agent target (numeric agent ID or 'all'); "
                "refusing to dispatch with an unspecified target."
            )
        result = await self._request("PUT", "/active-response", json=data, params=params)

        # Check for partial/total failures in the response body
        # Wazuh returns HTTP 200 even when the command fails on all agents
        resp_data = result.get("data", {})
        total_affected = resp_data.get("total_affected_items", 0)
        total_failed = resp_data.get("total_failed_items", 0)
        failed_items = resp_data.get("failed_items", [])

        if total_affected == 0:
            # Zero agents affected is a FAILURE, not success. Wazuh returns HTTP 200 with
            # total_affected_items == 0 both when a command failed on every agent AND when
            # the AR command doesn't exist / isn't configured (e.g. the custom
            # host-isolation / kill-process / quarantine scripts aren't deployed). Reporting
            # that as success would be false containment during a live incident — so refuse.
            errors = []
            for item in failed_items:
                err = item.get("error", {})
                agent_ids = item.get("id", [])
                errors.append(f"agents {agent_ids}: code {err.get('code')} - {err.get('message', 'unknown error')}")
            if errors:
                error_detail = "; ".join(errors)
            elif total_failed == 0:
                error_detail = (
                    "no agents affected and none reported failed — the active-response command is "
                    "likely not configured on the target agent(s). Deploy the required AR script."
                )
            else:
                error_detail = "no agents affected"
            raise ValueError(
                f"Active response command affected 0 agents "
                f"({total_affected} succeeded, {total_failed} failed): {error_detail}"
            )

        # Log partial failures as warnings but still return success
        if total_failed > 0 and total_affected > 0:
            for item in failed_items:
                err = item.get("error", {})
                agent_ids = item.get("id", [])
                logger.warning(
                    f"Active response partially failed on agents {agent_ids}: "
                    f"code {err.get('code')} - {err.get('message')}"
                )

        return result

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
        # Audit fix H6: Validate agent_id is numeric to prevent path traversal
        if not agent_id or not str(agent_id).isdigit():
            raise ValueError(f"agent_id must be numeric, got: {agent_id}")
        # Audit fix: Validate component to prevent path traversal
        if not component.isalnum():
            raise ValueError(f"component must be alphanumeric, got: {component}")
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
        """Make authenticated request to Wazuh API with rate limiting, circuit breaker, and retry logic.

        GET requests use retry + circuit breaker. PUT/DELETE requests use circuit breaker
        only (no retry) because active response commands are not idempotent — retrying a
        PUT that already executed could double-isolate an agent or double-block an IP.
        """
        # Apply rate limiting
        async with self._rate_limiter:
            await self._rate_limit_check()

            if method.upper() in ("PUT", "DELETE"):
                # Non-idempotent: circuit breaker only, no retry
                return await self._request_no_retry(method, endpoint, **kwargs)
            # Idempotent (GET, POST for auth): retry + circuit breaker
            return await self._request_with_resilience(method, endpoint, **kwargs)

    @RetryConfig.WAZUH_API_RETRY
    async def _request_with_resilience(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute request with circuit breaker and retry logic (idempotent methods only)."""
        return await self._circuit_breaker._call(self._execute_request, method, endpoint, **kwargs)

    async def _request_no_retry(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute request with circuit breaker but NO retry (non-idempotent methods)."""
        return await self._circuit_breaker._call(self._execute_request, method, endpoint, **kwargs)

    async def _execute_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Execute the actual HTTP request to Wazuh API."""
        # Ensure client is initialized. Double-checked lock so concurrent first
        # requests don't each re-init (which would close an in-use client).
        if not self.client:
            async with self._init_lock:
                if not self.client:
                    await self.initialize()
        if not self.token:
            async with self._auth_lock:
                if not self.token:
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
                try:
                    response = await self.client.request(method, url, headers=headers, **kwargs)
                    response.raise_for_status()
                    try:
                        data = response.json()
                    except (json.JSONDecodeError, ValueError):
                        raise ValueError(f"Invalid JSON response from Wazuh API after re-auth: {endpoint}")
                    if "data" not in data:
                        raise ValueError(f"Invalid response structure from Wazuh API after re-auth: {endpoint}")
                    return data
                except httpx.HTTPStatusError as retry_err:
                    logger.error(f"Wazuh API request failed after re-auth: {retry_err.response.status_code}")
                    raise ValueError(f"Wazuh API error after re-auth for {endpoint}: {retry_err.response.status_code}")
                except (httpx.ConnectError, httpx.TimeoutException) as retry_err:
                    logger.error(f"Connection lost during re-auth retry for {endpoint}: {retry_err}")
                    raise
            elif e.response.status_code == 429:
                # Wazuh-side rate limiting: wait per Retry-After and let retry logic handle it
                retry_after = int(e.response.headers.get("Retry-After", "30"))
                logger.warning(f"Wazuh API rate-limited on {endpoint}. Waiting {retry_after}s...")
                await asyncio.sleep(min(retry_after, 60))  # Cap at 60s to prevent abuse
                raise  # Let tenacity/circuit breaker handle the retry
            elif e.response.status_code >= 500:
                # Server errors: let them propagate as httpx exceptions so tenacity
                # retry logic can see them and retry (via _is_retryable)
                logger.error(f"Wazuh API server error: {e.response.status_code}")
                raise
            else:
                # Client errors (4xx except 401): not retryable, wrap as ValueError. Mark it
                # _service_alive so the circuit breaker treats it as a completed HTTP response
                # (liveness proven) rather than an unproven trial — a user probing a bad agent
                # id must not strand the breaker OPEN. Log at info: it's user input, not an outage.
                logger.info(f"Wazuh API request failed: {endpoint} returned HTTP {e.response.status_code}")
                err = ValueError(f"Wazuh API request failed: {endpoint} returned HTTP {e.response.status_code}")
                err._service_alive = True
                raise err
        except httpx.ConnectError as e:
            # Distinguish SSL errors from generic connection failures
            err_str = str(e).lower()
            if "ssl" in err_str or "certificate" in err_str or "verify" in err_str:
                logger.error(f"SSL certificate validation failed for {self.config.wazuh_host}")
                raise ConnectionError(
                    f"SSL certificate validation failed for {self.config.wazuh_host}. "
                    "Set WAZUH_VERIFY_SSL=false for self-signed certificates."
                )
            # Let other connection errors propagate for retry logic
            logger.error(f"Lost connection to Wazuh server at {self.config.wazuh_host}")
            raise
        except httpx.TimeoutException:
            # Let timeout errors propagate for retry logic
            logger.error("Request timeout to Wazuh server")
            raise

    async def get_manager_info(self) -> Dict[str, Any]:
        """Get Wazuh manager information (cached for 5 minutes)."""
        cache_key = "manager_info"
        return await self._get_cached(cache_key, "/")

    async def ping_manager(self) -> Dict[str, Any]:
        """Uncached liveness probe against the Manager root endpoint.

        Readiness gating must reflect the Manager's CURRENT reachability; the 5-minute
        cache on get_manager_info() would otherwise mask a fresh outage for up to 300s.
        """
        return await self._request("GET", "/")

    def _time_range_to_start(self, time_range: str) -> str:
        """Convert a time_range string like '24h' or '7d' to an ISO 8601 start timestamp."""
        hours = _TIME_RANGE_HOURS.get(time_range, 24)
        return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    @staticmethod
    def _alerts_and_total(result: Dict[str, Any]) -> Tuple[list, int, bool]:
        """Unpack a get_alerts() result into (sampled_alerts, true_total, truncated).

        get_alerts caps affected_items at `limit` but reports the real match count in
        total_affected_items (track_total_hits). Summary tools MUST report the real total,
        not len(affected_items) — otherwise a busy SIEM's magnitudes are silently wrong and
        everything past the first page is invisible. `truncated` says the in-Python analysis
        below (grouping, pattern counts) only saw a sample, not the whole result set.
        """
        data = result.get("data", {})
        alerts = data.get("affected_items", []) or []
        true_total = data.get("total_affected_items", len(alerts))
        if not isinstance(true_total, int) or true_total < len(alerts):
            true_total = len(alerts)
        return alerts, true_total, true_total > len(alerts)

    async def get_alert_summary(self, time_range: str, group_by: str) -> Dict[str, Any]:
        """Get alert summary — aggregated from Wazuh Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        result = await self._indexer_client.get_alerts(limit=1000, timestamp_start=start)
        alerts, total_alerts, truncated = self._alerts_and_total(result)
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
                "total_alerts": total_alerts,
                "alerts_sampled": len(alerts),
                "truncated": truncated,
                "groups": groups,
                **(
                    {
                        "truncation_warning": f"Grouping reflects the newest {len(alerts)} of {total_alerts} matching alerts."
                    }
                    if truncated
                    else {}
                ),
            }
        }

    async def analyze_alert_patterns(self, time_range: str, min_frequency: int) -> Dict[str, Any]:
        """Analyze alert patterns — aggregated from Wazuh Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        result = await self._indexer_client.get_alerts(limit=1000, timestamp_start=start)
        alerts, total_alerts, truncated = self._alerts_and_total(result)
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
        patterns = [{"rule_id": k, **v} for k, v in rule_counts.items() if v["count"] >= min_frequency]
        patterns.sort(key=lambda x: x["count"], reverse=True)
        return {
            "data": {
                "time_range": time_range,
                "min_frequency": min_frequency,
                "patterns": patterns,
                "total_patterns": len(patterns),
                "total_alerts": total_alerts,
                "alerts_analyzed": len(alerts),
                "truncated": truncated,
                **(
                    {
                        "truncation_warning": (
                            f"Pattern counts reflect the newest {len(alerts)} of {total_alerts} matching alerts; "
                            "frequencies are lower bounds."
                        )
                    }
                    if truncated
                    else {}
                ),
            }
        }

    async def search_security_events(
        self,
        query: str,
        time_range: str,
        limit: int,
        rule_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        level: Optional[str] = None,
        srcip: Optional[str] = None,
        dstip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Search security events via the Wazuh Indexer with Elasticsearch query_string and field filters.

        Args:
            query: Free-text search query (passed to Elasticsearch query_string DSL).
                   Supports Lucene syntax: AND, OR, NOT, field:value, wildcards, quoted phrases.
            time_range: Time window string (e.g., '24h', '7d').
            limit: Maximum number of results to return.
            rule_id: Optional filter by Wazuh rule ID (e.g., '5710').
            agent_id: Optional filter by Wazuh agent ID (e.g., '001').
            level: Optional minimum rule severity level (e.g., '10' for level >= 10).
            srcip: Optional filter by source IP address.
            dstip: Optional filter by destination IP address.

        Returns:
            Alert data in standard Wazuh format with affected_items and total counts.
        """
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        # Pass all filters directly to Elasticsearch — no local Python filtering needed
        result = await self._indexer_client.get_alerts(
            limit=limit,
            timestamp_start=start,
            query_text=query if query else None,
            rule_id=rule_id,
            agent_id=agent_id,
            level=level,
            srcip=srcip,
            dstip=dstip,
        )
        return result

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
        """Analyze security threat by searching alerts for the indicator via Elasticsearch."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        # Use Elasticsearch query_string for efficient server-side search
        result = await self._indexer_client.get_alerts(limit=100, query_text=indicator)
        alerts, matching_alerts, truncated = self._alerts_and_total(result)
        return {
            "data": {
                "indicator": indicator,
                "type": indicator_type,
                "matching_alerts": matching_alerts,
                "alerts_sampled": len(alerts),
                "truncated": truncated,
                "alerts": alerts[:20],
            }
        }

    async def check_ioc_reputation(self, indicator: str, indicator_type: str) -> Dict[str, Any]:
        """Check IoC reputation by searching alert history via Elasticsearch."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        # Use Elasticsearch query_string for server-side search
        result = await self._indexer_client.get_alerts(limit=500, query_text=indicator)
        alerts, occurrences, truncated = self._alerts_and_total(result)
        max_level = 0
        for alert in alerts:
            level = alert.get("rule", {}).get("level", 0)
            if isinstance(level, int) and level > max_level:
                max_level = level
        risk = "high" if max_level >= 10 else "medium" if max_level >= 5 else "low"
        return {
            "data": {
                "indicator": indicator,
                "type": indicator_type,
                "occurrences": occurrences,
                "occurrences_sampled": len(alerts),
                "truncated": truncated,
                "max_alert_level": max_level,
                "risk": risk,
            }
        }

    async def search_external_context(self, query: str, count: int = 5) -> Dict[str, Any]:
        """Search the web with You.com for additional security context."""
        if not self._youcom_api_key:
            return {
                "data": {
                    "query": query,
                    "enabled": False,
                    "results": [],
                    "message": "Set YDC_API_KEY to enable optional You.com web search context.",
                }
            }

        clamped_count = max(1, min(count, 10))
        payload = await self._search_youcom(query, clamped_count)
        web_results = payload.get("results", {}).get("web", [])[:clamped_count]
        results = []
        for item in web_results:
            results.append(
                {
                    "title": item.get("title"),
                    "url": item.get("url"),
                    "description": item.get("description"),
                    "snippets": item.get("snippets", []),
                }
            )
        return {
            "data": {
                "query": query,
                "enabled": True,
                "results": results,
                "search_uuid": payload.get("metadata", {}).get("search_uuid"),
            }
        }

    async def _search_youcom(self, query: str, count: int) -> Dict[str, Any]:
        """Search You.com behind its own circuit breaker, isolated from Wazuh API resilience state."""
        async with self._rate_limiter:
            return await self._youcom_circuit_breaker._call(self._execute_youcom_search, query, count)

    async def _execute_youcom_search(self, query: str, count: int) -> Dict[str, Any]:
        params = {"query": query, "count": count, "safesearch": "moderate", "livecrawl": "web"}
        url = f"{self._youcom_base_url}/v1/search"
        async with httpx.AsyncClient(
            timeout=self.config.request_timeout_seconds, verify=self._youcom_verify_ssl
        ) as client:
            response = await client.get(url, params=params, headers={"X-API-Key": self._youcom_api_key})
        if response.status_code >= 400:
            raise ValueError(f"You.com Search API error {response.status_code}: {response.text[:200]}")
        return response.json()

    async def perform_risk_assessment(self, agent_id: str = None) -> Dict[str, Any]:
        """Perform risk assessment from agent status, vulnerability data, and alert severity."""

        risk_factors: list = []
        params: Dict[str, Any] = {"select": "id,name,status,os.name,version"}
        if agent_id:
            params["agents_list"] = agent_id
        agents = await self._request("GET", "/agents", params=params)
        items = agents.get("data", {}).get("affected_items", [])
        total_agents = len(items)
        disconnected = [a for a in items if a.get("status") != "active"]
        if disconnected:
            risk_factors.append(
                {
                    "factor": "disconnected_agents",
                    "count": len(disconnected),
                    "severity": "high",
                    "details": [{"id": a.get("id"), "name": a.get("name")} for a in disconnected[:10]],
                }
            )

        # Vulnerability risk
        vuln_data: Dict[str, Any] = {}
        if self._indexer_client:
            try:
                vuln_summary = await self._indexer_client.get_vulnerability_summary()
                vuln_data = vuln_summary.get("data", {})
                critical = vuln_data.get("critical", 0)
                high = vuln_data.get("high", 0)
                if critical > 0:
                    risk_factors.append(
                        {"factor": "critical_vulnerabilities", "count": critical, "severity": "critical"}
                    )
                if high > 0:
                    risk_factors.append({"factor": "high_vulnerabilities", "count": high, "severity": "high"})
            except Exception:
                pass

        # Alert severity risk — count high-level alerts in last 24h
        alert_summary: Dict[str, int] = {}
        if self._indexer_client:
            try:
                start = self._time_range_to_start("24h")
                result = await self._indexer_client.get_alerts(limit=500, timestamp_start=start, level="10")
                high_alerts, high_total, _ = self._alerts_and_total(result)
                alert_summary["high_severity_alerts_24h"] = high_total
                if high_total > 10:
                    risk_factors.append(
                        {
                            "factor": "high_severity_alerts",
                            "count": high_total,
                            "severity": "high",
                        }
                    )
                elif high_total > 0:
                    risk_factors.append(
                        {
                            "factor": "elevated_alert_activity",
                            "count": high_total,
                            "severity": "medium",
                        }
                    )
            except Exception:
                pass

        # SCA compliance risk — sample first active agent
        sca_score: Optional[int] = None
        try:
            active_agents = [a for a in items if a.get("status") == "active"]
            if active_agents:
                sca = await self._request("GET", f"/sca/{active_agents[0].get('id')}")
                sca_items = sca.get("data", {}).get("affected_items", [])
                if sca_items:
                    scores = [p.get("score", 0) for p in sca_items if isinstance(p.get("score"), (int, float))]
                    if scores:
                        sca_score = int(sum(scores) / len(scores))
                        if sca_score < 50:
                            risk_factors.append(
                                {
                                    "factor": "low_sca_compliance",
                                    "score": sca_score,
                                    "severity": "high",
                                }
                            )
                        elif sca_score < 70:
                            risk_factors.append(
                                {
                                    "factor": "moderate_sca_compliance",
                                    "score": sca_score,
                                    "severity": "medium",
                                }
                            )
        except Exception:
            pass

        # Calculate weighted risk score (0-100)
        score = 0
        severity_weights = {"critical": 30, "high": 20, "medium": 10, "low": 5}
        for f in risk_factors:
            weight = severity_weights.get(f["severity"], 5)
            count = f.get("count", 1)
            score += weight * min(math.log2(count + 1), 5)  # Diminishing returns on count
        overall_risk_score = min(100, int(score))

        if overall_risk_score >= 70:
            risk_level = "critical"
        elif overall_risk_score >= 50:
            risk_level = "high"
        elif overall_risk_score >= 25:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "data": {
                "overall_risk_score": overall_risk_score,
                "risk_level": risk_level,
                "total_agents": total_agents,
                "risk_factors": risk_factors,
                "vulnerability_summary": vuln_data if vuln_data else None,
                "alert_summary": alert_summary if alert_summary else None,
                "sca_average_score": sca_score,
            }
        }

    async def get_top_security_threats(self, limit: int, time_range: str) -> Dict[str, Any]:
        """Get top threats with source IPs, affected agents, and timeline from Indexer."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        start = self._time_range_to_start(time_range)
        result = await self._indexer_client.get_alerts(limit=1000, timestamp_start=start)
        alerts, total_alerts, truncated = self._alerts_and_total(result)

        rule_data: Dict[str, Dict[str, Any]] = {}
        for alert in alerts:
            rule = alert.get("rule", {})
            rule_id = rule.get("id", "unknown")
            if rule_id not in rule_data:
                rule_data[rule_id] = {
                    "rule_id": rule_id,
                    "description": rule.get("description", ""),
                    "level": rule.get("level", 0),
                    "count": 0,
                    "groups": rule.get("groups", []),
                    "mitre": rule.get("mitre", {}),
                    "source_ips": set(),
                    "affected_agents": set(),
                    "first_seen": None,
                    "last_seen": None,
                }
            entry = rule_data[rule_id]
            entry["count"] += 1
            # Extract source IPs
            src_ip = alert.get("data", {}).get("srcip")
            if src_ip:
                entry["source_ips"].add(src_ip)
            # Extract affected agents
            agent_id = alert.get("agent", {}).get("id")
            agent_name = alert.get("agent", {}).get("name", "")
            if agent_id:
                entry["affected_agents"].add(f"{agent_id}:{agent_name}")
            # Track timeline
            ts = alert.get("timestamp")
            if ts:
                if entry["first_seen"] is None or ts < entry["first_seen"]:
                    entry["first_seen"] = ts
                if entry["last_seen"] is None or ts > entry["last_seen"]:
                    entry["last_seen"] = ts

        # Calculate threat score and build output
        threats = []
        for rule_id, data in rule_data.items():
            level = data["level"]
            count = data["count"]
            # Score: level weight * log(count) * affected_systems_factor
            affected_count = len(data["affected_agents"])
            threat_score = min(100, int(level * 5 * math.log2(count + 1) * (1 + 0.1 * affected_count)))

            threats.append(
                {
                    "rule_id": rule_id,
                    "description": data["description"],
                    "level": level,
                    "count": count,
                    "threat_score": threat_score,
                    "groups": data["groups"],
                    "mitre": data["mitre"] if data["mitre"] else None,
                    "source_ips": sorted(data["source_ips"])[:20],  # Cap at 20
                    "affected_agents": [
                        {"id": a.split(":")[0], "name": a.split(":", 1)[1] if ":" in a else ""}
                        for a in sorted(data["affected_agents"])
                    ][:20],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"],
                }
            )

        threats.sort(key=lambda x: (-x["threat_score"], -x["count"]))
        return {
            "data": {
                "time_range": time_range,
                "total_alerts": total_alerts,
                "total_alerts_analyzed": len(alerts),
                "truncated": truncated,
                "threats": threats[:limit],
                "total_unique_rules": len(rule_data),
                **(
                    {
                        "truncation_warning": (
                            f"Threat ranking reflects the newest {len(alerts)} of {total_alerts} matching alerts; "
                            "counts and rankings are lower bounds."
                        )
                    }
                    if truncated
                    else {}
                ),
            }
        }

    async def generate_security_report(self, report_type: str, include_recommendations: bool) -> Dict[str, Any]:
        """Generate security report with content differentiated by report_type."""
        # Time range varies by report type
        time_ranges = {"daily": "24h", "weekly": "7d", "monthly": "30d", "incident": "1h"}
        tr = time_ranges.get(report_type, "24h")

        report: Dict[str, Any] = {
            "report_type": report_type,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_range": tr,
            "sections": {},
        }

        # Section 1: Agent status (all report types)
        try:
            agents = await self._request("GET", "/agents", params={"limit": 500})
            items = agents.get("data", {}).get("affected_items", [])
            active = sum(1 for a in items if a.get("status") == "active")
            report["sections"]["agents"] = {"total": len(items), "active": active, "disconnected": len(items) - active}
        except Exception as e:
            report["sections"]["agents"] = {"error": str(e)}

        # Section 2: Manager info (all report types)
        try:
            info = await self._request("GET", "/")
            mgr = info.get("data", {})
            report["sections"]["manager"] = {
                "version": mgr.get("api_version"),
                "hostname": mgr.get("hostname"),
                "type": mgr.get("type"),
            }
        except Exception as e:
            report["sections"]["manager"] = {"error": str(e)}

        # Section 3: Alert summary (all report types)
        if self._indexer_client:
            try:
                start = self._time_range_to_start(tr)
                alerts_result = await self._indexer_client.get_alerts(limit=500, timestamp_start=start)
                alerts, total_alerts, truncated = self._alerts_and_total(alerts_result)
                level_dist: Dict[str, int] = {}
                for a in alerts:
                    lvl = a.get("rule", {}).get("level", 0)
                    bucket = "critical" if lvl >= 12 else "high" if lvl >= 10 else "medium" if lvl >= 7 else "low"
                    level_dist[bucket] = level_dist.get(bucket, 0) + 1
                report["sections"]["alerts"] = {
                    "total": total_alerts,
                    "sampled": len(alerts),
                    "truncated": truncated,
                    "by_severity": level_dist,
                    "time_range": tr,
                }
            except Exception as e:
                report["sections"]["alerts"] = {"error": str(e)}

        # Section 4: Vulnerability summary (all report types)
        if self._indexer_client:
            try:
                vuln_summary = await self._indexer_client.get_vulnerability_summary()
                report["sections"]["vulnerabilities"] = vuln_summary.get("data", {})
            except Exception as e:
                report["sections"]["vulnerabilities"] = {"error": str(e)}

        # Section 5: Top threats (daily, weekly, monthly, incident)
        if self._indexer_client:
            try:
                threats = await self.get_top_security_threats(limit=5, time_range=tr)
                report["sections"]["top_threats"] = threats.get("data", {}).get("threats", [])
            except Exception:
                report["sections"]["top_threats"] = []

        # Section 6: SCA compliance summary (weekly, monthly)
        if report_type in ("weekly", "monthly"):
            try:
                agents_result = await self._request(
                    "GET", "/agents", params={"status": "active", "limit": 5, "select": "id,name"}
                )
                agent_list = agents_result.get("data", {}).get("affected_items", [])
                sca_scores = []
                for ag in agent_list[:3]:
                    try:
                        sca = await self._request("GET", f"/sca/{ag.get('id')}")
                        sca_items = sca.get("data", {}).get("affected_items", [])
                        scores = [p.get("score", 0) for p in sca_items if isinstance(p.get("score"), (int, float))]
                        avg = int(sum(scores) / len(scores)) if scores else 0
                        sca_scores.append({"agent_id": ag.get("id"), "agent_name": ag.get("name"), "avg_score": avg})
                    except Exception:
                        pass
                report["sections"]["compliance_summary"] = {"agents_sampled": len(sca_scores), "scores": sca_scores}
            except Exception:
                pass

        # Section 7: Recommendations (when include_recommendations=True)
        if include_recommendations:
            recommendations = []
            alerts_section = report["sections"].get("alerts", {})
            critical_count = alerts_section.get("by_severity", {}).get("critical", 0)
            if critical_count > 0:
                recommendations.append(
                    {
                        "priority": "critical",
                        "action": f"Investigate {critical_count} critical-severity alerts immediately",
                    }
                )
            vuln_section = report["sections"].get("vulnerabilities", {})
            critical_vulns = vuln_section.get("critical", 0)
            if critical_vulns > 0:
                recommendations.append(
                    {
                        "priority": "critical",
                        "action": f"Patch {critical_vulns} critical vulnerabilities",
                    }
                )
            agent_section = report["sections"].get("agents", {})
            disconnected_count = agent_section.get("disconnected", 0)
            if disconnected_count > 0:
                recommendations.append(
                    {
                        "priority": "high",
                        "action": f"Investigate {disconnected_count} disconnected agents",
                    }
                )
            if not recommendations:
                recommendations.append(
                    {"priority": "info", "action": "No critical issues detected. Maintain monitoring."}
                )
            report["sections"]["recommendations"] = recommendations

        return {"data": report}

    async def run_compliance_check(self, framework: str, agent_id: str = None) -> Dict[str, Any]:
        """Run compliance check using Wazuh SCA data, filtered by framework relevance."""
        # Map compliance frameworks to SCA policy name patterns
        framework_policy_keywords: Dict[str, list] = {
            "PCI-DSS": ["pci", "payment", "card"],
            "HIPAA": ["hipaa", "health"],
            "SOX": ["sox", "sarbanes"],
            "GDPR": ["gdpr", "privacy", "data_protection"],
            "NIST": ["nist", "800-53", "cybersecurity"],
            "ISO27001": ["iso", "27001", "cis", "hardening", "benchmark", "configuration"],
        }
        keywords = framework_policy_keywords.get(framework, [])

        if agent_id:
            try:
                result = await self._request("GET", f"/sca/{agent_id}")
                sca_items = result.get("data", {}).get("affected_items", [])
                return self._format_compliance_result(
                    framework, keywords, [{"agent_id": agent_id, "sca_items": sca_items}]
                )
            except Exception as e:
                raise ValueError(
                    f"SCA data unavailable for agent {agent_id}: {e}. "
                    "The /sca endpoint may not be supported on this agent or Wazuh version."
                )

        agents_result = await self._request(
            "GET", "/agents", params={"status": "active", "limit": 10, "select": "id,name"}
        )
        agents = agents_result.get("data", {}).get("affected_items", [])
        agent_sca_data = []
        for agent in agents[:5]:
            aid = agent.get("id")
            try:
                sca = await self._request("GET", f"/sca/{aid}")
                agent_sca_data.append(
                    {
                        "agent_id": aid,
                        "agent_name": agent.get("name"),
                        "sca_items": sca.get("data", {}).get("affected_items", []),
                    }
                )
            except Exception:
                agent_sca_data.append({"agent_id": aid, "agent_name": agent.get("name"), "sca_items": []})

        return self._format_compliance_result(framework, keywords, agent_sca_data)

    @staticmethod
    def _format_compliance_result(framework: str, keywords: list, agent_data: list) -> Dict[str, Any]:
        """Summarize SCA configuration-hardening coverage for a framework.

        Honesty constraints (this is a compliance-adjacent tool, so a misleading result is
        the most dangerous kind of wrong):
        - It never emits pass/fail. SCA/CIS checks measure configuration hardening, which is
          input to a controls assessment, not the assessment itself.
        - If the framework has specific policy keywords but NO matching SCA policy is loaded
          on any checked agent, it returns not_assessable instead of silently scoring generic
          CIS benchmarks and labelling them (e.g.) "HIPAA" — which would fabricate a verdict.
        """
        results = []
        total_pass = 0
        total_fail = 0
        total_checks = 0
        any_framework_policy = False

        for agent in agent_data:
            sca_items = agent.get("sca_items", [])
            if keywords:
                relevant = [
                    p
                    for p in sca_items
                    if any(kw in (p.get("policy_id", "") + " " + p.get("name", "")).lower() for kw in keywords)
                ]
            else:
                relevant = sca_items
            if relevant:
                any_framework_policy = True

            agent_pass = sum(p.get("pass", 0) for p in relevant)
            agent_fail = sum(p.get("fail", 0) for p in relevant)
            agent_total = sum(p.get("total_checks", 0) for p in relevant)
            agent_score = int(agent_pass / agent_total * 100) if agent_total > 0 else None

            total_pass += agent_pass
            total_fail += agent_fail
            total_checks += agent_total

            results.append(
                {
                    "agent_id": agent.get("agent_id"),
                    "agent_name": agent.get("agent_name"),
                    "hardening_coverage_pct": agent_score,
                    "pass": agent_pass,
                    "fail": agent_fail,
                    "total_checks": agent_total,
                    "policies": [
                        {
                            "policy_id": p.get("policy_id"),
                            "name": p.get("name"),
                            "score": p.get("score"),
                            "pass": p.get("pass"),
                            "fail": p.get("fail"),
                        }
                        for p in relevant
                    ],
                }
            )

        # No SCA policy maps to this framework → we cannot honestly assess it from SCA data.
        if keywords and not any_framework_policy:
            return {
                "data": {
                    "framework": framework,
                    "assessment": "not_assessable",
                    "reason": (
                        f"No SCA/CIS policy matching {framework} is loaded on the checked agent(s). "
                        f"This tool measures configuration hardening and cannot substitute for a {framework} "
                        "controls assessment. Load a framework-specific SCA policy or assess out of band."
                    ),
                    "agents_checked": len(agent_data),
                }
            }

        coverage = int(total_pass / total_checks * 100) if total_checks > 0 else None

        return {
            "data": {
                "framework": framework,
                "assessment": "hardening_coverage",
                "hardening_coverage_pct": coverage,
                "disclaimer": (
                    "Percentage of mapped SCA/CIS configuration checks passing. This is a hardening "
                    "coverage indicator, NOT a pass/fail compliance certification."
                ),
                "total_checks": total_checks,
                "total_pass": total_pass,
                "total_fail": total_fail,
                "agents_checked": len(results),
                "results": results,
            }
        }

    # =========================================================================
    # ISO 27001:2022 Compliance Tools
    # =========================================================================

    async def get_sca_policy_checks(self, agent_id: str, policy_id: str) -> Dict[str, Any]:
        """Get individual SCA checks for a specific policy on an agent."""
        result = await self._request("GET", f"/sca/{agent_id}/checks/{policy_id}")
        checks = result.get("data", {}).get("affected_items", [])
        passed = [c for c in checks if c.get("result") == "passed"]
        failed = [c for c in checks if c.get("result") == "failed"]
        not_applicable = [c for c in checks if c.get("result") == "not applicable"]
        return {
            "data": {
                "agent_id": agent_id,
                "policy_id": policy_id,
                "total_checks": len(checks),
                "passed": len(passed),
                "failed": len(failed),
                "not_applicable": len(not_applicable),
                "score": int(len(passed) / len(checks) * 100) if checks else 0,
                "failed_checks": [
                    {
                        "id": c.get("id"),
                        "title": c.get("title"),
                        "description": c.get("description"),
                        "rationale": c.get("rationale"),
                        "remediation": c.get("remediation"),
                        "result": c.get("result"),
                    }
                    for c in failed[:50]
                ],
                "passed_checks": [
                    {"id": c.get("id"), "title": c.get("title"), "result": c.get("result")} for c in passed[:50]
                ],
            }
        }

    async def get_iso27001_dashboard(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Return an ISO 27001:2022 compliance dashboard aggregated from Wazuh data."""

        # --- gather raw data concurrently ---
        async def _safe(coro, default):
            try:
                return await coro
            except Exception:
                return default

        agents_coro = self._request(
            "GET", "/agents", params={"status": "active", "limit": 500, "select": "id,name,os.name"}
        )
        # Alerts live in the Indexer — the Manager API removed its /alerts endpoint.
        # Bound to a fixed reporting window so the dashboard reflects recent posture
        # (and matches the other ISO tools) rather than counting all alert history.
        _iso_window_start = (datetime.now(timezone.utc) - timedelta(days=_ISO27001_ALERT_WINDOW_DAYS)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        alerts_coro = self.get_alerts(limit=500, timestamp_start=_iso_window_start)
        stats_coro = self._request("GET", "/manager/stats/analysisd")

        agents_res, alerts_res, stats_res = await asyncio.gather(
            _safe(agents_coro, {}),
            _safe(alerts_coro, {}),
            _safe(stats_coro, {}),
        )

        agents = agents_res.get("data", {}).get("affected_items", [])
        alerts = alerts_res.get("data", {}).get("affected_items", [])

        # SCA: fetch for up to 5 agents
        sca_results = []
        for ag in agents[:5]:
            aid = ag.get("id")
            try:
                sca = await self._request("GET", f"/sca/{aid}")
                sca_results.append(
                    {
                        "agent_id": aid,
                        "agent_name": ag.get("name"),
                        "sca_items": sca.get("data", {}).get("affected_items", []),
                    }
                )
            except Exception:
                sca_results.append({"agent_id": aid, "agent_name": ag.get("name"), "sca_items": []})

        # Vulnerability summary (indexer if available, else skip).
        # vuln_query_ok gates scoring: a *successful* query that returns zero vulns is a
        # legitimate 100/pass, but a failed query (Indexer outage/auth error) or no target
        # must score the vuln controls as no_data — not silently as full compliance.
        vuln_summary: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        vuln_query_ok = False
        vuln_agents_counted = 0
        if self._indexer_client:
            try:
                if agent_id:
                    # Explicit single-agent scope requested.
                    vuln_targets = [agent_id]
                else:
                    # Aggregate across ALL active agents, not just agents[0]. A.8.8 is the
                    # heaviest-weighted control (weight 4); scoring it from a single agent
                    # made the whole dashboard hostage to one host's vuln posture.
                    vuln_targets = [a.get("id") for a in agents if a.get("id")]
                for tid in vuln_targets:
                    vuln_res = await self._indexer_client.get_vulnerabilities(agent_id=tid, limit=500)
                    for v in vuln_res.get("data", {}).get("affected_items", []):
                        sev = (v.get("severity") or "").lower()
                        if sev in vuln_summary:
                            vuln_summary[sev] += 1
                    vuln_agents_counted += 1
                    vuln_query_ok = True
            except Exception:
                logger.warning(
                    "ISO27001: vulnerability query failed; scoring vulnerability controls as no_data",
                    exc_info=True,
                )

        # Build per-control evidence
        alert_groups: Dict[str, int] = {}
        for a in alerts:
            for g in a.get("rule", {}).get("groups") or []:
                alert_groups[g] = alert_groups.get(g, 0) + 1

        # --- Confidence thresholds ---
        # confidence = how reliable the score is, based on evidence quantity
        def _confidence(evidence_count: int, source: str) -> str:
            if source == "sca":
                if evidence_count >= 50:
                    return "high"
                if evidence_count >= 10:
                    return "medium"
                return "low"
            if source == "vulnerabilities":
                # Confidence reflects whether the query actually succeeded, not merely
                # whether an Indexer client is configured.
                return "high" if vuln_query_ok else "none"
            if source == "alerts":
                if evidence_count >= 20:
                    return "high"
                if evidence_count >= 5:
                    return "medium"
                return "low"
            if source in ("agents", "stats"):
                return "medium" if evidence_count > 0 else "none"
            return "none"

        control_statuses = []
        # domain → list of (weighted_score, weight) tuples for weighted aggregation
        domain_weighted: Dict[str, list] = {"A.5": [], "A.6": [], "A.7": [], "A.8": []}

        for ctrl_id, ctrl in _ISO27001_CONTROL_MAP.items():
            source = ctrl["data_source"]
            weight = ctrl.get("weight", 1)
            score: Optional[int] = None
            evidence_count = 0
            status = "no_data"

            if source == "sca":
                kws = ctrl["sca_keywords"]
                total_p, total_f, total_c = 0, 0, 0
                for sr in sca_results:
                    for item in sr["sca_items"]:
                        name_lower = (item.get("policy_id", "") + " " + item.get("name", "")).lower()
                        if not kws or any(kw in name_lower for kw in kws):
                            total_p += item.get("pass", 0)
                            total_f += item.get("fail", 0)
                            total_c += item.get("total_checks", 0)
                if total_c > 0:
                    raw = total_p / total_c * 100
                    # Stricter threshold: penalise heavily if fail rate > 30%
                    fail_rate = total_f / total_c
                    penalty = max(0, (fail_rate - 0.30) * 50) if fail_rate > 0.30 else 0
                    score = max(0, int(raw - penalty))
                    evidence_count = total_c
                    status = "pass" if score >= 75 else "fail"  # Raised from 70→75

            elif source == "alerts":
                groups = ctrl["rule_groups"]
                cnt = sum(alert_groups.get(g, 0) for g in groups) if groups else len(alerts)
                evidence_count = cnt
                # Alert-based controls measure whether DETECTION is active, not effectiveness.
                # The old score = min(100, cnt*5) was inverted — more malware/auth-failure
                # alerts produced a HIGHER "compliance" score, and a clean environment scored 0.
                # Raw alert volume is not a compliance measure (we have no resolution data to
                # tell handled from unhandled), so we no longer emit a volume-derived score:
                # report detection coverage as a status and leave the score unscored (None),
                # keeping it out of the weighted compliance aggregate.
                score = None
                status = "monitoring_active" if cnt > 0 else "no_data"

            elif source == "vulnerabilities":
                if not vuln_query_ok:
                    # No successful vulnerability query — cannot assert compliance.
                    status = "no_data"
                    score = None
                    evidence_count = 0
                else:
                    total_vulns = sum(vuln_summary.values())
                    critical = vuln_summary.get("critical", 0)
                    high = vuln_summary.get("high", 0)
                    evidence_count = total_vulns
                    # Weighted penalty: critical = -15 pts each (up from -10), high = -5 (up from -3)
                    score = max(0, 100 - critical * 15 - high * 5 - vuln_summary.get("medium", 0))
                    status = "pass" if score >= 75 else "fail"

            elif source == "agents":
                evidence_count = len(agents)
                score = min(100, len(agents) * 10) if agents else 0
                status = "active" if agents else "no_data"

            elif source == "stats":
                # /manager/stats/analysisd returns data.affected_items[0].{...}, not data.{...}
                stats_items = stats_res.get("data", {}).get("affected_items", []) if stats_res else []
                analysisd = stats_items[0] if stats_items else {}
                events = analysisd.get("total_events_decoded", analysisd.get("events_decoded", 0))
                evidence_count = events if isinstance(events, int) else 0
                score = 100 if evidence_count > 0 else 0
                status = "active" if evidence_count > 0 else "no_data"

            confidence = _confidence(evidence_count, source)
            domain = ctrl["domain"]
            if score is not None:
                domain_weighted[domain].append((score, weight))

            control_statuses.append(
                {
                    "control_id": ctrl_id,
                    "title": ctrl["title"],
                    "domain": domain,
                    "data_source": source,
                    "status": status,
                    "score": score,
                    "weight": weight,
                    "confidence": confidence,
                    "evidence_count": evidence_count,
                }
            )

        # --- Weighted domain scores ---
        domain_names = {"A.5": "Organizational", "A.6": "People", "A.7": "Physical", "A.8": "Technological"}
        domain_summary = {}
        for domain, weighted_pairs in domain_weighted.items():
            if weighted_pairs:
                total_w = sum(w for _, w in weighted_pairs)
                weighted_avg = int(sum(s * w for s, w in weighted_pairs) / total_w) if total_w else None
                # Count the scored controls in this domain whose confidence is low/none.
                # The old generator ignored its loop variable and re-evaluated the SAME
                # first-matching control for every pair, so this was always 0 or len(pairs).
                low_conf = sum(
                    1
                    for c in control_statuses
                    if c["control_id"].startswith(domain)
                    and c["score"] is not None
                    and c["confidence"] in ("low", "none")
                )
            else:
                weighted_avg = None
                low_conf = 0
            domain_summary[domain] = {
                "name": domain_names.get(domain, domain),
                "weighted_score": weighted_avg,
                "controls_measured": len(weighted_pairs),
                "low_confidence_controls": low_conf,
            }

        # --- Overall weighted score ---
        all_weighted = [(c["score"], c["weight"]) for c in control_statuses if c["score"] is not None]
        if all_weighted:
            total_w = sum(w for _, w in all_weighted)
            overall_score = int(sum(s * w for s, w in all_weighted) / total_w) if total_w else None
        else:
            overall_score = None

        overall_confidence = (
            "high"
            if sum(1 for c in control_statuses if c["confidence"] in ("low", "none")) <= 2
            else "medium" if sum(1 for c in control_statuses if c["confidence"] == "none") <= 4 else "low"
        )

        failing = [c for c in control_statuses if c["status"] == "fail"]
        no_data = [c for c in control_statuses if c["status"] == "no_data"]

        # --- Per-device endpoint panel (Board-level: laptops/computers) ---
        # Shows each active endpoint's SCA score and vulnerability exposure
        endpoint_devices = []
        for sr in sca_results:
            aid = sr["agent_id"]
            aname = sr.get("agent_name", aid)
            sca_items = sr["sca_items"]

            # Overall SCA score for this device
            dev_pass = sum(p.get("pass", 0) for p in sca_items)
            dev_total = sum(p.get("total_checks", 0) for p in sca_items)
            dev_score = int(dev_pass / dev_total * 100) if dev_total else None

            # Vuln count for this device (from shared summary — per-device needs indexer)
            # We flag "unknown" unless we have per-agent data
            endpoint_devices.append(
                {
                    "agent_id": aid,
                    "device_name": aname,
                    "sca_score": dev_score,
                    "sca_policies": len(sca_items),
                    "sca_status": (
                        "pass" if (dev_score or 0) >= 75 else ("fail" if dev_score is not None else "no_data")
                    ),
                    "os": next((a.get("os", {}).get("name") for a in agents if a.get("id") == aid), None),
                }
            )

        # Board-level summary sentence
        passing_devices = sum(1 for d in endpoint_devices if d["sca_status"] == "pass")
        total_devices = len(endpoint_devices)
        board_summary = (
            f"{passing_devices}/{total_devices} endpoint device(s) meet the ISO 27001 A.8.1 configuration-hardening "
            f"baseline (SCA/CIS checks). "
            f"{'All sampled devices meet the hardening baseline.' if passing_devices == total_devices else f'{total_devices - passing_devices} device(s) need hardening remediation.'} "
            f"Critical vulnerabilities outstanding: {vuln_summary.get('critical', 0)}. "
            "This reflects configuration hardening only, not full ISO 27001 compliance."
            if total_devices > 0
            else "No active endpoint agents found."
        )

        # Posture band — a coverage indicator, deliberately NOT a pass/fail compliance
        # verdict. Only 14 of the 93 Annex A controls are mapped to Wazuh data, so a
        # "pass" here would be read as whole-framework compliance, which it is not.
        controls_mapped = len(_ISO27001_CONTROL_MAP)
        if overall_score is None:
            posture = "insufficient_data"
        elif overall_score >= 75:
            posture = "strong_where_measured"
        elif overall_score >= 50:
            posture = "moderate_where_measured"
        else:
            posture = "weak_where_measured"

        return {
            "data": {
                "framework": "ISO27001:2022",
                "assessment_type": "control_coverage_indicator",
                "disclaimer": (
                    f"This is a control-coverage indicator, NOT a compliance certification. Only "
                    f"{controls_mapped} of 93 ISO 27001:2022 Annex A controls are mapped to Wazuh "
                    "telemetry (A.7 Physical has none). Scores reflect only the mapped, technically "
                    "measurable controls and must not be read as whole-framework compliance."
                ),
                "controls_mapped": controls_mapped,
                "controls_total": _ISO27001_TOTAL_ANNEX_A_CONTROLS,
                "coverage_pct_of_framework": int(controls_mapped / _ISO27001_TOTAL_ANNEX_A_CONTROLS * 100),
                "overall_weighted_score": overall_score,
                "posture": posture,
                "overall_confidence": overall_confidence,
                "scoring": {
                    "method": "weighted_average",
                    "note": (
                        "Weighted by control importance over the MAPPED controls only (A.8.8 "
                        "vulnerabilities weight=4). Alert-based controls report detection coverage "
                        "and are not scored on volume. No pass/fail verdict is emitted."
                    ),
                    "vuln_agents_aggregated": vuln_agents_counted,
                    "sca_agents_sampled": len(sca_results),
                },
                "active_agents": len(agents),
                "vulnerability_summary": vuln_summary,
                "domain_summary": domain_summary,
                "controls": control_statuses,
                "failing_controls": [
                    {"control_id": c["control_id"], "title": c["title"], "score": c["score"], "weight": c["weight"]}
                    for c in sorted(failing, key=lambda x: x["weight"], reverse=True)
                ],
                "no_data_controls": [c["control_id"] for c in no_data],
                "endpoint_device_panel": {
                    "board_summary": board_summary,
                    "devices": endpoint_devices,
                    "total_devices": total_devices,
                    "compliant_devices": passing_devices,
                    "non_compliant_devices": total_devices - passing_devices,
                },
            }
        }

    async def get_iso27001_control_detail(self, control_id: str, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Return detailed Wazuh evidence for a specific ISO 27001 Annex A control."""
        # Handle domain-level queries (e.g. "A.8" → all A.8.x controls)
        if control_id in ("A.5", "A.6", "A.7", "A.8"):
            controls_in_domain = {k: v for k, v in _ISO27001_CONTROL_MAP.items() if v["domain"] == control_id}
        else:
            if control_id not in _ISO27001_CONTROL_MAP:
                return {"error": f"Control '{control_id}' not found in ISO 27001 map"}
            controls_in_domain = {control_id: _ISO27001_CONTROL_MAP[control_id]}

        evidence_blocks = []
        for ctrl_id, ctrl in controls_in_domain.items():
            block: Dict[str, Any] = {
                "control_id": ctrl_id,
                "title": ctrl["title"],
                "data_source": ctrl["data_source"],
                "evidence": {},
            }
            source = ctrl["data_source"]
            try:
                if source == "sca":
                    target = agent_id
                    if not target:
                        agents_res = await self._request(
                            "GET", "/agents", params={"status": "active", "limit": 1, "select": "id"}
                        )
                        items = agents_res.get("data", {}).get("affected_items", [])
                        target = items[0].get("id") if items else None
                    if target:
                        sca_res = await self._request("GET", f"/sca/{target}")
                        sca_items = sca_res.get("data", {}).get("affected_items", [])
                        kws = ctrl["sca_keywords"]
                        relevant = [
                            p
                            for p in sca_items
                            if not kws
                            or any(kw in (p.get("policy_id", "") + " " + p.get("name", "")).lower() for kw in kws)
                        ] or sca_items
                        block["evidence"] = {
                            "agent_id": target,
                            "policies": [
                                {
                                    "policy_id": p.get("policy_id"),
                                    "name": p.get("name"),
                                    "score": p.get("score"),
                                    "pass": p.get("pass"),
                                    "fail": p.get("fail"),
                                    "total_checks": p.get("total_checks"),
                                }
                                for p in relevant[:10]
                            ],
                        }

                elif source == "alerts":
                    # Alerts live in the Indexer — the Manager API removed its /alerts endpoint
                    groups = ctrl["rule_groups"]
                    alerts_res = await self.get_alerts(
                        limit=100,
                        agent_id=agent_id,
                        rule_groups=groups or None,
                    )
                    alert_items = alerts_res.get("data", {}).get("affected_items", [])
                    block["evidence"] = {
                        "alert_count": len(alert_items),
                        "rule_groups_searched": groups,
                        "recent_alerts": [
                            {
                                "id": a.get("id"),
                                "timestamp": a.get("timestamp"),
                                "rule_id": a.get("rule", {}).get("id"),
                                "rule_description": a.get("rule", {}).get("description"),
                                "level": a.get("rule", {}).get("level"),
                                "agent": a.get("agent", {}).get("name"),
                            }
                            for a in alert_items[:20]
                        ],
                    }

                elif source == "vulnerabilities":
                    if self._indexer_client:
                        target = agent_id
                        if not target:
                            agents_res = await self._request(
                                "GET", "/agents", params={"status": "active", "limit": 1, "select": "id"}
                            )
                            items = agents_res.get("data", {}).get("affected_items", [])
                            target = items[0].get("id") if items else None
                        if target:
                            vuln_res = await self._indexer_client.get_vulnerabilities(agent_id=target, limit=200)
                            vulns = vuln_res.get("data", {}).get("affected_items", [])
                            by_sev: Dict[str, int] = {}
                            for v in vulns:
                                sev = (v.get("severity") or "unknown").lower()
                                by_sev[sev] = by_sev.get(sev, 0) + 1
                            block["evidence"] = {
                                "agent_id": target,
                                "total_vulnerabilities": len(vulns),
                                "by_severity": by_sev,
                                "critical_vulnerabilities": [
                                    {
                                        "cve": v.get("cve"),
                                        # name/version live under package.* in the normalized
                                        # vuln doc; the old top-level reads always yielded null.
                                        "name": (v.get("package") or {}).get("name"),
                                        "severity": v.get("severity"),
                                        "version": (v.get("package") or {}).get("version"),
                                    }
                                    for v in vulns
                                    if (v.get("severity") or "").lower() == "critical"
                                ][:20],
                            }
                    else:
                        block["evidence"] = {"note": "Wazuh Indexer not configured — vulnerability data unavailable"}

                elif source == "agents":
                    params = {"status": "active", "limit": 100, "select": "id,name,status,os.name,lastKeepAlive"}
                    if agent_id:
                        params["agents_list"] = agent_id
                    agents_res = await self._request("GET", "/agents", params=params)
                    agent_items = agents_res.get("data", {}).get("affected_items", [])
                    block["evidence"] = {
                        "active_agents": len(agent_items),
                        "agents": [
                            {
                                "id": a.get("id"),
                                "name": a.get("name"),
                                "os": a.get("os", {}).get("name"),
                                "last_seen": a.get("lastKeepAlive"),
                            }
                            for a in agent_items[:20]
                        ],
                    }

                elif source == "stats":
                    stats_res = await self._request("GET", "/manager/stats/analysisd")
                    block["evidence"] = {"analysisd_stats": stats_res.get("data", {})}

            except Exception as e:
                block["evidence"] = {"error": str(e)}

            evidence_blocks.append(block)

        return {
            "data": {
                "queried_control": control_id,
                "framework": "ISO27001:2022",
                "controls": evidence_blocks,
            }
        }

    async def get_iso27001_gap_analysis(self, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Identify ISO 27001 controls with gaps — failing SCA, critical vulns, or no evidence."""
        dashboard = await self.get_iso27001_dashboard(agent_id=agent_id)
        controls = dashboard.get("data", {}).get("controls", [])

        gaps = []
        for c in controls:
            ctrl_id = c["control_id"]
            ctrl_meta = _ISO27001_CONTROL_MAP.get(ctrl_id, {})
            status = c["status"]
            score = c["score"]

            if status == "no_data":
                gaps.append(
                    {
                        "control_id": ctrl_id,
                        "title": ctrl_meta.get("title", ""),
                        "domain": c["domain"],
                        "gap_type": "no_evidence",
                        "severity": "high",
                        "score": None,
                        "recommendation": (
                            f"No Wazuh data available for this control. "
                            f"Data source expected: {ctrl_meta.get('data_source', 'unknown')}. "
                            "Ensure the relevant Wazuh module is enabled (e.g. SCA, vulnerability scanner, FIM)."
                        ),
                    }
                )
            elif status == "fail" and score is not None:
                gaps.append(
                    {
                        "control_id": ctrl_id,
                        "title": ctrl_meta.get("title", ""),
                        "domain": c["domain"],
                        "gap_type": "failing_checks",
                        "severity": "critical" if score < 40 else "medium",
                        "score": score,
                        "recommendation": self._iso27001_remediation_hint(ctrl_id, score),
                    }
                )

        gaps.sort(key=lambda g: {"critical": 0, "high": 1, "medium": 2}.get(g["severity"], 3))

        domain_gap_counts: Dict[str, int] = {}
        for g in gaps:
            d = g["domain"]
            domain_gap_counts[d] = domain_gap_counts.get(d, 0) + 1

        return {
            "data": {
                "framework": "ISO27001:2022",
                "total_gaps": len(gaps),
                "gaps_by_domain": domain_gap_counts,
                "gaps": gaps,
                "summary": (
                    f"{len(gaps)} gap(s) identified across ISO 27001:2022 Annex A controls. "
                    f"Critical: {sum(1 for g in gaps if g['severity'] == 'critical')}, "
                    f"High: {sum(1 for g in gaps if g['severity'] == 'high')}, "
                    f"Medium: {sum(1 for g in gaps if g['severity'] == 'medium')}."
                ),
            }
        }

    @staticmethod
    def _iso27001_remediation_hint(control_id: str, score: int) -> str:
        """Return a human-readable remediation hint for a failing ISO 27001 control."""
        hints = {
            "A.8.1": "Review SCA policy results for endpoint devices. Apply CIS benchmark hardening to workstations and servers.",
            "A.8.2": "Audit privileged account usage. Review sudo/rootcheck alerts and restrict unnecessary privilege grants.",
            "A.8.4": "Enable File Integrity Monitoring (FIM) on source code directories. Investigate recent syscheck alerts.",
            "A.8.5": "Investigate authentication failure alerts. Enforce MFA, review SSH key policies, and check PAM configuration.",
            "A.8.7": "Review malware/rootcheck alerts. Ensure antivirus definitions are current and rootkit checks are enabled.",
            "A.8.8": "Patch critical and high-severity vulnerabilities. Prioritize CVEs with public exploits.",
            "A.8.9": "Improve SCA scores by applying CIS benchmark recommendations. Review failing checks in detail.",
            "A.8.12": "Investigate FIM alerts for unexpected file changes. Review data access controls and DLP policies.",
            "A.8.15": "Verify log collection is active on all agents. Check analysisd stats and ensure log retention policies are in place.",
            "A.8.16": "Increase alert monitoring coverage. Ensure SIEM rules are tuned and critical rules are active.",
            "A.8.20": "Review firewall rules and network alert patterns. Tighten ingress/egress controls.",
            "A.8.22": "Verify network segmentation is in place. Check agent port exposure and review firewall policies.",
            "A.5.26": "Define and test an incident response procedure. Ensure Wazuh active response is configured.",
            "A.6.3": "Ensure all endpoints have active Wazuh agents. Disconnected agents indicate gaps in monitoring coverage.",
        }
        hint = hints.get(control_id, "Review Wazuh data for this control and apply relevant hardening measures.")
        return f"Score: {score}%. {hint}"

    async def get_iso27001_alerts(self, time_range: str = "24h", agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Get recent alerts mapped to ISO 27001:2022 Annex A control domains."""
        hours = _TIME_RANGE_HOURS.get(time_range, 24)
        since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

        try:
            # Alerts live in the Indexer — the Manager API removed its /alerts endpoint
            result = await self.get_alerts(limit=500, timestamp_start=since, agent_id=agent_id)
        except Exception as e:
            return {"error": f"Failed to fetch alerts: {e}"}

        alerts = result.get("data", {}).get("affected_items", [])

        # Build group → alert count index
        alert_group_counts: Dict[str, int] = {}
        for a in alerts:
            for g in a.get("rule", {}).get("groups") or []:
                alert_group_counts[g] = alert_group_counts.get(g, 0) + 1

        # Map alerts to ISO 27001 controls
        control_alert_map: Dict[str, Dict] = {}
        for ctrl_id, ctrl in _ISO27001_CONTROL_MAP.items():
            if ctrl["data_source"] != "alerts":
                continue
            groups = ctrl["rule_groups"]
            if groups:
                count = sum(alert_group_counts.get(g, 0) for g in groups)
            else:
                count = len(alerts)

            # Collect sample alerts for this control
            if groups:
                samples = [a for a in alerts if any(g in (a.get("rule", {}).get("groups") or []) for g in groups)][:10]
            else:
                samples = alerts[:10]

            control_alert_map[ctrl_id] = {
                "control_id": ctrl_id,
                "title": ctrl["title"],
                "domain": ctrl["domain"],
                "alert_count": count,
                "sample_alerts": [
                    {
                        "timestamp": a.get("timestamp"),
                        "rule_id": a.get("rule", {}).get("id"),
                        "description": a.get("rule", {}).get("description"),
                        "level": a.get("rule", {}).get("level"),
                        "agent": a.get("agent", {}).get("name"),
                    }
                    for a in samples
                ],
            }

        # Sort by alert count descending
        sorted_controls = sorted(control_alert_map.values(), key=lambda x: x["alert_count"], reverse=True)

        return {
            "data": {
                "framework": "ISO27001:2022",
                "time_range": time_range,
                "total_alerts_fetched": len(alerts),
                "controls_with_alerts": [c for c in sorted_controls if c["alert_count"] > 0],
                "controls_without_alerts": [c["control_id"] for c in sorted_controls if c["alert_count"] == 0],
            }
        }

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
            level = int(rule.get("level", 0))
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
        """Search manager logs by free text.

        Uses the ``search`` parameter (substring match). The ``q`` parameter requires
        structured ``field=value`` syntax and returns HTTP 400 on bare search terms,
        which is what LLM callers typically pass.
        """
        params = {"search": query, "limit": limit}
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

    @staticmethod
    def _sanitize_ar_argument(value: str, param_name: str) -> str:
        """Sanitize active response argument to prevent command injection.

        Active response arguments are passed to shell commands on agents.
        Only allow safe characters to prevent shell metacharacter injection.
        """
        import re

        # Strip leading/trailing whitespace
        value = value.strip()
        if not value:
            raise ValueError(f"{param_name} cannot be empty")
        # Block shell metacharacters and control chars
        if re.search(r'[;&|`$(){}\[\]<>!\\\'"\n\r\t]', value):
            raise ValueError(f"{param_name} contains invalid characters")
        # Audit fix M6: Block flag injection for standalone values
        if not param_name.startswith("parameter:") and value.startswith("-"):
            raise ValueError(f"{param_name} must not start with '-'")
        return value

    @staticmethod
    def _validate_ip(ip_address: str, param_name: str = "ip_address") -> str:
        """Validate IPv4 or IPv6 address format."""
        import re

        ip_address = ip_address.strip()
        # IPv4
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip_address):
            octets = ip_address.split(".")
            if all(0 <= int(o) <= 255 for o in octets):
                return ip_address
        # IPv6 (simplified check)
        if ":" in ip_address and re.match(r"^[0-9a-fA-F:]+$", ip_address):
            return ip_address
        raise ValueError(f"Invalid IP address format for {param_name}: {ip_address}")

    def _build_protected_networks(self, extra: str) -> list:
        """Build the block_ip protected-target list from env + the manager host + loopback."""
        networks = [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("::1/128"),
        ]
        # Protect the Wazuh manager's own address so the SOC can't cut itself off.
        try:
            networks.append(ipaddress.ip_network(f"{self.config.wazuh_host}/32", strict=False))
        except ValueError:
            pass  # hostname, not an IP — can't pin it here
        for token in extra.split(","):
            token = token.strip()
            if not token:
                continue
            try:
                networks.append(ipaddress.ip_network(token, strict=False))
            except ValueError:
                logger.warning(f"Ignoring invalid WAZUH_PROTECTED_IPS entry: {token!r}")
        return networks

    def _is_protected_target(self, ip_address: str) -> bool:
        """True if ip_address falls inside a protected network (must never be blocked)."""
        try:
            addr = ipaddress.ip_address(ip_address)
        except ValueError:
            return False
        return any(addr in net for net in self._protected_networks)

    async def block_ip(
        self, ip_address: str, duration: int = 0, agent_id: str = None, all_agents: bool = False
    ) -> Dict[str, Any]:
        """Block IP via firewall-drop active response.

        Requires an explicit target: either a specific agent_id, or all_agents=True to
        fan out fleet-wide. It no longer silently defaults to "all" — an attacker-embedded
        "block <ip>" in a log line must not weaponize the whole fleet by omission.
        """
        ip_address = self._validate_ip(ip_address)
        if self._is_protected_target(ip_address):
            raise ValueError(
                f"Refusing to block protected target {ip_address}: it is loopback, the Wazuh "
                "manager, or on the WAZUH_PROTECTED_IPS denylist. Blocking it would be self-inflicted DoS."
            )
        if not agent_id and not all_agents:
            raise ValueError(
                "block_ip requires an explicit target: pass agent_id for a single agent, or "
                "all_agents=True to deliberately block fleet-wide."
            )
        ip_address = self._sanitize_ar_argument(ip_address, "ip_address")
        arguments = [f"-srcip {ip_address}"]
        if duration and duration > 0:
            arguments.append(f"-timeout {int(duration)}")
        data = {
            "command": "!firewall-drop",
            "agent_list": [agent_id] if agent_id else ["all"],
            "arguments": arguments,
            "alert": {"data": {"srcip": ip_address}},
        }
        return await self.execute_active_response(data)

    async def isolate_host(self, agent_id: str) -> Dict[str, Any]:
        """Isolate host from network via active response."""
        if not agent_id:
            raise ValueError("agent_id is required for host isolation")
        data = {"command": "!host-isolation", "agent_list": [agent_id], "arguments": []}
        return await self.execute_active_response(data)

    async def kill_process(self, agent_id: str, process_id: int) -> Dict[str, Any]:
        """Kill process on agent via active response."""
        if not agent_id:
            raise ValueError("agent_id is required for kill_process")
        try:
            pid = int(process_id)
        except (ValueError, TypeError):
            raise ValueError(f"process_id must be numeric, got: {process_id}")
        data = {"command": "!kill-process", "agent_list": [agent_id], "arguments": [str(pid)]}
        return await self.execute_active_response(data)

    async def disable_user(self, agent_id: str, username: str) -> Dict[str, Any]:
        """Disable user account on agent via active response."""
        if not agent_id:
            raise ValueError("agent_id is required for disable_user")
        username = self._sanitize_ar_argument(username, "username")
        # The stock disable-account script reads the target user from
        # alert.data.dstuser and ignores extra_args; pass it there (and keep it in
        # arguments for custom scripts that expect a positional username).
        data = {
            "command": "!disable-account",
            "agent_list": [agent_id],
            "arguments": [username],
            "alert": {"data": {"dstuser": username}},
        }
        return await self.execute_active_response(data)

    async def quarantine_file(self, agent_id: str, file_path: str) -> Dict[str, Any]:
        """Quarantine file on agent via active response."""
        if not agent_id:
            raise ValueError("agent_id is required for quarantine_file")
        file_path = self._sanitize_ar_argument(file_path, "file_path")
        data = {"command": "!quarantine", "agent_list": [agent_id], "arguments": [file_path]}
        return await self.execute_active_response(data)

    # Known Wazuh active response commands (with ! prefix for stateful execution)
    ALLOWED_AR_COMMANDS = frozenset(
        [
            "!firewall-drop",
            "!host-isolation",
            "!kill-process",
            "!disable-account",
            "!enable-account",
            "!quarantine",
            "!host-deny",
            "!restart-wazuh",
        ]
    )

    async def run_active_response(self, agent_id: str, command: str, parameters: dict = None) -> Dict[str, Any]:
        """Execute generic active response command."""
        # Normalize to the "!" stateful-execution form so callers may pass either
        # "firewall-drop" or "!firewall-drop" (the tool validator accepts both, but the
        # allowlist is keyed on the "!" form — without this the tool could never succeed).
        command = command if command.startswith("!") else f"!{command}"
        if command not in self.ALLOWED_AR_COMMANDS:
            raise ValueError(
                f"Unknown active response command: {command}. "
                f"Allowed commands: {', '.join(sorted(self.ALLOWED_AR_COMMANDS))}"
            )
        args = []
        if parameters:
            args = [self._sanitize_ar_argument(f"{k}={v}", f"parameter:{k}") for k, v in parameters.items()]
        data = {"command": command, "agent_list": [agent_id], "arguments": args}
        return await self.execute_active_response(data)

    async def firewall_drop(self, agent_id: str, src_ip: str, duration: int = 0) -> Dict[str, Any]:
        """Add firewall drop rule via active response."""
        src_ip = self._validate_ip(src_ip, "src_ip")
        src_ip = self._sanitize_ar_argument(src_ip, "src_ip")
        arguments = [f"-srcip {src_ip}"]
        if duration and duration > 0:
            arguments.append(f"-timeout {int(duration)}")
        data = {
            "command": "!firewall-drop",
            "agent_list": [agent_id],
            "arguments": arguments,
            "alert": {"data": {"srcip": src_ip}},
        }
        return await self.execute_active_response(data)

    async def host_deny(self, agent_id: str, src_ip: str) -> Dict[str, Any]:
        """Add hosts.deny entry via active response."""
        src_ip = self._validate_ip(src_ip, "src_ip")
        src_ip = self._sanitize_ar_argument(src_ip, "src_ip")
        data = {
            "command": "!host-deny",
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
        """Check if IP is blocked by searching active response alerts via Elasticsearch."""
        if not self._indexer_client:
            raise IndexerNotConfiguredError()
        # Use Elasticsearch query_string to search for both the IP and firewall-drop.
        # Scope to the requested agent when given, instead of ignoring agent_id and
        # reporting a fleet-wide block status for a per-agent question.
        query = f'"{ip_address}" AND "firewall-drop"'
        result = await self._indexer_client.get_alerts(limit=50, query_text=query, agent_id=agent_id)
        _, total, _ = self._alerts_and_total(result)
        return {
            "data": {
                "ip_address": ip_address,
                "agent_id": agent_id,
                "scope": "agent" if agent_id else "fleet",
                "blocked": total > 0,
                "matching_alerts": total,
            }
        }

    async def check_agent_isolation(self, agent_id: str) -> Dict[str, Any]:
        """Check agent isolation status by examining agent connectivity and alert history."""
        result = await self._request("GET", "/agents", params={"agents_list": agent_id, "select": "id,name,status"})
        agents = result.get("data", {}).get("affected_items", [])
        if not agents:
            raise ValueError(f"Agent {agent_id} not found")
        agent = agents[0]
        status = agent.get("status")
        # Check alert history for isolation commands if indexer is available
        isolation_confirmed = False
        if self._indexer_client and status == "disconnected":
            try:
                query = f'"host-isolation" AND "{agent_id}"'
                alerts = await self._indexer_client.get_alerts(limit=5, query_text=query)
                items = alerts.get("data", {}).get("affected_items", [])
                isolation_confirmed = len(items) > 0
            except Exception:
                pass
        return {
            "data": {
                "agent_id": agent_id,
                "status": status,
                "possibly_isolated": status == "disconnected",
                "isolation_confirmed": isolation_confirmed,
                "name": agent.get("name"),
                "note": "A disconnected agent may be isolated or simply offline. "
                "Check isolation_confirmed for active response evidence.",
            }
        }

    async def check_process(self, agent_id: str, process_id: int) -> Dict[str, Any]:
        """Check if a process is still running on an agent."""
        result = await self._request("GET", f"/syscollector/{agent_id}/processes", params={"limit": 500})
        processes = result.get("data", {}).get("affected_items", [])
        running = any(str(p.get("pid")) == str(process_id) for p in processes)
        return {"data": {"agent_id": agent_id, "process_id": process_id, "running": running}}

    async def check_user_status(self, agent_id: str, username: str) -> Dict[str, Any]:
        """Check user account status by searching active response alerts via Elasticsearch."""
        disable_evidence = False
        enable_evidence = False
        if self._indexer_client:
            try:
                # Search for disable-account events for this user and agent
                disable_query = f'"disable-account" AND "{username}" AND "{agent_id}"'
                disable_result = await self._indexer_client.get_alerts(limit=5, query_text=disable_query)
                disable_evidence = len(disable_result.get("data", {}).get("affected_items", [])) > 0

                # Search for enable-account events
                enable_query = f'"enable-account" AND "{username}" AND "{agent_id}"'
                enable_result = await self._indexer_client.get_alerts(limit=5, query_text=enable_query)
                enable_evidence = len(enable_result.get("data", {}).get("affected_items", [])) > 0
            except Exception:
                pass
        # Most recent action takes precedence
        likely_disabled = disable_evidence and not enable_evidence
        return {
            "data": {
                "agent_id": agent_id,
                "username": username,
                "likely_disabled": likely_disabled,
                "disable_action_found": disable_evidence,
                "enable_action_found": enable_evidence,
                "note": "Status based on active response alert history. " "Verify on the host for definitive status.",
            }
        }

    async def check_file_quarantine(self, agent_id: str, file_path: str) -> Dict[str, Any]:
        """Check if a file has been quarantined via FIM events."""
        # FIM data is per-agent: GET /syscheck/{agent_id}. GET /syscheck (no id) is 405.
        result = await self._request("GET", f"/syscheck/{agent_id}", params={"q": f"file={file_path}"})
        events = result.get("data", {}).get("affected_items", [])
        quarantined = any(e.get("type") == "deleted" or "quarantine" in str(e) for e in events)
        return {"data": {"agent_id": agent_id, "file_path": file_path, "quarantined": quarantined}}

    # =========================================================================
    # Rollback Tools
    # =========================================================================

    async def unisolate_host(self, agent_id: str) -> Dict[str, Any]:
        """Remove host isolation via active response."""
        data = {"command": "!host-isolation", "agent_list": [agent_id], "arguments": ["undo"]}
        return await self.execute_active_response(data)

    async def enable_user(self, agent_id: str, username: str) -> Dict[str, Any]:
        """Re-enable user account via active response."""
        username = self._sanitize_ar_argument(username, "username")
        data = {"command": "!enable-account", "agent_list": [agent_id], "arguments": [username]}
        return await self.execute_active_response(data)

    async def restore_file(self, agent_id: str, file_path: str) -> Dict[str, Any]:
        """Restore a quarantined file via active response."""
        file_path = self._sanitize_ar_argument(file_path, "file_path")
        data = {"command": "!quarantine", "agent_list": [agent_id], "arguments": ["restore", file_path]}
        return await self.execute_active_response(data)

    @staticmethod
    def _normalize_ar_command(value: Optional[str]) -> Optional[str]:
        """Validate and normalize an operator-supplied active-response command name."""
        if not value or not str(value).strip():
            return None
        command = str(value).strip()
        if not re.match(r"^!?[a-zA-Z0-9_-]{1,64}$", command):
            raise ValueError(f"Invalid active-response command name: {command!r}")
        return command if command.startswith("!") else f"!{command}"

    async def _undo_block(
        self, agent_id: str, src_ip: str, undo_command: Optional[str], block_kind: str
    ) -> Dict[str, Any]:
        """Remove an active-response block using an operator-configured undo command.

        Stock Wazuh has no API path to trigger the stateful 'delete' action — the API
        only sends 'add', and the stock firewall-drop/host-deny scripts decide add vs
        delete from that field, not from extra_args. Re-invoking the block command here
        would silently RE-BLOCK the address. So this requires an operator-deployed undo
        script; without one it raises rather than doing the wrong thing.
        """
        self._validate_ip(src_ip)
        src_ip = self._sanitize_ar_argument(src_ip, "src_ip")
        if not undo_command:
            env_var = "WAZUH_AR_FIREWALL_UNDO_COMMAND" if block_kind == "firewall" else "WAZUH_AR_HOSTDENY_UNDO_COMMAND"
            raise ValueError(
                f"Cannot remove a {block_kind} block through the Wazuh API: stock active-response "
                f"scripts only support the 'add' action via the API, so this would re-block "
                f"{src_ip} instead of removing it. Configure an operator-deployed undo script "
                f"and set {env_var} to its command name, or rely on the manager's "
                f"<active-response><timeout> to expire the block automatically."
            )
        data = {
            "command": undo_command,
            "agent_list": [agent_id],
            "arguments": [f"-srcip {src_ip}"],
            "alert": {"data": {"srcip": src_ip}},
        }
        return await self.execute_active_response(data)

    async def firewall_allow(self, agent_id: str, src_ip: str) -> Dict[str, Any]:
        """Remove a firewall-drop block via an operator-configured undo active response."""
        return await self._undo_block(agent_id, src_ip, self._ar_firewall_undo_command, "firewall")

    async def host_allow(self, agent_id: str, src_ip: str) -> Dict[str, Any]:
        """Remove a hosts.deny block via an operator-configured undo active response."""
        return await self._undo_block(agent_id, src_ip, self._ar_hostdeny_undo_command, "host-deny")

    async def close(self):
        """Close the HTTP client and indexer client, releasing all connections."""
        try:
            if self.client:
                await self.client.aclose()
        except Exception:
            pass  # Best-effort close; connection may already be broken
        finally:
            self.client = None
        try:
            if self._indexer_client:
                await self._indexer_client.close()
        except Exception:
            pass
        self.token = None
        self._cache.clear()
