"""Enhanced Wazuh API client with comprehensive error handling and security features."""

import asyncio
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from urllib.parse import urljoin
import aiohttp

# Clean absolute imports within the package
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.utils import (
    get_logger,
    AuthenticationError,
    AuthorizationError,
    ConnectionError,
    APIError,
    RateLimitError,
    handle_api_error,
    handle_connection_error,
    validate_alert_query,
    validate_agent_query,
    sanitize_string,
    global_rate_limiter,
    RateLimitConfig,
)

# Import additional utilities that may not be available
try:
    from wazuh_mcp_server.utils.logging import log_performance, LogContext
except ImportError:
    # Fallback implementations
    def log_performance(func):
        return func
    
    class LogContext:
        def __init__(self, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

try:
    from wazuh_mcp_server.utils.error_recovery import error_recovery_manager
except ImportError:
    # Fallback error recovery
    class _MinimalErrorRecovery:
        def handle_error(self, error, context=None):
            raise error
        def __call__(self, func):
            return func
    
    error_recovery_manager = _MinimalErrorRecovery()

logger = get_logger(__name__)


class WazuhAPIClient:
    """Production-grade Wazuh API client with comprehensive features."""
    
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.jwt_token: Optional[str] = None
        self.jwt_expiration: Optional[datetime] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.base_url = f"{config.base_url}/{config.api_version}"
        
        # Configure rate limiting
        global_rate_limiter.configure_endpoint(
            "wazuh_auth", 
            RateLimitConfig(max_requests=10, time_window=60)  # 10 auth requests per minute
        )
        global_rate_limiter.configure_endpoint(
            "wazuh_api", 
            RateLimitConfig(max_requests=100, time_window=60)  # 100 API requests per minute
        )
        
        # Performance metrics
        self.request_count = 0
        self.error_count = 0
        self.last_health_check = None
        
        logger.info(f"Initialized Wazuh API client for {config.host}:{config.port}")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._create_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit with proper cleanup."""
        if self.session:
            await self.session.close()
            logger.debug("Wazuh API client session closed")
    
    async def _create_session(self):
        """Create aiohttp session with proper configuration."""
        timeout = aiohttp.ClientTimeout(total=self.config.request_timeout_seconds)
        connector = aiohttp.TCPConnector(
            ssl=self.config.verify_ssl,
            limit=self.config.max_connections,
            limit_per_host=self.config.pool_size,
            keepalive_timeout=60,
            enable_cleanup_closed=True
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "WazuhMCP/2.1.0"}
        )
        
        logger.debug("Created Wazuh API session with optimized settings")
    
    def _is_jwt_valid(self) -> bool:
        """Check if JWT token is valid and not near expiration."""
        if not self.jwt_token or not self.jwt_expiration:
            return False
        
        # Consider token invalid if less than 2 minutes remaining
        remaining = (self.jwt_expiration - datetime.utcnow()).total_seconds()
        return remaining > 120
    
    @log_performance
    async def authenticate(self, force_refresh: bool = False) -> str:
        """Authenticate with Wazuh API and get JWT token with error recovery."""
        if not force_refresh and self._is_jwt_valid():
            return self.jwt_token
        
        async def _do_authenticate() -> str:
            # Rate limit authentication attempts
            await global_rate_limiter.enforce_rate_limit("wazuh_auth")
            
            auth_url = urljoin(self.base_url, "/security/user/authenticate")
            auth = aiohttp.BasicAuth(self.config.username, self.config.password)
            
            request_id = f"auth_{int(time.time())}"
            
            with LogContext(request_id, user_id=self.config.username):
                logger.info("Authenticating with Wazuh API", extra={
                    "details": {"url": auth_url, "username": self.config.username}
                })
                
                async with self.session.get(auth_url, auth=auth) as response:
                    if response.status != 200:
                        response_data = None
                        try:
                            response_data = await response.json()
                        except (aiohttp.ClientError, json.JSONDecodeError, ValueError) as e:
                            logger.warning(f"Failed to parse JSON response: {e}")
                            response_data = {"error": "Invalid response format"}
                        handle_api_error(response.status, response_data)
                    
                    data = await response.json()
                    token = data.get("data", {}).get("token")
                    
                    if not token:
                        raise AuthenticationError("JWT token not found in response")
                    
                    self.jwt_token = token
                    # Set expiration to 14 minutes (Wazuh default is 15 minutes)
                    self.jwt_expiration = datetime.utcnow() + timedelta(minutes=14)
                    
                    logger.info("Successfully authenticated with Wazuh API", extra={
                        "details": {"expires_at": self.jwt_expiration.isoformat()}
                    })
                    
                    return self.jwt_token
        
        try:
            return await _do_authenticate()
        except aiohttp.ClientError as e:
            handle_connection_error(e, urljoin(self.base_url, "/security/user/authenticate"))
        except Exception as e:
            # Use error recovery for authentication failures
            recovery_result = await error_recovery_manager.handle_error(
                e,
                "wazuh_authentication",
                retry_func=_do_authenticate,
                context={"username": self.config.username, "force_refresh": force_refresh}
            )
            
            if recovery_result.get("success"):
                token = recovery_result.get("data")
                if token:
                    return token
            
            logger.error(f"Authentication failed after recovery attempts: {str(e)}")
            raise AuthenticationError(f"Authentication failed: {str(e)}")
    
    async def _make_request_internal(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        retry_auth: bool = True
    ) -> Dict[str, Any]:
        """Internal method to make authenticated API request."""
        # Rate limit API requests
        await global_rate_limiter.enforce_rate_limit("wazuh_api")
        
        token = await self.authenticate()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        url = urljoin(self.base_url, endpoint)
        request_id = f"req_{int(time.time() * 1000)}"
        
        with LogContext(request_id):
            logger.debug(f"Making {method} request to {endpoint}", extra={
                "details": {"params": params, "endpoint": endpoint}
            })
            
            kwargs = {"headers": headers}
            if params:
                kwargs["params"] = params
            if data:
                kwargs["json"] = data
            
            async with self.session.request(method, url, **kwargs) as response:
                self.request_count += 1
                
                # Handle authentication retry
                if response.status == 401 and retry_auth:
                    logger.info("Token expired, re-authenticating...")
                    token = await self.authenticate(force_refresh=True)
                    headers["Authorization"] = f"Bearer {token}"
                    kwargs["headers"] = headers
                    
                    async with self.session.request(method, url, **kwargs) as retry_response:
                        if retry_response.status != 200:
                            response_data = None
                            try:
                                response_data = await retry_response.json()
                            except (ValueError, TypeError, aiohttp.ContentTypeError):
                                # JSON parsing failed, continue with None response_data
                                pass
                            handle_api_error(retry_response.status, response_data)
                        
                        result = await retry_response.json()
                        logger.debug(f"Request completed successfully after auth retry")
                        return result
                
                if response.status != 200:
                    response_data = None
                    try:
                        response_data = await response.json()
                    except (aiohttp.ClientError, json.JSONDecodeError, ValueError) as e:
                        logger.warning(f"Failed to parse JSON response: {e}")
                        response_data = {"error": "Invalid response format"}
                    handle_api_error(response.status, response_data)
                
                result = await response.json()
                logger.debug(f"Request completed successfully")
                return result
    
    async def _request(
        self, 
        method: str, 
        endpoint: str, 
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        retry_auth: bool = True
    ) -> Dict[str, Any]:
        """Make authenticated API request with comprehensive error handling and recovery."""
        
        try:
            return await self._make_request_internal(method, endpoint, params, data, retry_auth)
        except aiohttp.ClientError as e:
            self.error_count += 1
            handle_connection_error(e, urljoin(self.base_url, endpoint))
        except (json.JSONDecodeError, asyncio.TimeoutError, AuthenticationError, 
                AuthorizationError, APIError, RateLimitError) as e:
            self.error_count += 1
            logger.error(f"API error ({type(e).__name__}): {str(e)}")
            
            # Use error recovery manager for intelligent recovery
            recovery_result = await error_recovery_manager.handle_error(
                e,
                f"wazuh_server_{method.lower()}",
                retry_func=lambda: self._make_request_internal(method, endpoint, params, data, retry_auth=False),
                context={"endpoint": endpoint, "method": method, "params": params}
            )
            
            if recovery_result.get("success"):
                return recovery_result.get("data")
            else:
                raise APIError(f"API request failed ({type(e).__name__}): {str(e)}")
        except Exception as e:
            # Log unexpected exceptions but allow them to bubble up for proper debugging
            self.error_count += 1
            logger.error(f"Unexpected error in API request: {type(e).__name__}: {str(e)}")
            raise
    
    @log_performance
    async def get_alerts(
        self, 
        limit: int = 100, 
        offset: int = 0,
        level: Optional[int] = None, 
        sort: str = "-timestamp",
        time_range: Optional[int] = None,
        agent_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get alerts from Wazuh with validation and filtering."""
        
        # Validate parameters
        query_params = {
            "limit": min(limit, self.config.max_alerts_per_query),
            "offset": offset,
            "sort": sort
        }
        
        # Validate using Pydantic model
        validated_query = validate_alert_query(query_params)
        
        params = {
            "limit": validated_query.limit,
            "offset": validated_query.offset,
            "sort": validated_query.sort
        }
        
        if level is not None:
            params["level"] = level
        
        if time_range:
            # Add time range filter (last X seconds)
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(seconds=time_range)
            params["timestamp"] = f"{start_time.isoformat()}Z..{end_time.isoformat()}Z"
        
        if agent_id:
            # Sanitize agent ID
            params["agent.id"] = sanitize_string(agent_id, 20)
        
        logger.info(f"Fetching alerts", extra={
            "details": {"limit": params["limit"], "level": level, "agent_id": agent_id}
        })
        
        return await self._request("GET", "/alerts", params=params)
    
    @log_performance
    async def get_agents(
        self, 
        status: Optional[str] = None,
        os_platform: Optional[str] = None,
        limit: int = 500
    ) -> Dict[str, Any]:
        """Get agent information with filtering."""
        
        params = {"limit": min(limit, 1000)}
        
        if status:
            # Validate status
            valid_statuses = ["active", "disconnected", "never_connected", "pending"]
            if status in valid_statuses:
                params["status"] = status
            else:
                raise ValueError(f"Invalid status. Must be one of: {valid_statuses}")
        
        if os_platform:
            params["os.platform"] = sanitize_string(os_platform, 50)
        
        logger.info(f"Fetching agents", extra={
            "details": {"status": status, "os_platform": os_platform, "limit": limit}
        })
        
        return await self._request("GET", "/agents", params=params)
    
    @log_performance
    async def get_agent_vulnerabilities(self, agent_id: str) -> Dict[str, Any]:
        """Get vulnerabilities for a specific agent (deprecated in 4.8.0+)."""
        
        # Sanitize and validate agent ID
        clean_agent_id = sanitize_string(agent_id, 20)
        if not clean_agent_id:
            raise ValueError("Invalid agent ID")
        
        logger.warning(f"Using deprecated vulnerability endpoint for agent {clean_agent_id} - consider upgrading to Wazuh 4.8.0+ and using Indexer API")
        
        return await self._request("GET", f"/vulnerability/{clean_agent_id}")
    
    @log_performance
    async def get_rules(self, rule_id: Optional[str] = None, limit: int = 100) -> Dict[str, Any]:
        """Get Wazuh rules."""
        
        params = {"limit": min(limit, 1000)}
        
        if rule_id:
            params["rule_ids"] = sanitize_string(rule_id, 20)
        
        logger.info(f"Fetching rules", extra={"details": {"rule_id": rule_id, "limit": limit}})
        
        return await self._request("GET", "/rules", params=params)
    
    @log_performance
    async def get_decoders(self, limit: int = 100) -> Dict[str, Any]:
        """Get Wazuh decoders."""
        
        params = {"limit": min(limit, 1000)}
        
        logger.info(f"Fetching decoders", extra={"details": {"limit": limit}})
        
        return await self._request("GET", "/decoders", params=params)
    
    @log_performance
    async def get_agent_stats(self, agent_id: str) -> Dict[str, Any]:
        """Get statistics for a specific agent."""
        
        clean_agent_id = sanitize_string(agent_id, 20)
        if not clean_agent_id:
            raise ValueError("Invalid agent ID")
        
        logger.info(f"Fetching stats for agent {clean_agent_id}")
        
        return await self._request("GET", f"/agents/{clean_agent_id}/stats/logcollector")

    @log_performance
    async def get_agent_processes(self, agent_id: str) -> Dict[str, Any]:
        """Get running processes for a specific agent."""
        
        clean_agent_id = sanitize_string(agent_id, 20)
        if not clean_agent_id:
            raise ValueError("Invalid agent ID")
        
        logger.info(f"Fetching processes for agent {clean_agent_id}")
        
        return await self._request("GET", f"/syscollector/{clean_agent_id}/processes")

    @log_performance
    async def get_agent_ports(self, agent_id: str) -> Dict[str, Any]:
        """Get open ports for a specific agent."""
        
        clean_agent_id = sanitize_string(agent_id, 20)
        if not clean_agent_id:
            raise ValueError("Invalid agent ID")
        
        logger.info(f"Fetching ports for agent {clean_agent_id}")
        
        return await self._request("GET", f"/syscollector/{clean_agent_id}/ports")

    @log_performance
    async def get_wazuh_stats(self, component: str, stat_type: str, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Get statistics from Wazuh."""
        if component == "manager":
            endpoint = f"/manager/stats/{stat_type}"
            logger.info(f"Fetching manager stats for {stat_type}")
        elif component == "agent":
            if not agent_id:
                raise ValueError("agent_id is required for agent stats")
            clean_agent_id = sanitize_string(agent_id, 20)
            if not clean_agent_id:
                raise ValueError("Invalid agent ID")
            endpoint = f"/agents/{clean_agent_id}/stats/{stat_type}"
            logger.info(f"Fetching agent stats for {stat_type} on agent {clean_agent_id}")
        else:
            raise ValueError(f"Invalid component: {component}")

        return await self._request("GET", endpoint)

    @log_performance
    async def search_wazuh_logs(self, log_source: str, query: str, limit: int = 100, agent_id: Optional[str] = None) -> Dict[str, Any]:
        """Search Wazuh logs."""
        params = {"limit": limit, "q": query}
        if log_source == "manager":
            endpoint = "/manager/logs"
            logger.info(f"Searching manager logs for '{query}'")
        elif log_source == "agent":
            if not agent_id:
                raise ValueError("agent_id is required for agent logs")
            clean_agent_id = sanitize_string(agent_id, 20)
            if not clean_agent_id:
                raise ValueError("Invalid agent ID")
            endpoint = f"/agents/{clean_agent_id}/logs"
            logger.info(f"Searching agent logs for '{query}' on agent {clean_agent_id}")
        else:
            raise ValueError(f"Invalid log_source: {log_source}")

        return await self._request("GET", endpoint, params=params)
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check of Wazuh API and client with error recovery."""
        async def _do_health_check() -> Dict[str, Any]:
            # Basic connectivity test
            result = await self._request("GET", "/")
            
            # Calculate error rate
            error_rate = (self.error_count / max(self.request_count, 1)) * 100
            
            health_data = {
                "status": "healthy",
                "wazuh_version": result.get("data", {}).get("title", "unknown"),
                "api_version": result.get("data", {}).get("api_version", "unknown"),
                "client_stats": {
                    "total_requests": self.request_count,
                    "error_count": self.error_count,
                    "error_rate_percentage": round(error_rate, 2),
                    "token_valid": self._is_jwt_valid()
                },
                "last_check": datetime.utcnow().isoformat()
            }
            
            self.last_health_check = datetime.utcnow()
            logger.info("Health check passed", extra={"details": health_data})
            return health_data
        
        try:
            return await _do_health_check()
        except Exception as e:
            # Use error recovery for health checks
            recovery_result = await error_recovery_manager.handle_error(
                e,
                "wazuh_health_check",
                retry_func=_do_health_check,
                context={"host": self.config.host, "port": self.config.port}
            )
            
            if recovery_result.get("success"):
                return recovery_result.get("data")
            
            # Fallback to degraded health status
            health_data = {
                "status": "unhealthy",
                "error": str(e),
                "client_stats": {
                    "total_requests": self.request_count,
                    "error_count": self.error_count
                },
                "last_check": datetime.utcnow().isoformat(),
                "recovery_attempted": True
            }
            
            logger.error("Health check failed after recovery attempts", extra={"details": health_data})
            return health_data
    
    async def get_cluster_info(self) -> Dict[str, Any]:
        """Get Wazuh cluster information."""
        logger.info("Fetching cluster information")
        return await self._request("GET", "/cluster/status")

    async def get_cluster_nodes(self) -> Dict[str, Any]:
        """Get Wazuh cluster nodes information."""
        logger.info("Fetching cluster nodes information")
        return await self._request("GET", "/cluster/nodes")
    
    async def restart_agent(self, agent_id: str) -> Dict[str, Any]:
        """Restart a specific agent."""
        clean_agent_id = sanitize_string(agent_id, 20)
        if not clean_agent_id:
            raise ValueError("Invalid agent ID")
        
        logger.warning(f"Restarting agent {clean_agent_id}")
        return await self._request("PUT", f"/agents/{clean_agent_id}/restart")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get client performance metrics."""
        return {
            "total_requests": self.request_count,
            "error_count": self.error_count,
            "error_rate": (self.error_count / max(self.request_count, 1)) * 100,
            "token_valid": self._is_jwt_valid(),
            "token_expires": self.jwt_expiration.isoformat() if self.jwt_expiration else None,
            "last_health_check": self.last_health_check.isoformat() if self.last_health_check else None
        }