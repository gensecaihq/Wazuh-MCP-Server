#!/usr/bin/env python3
"""
Wazuh MCP Server - Production-Ready Security Operations Platform

A FastMCP-powered server providing AI-enhanced security operations with Wazuh SIEM integration.
Features comprehensive error handling, monitoring, authentication, and performance optimization.
"""

import os
import sys
import asyncio
import json
import logging
import signal
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
import time
import traceback
from contextlib import asynccontextmanager

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Check Python version before any imports
if sys.version_info < (3, 10):
    print(f"ERROR: FastMCP requires Python 3.10+. Current: {sys.version}")
    sys.exit(1)

# Import dependencies with proper error handling
try:
    from fastmcp import FastMCP, Context
    import httpx
    from dateutil.parser import isoparse
    from dotenv import load_dotenv
except ImportError as e:
    print(f"CRITICAL ERROR: Missing required dependency: {e}")
    print("Please install: pip install fastmcp>=2.10.6 httpx>=0.27.0 python-dateutil>=2.8.2 python-dotenv>=0.19.0")
    sys.exit(1)

# Load environment variables
load_dotenv()

# Import local modules
from wazuh_mcp_server.config import WazuhConfig, ConfigurationError
from wazuh_mcp_server.__version__ import __version__
from wazuh_mcp_server.utils.logging import setup_logging, get_logger, LogContext, log_performance, sanitize_log_data
from wazuh_mcp_server.utils.exceptions import WazuhMCPError, APIError, ValidationError
from wazuh_mcp_server.utils.rate_limiter import RateLimiter
from wazuh_mcp_server.utils.validation import validate_int_range, validate_string, validate_time_range
from wazuh_mcp_server.tools.factory import ToolFactory

# Initialize logging
logger = get_logger(__name__)

# Global server state
_config: Optional[WazuhConfig] = None
_http_client: Optional[httpx.AsyncClient] = None
_rate_limiter: Optional[RateLimiter] = None
_server_start_time: Optional[datetime] = None
_health_status: Dict[str, Any] = {"status": "starting", "checks": {}}
_tool_factory = None

# Create FastMCP server instance
mcp = FastMCP("Wazuh MCP Server")

# Performance metrics
_metrics = {
    "requests_total": 0,
    "requests_failed": 0,
    "avg_response_time": 0,
    "last_error": None,
    "uptime_start": None
}


class ServerError(Exception):
    """Base exception for server-level errors."""
    pass


def get_config() -> WazuhConfig:
    """Get global configuration, loading if necessary."""
    global _config
    if _config is None:
        try:
            _config = WazuhConfig.from_env()
            logger.info("Configuration loaded successfully")
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e}")
            raise ServerError(f"Configuration validation failed: {e}")
    return _config


async def get_http_client() -> httpx.AsyncClient:
    """Get or create HTTP client with optimal configuration."""
    global _http_client
    
    if _http_client is None:
        config = get_config()
        
        # Production-grade HTTP client configuration
        timeout = httpx.Timeout(
            connect=10.0,
            read=config.request_timeout_seconds,
            write=10.0,
            pool=30.0
        )
        
        limits = httpx.Limits(
            max_keepalive_connections=min(config.max_connections, 20),  # Cap at 20
            max_connections=min(config.max_connections * 2, 50),  # Cap at 50
            keepalive_expiry=30
        )
        
        _http_client = httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            verify=config.verify_ssl,
            follow_redirects=True,
            http2=True  # Enable HTTP/2 for better performance
        )
        
        logger.info("HTTP client initialized with production settings")
    
    return _http_client


async def get_rate_limiter() -> RateLimiter:
    """Get or create rate limiter with production-ready configuration."""
    global _rate_limiter
    
    if _rate_limiter is None:
        config = get_config()
        _rate_limiter = RateLimiter(
            max_requests=60,   # Reduced for better protection
            window_seconds=60,  # 1 minute window
            burst_size=10,     # Smaller burst to prevent abuse
            enable_per_ip=True,  # Enable per-IP rate limiting
            enable_per_user=True  # Enable per-user rate limiting
        )
        logger.info("Rate limiter initialized with per-IP and per-user limits")
    
    return _rate_limiter


async def wazuh_api_request(
    endpoint: str, 
    method: str = 'GET', 
    params: Optional[Dict] = None,
    data: Optional[Dict] = None,
    ctx: Optional[Context] = None
) -> Dict[str, Any]:
    """Make authenticated request to Wazuh API with comprehensive error handling."""
    config = get_config()
    client = await get_http_client()
    rate_limiter = await get_rate_limiter()
    
    # Apply rate limiting
    if not await rate_limiter.acquire():
        # Rate limit exceeded, wait for reset
        reset_time = await rate_limiter.time_until_reset()
        if ctx:
            await ctx.warning(f"Rate limit exceeded, waiting {reset_time:.1f}s")
        await asyncio.sleep(min(reset_time, 5.0))  # Cap wait time at 5 seconds
    
    url = f"{config.base_url}{endpoint}"
    auth = (config.username, config.password)
    
    start_time = time.time()
    
    # Retry logic with exponential backoff
    last_error = None
    for attempt in range(3):  # Max 3 attempts
        try:
            if ctx:
                await ctx.info(f"API request: {method} {endpoint} (attempt {attempt + 1})")
            
            request_kwargs = {
                'auth': auth,
                'params': params or {},
                'headers': {
                    'Content-Type': 'application/json',
                    'User-Agent': f'Wazuh-MCP-Server/{__version__}'
                }
            }
            
            if data:
                request_kwargs['json'] = data
            
            response = await client.request(method, url, **request_kwargs)
            
            # Handle different response status codes
            if response.status_code == 200:
                result = response.json()
                
                # Update metrics
                duration = time.time() - start_time
                _metrics["requests_total"] += 1
                _metrics["avg_response_time"] = (
                    (_metrics["avg_response_time"] * (_metrics["requests_total"] - 1) + duration) / 
                    _metrics["requests_total"]
                )
                
                if ctx:
                    await ctx.info(f"API request successful ({duration:.3f}s)")
                
                return result
            
            elif response.status_code == 401:
                raise APIError("Authentication failed - check credentials")
            elif response.status_code == 403:
                raise APIError("Access denied - insufficient permissions")
            elif response.status_code == 404:
                raise APIError(f"Endpoint not found: {endpoint}")
            elif response.status_code >= 500:
                raise APIError(f"Server error: {response.status_code}")
            else:
                raise APIError(f"Unexpected response: {response.status_code}")
                
        except httpx.RequestError as e:
            last_error = APIError(f"Network error: {str(e)}")
            logger.warning(f"Network error on attempt {attempt + 1}: {e}")
        except httpx.HTTPStatusError as e:
            last_error = APIError(f"HTTP error: {e.response.status_code}")
            logger.warning(f"HTTP error on attempt {attempt + 1}: {e}")
        except Exception as e:
            last_error = APIError(f"Unexpected error: {str(e)}")
            logger.error(f"Unexpected error on attempt {attempt + 1}: {e}")
        
        # Exponential backoff
        if attempt < 2:  # Don't wait after last attempt
            wait_time = (2 ** attempt) + (time.time() % 1)  # Add jitter
            await asyncio.sleep(wait_time)
    
    # Update failure metrics
    _metrics["requests_failed"] += 1
    _metrics["last_error"] = str(last_error)
    
    if ctx:
        await ctx.error(f"API request failed after 3 attempts: {last_error}")
    
    raise last_error


# ============================================================================
# HEALTH AND MONITORING
# ============================================================================

@mcp.tool
async def get_server_health(ctx: Context = None) -> Dict[str, Any]:
    """Get comprehensive server health status and metrics."""
    await ctx.info("Checking server health")
    
    try:
        global _health_status, _metrics, _server_start_time
        
        # Update health checks
        health_checks = {}
        
        # Configuration check
        try:
            config = get_config()
            health_checks["configuration"] = {"status": "healthy", "details": "Configuration loaded"}
        except Exception as e:
            health_checks["configuration"] = {"status": "unhealthy", "details": str(e)}
        
        # HTTP client check
        try:
            client = await get_http_client()
            health_checks["http_client"] = {"status": "healthy", "details": "HTTP client ready"}
        except Exception as e:
            health_checks["http_client"] = {"status": "unhealthy", "details": str(e)}
        
        # Wazuh API connectivity check with timeout
        try:
            # Use asyncio.wait_for for compatibility
            test_response = await asyncio.wait_for(
                wazuh_api_request('/agents', params={'limit': 1}, ctx=ctx),
                timeout=5.0
            )
            if test_response.get('data'):
                health_checks["wazuh_api"] = {"status": "healthy", "details": "API connection and functionality verified"}
            else:
                health_checks["wazuh_api"] = {"status": "degraded", "details": "API connected but returned no data"}
        except asyncio.TimeoutError:
            health_checks["wazuh_api"] = {"status": "unhealthy", "details": "API connection timeout"}
        except Exception as e:
            health_checks["wazuh_api"] = {"status": "unhealthy", "details": str(e)}
        
        # Overall status
        all_healthy = all(check["status"] == "healthy" for check in health_checks.values())
        overall_status = "healthy" if all_healthy else "degraded"
        
        # Calculate uptime
        uptime_seconds = 0
        if _server_start_time:
            uptime_seconds = (datetime.now() - _server_start_time).total_seconds()
        
        health_data = {
            "status": overall_status,
            "timestamp": datetime.now().isoformat(),
            "uptime_seconds": uptime_seconds,
            "version": __version__,
            "checks": health_checks,
            "metrics": {
                "requests_total": _metrics["requests_total"],
                "requests_failed": _metrics["requests_failed"],
                "success_rate": (
                    ((_metrics["requests_total"] - _metrics["requests_failed"]) / _metrics["requests_total"]) * 100
                    if _metrics["requests_total"] > 0 else 100
                ),
                "avg_response_time_ms": round(_metrics["avg_response_time"] * 1000, 2),
                "last_error": _metrics["last_error"]
            }
        }
        
        _health_status = health_data
        await ctx.info(f"Health check completed - status: {overall_status}")
        
        return health_data
        
    except Exception as e:
        await ctx.error(f"Health check failed: {str(e)}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }


# ============================================================================
# ALERT TOOLS
# ============================================================================

@mcp.tool
@log_performance
async def get_wazuh_alerts(
    limit: int = 100,
    level: Optional[int] = None,
    time_range: Optional[int] = None,
    agent_id: str = "",
    ctx: Context = None
) -> Dict[str, Any]:
    """Retrieve Wazuh alerts with advanced filtering and enrichment.
    
    Args:
        limit: Maximum number of alerts to retrieve (1-10000)
        level: Minimum alert level (1-15)
        time_range: Time range in seconds (300-86400)
        agent_id: Filter alerts by specific agent ID
        
    Returns:
        Dictionary containing enriched alerts and metadata
    """
    with LogContext(f"alerts-{int(time.time())}", user_id="mcp-client"):
        await ctx.info(f"Retrieving alerts - limit: {limit}, level: {level}, agent: {agent_id or 'all'}")
        
        try:
            # Validate and sanitize inputs
            limit = validate_int_range(limit, 1, 10000, 100)
            level = validate_int_range(level, 1, 15, None) if level else None
            time_range = validate_int_range(time_range, 300, 86400, None) if time_range else None
            agent_id = validate_string(agent_id, 50, "")
            
            # Build API parameters
            params = {'limit': limit, 'sort': '-timestamp'}
            if level:
                params['rule.level'] = f">={level}"
            if time_range:
                # Calculate timestamp for time range
                cutoff_time = datetime.now() - timedelta(seconds=time_range)
                params['timestamp'] = f">={cutoff_time.isoformat()}"
            if agent_id:
                params['agent.id'] = agent_id
            
            # Make API request
            response = await wazuh_api_request('/alerts', params=params, ctx=ctx)
            alerts = response.get('data', {}).get('affected_items', [])
            
            # Enrich alerts with additional context
            enriched_alerts = []
            for alert in alerts:
                try:
                    rule_level = alert.get('rule', {}).get('level', 0)
                    rule_groups = alert.get('rule', {}).get('groups', [])
                    
                    # Calculate risk score
                    risk_score = min(rule_level * 10, 100)
                    if agent_id and any('critical' in str(g).lower() for g in rule_groups):
                        risk_score = min(risk_score * 1.5, 100)
                    
                    # Determine severity
                    severity = (
                        'critical' if rule_level >= 12 else
                        'high' if rule_level >= 8 else
                        'medium' if rule_level >= 4 else 'low'
                    )
                    
                    # Categorize alert
                    category = 'general'
                    if rule_groups:
                        groups_str = ' '.join(str(g).lower() for g in rule_groups)
                        if 'authentication' in groups_str:
                            category = 'authentication'
                        elif 'intrusion' in groups_str:
                            category = 'intrusion'
                        elif 'malware' in groups_str:
                            category = 'malware'
                        elif 'compliance' in groups_str:
                            category = 'compliance'
                    
                    enriched_alert = {
                        **alert,
                        'enrichment': {
                            'risk_score': int(risk_score),
                            'severity_label': severity,
                            'category': category,
                            'is_high_priority': rule_level >= 8,
                            'requires_investigation': rule_level >= 10
                        }
                    }
                    enriched_alerts.append(enriched_alert)
                    
                except Exception as e:
                    logger.warning(f"Alert enrichment failed: {e}")
                    enriched_alerts.append(alert)
            
            await ctx.info(f"Successfully retrieved {len(enriched_alerts)} enriched alerts")
            
            return {
                'success': True,
                'alerts': enriched_alerts,
                'total_count': len(enriched_alerts),
                'query_params': {
                    'limit': limit,
                    'level': level,
                    'time_range': time_range,
                    'agent_id': agent_id
                },
                'metadata': {
                    'timestamp': datetime.now().isoformat(),
                    'source': 'wazuh_api',
                    'enrichment_enabled': True,
                    'server_version': __version__
                }
            }
            
        except Exception as e:
            await ctx.error(f"Alert retrieval failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }


@mcp.tool
@log_performance
async def analyze_security_threats(
    time_range: str = "24h",
    focus_area: str = "all",
    min_severity: int = 5,
    ctx: Context = None
) -> Dict[str, Any]:
    """AI-powered threat analysis with comprehensive insights and recommendations.
    
    Args:
        time_range: Time range to analyze (1h, 6h, 24h, 7d, 30d)
        focus_area: Analysis focus (network, file, process, authentication, all)
        min_severity: Minimum severity level to include (1-15)
        
    Returns:
        Comprehensive threat analysis with AI insights and recommendations
    """
    await ctx.info(f"Starting AI threat analysis for {time_range}, focus: {focus_area}")
    
    try:
        # Convert time range to seconds
        time_seconds = validate_time_range(time_range)
        focus_area = validate_string(focus_area, 50, "all")
        min_severity = validate_int_range(min_severity, 1, 15, 5)
        
        # Get alerts for analysis
        params = {
            'limit': 500,
            'sort': '-timestamp',
            'rule.level': f">={min_severity}"
        }
        
        # Add time range filter
        cutoff_time = datetime.now() - timedelta(seconds=time_seconds)
        params['timestamp'] = f">={cutoff_time.isoformat()}"
        
        response = await wazuh_api_request('/alerts', params=params, ctx=ctx)
        alerts = response.get('data', {}).get('affected_items', [])
        
        if not alerts:
            return {
                'success': True,
                'analysis': 'No threats detected in the specified time range',
                'threat_level': 'LOW',
                'recommendations': ['Continue monitoring', 'Review detection rules'],
                'metadata': {'alert_count': 0, 'time_range': time_range}
            }
        
        # Prepare analysis data with efficient processing
        alert_summary = []
        threat_indicators = {
            'high_severity_count': 0,
            'unique_rules': set(),
            'affected_agents': set(),
            'attack_patterns': [],
            'time_distribution': defaultdict(int)
        }
        
        # Process alerts in chunks for better memory efficiency
        chunk_size = 50
        max_alerts_to_process = min(100, len(alerts))  # Limit for performance
        
        for i in range(0, max_alerts_to_process, chunk_size):
            chunk = alerts[i:i + chunk_size]
            for alert in chunk:
                try:
                    rule = alert.get('rule', {})
                    rule_level = rule.get('level', 0)
                    rule_id = rule.get('id', '')
                    agent_info = alert.get('agent', {})
                    timestamp = alert.get('timestamp', '')
                    
                    # Collect summary info
                    alert_summary.append({
                        'rule_description': rule.get('description', '')[:200],
                        'level': rule_level,
                        'agent_name': agent_info.get('name', '')[:50],
                        'timestamp': timestamp,
                        'location': alert.get('location', '')[:100]
                    })
                    
                    # Update threat indicators
                    if rule_level >= 8:
                        threat_indicators['high_severity_count'] += 1
                    
                    threat_indicators['unique_rules'].add(rule_id)
                    threat_indicators['affected_agents'].add(agent_info.get('id', ''))
                    
                    # Time distribution (by hour)
                    try:
                        dt = isoparse(timestamp)
                        hour_key = dt.strftime('%H:00')
                        threat_indicators['time_distribution'][hour_key] += 1
                    except Exception:
                        pass
                        
                except Exception as e:
                    logger.warning(f"Error processing alert for analysis: {e}")
                    continue
        
        # Calculate threat level
        high_severity_ratio = threat_indicators['high_severity_count'] / len(alerts)
        unique_rules_count = len(threat_indicators['unique_rules'])
        affected_agents_count = len(threat_indicators['affected_agents'])
        
        if high_severity_ratio > 0.3 or unique_rules_count > 20:
            threat_level = 'CRITICAL'
        elif high_severity_ratio > 0.15 or unique_rules_count > 10:
            threat_level = 'HIGH'
        elif high_severity_ratio > 0.05 or unique_rules_count > 5:
            threat_level = 'MEDIUM'
        else:
            threat_level = 'LOW'
        
        # AI Analysis using FastMCP's built-in sampling
        analysis_prompt = f"""
        Analyze these Wazuh security events for threats and provide actionable insights:
        
        **Analysis Context:**
        - Time Range: {time_range}
        - Focus Area: {focus_area}
        - Total Alerts: {len(alerts)}
        - High Severity Alerts: {threat_indicators['high_severity_count']}
        - Unique Rules Triggered: {unique_rules_count}
        - Affected Agents: {affected_agents_count}
        - Calculated Threat Level: {threat_level}
        
        **Sample Alert Data:** {alert_summary[:20]}
        
        **Time Distribution:** {dict(threat_indicators['time_distribution'])}
        
        Provide analysis in JSON format:
        {{
            "executive_summary": "Brief overall assessment",
            "key_findings": ["finding1", "finding2", "finding3"],
            "attack_patterns": ["pattern1", "pattern2"],
            "affected_systems": ["system1", "system2"],
            "immediate_actions": ["action1", "action2"],
            "strategic_recommendations": ["rec1", "rec2"],
            "urgency_level": "LOW|MEDIUM|HIGH|IMMEDIATE",
            "confidence_score": 0.85
        }}
        
        Focus on actionable, specific recommendations based on the security data.
        """
        
        try:
            # Use asyncio wait_for for timeout with better compatibility
            analysis_result = await asyncio.wait_for(
                ctx.sample(
                    analysis_prompt,
                    model="claude-3-sonnet-20240229",
                    max_tokens=1500,
                    temperature=0.3
                ),
                timeout=30.0  # 30 second timeout
            )
            
            # Parse AI response safely
            try:
                import json
                ai_analysis = json.loads(analysis_result.content)
            except json.JSONDecodeError:
                # If response isn't valid JSON, create structured response
                ai_analysis = {
                    "executive_summary": analysis_result.content[:500],
                    "key_findings": [
                        f"{len(alerts)} security events analyzed",
                        f"{threat_indicators['high_severity_count']} high-severity alerts",
                        f"{unique_rules_count} unique rules triggered"
                    ],
                    "immediate_actions": ["Review high-severity alerts", "Check affected systems"],
                    "urgency_level": threat_level,
                    "confidence_score": 0.7
                }
                    
        except asyncio.TimeoutError:
            await ctx.error("AI analysis timed out after 30 seconds")
            ai_analysis = {
                "executive_summary": f"Analysis completed with {threat_level} threat level detected",
                "key_findings": [
                    f"{len(alerts)} security events analyzed",
                    f"{threat_indicators['high_severity_count']} high-severity alerts",
                    f"{unique_rules_count} unique rules triggered"
                ],
                "immediate_actions": ["Review high-severity alerts", "Check affected systems"],
                "urgency_level": threat_level,
                "error": "AI analysis timed out"
            }
        except Exception as e:
            await ctx.error(f"AI analysis failed: {e}")
            ai_analysis = {
                "executive_summary": f"Analysis completed with {threat_level} threat level detected",
                "key_findings": [
                    f"{len(alerts)} security events analyzed",
                    f"{threat_indicators['high_severity_count']} high-severity alerts",
                    f"{unique_rules_count} unique rules triggered"
                ],
                "immediate_actions": ["Review high-severity alerts", "Check affected systems"],
                "urgency_level": threat_level,
                "error": f"AI analysis unavailable: {str(e)}"
            }
        
        await ctx.info("AI threat analysis completed successfully")
        
        return {
            'success': True,
            'threat_level': threat_level,
            'ai_analysis': ai_analysis,
            'statistical_summary': {
                'total_alerts': len(alerts),
                'high_severity_alerts': threat_indicators['high_severity_count'],
                'unique_rules': unique_rules_count,
                'affected_agents': affected_agents_count,
                'time_distribution': dict(threat_indicators['time_distribution'])
            },
            'raw_data': {
                'time_range': time_range,
                'focus_area': focus_area,
                'min_severity': min_severity
            },
            'metadata': {
                'analysis_timestamp': datetime.now().isoformat(),
                'model_used': 'claude-3-sonnet-20240229',
                'server_version': __version__
            }
        }
        
    except Exception as e:
        await ctx.error(f"Threat analysis failed: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


# ============================================================================
# AGENT TOOLS
# ============================================================================

@mcp.tool
@log_performance
async def check_wazuh_agent_health(
    agent_id: str = "",
    include_disconnected: bool = True,
    health_threshold: float = 0.0,
    ctx: Context = None
) -> Dict[str, Any]:
    """Check health status of Wazuh agents with comprehensive diagnostics.
    
    Args:
        agent_id: Specific agent ID to check (empty for all agents)
        include_disconnected: Include offline/disconnected agents
        health_threshold: Health score threshold (0-100) for filtering
        
    Returns:
        Comprehensive agent health report with recommendations
    """
    await ctx.info(f"Checking agent health - ID: {agent_id or 'all'}, threshold: {health_threshold}")
    
    try:
        # Validate inputs
        agent_id = validate_string(agent_id, 20, "")
        health_threshold = max(0.0, min(100.0, float(health_threshold or 0)))
        
        # Build API parameters
        params = {'sort': '+id'}
        if agent_id:
            params['agents_list'] = agent_id
        
        # Get agents data
        response = await wazuh_api_request('/agents', params=params, ctx=ctx)
        agents = response.get('data', {}).get('affected_items', [])
        
        if agent_id and not agents:
            return {
                'success': False,
                'error': f'Agent {agent_id} not found',
                'agent_id': agent_id
            }
        
        # Process agents and calculate health
        status_summary = {
            'active': [],
            'disconnected': [],
            'never_connected': [],
            'pending': []
        }
        
        total_health_score = 0
        processed_agents = 0
        
        for agent in agents:
            try:
                status = agent.get('status', 'unknown').lower()
                
                # Skip disconnected if not requested
                if not include_disconnected and status != 'active':
                    continue
                
                # Calculate comprehensive health score
                health_score = calculate_agent_health_score(agent)
                
                # Apply threshold filter
                if health_score < health_threshold:
                    continue
                
                # Get additional agent info
                agent_info = {
                    'id': agent.get('id'),
                    'name': agent.get('name'),
                    'ip': agent.get('ip'),
                    'status': status,
                    'last_keep_alive': agent.get('lastKeepAlive'),
                    'version': agent.get('version'),
                    'os_name': agent.get('os', {}).get('name', 'Unknown'),
                    'os_version': agent.get('os', {}).get('version', ''),
                    'health_score': health_score,
                    'health_status': get_health_status_label(health_score),
                    'registration_time': agent.get('dateAdd'),
                    'config_sum': agent.get('configSum'),
                    'merged_sum': agent.get('mergedSum')
                }
                
                # Add to appropriate status category
                if status in status_summary:
                    status_summary[status].append(agent_info)
                    total_health_score += health_score
                    processed_agents += 1
                    
            except Exception as e:
                await ctx.error(f"Error processing agent {agent.get('id', 'unknown')}: {e}")
                continue
        
        # Calculate overall metrics
        total_agents = sum(len(agents_list) for agents_list in status_summary.values())
        active_count = len(status_summary['active'])
        disconnected_count = len(status_summary['disconnected'])
        
        # Calculate health percentage and overall status
        health_percentage = (active_count / total_agents * 100) if total_agents > 0 else 0
        avg_health_score = (total_health_score / processed_agents) if processed_agents > 0 else 0
        
        overall_status = (
            'HEALTHY' if health_percentage >= 90 and avg_health_score >= 80 else
            'DEGRADED' if health_percentage >= 70 and avg_health_score >= 60 else
            'CRITICAL'
        )
        
        # Generate recommendations
        recommendations = generate_agent_recommendations(status_summary, health_percentage, avg_health_score)
        
        await ctx.info(f"Health check completed: {active_count}/{total_agents} agents active ({health_percentage:.1f}%)")
        
        return {
            'success': True,
            'health_summary': {
                'total_agents': total_agents,
                'active_agents': active_count,
                'disconnected_agents': disconnected_count,
                'health_percentage': round(health_percentage, 2),
                'avg_health_score': round(avg_health_score, 2),
                'overall_status': overall_status
            },
            'agent_details': status_summary,
            'recommendations': recommendations,
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'health_threshold': health_threshold,
                'include_disconnected': include_disconnected,
                'server_version': __version__
            }
        }
        
    except Exception as e:
        await ctx.error(f"Agent health check failed: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }


# ============================================================================
# RESOURCES
# ============================================================================

@mcp.resource("wazuh://cluster/status")
async def get_cluster_status() -> Dict[str, Any]:
    """Get real-time Wazuh cluster status with comprehensive information."""
    try:
        # Get cluster status
        cluster_response = await wazuh_api_request('/cluster/status')
        cluster_data = cluster_response.get('data', {}).get('affected_items', [{}])[0]
        
        # Get manager information
        manager_response = await wazuh_api_request('/manager/info')
        manager_data = manager_response.get('data', {}).get('affected_items', [{}])[0]
        
        # Get cluster nodes if clustering is enabled
        nodes_data = []
        if cluster_data.get('enabled'):
            try:
                nodes_response = await wazuh_api_request('/cluster/nodes')
                nodes_data = nodes_response.get('data', {}).get('affected_items', [])
            except Exception as e:
                logger.warning(f"Failed to get cluster nodes: {e}")
        
        return {
            'cluster_info': cluster_data,
            'manager_info': manager_data,
            'nodes': nodes_data,
            'status': 'healthy' if cluster_data.get('enabled') else 'standalone',
            'last_updated': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting cluster status: {e}")
        return {
            'error': str(e),
            'status': 'unavailable',
            'last_updated': datetime.now().isoformat()
        }


@mcp.resource("wazuh://security/overview")
async def get_security_overview() -> Dict[str, Any]:
    """Get comprehensive security overview with real-time threat assessment."""
    try:
        # Get multiple data sources in parallel
        tasks = [
            wazuh_api_request('/alerts', {'limit': 1000, 'sort': '-timestamp'}),
            wazuh_api_request('/alerts', {'limit': 100, 'rule.level': '>=10', 'sort': '-timestamp'}),
            wazuh_api_request('/agents', {'sort': '+id'})
        ]
        
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process responses safely
        recent_alerts = []
        critical_alerts = []
        agents = []
        
        if not isinstance(responses[0], Exception):
            recent_alerts = responses[0].get('data', {}).get('affected_items', [])
        
        if not isinstance(responses[1], Exception):
            critical_alerts = responses[1].get('data', {}).get('affected_items', [])
        
        if not isinstance(responses[2], Exception):
            agents = responses[2].get('data', {}).get('affected_items', [])
        
        # Calculate security metrics
        active_agents = len([a for a in agents if a.get('status', '').lower() == 'active'])
        agent_health_percentage = (active_agents / len(agents) * 100) if agents else 0
        
        # Analyze recent alerts for patterns
        alert_analysis = analyze_alert_patterns(recent_alerts)
        
        # Risk assessment
        risk_level = calculate_risk_level(recent_alerts, critical_alerts, agents)
        
        return {
            'overall_status': risk_level['status'],
            'risk_score': risk_level['score'],
            'risk_factors': risk_level['factors'],
            'recent_activity': {
                'last_hour_alerts': len([a for a in recent_alerts if is_within_last_hour(a.get('timestamp'))]),
                'critical_alerts_24h': len(critical_alerts),
                'alert_rate_trend': alert_analysis['trend'],
                'top_alert_rules': alert_analysis['top_rules'][:5]
            },
            'infrastructure': {
                'total_agents': len(agents),
                'active_agents': active_agents,
                'agent_health_percentage': round(agent_health_percentage, 1),
                'disconnected_agents': len([a for a in agents if a.get('status', '').lower() == 'disconnected'])
            },
            'threat_indicators': {
                'high_severity_alerts': len([a for a in recent_alerts if a.get('rule', {}).get('level', 0) >= 8]),
                'unique_threats': len(set(a.get('rule', {}).get('id') for a in recent_alerts if a.get('rule', {}).get('id'))),
                'affected_agents': len(set(a.get('agent', {}).get('id') for a in recent_alerts if a.get('agent', {}).get('id'))),
                'attack_patterns': alert_analysis['patterns']
            },
            'recommendations': generate_security_recommendations(risk_level, alert_analysis, agent_health_percentage),
            'last_updated': datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting security overview: {e}")
        return {
            'error': str(e),
            'overall_status': 'unknown',
            'last_updated': datetime.now().isoformat()
        }


# ============================================================================
# PROMPTS
# ============================================================================

@mcp.prompt("security_briefing")
def security_briefing_prompt(time_range: str = "24h") -> str:
    """Generate a comprehensive security briefing request prompt."""
    return f"""Create a comprehensive security briefing for the last {time_range} based on Wazuh SIEM data.

**Required Sections:**

1. **Executive Summary**
   - Overall security posture assessment
   - Key risk indicators and trends
   - Critical items requiring immediate attention
   - Risk level classification (LOW/MEDIUM/HIGH/CRITICAL)

2. **Threat Landscape Analysis**
   - Most frequent alert types and their significance
   - Emerging threat patterns or anomalous activity
   - Geographic, temporal, or behavioral attack patterns
   - Threat actor TTPs (Tactics, Techniques, Procedures)

3. **Infrastructure Health Assessment**
   - Agent connectivity and coverage status
   - Monitoring effectiveness and blind spots
   - System performance and reliability metrics
   - Configuration compliance status

4. **Critical Security Incidents**
   - High-severity alerts requiring investigation
   - Potential security incidents and impact assessment
   - Evidence of coordinated or advanced attacks
   - Incident response recommendations

5. **Compliance and Governance**
   - Regulatory compliance violations detected
   - Policy enforcement effectiveness
   - Audit trail completeness and integrity
   - Data protection status

6. **Strategic Recommendations**
   - Immediate actions required (next 24 hours)
   - Short-term improvements (next 7 days)
   - Strategic security enhancements (next 30 days)
   - Resource allocation recommendations

**Format Requirements:**
- Professional executive briefing suitable for security leadership
- Clear, concise language with quantified metrics where possible
- Actionable insights with specific next steps
- Risk-based prioritization of recommendations
- Include confidence levels for assessments"""


@mcp.prompt("incident_investigation")
def incident_investigation_prompt(incident_data: str) -> str:
    """Generate a comprehensive incident investigation prompt."""
    return f"""Conduct a thorough security incident investigation using the provided data:

**Incident Data:** {incident_data}

**Investigation Framework:**

1. **Initial Assessment**
   - Incident classification and severity rating
   - Affected systems and potential blast radius
   - Initial containment status
   - Evidence preservation requirements

2. **Technical Analysis**
   - Attack vector identification and analysis
   - Indicators of Compromise (IOCs) extraction
   - Malware analysis (if applicable)
   - Network traffic analysis patterns

3. **Timeline Reconstruction**
   - Chronological sequence of events
   - Attack progression and lateral movement
   - Data exfiltration timeline (if applicable)
   - Response actions timeline

4. **Scope and Impact Assessment**
   - Affected systems and data inventory
   - Business impact quantification
   - Regulatory notification requirements
   - Customer/stakeholder impact

5. **Attribution and Intelligence**
   - Threat actor profiling
   - Campaign linkage analysis
   - Threat intelligence correlation
   - Similar incident patterns

6. **Response Recommendations**
   - Immediate containment actions
   - Eradication procedures
   - Recovery planning
   - Lessons learned integration

**Deliverables:**
- Executive incident summary
- Technical investigation report
- Evidence package with IOCs
- Recovery and remediation plan
- Post-incident security improvements"""


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_agent_health_score(agent: Dict[str, Any]) -> float:
    """Calculate comprehensive agent health score (0-100)."""
    try:
        score = 100.0
        
        # Status scoring (40% weight)
        status = agent.get('status', '').lower()
        if status == 'active':
            score *= 1.0
        elif status == 'disconnected':
            score *= 0.3
        elif status == 'never_connected':
            score *= 0.0
        else:
            score *= 0.1
        
        # Last keep alive scoring (30% weight)
        last_alive = agent.get('lastKeepAlive')
        if last_alive:
            try:
                last_alive_dt = isoparse(last_alive)
                now = datetime.now(last_alive_dt.tzinfo)
                time_diff = now - last_alive_dt
                hours_since = time_diff.total_seconds() / 3600
                
                if hours_since <= 0.5:  # Within 30 minutes
                    alive_score = 1.0
                elif hours_since <= 1:  # Within 1 hour
                    alive_score = 0.9
                elif hours_since <= 6:  # Within 6 hours
                    alive_score = 0.7
                elif hours_since <= 24:  # Within 24 hours
                    alive_score = 0.4
                else:  # More than 24 hours
                    alive_score = 0.1
                
                score *= alive_score
            except Exception:
                score *= 0.6
        else:
            score *= 0.5
        
        # Version scoring (20% weight)
        version = agent.get('version', '')
        if version:
            if 'v4.8' in version or 'v4.9' in version:
                version_score = 1.0
            elif 'v4.' in version:
                version_score = 0.9
            elif 'v3.' in version:
                version_score = 0.7
            else:
                version_score = 0.5
            score *= version_score
        else:
            score *= 0.8
        
        # Configuration sync scoring (10% weight)
        config_sum = agent.get('configSum')
        merged_sum = agent.get('mergedSum')
        if config_sum and merged_sum:
            # Simplified check - in production you'd compare with expected values
            config_score = 1.0
        else:
            config_score = 0.8
        
        score *= config_score
        
        return round(max(0, min(100, score)), 1)
        
    except Exception as e:
        logger.warning(f"Error calculating agent health score: {e}")
        return 0.0


def get_health_status_label(health_score: float) -> str:
    """Get health status label from numerical score."""
    if health_score >= 90:
        return 'excellent'
    elif health_score >= 75:
        return 'good'
    elif health_score >= 50:
        return 'fair'
    elif health_score >= 25:
        return 'poor'
    else:
        return 'critical'


def generate_agent_recommendations(status_summary: Dict[str, List], health_percentage: float, avg_health_score: float) -> List[str]:
    """Generate intelligent agent management recommendations."""
    recommendations = []
    
    try:
        # Critical health issues
        if health_percentage < 50:
            recommendations.append("🚨 CRITICAL: Less than 50% of agents are active - immediate investigation required")
        elif health_percentage < 70:
            recommendations.append("⚠️ WARNING: Agent health below 70% - review network connectivity and agent configurations")
        
        # Disconnected agents
        disconnected_count = len(status_summary.get('disconnected', []))
        if disconnected_count > 0:
            recommendations.append(f"🔌 Network Issue: {disconnected_count} agents disconnected - check network connectivity and firewall rules")
        
        # Pending agents
        pending_count = len(status_summary.get('pending', []))
        if pending_count > 0:
            recommendations.append(f"📋 Pending Agents: {pending_count} agents awaiting approval - review and approve legitimate agents")
        
        # Version updates
        active_agents = status_summary.get('active', [])
        outdated_agents = [a for a in active_agents if a.get('version', '') and not any(v in a['version'] for v in ['v4.8', 'v4.9'])]
        if outdated_agents:
            recommendations.append(f"📦 Updates Available: {len(outdated_agents)} agents need version updates for security and performance improvements")
        
        # Performance optimization
        if avg_health_score < 80 and health_percentage >= 70:
            recommendations.append("⚡ Performance: Consider optimizing agent configurations and monitoring intervals")
        
        # Positive feedback
        if health_percentage >= 95 and avg_health_score >= 85:
            recommendations.append("✅ Excellent: Agent infrastructure is healthy - maintain current monitoring practices")
        
        # Backup recommendations
        if not recommendations:
            recommendations.append("📊 Continue monitoring agent health and investigate any status changes")
        
    except Exception as e:
        logger.error(f"Error generating agent recommendations: {e}")
        recommendations = ["Unable to generate specific recommendations - review agent status manually"]
    
    return recommendations


def analyze_alert_patterns(alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze alert patterns for trends and insights."""
    try:
        if not alerts:
            return {'trend': 'no_data', 'patterns': [], 'top_rules': []}
        
        # Time-based analysis
        hourly_counts = defaultdict(int)
        rule_counts = Counter()
        category_counts = Counter()
        
        for alert in alerts:
            try:
                # Time distribution
                timestamp = alert.get('timestamp', '')
                if timestamp:
                    dt = isoparse(timestamp)
                    hour_key = dt.strftime('%H:00')
                    hourly_counts[hour_key] += 1
                
                # Rule analysis
                rule = alert.get('rule', {})
                rule_id = rule.get('id', 'unknown')
                rule_desc = rule.get('description', '')
                rule_counts[(rule_id, rule_desc)] += 1
                
                # Category analysis
                groups = rule.get('groups', [])
                if groups:
                    groups_str = ' '.join(str(g).lower() for g in groups)
                    if 'authentication' in groups_str:
                        category_counts['authentication'] += 1
                    elif 'intrusion' in groups_str:
                        category_counts['intrusion'] += 1
                    elif 'malware' in groups_str:
                        category_counts['malware'] += 1
                    else:
                        category_counts['general'] += 1
                        
            except Exception:
                continue
        
        # Calculate trend
        counts = list(hourly_counts.values())
        if len(counts) >= 3:
            recent_avg = sum(counts[-3:]) / 3
            earlier_avg = sum(counts[:-3]) / max(1, len(counts) - 3) if len(counts) > 3 else 0
            
            if recent_avg > earlier_avg * 1.3:
                trend = 'increasing'
            elif recent_avg < earlier_avg * 0.7:
                trend = 'decreasing'
            else:
                trend = 'stable'
        else:
            trend = 'insufficient_data'
        
        # Identify patterns
        patterns = []
        if category_counts.get('authentication', 0) > len(alerts) * 0.3:
            patterns.append('High authentication activity detected')
        if category_counts.get('intrusion', 0) > len(alerts) * 0.2:
            patterns.append('Potential intrusion attempts detected')
        if category_counts.get('malware', 0) > 0:
            patterns.append('Malware activity detected')
        
        # Top rules
        top_rules = [
            {'rule_id': rule_info[0], 'description': rule_info[1], 'count': count}
            for rule_info, count in rule_counts.most_common(10)
        ]
        
        return {
            'trend': trend,
            'patterns': patterns,
            'top_rules': top_rules,
            'category_distribution': dict(category_counts),
            'hourly_distribution': dict(hourly_counts)
        }
        
    except Exception as e:
        logger.error(f"Error analyzing alert patterns: {e}")
        return {'trend': 'analysis_error', 'patterns': [], 'top_rules': []}


def calculate_risk_level(recent_alerts: List, critical_alerts: List, agents: List) -> Dict[str, Any]:
    """Calculate overall security risk level with detailed factors."""
    try:
        # Initialize risk factors
        risk_factors = {
            'alert_volume': 0,
            'critical_alerts': 0,
            'infrastructure_health': 0,
            'threat_diversity': 0
        }
        
        # Alert volume risk (0-25 points)
        alert_count = len(recent_alerts)
        if alert_count > 1000:
            risk_factors['alert_volume'] = 25
        elif alert_count > 500:
            risk_factors['alert_volume'] = 20
        elif alert_count > 100:
            risk_factors['alert_volume'] = 15
        elif alert_count > 50:
            risk_factors['alert_volume'] = 10
        else:
            risk_factors['alert_volume'] = 5
        
        # Critical alerts risk (0-35 points)
        critical_count = len(critical_alerts)
        if critical_count > 50:
            risk_factors['critical_alerts'] = 35
        elif critical_count > 20:
            risk_factors['critical_alerts'] = 30
        elif critical_count > 10:
            risk_factors['critical_alerts'] = 25
        elif critical_count > 5:
            risk_factors['critical_alerts'] = 20
        elif critical_count > 0:
            risk_factors['critical_alerts'] = 15
        else:
            risk_factors['critical_alerts'] = 0
        
        # Infrastructure health risk (0-25 points)
        if agents:
            active_agents = len([a for a in agents if a.get('status', '').lower() == 'active'])
            health_ratio = active_agents / len(agents)
            
            if health_ratio < 0.5:
                risk_factors['infrastructure_health'] = 25
            elif health_ratio < 0.7:
                risk_factors['infrastructure_health'] = 20
            elif health_ratio < 0.8:
                risk_factors['infrastructure_health'] = 15
            elif health_ratio < 0.9:
                risk_factors['infrastructure_health'] = 10
            else:
                risk_factors['infrastructure_health'] = 5
        else:
            risk_factors['infrastructure_health'] = 25  # No agents is high risk
        
        # Threat diversity risk (0-15 points)
        unique_rules = len(set(a.get('rule', {}).get('id') for a in recent_alerts if a.get('rule', {}).get('id')))
        if unique_rules > 50:
            risk_factors['threat_diversity'] = 15
        elif unique_rules > 20:
            risk_factors['threat_diversity'] = 12
        elif unique_rules > 10:
            risk_factors['threat_diversity'] = 8
        elif unique_rules > 5:
            risk_factors['threat_diversity'] = 5
        else:
            risk_factors['threat_diversity'] = 2
        
        # Calculate total risk score (0-100)
        total_risk = sum(risk_factors.values())
        
        # Determine risk status
        if total_risk >= 80:
            status = 'CRITICAL'
        elif total_risk >= 60:
            status = 'HIGH'
        elif total_risk >= 40:
            status = 'MEDIUM'
        else:
            status = 'LOW'
        
        return {
            'score': total_risk,
            'status': status,
            'factors': risk_factors
        }
        
    except Exception as e:
        logger.error(f"Error calculating risk level: {e}")
        return {'score': 50, 'status': 'UNKNOWN', 'factors': {}}


def generate_security_recommendations(risk_level: Dict, alert_analysis: Dict, agent_health: float) -> List[str]:
    """Generate intelligent security recommendations based on current state."""
    recommendations = []
    
    try:
        # Risk-based recommendations
        if risk_level['status'] == 'CRITICAL':
            recommendations.append("🚨 IMMEDIATE ACTION: Critical security risk detected - activate incident response procedures")
        elif risk_level['status'] == 'HIGH':
            recommendations.append("⚠️ HIGH PRIORITY: Elevated security risk - increase monitoring and review recent alerts")
        
        # Critical alerts
        if risk_level['factors'].get('critical_alerts', 0) > 20:
            recommendations.append("🔍 INVESTIGATE: Multiple critical alerts detected - prioritize threat hunting activities")
        
        # Infrastructure health
        if agent_health < 70:
            recommendations.append("🔧 INFRASTRUCTURE: Agent connectivity issues detected - review network and deployment status")
        
        # Alert patterns
        patterns = alert_analysis.get('patterns', [])
        if 'authentication' in str(patterns).lower():
            recommendations.append("🔐 AUTHENTICATION: Unusual authentication activity - review access controls and user behavior")
        if 'intrusion' in str(patterns).lower():
            recommendations.append("🛡️ INTRUSION: Potential intrusion attempts - strengthen network defenses and monitoring")
        if 'malware' in str(patterns).lower():
            recommendations.append("🦠 MALWARE: Malware activity detected - initiate containment and forensic analysis")
        
        # Trend analysis
        trend = alert_analysis.get('trend', '')
        if trend == 'increasing':
            recommendations.append("📈 TREND: Alert volume increasing - investigate potential ongoing attack or system issues")
        elif trend == 'decreasing':
            recommendations.append("📉 TREND: Alert volume decreasing - verify detection capabilities are functioning properly")
        
        # General recommendations
        if risk_level['status'] in ['LOW', 'MEDIUM'] and agent_health >= 80:
            recommendations.append("✅ MAINTAIN: Security posture is stable - continue current monitoring practices")
        
        # Backup recommendation
        if not recommendations:
            recommendations.append("📊 MONITOR: Continue regular security monitoring and threat assessment")
        
    except Exception as e:
        logger.error(f"Error generating security recommendations: {e}")
        recommendations = ["Unable to generate specific recommendations - conduct manual security review"]
    
    return recommendations


def is_within_last_hour(timestamp: str) -> bool:
    """Check if timestamp is within the last hour."""
    try:
        if not timestamp:
            return False
        dt = isoparse(timestamp)
        now = datetime.now(dt.tzinfo)
        return (now - dt).total_seconds() <= 3600
    except Exception:
        return False


# ============================================================================
# TOOL FACTORY MANAGEMENT
# ============================================================================

async def initialize_tool_factory():
    """Initialize tool factory and register all tools with FastMCP."""
    global _tool_factory
    
    try:
        logger.info("Initializing tool factory...")
        
        # Create a mock server instance for tool initialization
        from types import SimpleNamespace
        mock_server = SimpleNamespace()
        mock_server.config = get_config()
        mock_server.api_client = None  # Will be set later
        mock_server.security_analyzer = None
        mock_server.compliance_analyzer = None
        mock_server._get_current_timestamp = lambda: datetime.now().isoformat()
        
        # Initialize tool factory
        _tool_factory = ToolFactory(mock_server)
        
        # Get all tool definitions
        all_tools = _tool_factory.get_all_tool_definitions()
        
        # Import FunctionTool for creating tool instances
        from fastmcp.tools.tool import FunctionTool, ToolResult
        
        # Register each tool with FastMCP using the tool manager
        registered_count = 0
        for tool_def in all_tools:
            try:
                tool_name = tool_def.name
                
                # Create a dynamic handler function for this tool
                def create_tool_handler(tool_name_capture):
                    async def tool_handler(arguments: Dict[str, Any]):
                        """Dynamic tool handler that routes to the tool factory."""
                        try:
                            result = await _tool_factory.handle_tool_call(tool_name_capture, arguments)
                            # Convert result to ToolResult format
                            if isinstance(result, dict):
                                return ToolResult(structured_content=result)
                            else:
                                return ToolResult(content=[{"type": "text", "text": str(result)}])
                        except Exception as e:
                            logger.error(f"Error handling tool '{tool_name_capture}': {e}")
                            return ToolResult(content=[{"type": "text", "text": f"Error: {str(e)}"}])
                    return tool_handler
                
                # Create the handler with captured tool name
                handler = create_tool_handler(tool_name)
                
                # Create FunctionTool instance with proper schema
                function_tool = FunctionTool.from_function(
                    fn=handler,
                    name=tool_def.name,
                    description=tool_def.description,
                    output_schema={"type": "object", "properties": {"result": {"type": "object"}}}
                )
                
                # Set the parameters to match the original tool definition
                function_tool.parameters = tool_def.inputSchema
                
                # Add tool to FastMCP's tool manager
                mcp._tool_manager.add_tool(function_tool)
                
                registered_count += 1
                logger.debug(f"Registered tool: {tool_def.name}")
                
            except Exception as e:
                logger.error(f"Failed to register tool '{tool_def.name}': {e}")
                logger.error(traceback.format_exc())
                continue
        
        # Get tool statistics
        stats = _tool_factory.get_tool_statistics()
        
        logger.info(f"Tool factory initialized successfully:")
        logger.info(f"  - Total categories: {stats['total_categories']}")
        logger.info(f"  - Total tools available: {stats['total_tools']}")
        logger.info(f"  - Tools registered with FastMCP: {registered_count}")
        
        # Log category breakdown
        for category, info in stats['categories'].items():
            logger.info(f"  - {category}: {info['tool_count']} tools")
        
        return True
        
    except Exception as e:
        logger.error(f"Tool factory initialization failed: {e}")
        logger.error(traceback.format_exc())
        return False


# ============================================================================
# SERVER LIFECYCLE MANAGEMENT
# ============================================================================

async def initialize_server() -> bool:
    """Initialize server components with proper error handling."""
    global _server_start_time, _health_status, _metrics
    
    try:
        _server_start_time = datetime.now()
        _metrics["uptime_start"] = _server_start_time
        
        logger.info(f"Initializing Wazuh MCP Server v{__version__}")
        
        # Load and validate configuration
        config = get_config()
        logger.info(f"Configuration loaded - Wazuh API: {config.base_url}")
        
        # Initialize HTTP client
        await get_http_client()
        logger.info("HTTP client initialized")
        
        # Initialize rate limiter
        await get_rate_limiter()
        logger.info("Rate limiter initialized")
        
        # Initialize tool factory and register tools with FastMCP
        await initialize_tool_factory()
        
        # Test Wazuh API connectivity
        try:
            await wazuh_api_request('/security/user/authenticate')
            logger.info("Wazuh API connectivity test successful")
        except Exception as e:
            logger.warning(f"Wazuh API connectivity test failed: {e}")
            logger.warning("Server will continue but API calls may fail")
        
        # Update health status
        _health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "checks": {"initialization": "completed"}
        }
        
        logger.info("Server initialization completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Server initialization failed: {e}")
        logger.error(traceback.format_exc())
        
        _health_status = {
            "status": "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }
        
        return False


async def cleanup_server():
    """Clean up server resources on shutdown with comprehensive cleanup."""
    global _http_client, _rate_limiter, _health_status, _metrics, _server_start_time
    
    try:
        logger.info("Initiating graceful server shutdown...")
        
        # Update health status
        _health_status["status"] = "shutting_down"
        
        # Close HTTP client connections
        if _http_client:
            try:
                # Allow time for pending requests to complete
                await asyncio.sleep(0.5)
                await _http_client.aclose()
                _http_client = None
                logger.info("HTTP client closed successfully")
            except Exception as e:
                logger.error(f"Error closing HTTP client: {e}")
        
        # Clear rate limiter state
        if _rate_limiter:
            _rate_limiter = None
            logger.info("Rate limiter cleared")
        
        # Clear global state
        _health_status = {"status": "stopped", "checks": {}}
        _metrics = {
            "requests_total": 0,
            "requests_failed": 0,
            "avg_response_time": 0,
            "last_error": None,
            "uptime_start": None
        }
        _server_start_time = None
        
        # Force garbage collection to free memory
        import gc
        gc.collect()
        
        logger.info("Server shutdown completed successfully")
        
    except Exception as e:
        logger.error(f"Error during server cleanup: {e}")
        # Continue shutdown even if cleanup fails


def setup_signal_handlers():
    """Set up graceful shutdown signal handlers."""
    shutdown_event = asyncio.Event()
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, initiating graceful shutdown...")
        shutdown_event.set()
        # Cancel any running tasks
        for task in asyncio.all_tasks():
            if not task.done():
                task.cancel()
        
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    return shutdown_event


async def main():
    """Main entry point with comprehensive error handling and graceful shutdown."""
    # Setup logging
    setup_logging(
        log_level=os.getenv('LOG_LEVEL', 'INFO'),
        enable_structured=True,
        enable_rotation=True
    )
    
    # Setup signal handlers
    setup_signal_handlers()
    
    try:
        # Initialize server
        if not await initialize_server():
            logger.error("Server initialization failed - exiting")
            sys.exit(1)
        
        config = get_config()
        
        # Determine transport mode from environment or command line
        transport_mode = os.getenv("MCP_TRANSPORT", "stdio").lower()
        if len(sys.argv) > 1:
            if sys.argv[1] in ["--http", "--server", "--remote"]:
                transport_mode = "http"
            elif sys.argv[1] in ["--stdio", "--local"]:
                transport_mode = "stdio"
        
        # Log server information
        logger.info(f"Starting Wazuh MCP Server v{__version__}")
        logger.info(f"Python version: {sys.version}")
        logger.info(f"FastMCP framework: Production-ready")
        logger.info(f"Transport mode: {transport_mode.upper()}")
        logger.info(f"Configuration: {config.host}:{config.port}")
        
        # Log registered components
        tool_count = len([name for name in dir(mcp) if name.startswith('_tools')])
        resource_count = len([name for name in dir(mcp) if name.startswith('_resources')])
        prompt_count = len([name for name in dir(mcp) if name.startswith('_prompts')])
        
        logger.info(f"Registered components: {tool_count} tools, {resource_count} resources, {prompt_count} prompts")
        
        # Start server with appropriate transport
        if transport_mode == "http":
            # HTTP/SSE transport for remote access
            host = os.getenv("MCP_HOST", "localhost") 
            port = int(os.getenv("MCP_PORT", "3000"))
            logger.info(f"Server is ready and listening on HTTP transport at {host}:{port}")
            logger.info("Remote MCP server mode - supports HTTP POST + Server-Sent Events")
            await mcp.run_async(transport="http", host=host, port=port)
        else:
            # STDIO transport for local Claude Desktop integration
            logger.info("Server is ready and listening on STDIO transport")
            logger.info("Local MCP server mode - for Claude Desktop integration")
            await mcp.run_async(transport="stdio")
        
    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")
        logger.error(traceback.format_exc())
        sys.exit(1)
    finally:
        await cleanup_server()


if __name__ == "__main__":
    try:
        # Final system checks
        logger.info("Wazuh MCP Server starting...")
        
        # Run the server
        asyncio.run(main())
        
    except KeyboardInterrupt:
        logger.info("Startup interrupted")
    except Exception as e:
        logger.error(f"Critical startup error: {str(e)}")
        sys.exit(1)