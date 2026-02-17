#!/usr/bin/env python3
"""
Comprehensive Business Logic Test Suite
======================================
Tests MCP server components and business logic for error-free operation.
"""

import os
import sys
from pathlib import Path

import pytest

# Add src to path
src_path = Path(__file__).parent.parent.parent / "src"
sys.path.insert(0, str(src_path))


@pytest.mark.asyncio
async def test_server_imports():
    """Test that server modules can be imported."""
    from wazuh_mcp_server.config import get_config
    from wazuh_mcp_server.server import app

    assert app is not None
    config = get_config()
    assert config is not None


@pytest.mark.asyncio
async def test_wazuh_client_initialization():
    """Test Wazuh Client initialization."""
    from wazuh_mcp_server.api.wazuh_client import WazuhClient
    from wazuh_mcp_server.config import WazuhConfig

    config = WazuhConfig(
        wazuh_host="localhost", wazuh_user="test", wazuh_pass="test", wazuh_port=55000, verify_ssl=False
    )
    client = WazuhClient(config)
    assert client is not None
    assert client.config.wazuh_host == "localhost"


@pytest.mark.asyncio
async def test_wazuh_indexer_client():
    """Test Wazuh Indexer Client initialization."""
    from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient

    client = WazuhIndexerClient(host="localhost", port=9200, username="admin", password="admin", verify_ssl=False)
    assert client is not None
    assert client.host == "localhost"
    assert client.port == 9200


def test_configuration():
    """Test configuration loading."""
    from wazuh_mcp_server.config import ServerConfig

    # Test with environment variables
    os.environ.setdefault("WAZUH_HOST", "localhost")
    os.environ.setdefault("WAZUH_USER", "test")
    os.environ.setdefault("WAZUH_PASS", "test")

    config = ServerConfig.from_env()
    assert config is not None
    assert config.MCP_PORT == 3000


def test_security_validation():
    """Test security validation functions."""
    from wazuh_mcp_server.security import ToolValidationError, validate_agent_id, validate_limit, validate_time_range

    # Test validate_limit
    assert validate_limit(50) == 50
    assert validate_limit(None) == 100  # Default

    # Test with invalid values
    with pytest.raises(ToolValidationError):
        validate_limit(0)  # Below min

    with pytest.raises(ToolValidationError):
        validate_limit(2000)  # Above max

    # Test validate_agent_id
    assert validate_agent_id("001") == "001"
    assert validate_agent_id(None) is None

    # Test validate_time_range
    assert validate_time_range("24h") == "24h"
    assert validate_time_range("7d") == "7d"


def test_auth_manager():
    """Test authentication manager."""
    from wazuh_mcp_server.auth import AuthManager

    manager = AuthManager()
    assert manager is not None

    # Test API key creation
    api_key = manager.create_api_key(name="Test Key", scopes=["wazuh:read"])
    assert api_key.startswith("wazuh_")
    assert len(api_key) == 49  # wazuh_ (6) + base64 (43)

    # Test API key validation
    key_obj = manager.validate_api_key(api_key)
    assert key_obj is not None
    assert key_obj.name == "Test Key"


def test_rate_limiter():
    """Test rate limiter functionality."""
    from wazuh_mcp_server.security import RateLimiter

    limiter = RateLimiter(max_requests=5, window_seconds=60)
    assert limiter is not None

    # First 5 requests should be allowed
    for _ in range(5):
        allowed, retry_after = limiter.is_allowed("test_client")
        assert allowed is True

    # 6th request should be rate limited
    allowed, retry_after = limiter.is_allowed("test_client")
    assert allowed is False


def test_docker_compatibility():
    """Test Docker environment compatibility."""
    import platform
    import socket

    # Basic platform checks
    assert platform.system() in ["Darwin", "Linux", "Windows"]
    assert platform.python_version().startswith("3.")

    # Test socket operations work
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.close()


def test_dependencies():
    """Test all required dependencies are importable."""
    dependencies = ["httpx", "pydantic", "fastapi", "uvicorn", "jose", "tenacity"]

    for dep in dependencies:
        module = __import__(dep.replace("-", "_"))
        assert module is not None


def test_resilience_patterns():
    """Test resilience patterns."""
    from wazuh_mcp_server.resilience import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState, GracefulShutdown

    # Test circuit breaker config
    config = CircuitBreakerConfig(failure_threshold=3, recovery_timeout=30)
    assert config.failure_threshold == 3

    # Test circuit breaker
    cb = CircuitBreaker(config)
    assert cb.state == CircuitBreakerState.CLOSED

    # Test graceful shutdown
    shutdown = GracefulShutdown()
    assert shutdown is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
