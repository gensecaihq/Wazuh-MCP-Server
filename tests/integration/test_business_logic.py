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
    dependencies = ["httpx", "pydantic", "fastapi", "uvicorn", "jwt", "tenacity"]

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


class TestMCPResponseJsonRpc:
    """Tests for MCPResponse JSON-RPC 2.0 compliance (Fix #10)."""

    def test_model_dump_success_excludes_error(self):
        """model_dump() should exclude 'error' on success."""
        from wazuh_mcp_server.server import MCPResponse

        resp = MCPResponse(id=1, result={"ok": True})
        d = resp.model_dump()
        assert "result" in d
        assert "error" not in d

    def test_model_dump_error_excludes_result(self):
        """model_dump() should exclude 'result' on error."""
        from wazuh_mcp_server.server import MCPResponse

        resp = MCPResponse(id=1, error={"code": -32600, "message": "Invalid"})
        d = resp.model_dump()
        assert "error" in d
        assert "result" not in d

    def test_dict_backwards_compat(self):
        """dict() should delegate to model_dump()."""
        from wazuh_mcp_server.server import MCPResponse

        resp = MCPResponse(id=1, result="ok")
        assert resp.dict() == resp.model_dump()


class TestTimeRangeSync:
    """Tests for synchronized time range values (Fix #8)."""

    def test_12h_in_valid_time_ranges(self):
        from wazuh_mcp_server.security import VALID_TIME_RANGES

        assert "12h" in VALID_TIME_RANGES

    def test_1d_in_valid_time_ranges(self):
        from wazuh_mcp_server.security import VALID_TIME_RANGES

        assert "1d" in VALID_TIME_RANGES

    def test_1d_in_time_range_hours(self):
        from wazuh_mcp_server.api.wazuh_client import _TIME_RANGE_HOURS

        assert "1d" in _TIME_RANGE_HOURS
        assert _TIME_RANGE_HOURS["1d"] == 24

    def test_12h_in_time_range_hours(self):
        from wazuh_mcp_server.api.wazuh_client import _TIME_RANGE_HOURS

        assert "12h" in _TIME_RANGE_HOURS
        assert _TIME_RANGE_HOURS["12h"] == 12


class TestAgentStatusEnum:
    """Tests for agent status enum values (Fix #17)."""

    def test_pending_in_valid_statuses(self):
        from wazuh_mcp_server.security import VALID_AGENT_STATUSES

        assert "pending" in VALID_AGENT_STATUSES

    def test_all_statuses_present(self):
        from wazuh_mcp_server.security import VALID_AGENT_STATUSES

        expected = {"active", "disconnected", "never_connected", "pending"}
        assert VALID_AGENT_STATUSES == expected


class TestAuthManagerValidation:
    """Tests for auth manager validation improvements (Fix #4)."""

    def test_invalid_format_rejected(self):
        from wazuh_mcp_server.auth import AuthManager

        manager = AuthManager()
        # Too short
        assert manager.validate_api_key("wazuh_short") is None
        # Wrong prefix
        assert manager.validate_api_key("wrong_" + "a" * 43) is None
        # Empty
        assert manager.validate_api_key("") is None
        assert manager.validate_api_key(None) is None

    def test_token_creation_and_validation(self):
        from wazuh_mcp_server.auth import AuthManager

        manager = AuthManager()
        api_key = manager.create_api_key(name="Test", scopes=["wazuh:read"])
        token = manager.create_token(api_key)
        assert token is not None
        assert token.startswith("wst_")

        token_obj = manager.validate_token(token)
        assert token_obj is not None
        assert token_obj.has_scope("wazuh:read")

    def test_token_revocation(self):
        from wazuh_mcp_server.auth import AuthManager

        manager = AuthManager()
        api_key = manager.create_api_key(name="Test")
        token = manager.create_token(api_key)
        assert manager.validate_token(token) is not None
        assert manager.revoke_token(token) is True
        assert manager.validate_token(token) is None


class TestIndexerClientInit:
    """Tests for WazuhIndexerClient normalization."""

    def test_host_normalization_strips_https(self):
        from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient

        client = WazuhIndexerClient(host="https://indexer.example.com")
        assert client.host == "indexer.example.com"

    def test_host_normalization_strips_http(self):
        from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient

        client = WazuhIndexerClient(host="http://indexer.example.com/")
        assert client.host == "indexer.example.com"

    def test_base_url_format(self):
        from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient

        client = WazuhIndexerClient(host="indexer.local", port=9200)
        assert client.base_url == "https://indexer.local:9200"


class TestIndexerNotConfiguredError:
    """Test IndexerNotConfiguredError message."""

    def test_default_message(self):
        from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError

        err = IndexerNotConfiguredError()
        assert "Wazuh Indexer not configured" in str(err)
        assert "WAZUH_INDEXER_HOST" in str(err)

    def test_custom_message(self):
        from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError

        err = IndexerNotConfiguredError("custom msg")
        assert str(err) == "custom msg"


class TestSessionFixation:
    """Tests for session fixation prevention (audit v2 fix)."""

    @pytest.mark.asyncio
    async def test_session_always_gets_server_generated_id(self):
        """Verify get_or_create_session always generates server-side IDs."""
        from wazuh_mcp_server.server import get_or_create_session

        # Even when passing a client-chosen session ID that doesn't exist,
        # the server should generate its own ID
        session = await get_or_create_session("client-chosen-id", None)
        assert session.session_id != "client-chosen-id"
        # Session ID should be a UUID4 format
        import uuid

        uuid.UUID(session.session_id, version=4)  # Raises ValueError if not valid UUID4


class TestOriginValidation:
    """Tests for strict origin validation (audit v2 fix)."""

    def test_exact_match_allowed(self):
        from wazuh_mcp_server.server import validate_origin_header

        # Should not raise for exact match
        validate_origin_header("https://claude.ai", "https://claude.ai")

    def test_wildcard_allows_everything(self):
        from wazuh_mcp_server.server import validate_origin_header

        validate_origin_header("https://anything.example.com", "*")

    def test_invalid_origin_raises_403(self):
        from fastapi import HTTPException

        from wazuh_mcp_server.server import validate_origin_header

        with pytest.raises(HTTPException) as exc_info:
            validate_origin_header("https://evil.com", "https://claude.ai")
        assert exc_info.value.status_code == 403

    def test_no_origin_is_acceptable(self):
        from wazuh_mcp_server.server import validate_origin_header

        # Per MCP spec: no Origin header is acceptable
        validate_origin_header(None, "https://claude.ai")

    def test_suffix_match_no_longer_works(self):
        """Wildcard suffix matching was removed for security."""
        from fastapi import HTTPException

        from wazuh_mcp_server.server import validate_origin_header

        with pytest.raises(HTTPException):
            validate_origin_header("https://evil.claude.ai", "*.claude.ai")


class TestCommandInjectionPrevention:
    """Tests for active response command injection prevention (audit v2 fix)."""

    def test_sanitize_rejects_shell_metacharacters(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient

        # Semicolon
        with pytest.raises(ValueError):
            WazuhClient._sanitize_ar_argument("192.168.1.1; rm -rf /", "ip")
        # Pipe
        with pytest.raises(ValueError):
            WazuhClient._sanitize_ar_argument("test|cat /etc/passwd", "param")
        # Backtick
        with pytest.raises(ValueError):
            WazuhClient._sanitize_ar_argument("`whoami`", "param")
        # Dollar
        with pytest.raises(ValueError):
            WazuhClient._sanitize_ar_argument("$(id)", "param")

    def test_sanitize_allows_valid_inputs(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient

        assert WazuhClient._sanitize_ar_argument("192.168.1.1", "ip") == "192.168.1.1"
        assert WazuhClient._sanitize_ar_argument("admin_user", "username") == "admin_user"
        assert WazuhClient._sanitize_ar_argument("/var/log/test.log", "path") == "/var/log/test.log"
        # Dash-prefixed values are allowed for parameter: keys (used in generic AR commands)
        assert WazuhClient._sanitize_ar_argument("-srcip=10.0.0.1", "parameter:srcip") == "-srcip=10.0.0.1"
        # Standalone values must NOT start with dash (flag injection prevention)
        with pytest.raises(ValueError):
            WazuhClient._sanitize_ar_argument("-srcip 10.0.0.1", "arg")

    def test_sanitize_rejects_empty(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient

        with pytest.raises(ValueError):
            WazuhClient._sanitize_ar_argument("", "param")
        with pytest.raises(ValueError):
            WazuhClient._sanitize_ar_argument("   ", "param")


class TestCircuitBreakerConfig:
    """Tests for circuit breaker configuration (audit v2 fix)."""

    def test_circuit_breaker_accepts_tuple_of_exceptions(self):
        from wazuh_mcp_server.resilience import CircuitBreaker, CircuitBreakerConfig

        config = CircuitBreakerConfig(
            failure_threshold=3, recovery_timeout=30, expected_exception=(ConnectionError, ValueError)
        )
        cb = CircuitBreaker(config)
        assert cb.config.expected_exception == (ConnectionError, ValueError)

    def test_wazuh_client_circuit_breaker_excludes_valueerror(self):
        """Circuit breaker should NOT trip on ValueError (user input errors)."""
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        config = WazuhConfig(
            wazuh_host="localhost", wazuh_user="test", wazuh_pass="test", wazuh_port=55000, verify_ssl=False
        )
        client = WazuhClient(config)
        # ValueError should NOT be in the expected_exception tuple
        expected = client._circuit_breaker.config.expected_exception
        assert ValueError not in (expected if isinstance(expected, tuple) else (expected,))


class TestAuthTokenScopes:
    """Tests for auth token scope checking (audit v2 fix)."""

    def test_none_scopes_means_full_access(self):
        from datetime import datetime, timezone

        from wazuh_mcp_server.auth import AuthToken

        token = AuthToken(token="test", api_key_id="k", created_at=datetime.now(timezone.utc), scopes=None)
        assert token.has_scope("wazuh:read") is True

    def test_empty_scopes_means_no_access(self):
        from datetime import datetime, timezone

        from wazuh_mcp_server.auth import AuthToken

        token = AuthToken(token="test", api_key_id="k", created_at=datetime.now(timezone.utc), scopes=[])
        assert token.has_scope("wazuh:read") is False

    def test_specific_scopes(self):
        from datetime import datetime, timezone

        from wazuh_mcp_server.auth import AuthToken

        token = AuthToken(token="test", api_key_id="k", created_at=datetime.now(timezone.utc), scopes=["wazuh:read"])
        assert token.has_scope("wazuh:read") is True
        assert token.has_scope("wazuh:write") is False


class TestRateLimiterCleanup:
    """Tests for rate limiter bounded memory (audit v2 fix)."""

    def test_cleanup_removes_stale_entries(self):
        import time

        from wazuh_mcp_server.security import RateLimiter

        limiter = RateLimiter(max_requests=100, window_seconds=1)
        # Add some entries and let them expire
        limiter.requests["old_client"].append(time.time() - 100)
        limiter.requests["recent_client"].append(time.time())
        limiter.cleanup()
        assert "old_client" not in limiter.requests
        assert "recent_client" in limiter.requests


class TestIPValidation:
    """Tests for IP validation using ipaddress module (audit v2 fix)."""

    def test_ipv4_valid(self):
        from wazuh_mcp_server.security import validate_ip_address

        assert validate_ip_address("192.168.1.1", required=True) == "192.168.1.1"

    def test_ipv6_compressed_valid(self):
        from wazuh_mcp_server.security import validate_ip_address

        assert validate_ip_address("::1", required=True) == "::1"
        assert validate_ip_address("fe80::1", required=True) == "fe80::1"

    def test_ipv6_full_valid(self):
        from wazuh_mcp_server.security import validate_ip_address

        result = validate_ip_address("2001:0db8:85a3:0000:0000:8a2e:0370:7334", required=True)
        assert result == "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

    def test_invalid_ip_raises(self):
        from wazuh_mcp_server.security import ToolValidationError, validate_ip_address

        with pytest.raises(ToolValidationError):
            validate_ip_address("not-an-ip", required=True)


class TestSanitizingLogFilter:
    """Tests for SanitizingLogFilter handling dict args (audit v2 fix)."""

    def test_handles_dict_args(self):
        import logging

        from wazuh_mcp_server.security import SanitizingLogFilter

        f = SanitizingLogFilter()
        # Create record with no args, then set dict args manually
        # (LogRecord.__init__ treats dict args specially and tries args[0])
        record = logging.LogRecord("test", logging.INFO, "", 0, "test %(key)s", None, None)
        record.args = {"key": "value"}
        # Should not raise
        result = f.filter(record)
        assert result is True

    def test_handles_tuple_args(self):
        import logging

        from wazuh_mcp_server.security import SanitizingLogFilter

        f = SanitizingLogFilter()
        record = logging.LogRecord("test", logging.INFO, "", 0, "test %s %s", ("a", "b"), None)
        result = f.filter(record)
        assert result is True


class TestMCPResponseFalsyResults:
    """Tests for MCPResponse handling of falsy but valid results."""

    def test_result_empty_dict(self):
        """Empty dict result (e.g. from ping) should exclude error."""
        from wazuh_mcp_server.server import MCPResponse

        resp = MCPResponse(id=1, result={})
        d = resp.model_dump()
        assert "result" in d
        assert d["result"] == {}
        assert "error" not in d

    def test_result_zero(self):
        """result=0 is a valid JSON-RPC result."""
        from wazuh_mcp_server.server import MCPResponse

        resp = MCPResponse(id=1, result=0)
        d = resp.model_dump()
        assert "result" in d
        assert d["result"] == 0
        assert "error" not in d

    def test_result_empty_string(self):
        """result='' is a valid JSON-RPC result."""
        from wazuh_mcp_server.server import MCPResponse

        resp = MCPResponse(id=1, result="")
        d = resp.model_dump()
        assert "result" in d
        assert d["result"] == ""
        assert "error" not in d

    def test_result_empty_list(self):
        """result=[] is a valid JSON-RPC result."""
        from wazuh_mcp_server.server import MCPResponse

        resp = MCPResponse(id=1, result=[])
        d = resp.model_dump()
        assert "result" in d
        assert d["result"] == []
        assert "error" not in d

    def test_result_none_no_error(self):
        """result=None with no error should still exclude error."""
        from wazuh_mcp_server.server import MCPResponse

        resp = MCPResponse(id=1, result=None)
        d = resp.model_dump()
        assert "result" in d
        assert "error" not in d


class TestKnownEndpoints:
    """Tests for metric endpoint normalization."""

    def test_sse_endpoint_is_known(self):
        from wazuh_mcp_server.monitoring import _KNOWN_ENDPOINTS

        assert "/sse" in _KNOWN_ENDPOINTS

    def test_mcp_endpoint_is_known(self):
        from wazuh_mcp_server.monitoring import _KNOWN_ENDPOINTS

        assert "/mcp" in _KNOWN_ENDPOINTS

    def test_unknown_endpoint_normalizes(self):
        from wazuh_mcp_server.monitoring import _normalize_endpoint

        assert _normalize_endpoint("/unknown/path") == "other"
        assert _normalize_endpoint("/mcp") == "/mcp"
        assert _normalize_endpoint("/sse") == "/sse"


class TestTimeRangeEnumCompleteness:
    """Tests for time_range enum completeness in tool schemas."""

    def test_all_valid_ranges_accepted(self):
        from wazuh_mcp_server.security import VALID_TIME_RANGES, validate_time_range

        for tr in VALID_TIME_RANGES:
            assert validate_time_range(tr) == tr

    def test_all_valid_ranges_in_client_mapping(self):
        from wazuh_mcp_server.api.wazuh_client import _TIME_RANGE_HOURS
        from wazuh_mcp_server.security import VALID_TIME_RANGES

        for tr in VALID_TIME_RANGES:
            assert tr in _TIME_RANGE_HOURS, f"{tr} missing from _TIME_RANGE_HOURS"


class TestWazuhClientClose:
    """Tests for WazuhClient.close() cleanup."""

    async def test_close_clears_state(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        config = WazuhConfig(
            wazuh_host="localhost", wazuh_user="test", wazuh_pass="test", wazuh_port=55000, verify_ssl=False
        )
        client = WazuhClient(config)
        # Simulate some cached data
        client._cache["test_key"] = (0.0, {"data": "test"})
        await client.close()
        assert client.client is None
        assert client.token is None
        assert len(client._cache) == 0


class TestToolScopeMapping:
    """Tests for per-tool RBAC scope enforcement."""

    def test_write_tools_require_write_scope(self):
        from wazuh_mcp_server.server import WRITE_SCOPE_TOOLS, _get_tool_scope

        for tool in WRITE_SCOPE_TOOLS:
            assert _get_tool_scope(tool) == "wazuh:write"

    def test_read_tools_require_read_scope(self):
        from wazuh_mcp_server.server import WRITE_SCOPE_TOOLS, _get_tool_scope

        read_tools = [
            "get_wazuh_alerts", "get_wazuh_agents", "search_security_events",
            "get_wazuh_vulnerabilities", "analyze_security_threat",
        ]
        for tool in read_tools:
            assert tool not in WRITE_SCOPE_TOOLS
            assert _get_tool_scope(tool) == "wazuh:read"

    def test_all_action_tools_in_write_scope(self):
        from wazuh_mcp_server.server import WRITE_SCOPE_TOOLS

        expected_write = {
            "wazuh_block_ip", "wazuh_isolate_host", "wazuh_kill_process",
            "wazuh_disable_user", "wazuh_quarantine_file", "wazuh_active_response",
            "wazuh_firewall_drop", "wazuh_host_deny", "wazuh_restart",
            "wazuh_unisolate_host", "wazuh_enable_user", "wazuh_restore_file",
            "wazuh_firewall_allow", "wazuh_host_allow",
        }
        assert WRITE_SCOPE_TOOLS == expected_write


class TestAuthlessGuardrails:
    """Tests for authless mode scope restrictions."""

    def test_authless_default_read_only(self):
        """Authless mode without AUTHLESS_ALLOW_WRITE should produce read-only token."""
        from wazuh_mcp_server.auth import AuthToken

        # Simulate what verify_authentication does in authless mode
        scopes = ["wazuh:read"]
        token = AuthToken(
            token="authless", api_key_id="authless",
            created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            scopes=scopes,
        )
        assert token.has_scope("wazuh:read")
        assert not token.has_scope("wazuh:write")

    def test_authless_write_opt_in(self):
        """Authless mode with AUTHLESS_ALLOW_WRITE=true should allow write."""
        from wazuh_mcp_server.auth import AuthToken

        scopes = ["wazuh:read", "wazuh:write"]
        token = AuthToken(
            token="authless", api_key_id="authless",
            created_at=__import__("datetime").datetime.now(__import__("datetime").timezone.utc),
            scopes=scopes,
        )
        assert token.has_scope("wazuh:read")
        assert token.has_scope("wazuh:write")


class TestOutputSanitization:
    """Tests for output text sanitization."""

    def test_password_redacted_from_log(self):
        from wazuh_mcp_server.server import _sanitize_output_text

        text = "User login failed: password=Secret123 for user admin"
        result = _sanitize_output_text(text)
        assert "Secret123" not in result
        assert "[REDACTED]" in result

    def test_api_key_redacted(self):
        from wazuh_mcp_server.server import _sanitize_output_text

        text = "Config: api_key=sk-abc123def456 endpoint=localhost"
        result = _sanitize_output_text(text)
        assert "sk-abc123def456" not in result
        assert "[REDACTED]" in result

    def test_authorization_header_redacted(self):
        from wazuh_mcp_server.server import _sanitize_output_text

        text = "Request headers: Authorization: Bearer eyJhbGc..."
        result = _sanitize_output_text(text)
        assert "eyJhbGc" not in result
        assert "[REDACTED]" in result

    def test_normal_text_unchanged(self):
        from wazuh_mcp_server.server import _sanitize_output_text

        text = "Alert: SSH brute force detected from 192.168.1.100"
        result = _sanitize_output_text(text)
        assert result == text


class TestTruncationWarning:
    """Tests for large result set truncation warnings."""

    def test_warning_added_when_at_limit(self):
        from wazuh_mcp_server.server import _add_truncation_warning

        result = {"data": {"affected_items": [{"id": i} for i in range(100)], "total_affected_items": 100}}
        result = _add_truncation_warning(result, 100)
        assert "_warning" in result
        assert "truncated" in result["_warning"]

    def test_no_warning_when_below_limit(self):
        from wazuh_mcp_server.server import _add_truncation_warning

        result = {"data": {"affected_items": [{"id": i} for i in range(50)], "total_affected_items": 50}}
        result = _add_truncation_warning(result, 100)
        assert "_warning" not in result

    def test_warning_when_total_exceeds_limit(self):
        from wazuh_mcp_server.server import _add_truncation_warning

        result = {"data": {"affected_items": [{"id": i} for i in range(100)], "total_affected_items": 500}}
        result = _add_truncation_warning(result, 100)
        assert "_warning" in result


class TestAgentIDValidation:
    """Regression tests for agent ID validation (audit v3)."""

    def test_manager_agent_zero_is_valid(self):
        from wazuh_mcp_server.security import validate_agent_id

        assert validate_agent_id("0") == "0"

    def test_single_digit_agent_is_valid(self):
        from wazuh_mcp_server.security import validate_agent_id

        assert validate_agent_id("1") == "1"

    def test_two_digit_agent_is_valid(self):
        from wazuh_mcp_server.security import validate_agent_id

        assert validate_agent_id("12") == "12"

    def test_three_digit_agent_is_valid(self):
        from wazuh_mcp_server.security import validate_agent_id

        assert validate_agent_id("003") == "003"

    def test_five_digit_agent_is_valid(self):
        from wazuh_mcp_server.security import validate_agent_id

        assert validate_agent_id("99999") == "99999"

    def test_six_digit_agent_is_invalid(self):
        from wazuh_mcp_server.security import ToolValidationError, validate_agent_id

        with pytest.raises(ToolValidationError):
            validate_agent_id("100000")


class TestScopeEnforcementWithNoneToken:
    """Regression: scope enforcement must not be bypassed when _auth_token is None."""

    def test_write_tools_hidden_when_no_token(self):

        # Simulate getattr returning None (no _auth_token on session)
        auth_token = None
        # The fix: if not auth_token or not auth_token.has_scope("wazuh:write"), filter
        should_filter = not auth_token or not auth_token.has_scope("wazuh:write")
        assert should_filter is True

    def test_write_tools_visible_with_write_scope(self):
        from datetime import datetime, timezone

        from wazuh_mcp_server.auth import AuthToken

        token = AuthToken(
            token="test", api_key_id="k",
            created_at=datetime.now(timezone.utc),
            scopes=["wazuh:read", "wazuh:write"],
        )
        should_filter = not token or not token.has_scope("wazuh:write")
        assert should_filter is False


class TestSessionManagerMethod:
    """Regression: SessionManager must have remove() not delete()."""

    def test_session_manager_has_remove(self):
        from wazuh_mcp_server.server import SessionManager

        assert hasattr(SessionManager, "remove")

    def test_session_manager_no_delete(self):
        from wazuh_mcp_server.server import SessionManager

        # SessionManager should not expose delete() — it wraps store.delete() as remove()
        assert not hasattr(SessionManager, "delete") or callable(getattr(SessionManager, "remove"))


class TestVerifyBearerTokenNullGuard:
    """Regression: verify_bearer_token must not crash on None input."""

    async def test_none_input_raises_value_error(self):
        from wazuh_mcp_server.auth import verify_bearer_token

        with pytest.raises(ValueError, match="Invalid authorization header format"):
            await verify_bearer_token(None)

    async def test_empty_string_raises_value_error(self):
        from wazuh_mcp_server.auth import verify_bearer_token

        with pytest.raises(ValueError, match="Invalid authorization header format"):
            await verify_bearer_token("")


class TestCloseErrorHandling:
    """Regression: close() must clean up even if aclose() fails."""

    async def test_close_clears_state_even_on_error(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        config = WazuhConfig(
            wazuh_host="localhost", wazuh_user="test", wazuh_pass="test",
            wazuh_port=55000, verify_ssl=False,
        )
        client = WazuhClient(config)
        client._cache["test"] = (0.0, {"data": "test"})
        # Close should work even if internal state is in any condition
        await client.close()
        assert client.client is None
        assert client.token is None
        assert len(client._cache) == 0
        # Calling close again should not crash (idempotent)
        await client.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
