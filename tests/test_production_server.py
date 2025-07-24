#!/usr/bin/env python3
"""
Comprehensive test suite for the production-ready Wazuh MCP Server.
Tests all core functionality, error handling, and production features.
"""

import sys
import os
import pytest
import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from datetime import datetime, timedelta
import tempfile

# Add the source directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from wazuh_mcp_server import server
from wazuh_mcp_server.config import WazuhConfig, ConfigurationError
from wazuh_mcp_server.utils.exceptions import APIError, ValidationError


class TestWazuhMCPServer:
    """Test suite for the main server functionality."""
    
    @pytest.fixture
    def mock_config(self):
        """Mock configuration for testing."""
        return WazuhConfig(
            host="test-wazuh.example.com",
            port=55000,
            username="test_user",
            password="test_password_123",
            verify_ssl=False,
            request_timeout_seconds=30,
            max_connections=10
        )
    
    @pytest.fixture
    def mock_http_client(self):
        """Mock HTTP client for testing."""
        client = AsyncMock()
        client.request = AsyncMock()
        client.aclose = AsyncMock()
        return client
    
    @pytest.fixture
    def sample_alerts(self):
        """Sample alert data for testing."""
        return [
            {
                "rule": {
                    "id": "5551",
                    "level": 8,
                    "description": "Multiple authentication failures",
                    "groups": ["authentication", "pci_dss_8.2.3"]
                },
                "agent": {"id": "001", "name": "web-server-01"},
                "timestamp": "2024-01-15T10:30:00.000Z",
                "location": "/var/log/auth.log"
            },
            {
                "rule": {
                    "id": "31106",
                    "level": 12,
                    "description": "Malware detected",
                    "groups": ["malware", "virustotal"]
                },
                "agent": {"id": "002", "name": "db-server-01"},
                "timestamp": "2024-01-15T10:32:00.000Z",
                "location": "/var/log/syslog"
            }
        ]
    
    @pytest.fixture
    def sample_agents(self):
        """Sample agent data for testing."""
        return [
            {
                "id": "001",
                "name": "web-server-01",
                "ip": "192.168.1.100",
                "status": "active",
                "lastKeepAlive": "2024-01-15T10:29:00.000Z",
                "version": "v4.8.0",
                "os": {"name": "Ubuntu 22.04"},
                "dateAdd": "2024-01-01T00:00:00.000Z"
            },
            {
                "id": "002",
                "name": "db-server-01",
                "ip": "192.168.1.101",
                "status": "disconnected",
                "lastKeepAlive": "2024-01-15T08:00:00.000Z",
                "version": "v4.7.3",
                "os": {"name": "CentOS 8"},
                "dateAdd": "2024-01-01T00:00:00.000Z"
            }
        ]
    
    @pytest.mark.asyncio
    async def test_server_initialization(self, mock_config):
        """Test server initialization process."""
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_http_client') as mock_get_client:
                mock_get_client.return_value = AsyncMock()
                
                # Test successful initialization
                result = await server.initialize_server()
                assert result is True
                assert server._server_start_time is not None
                assert server._health_status["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_wazuh_api_request_success(self, mock_config, mock_http_client):
        """Test successful Wazuh API request."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"affected_items": [{"test": "data"}]}
        }
        mock_http_client.request.return_value = mock_response
        
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_http_client', return_value=mock_http_client):
                with patch('wazuh_mcp_server.server.get_rate_limiter') as mock_rate_limiter:
                    mock_rate_limiter.return_value.acquire = AsyncMock()
                    
                    result = await server.wazuh_api_request('/test-endpoint')
                    
                    assert result == {"data": {"affected_items": [{"test": "data"}]}}
                    mock_http_client.request.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_wazuh_api_request_auth_failure(self, mock_config, mock_http_client):
        """Test API request with authentication failure."""
        # Mock 401 response
        mock_response = Mock()
        mock_response.status_code = 401
        mock_http_client.request.return_value = mock_response
        
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_http_client', return_value=mock_http_client):
                with patch('wazuh_mcp_server.server.get_rate_limiter') as mock_rate_limiter:
                    mock_rate_limiter.return_value.acquire = AsyncMock()
                    
                    with pytest.raises(APIError, match="Authentication failed"):
                        await server.wazuh_api_request('/test-endpoint')
    
    @pytest.mark.asyncio
    async def test_get_wazuh_alerts(self, mock_config, sample_alerts):
        """Test get_wazuh_alerts tool functionality."""
        mock_ctx = AsyncMock()
        
        with patch('wazuh_mcp_server.server.wazuh_api_request') as mock_api:
            mock_api.return_value = {"data": {"affected_items": sample_alerts}}
            
            result = await server.get_wazuh_alerts(
                limit=100,
                level=5,
                ctx=mock_ctx
            )
            
            assert result["success"] is True
            assert len(result["alerts"]) == 2
            assert result["total_count"] == 2
            
            # Check enrichment
            first_alert = result["alerts"][0]
            assert "enrichment" in first_alert
            assert first_alert["enrichment"]["severity_label"] == "high"
            assert first_alert["enrichment"]["category"] == "authentication"
            
            # Verify context calls
            mock_ctx.info.assert_called()
    
    @pytest.mark.asyncio
    async def test_get_wazuh_alerts_validation(self, mock_config):
        """Test input validation for get_wazuh_alerts."""
        mock_ctx = AsyncMock()
        
        with patch('wazuh_mcp_server.server.wazuh_api_request') as mock_api:
            mock_api.return_value = {"data": {"affected_items": []}}
            
            # Test limit validation (should clamp to max)
            result = await server.get_wazuh_alerts(
                limit=20000,  # Over max
                level=20,     # Over max
                ctx=mock_ctx
            )
            
            assert result["success"] is True
            assert result["query_params"]["limit"] == 10000  # Clamped to max
            assert result["query_params"]["level"] == 15     # Clamped to max
    
    @pytest.mark.asyncio
    async def test_analyze_security_threats(self, mock_config, sample_alerts):
        """Test AI-powered threat analysis."""
        mock_ctx = AsyncMock()
        mock_ctx.sample = AsyncMock(return_value=Mock(content='{"threat_level": "HIGH", "key_findings": ["Multiple attacks detected"]}'))
        
        with patch('wazuh_mcp_server.server.wazuh_api_request') as mock_api:
            mock_api.return_value = {"data": {"affected_items": sample_alerts}}
            
            result = await server.analyze_security_threats(
                time_range="24h",
                focus_area="authentication",
                min_severity=5,
                ctx=mock_ctx
            )
            
            assert result["success"] is True
            assert result["threat_level"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            assert "ai_analysis" in result
            assert "statistical_summary" in result
            
            # Verify AI model was called
            mock_ctx.sample.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_check_wazuh_agent_health(self, mock_config, sample_agents):
        """Test agent health checking functionality."""
        mock_ctx = AsyncMock()
        
        with patch('wazuh_mcp_server.server.wazuh_api_request') as mock_api:
            mock_api.return_value = {"data": {"affected_items": sample_agents}}
            
            result = await server.check_wazuh_agent_health(
                agent_id="",
                include_disconnected=True,
                health_threshold=0.0,
                ctx=mock_ctx
            )
            
            assert result["success"] is True
            assert result["health_summary"]["total_agents"] == 2
            assert result["health_summary"]["active_agents"] == 1
            assert result["health_summary"]["disconnected_agents"] == 1
            assert "recommendations" in result
            
            # Check agent details
            assert len(result["agent_details"]["active"]) == 1
            assert len(result["agent_details"]["disconnected"]) == 1
    
    @pytest.mark.asyncio
    async def test_get_server_health(self, mock_config):
        """Test server health monitoring."""
        mock_ctx = AsyncMock()
        
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_http_client') as mock_get_client:
                mock_get_client.return_value = AsyncMock()
                with patch('wazuh_mcp_server.server.wazuh_api_request') as mock_api:
                    mock_api.return_value = {"data": {"authenticated": True}}
                    
                    result = await server.get_server_health(ctx=mock_ctx)
                    
                    assert result["status"] in ["healthy", "degraded", "unhealthy"]
                    assert "checks" in result
                    assert "metrics" in result
                    assert "timestamp" in result
                    assert "version" in result
    
    @pytest.mark.asyncio
    async def test_get_cluster_status(self, mock_config):
        """Test cluster status resource."""
        with patch('wazuh_mcp_server.server.wazuh_api_request') as mock_api:
            mock_api.side_effect = [
                {"data": {"affected_items": [{"enabled": True, "running": "yes"}]}},
                {"data": {"affected_items": [{"version": "4.8.0", "type": "manager"}]}},
                {"data": {"affected_items": [{"name": "worker-1", "type": "worker"}]}}
            ]
            
            result = await server.get_cluster_status()
            
            assert "cluster_info" in result
            assert "manager_info" in result
            assert "status" in result
            assert result["status"] == "healthy"
    
    @pytest.mark.asyncio
    async def test_get_security_overview(self, mock_config, sample_alerts, sample_agents):
        """Test security overview resource."""
        with patch('wazuh_mcp_server.server.wazuh_api_request') as mock_api:
            mock_api.side_effect = [
                {"data": {"affected_items": sample_alerts}},  # Recent alerts
                {"data": {"affected_items": sample_alerts[:1]}},  # Critical alerts
                {"data": {"affected_items": sample_agents}}  # Agents
            ]
            
            result = await server.get_security_overview()
            
            assert "overall_status" in result
            assert "risk_score" in result
            assert "recent_activity" in result
            assert "infrastructure" in result
            assert "threat_indicators" in result
            assert "recommendations" in result
    
    def test_calculate_agent_health_score(self, sample_agents):
        """Test agent health scoring algorithm."""
        # Test active agent
        active_agent = sample_agents[0]
        score = server.calculate_agent_health_score(active_agent)
        assert 80 <= score <= 100  # Should be high for active agent
        
        # Test disconnected agent
        disconnected_agent = sample_agents[1]
        score = server.calculate_agent_health_score(disconnected_agent)
        assert 0 <= score <= 50  # Should be low for disconnected agent
    
    def test_analyze_alert_patterns(self, sample_alerts):
        """Test alert pattern analysis."""
        result = server.analyze_alert_patterns(sample_alerts)
        
        assert "trend" in result
        assert "patterns" in result
        assert "top_rules" in result
        assert "category_distribution" in result
        
        # Check patterns detection
        assert len(result["patterns"]) > 0
        assert any("authentication" in pattern.lower() for pattern in result["patterns"])
    
    def test_calculate_risk_level(self, sample_alerts, sample_agents):
        """Test risk level calculation."""
        result = server.calculate_risk_level(sample_alerts, sample_alerts[:1], sample_agents)
        
        assert "score" in result
        assert "status" in result
        assert "factors" in result
        assert result["status"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert 0 <= result["score"] <= 100
    
    def test_generate_security_recommendations(self, sample_alerts, sample_agents):
        """Test security recommendations generation."""
        risk_level = {"status": "HIGH", "factors": {"critical_alerts": 30}}
        alert_analysis = {"patterns": ["authentication activity"], "trend": "increasing"}
        
        recommendations = server.generate_security_recommendations(risk_level, alert_analysis, 85.0)
        
        assert len(recommendations) > 0
        assert any("HIGH PRIORITY" in rec for rec in recommendations)
    
    @pytest.mark.asyncio
    async def test_cleanup_server(self, mock_http_client):
        """Test server cleanup process."""
        server._http_client = mock_http_client
        
        await server.cleanup_server()
        
        mock_http_client.aclose.assert_called_once()
        assert server._http_client is None


class TestErrorHandling:
    """Test error handling and edge cases."""
    
    @pytest.mark.asyncio
    async def test_api_request_network_error(self):
        """Test handling of network errors in API requests."""
        mock_ctx = AsyncMock()
        
        with patch('wazuh_mcp_server.server.get_config') as mock_get_config:
            mock_get_config.return_value = Mock(
                base_url="https://test.example.com",
                username="test",
                password="pass",
                request_timeout_seconds=30
            )
            
            with patch('wazuh_mcp_server.server.get_http_client') as mock_get_client:
                mock_client = AsyncMock()
                mock_client.request.side_effect = Exception("Network error")
                mock_get_client.return_value = mock_client
                
                with patch('wazuh_mcp_server.server.get_rate_limiter') as mock_rate_limiter:
                    mock_rate_limiter.return_value.acquire = AsyncMock()
                    
                    with pytest.raises(APIError):
                        await server.wazuh_api_request('/test', ctx=mock_ctx)
    
    @pytest.mark.asyncio
    async def test_get_alerts_api_error(self):
        """Test error handling in get_wazuh_alerts."""
        mock_ctx = AsyncMock()
        
        with patch('wazuh_mcp_server.server.wazuh_api_request') as mock_api:
            mock_api.side_effect = APIError("API connection failed")
            
            result = await server.get_wazuh_alerts(ctx=mock_ctx)
            
            assert result["success"] is False
            assert "error" in result
            assert "API connection failed" in result["error"]
    
    @pytest.mark.asyncio
    async def test_agent_health_api_error(self):
        """Test error handling in check_wazuh_agent_health."""
        mock_ctx = AsyncMock()
        
        with patch('wazuh_mcp_server.server.wazuh_api_request') as mock_api:
            mock_api.side_effect = APIError("Agents endpoint unavailable")
            
            result = await server.check_wazuh_agent_health(ctx=mock_ctx)
            
            assert result["success"] is False
            assert "error" in result
            assert "Agents endpoint unavailable" in result["error"]
    
    def test_invalid_agent_data(self):
        """Test handling of invalid agent data."""
        invalid_agent = {"id": "test", "status": "unknown"}  # Missing required fields
        
        # Should handle gracefully without crashing
        score = server.calculate_agent_health_score(invalid_agent)
        assert 0 <= score <= 100
    
    def test_empty_alerts_analysis(self):
        """Test alert analysis with empty data."""
        result = server.analyze_alert_patterns([])
        
        assert result["trend"] == "no_data"
        assert result["patterns"] == []
        assert result["top_rules"] == []


class TestConfiguration:
    """Test configuration management."""
    
    def test_config_validation_success(self):
        """Test successful configuration validation."""
        config = WazuhConfig(
            host="wazuh.example.com",
            port=55000,
            username="admin",
            password="secure_password_123",
            verify_ssl=True
        )
        
        assert config.host == "wazuh.example.com"
        assert config.port == 55000
        assert config.base_url == "https://wazuh.example.com:55000"
    
    def test_config_validation_failures(self):
        """Test configuration validation failures."""
        # Test missing host
        with pytest.raises(ValueError):
            WazuhConfig(
                host="",
                username="admin",
                password="password"
            )
        
        # Test weak password
        with pytest.raises(ValueError):
            WazuhConfig(
                host="wazuh.example.com",
                username="admin",
                password="123"  # Too short
            )
        
        # Test default weak password
        with pytest.raises(ValueError):
            WazuhConfig(
                host="wazuh.example.com",
                username="admin",
                password="admin"  # Default/weak
            )
    
    def test_config_from_env(self):
        """Test configuration loading from environment variables."""
        env_vars = {
            "WAZUH_HOST": "test.wazuh.com",
            "WAZUH_PORT": "55000",
            "WAZUH_USER": "test_user",
            "WAZUH_PASS": "test_password_123",
            "VERIFY_SSL": "false"
        }
        
        with patch.dict(os.environ, env_vars):
            config = WazuhConfig.from_env()
            
            assert config.host == "test.wazuh.com"
            assert config.port == 55000
            assert config.username == "test_user"
            assert config.verify_ssl is False


class TestUtilities:
    """Test utility functions."""
    
    def test_validate_int_range(self):
        """Test integer range validation."""
        from wazuh_mcp_server.utils.validation import validate_int_range
        
        # Test normal case
        assert validate_int_range(50, 1, 100, 10) == 50
        
        # Test clamping to min
        assert validate_int_range(-5, 1, 100, 10) == 1
        
        # Test clamping to max
        assert validate_int_range(150, 1, 100, 10) == 100
        
        # Test invalid input with default
        assert validate_int_range("invalid", 1, 100, 10) == 10
        assert validate_int_range(None, 1, 100, 10) == 10
    
    def test_validate_string(self):
        """Test string validation and sanitization."""
        from wazuh_mcp_server.utils.validation import validate_string
        
        # Test normal case
        assert validate_string("test", 10, "default") == "test"
        
        # Test truncation
        assert validate_string("very_long_string", 5, "default") == "very_"
        
        # Test None input
        assert validate_string(None, 10, "default") == "default"
        
        # Test dangerous character removal
        result = validate_string("test<script>", 20, "")
        assert "<script>" not in result
    
    def test_validate_time_range(self):
        """Test time range validation."""
        from wazuh_mcp_server.utils.validation import validate_time_range
        
        # Test valid time ranges
        assert validate_time_range("1h") == 3600
        assert validate_time_range("24h") == 86400
        assert validate_time_range("7d") == 604800
        
        # Test invalid time range
        assert validate_time_range("invalid") == 3600  # Default to 1 hour


@pytest.mark.integration
class TestIntegration:
    """Integration tests (require actual Wazuh instance or mocking)."""
    
    @pytest.mark.skip(reason="Requires live Wazuh instance")
    @pytest.mark.asyncio
    async def test_full_server_workflow(self):
        """Test complete server workflow with real Wazuh API."""
        # This test would require a real Wazuh instance
        # Skip by default, enable for integration testing
        pass
    
    @pytest.mark.asyncio
    async def test_server_startup_shutdown(self):
        """Test server startup and shutdown process."""
        with patch('wazuh_mcp_server.server.initialize_server', return_value=True):
            with patch('wazuh_mcp_server.server.cleanup_server') as mock_cleanup:
                with patch('wazuh_mcp_server.server.mcp.run_async') as mock_run:
                    mock_run.side_effect = KeyboardInterrupt()
                    
                    # Should handle KeyboardInterrupt gracefully
                    try:
                        await server.main()
                    except SystemExit:
                        pass
                    
                    mock_cleanup.assert_called_once()


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])