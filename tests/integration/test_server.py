"""Comprehensive tests for the Wazuh MCP Server."""

import pytest
import json
from unittest.mock import AsyncMock, patch, MagicMock
from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.config import WazuhConfig, ConfigurationError


class TestWazuhMCPServer:
    """Test cases for WazuhMCPServer."""
    
    @pytest.fixture
    def mock_config_env(self):
        """Mock environment for config creation."""
        with patch.dict('os.environ', {
            'WAZUH_HOST': 'test.example.com',
            'WAZUH_USER': 'testuser',
            'WAZUH_PASS': 'testpassword123',
            'WAZUH_PORT': '55000',
            'DEBUG': 'true'
        }):
            yield
    
    @pytest.fixture
    def server(self, mock_config_env):
        """Create a WazuhMCPServer instance for testing."""
        with patch('src.wazuh_mcp_server.setup_logging'):
            server = WazuhMCPServer()
            return server
    
    def test_server_initialization(self, mock_config_env):
        """Test server initialization."""
        with patch('src.wazuh_mcp_server.setup_logging'):
            server = WazuhMCPServer()
            
            assert server.config is not None
            assert server.api_client is not None
            assert server.security_analyzer is not None
            assert server.compliance_analyzer is not None
    
    def test_server_initialization_config_error(self):
        """Test server initialization with config error."""
        with patch('src.config.WazuhConfig.from_env') as mock_config:
            mock_config.side_effect = Exception("Config error")
            
            with pytest.raises(ConfigurationError):
                WazuhMCPServer()
    
    def test_format_alerts(self, server, sample_alerts, mock_wazuh_api_response):
        """Test alert formatting."""
        api_response = mock_wazuh_api_response(sample_alerts)
        formatted = server._format_alerts(api_response)
        
        assert "total_alerts" in formatted
        assert "alerts" in formatted
        assert "query_time" in formatted
        assert len(formatted["alerts"]) == len(sample_alerts)
        
        # Check first alert format
        first_alert = formatted["alerts"][0]
        assert "id" in first_alert
        assert "timestamp" in first_alert
        assert "rule" in first_alert
        assert "agent" in first_alert
    
    def test_format_agents(self, server, sample_agents, mock_wazuh_api_response):
        """Test agent formatting."""
        api_response = mock_wazuh_api_response(sample_agents)
        formatted = server._format_agents(api_response)
        
        assert "summary" in formatted
        assert "total_agents" in formatted
        assert "agents" in formatted
        
        # Check summary counts
        summary = formatted["summary"]
        assert summary["active"] == 2  # From sample data
        assert summary["disconnected"] == 1
        
        assert len(formatted["agents"]) == len(sample_agents)
    
    def test_assess_agent_health_healthy(self, server, sample_agents):
        """Test agent health assessment for healthy agent."""
        healthy_agent = sample_agents[0]  # Active agent
        health = server._assess_agent_health(healthy_agent)
        
        assert health["health_status"] == "healthy"
        assert health["agent_id"] == "001"
        assert health["status"] == "active"
        assert "details" in health
    
    def test_assess_agent_health_unhealthy(self, server, sample_agents):
        """Test agent health assessment for unhealthy agent."""
        unhealthy_agent = sample_agents[1]  # Disconnected agent
        health = server._assess_agent_health(unhealthy_agent)
        
        assert health["health_status"] == "unhealthy"
        assert health["agent_id"] == "002"
        assert health["status"] == "disconnected"
    
    def test_assess_all_agents_health(self, server, sample_agents, mock_wazuh_api_response):
        """Test health assessment for all agents."""
        api_response = mock_wazuh_api_response(sample_agents)
        health_report = server._assess_all_agents_health(api_response)
        
        assert health_report["total_agents"] == 3
        assert health_report["healthy"] == 2
        assert health_report["unhealthy"] == 1
        assert health_report["health_percentage"] == pytest.approx(66.67, rel=1e-2)
        assert len(health_report["agents"]) == 3
    
    def test_generate_alert_summary(self, server, sample_alerts, mock_wazuh_api_response):
        """Test alert summary generation."""
        api_response = mock_wazuh_api_response(sample_alerts)
        summary = server._generate_alert_summary(api_response)
        
        assert "total_alerts" in summary
        assert "severity_distribution" in summary
        assert "top_rules" in summary
        assert "top_agents" in summary
        
        # Check severity distribution
        severity_dist = summary["severity_distribution"]
        assert "low" in severity_dist
        assert "medium" in severity_dist
        assert "high" in severity_dist
    
    def test_generate_alert_summary_empty(self, server, mock_wazuh_api_response):
        """Test alert summary with no alerts."""
        api_response = mock_wazuh_api_response([])
        summary = server._generate_alert_summary(api_response)
        
        assert "message" in summary
        assert summary["message"] == "No alerts to summarize"
    
    @pytest.mark.asyncio
    async def test_handle_get_alerts(self, server):
        """Test get_alerts tool handler."""
        with patch.object(server.api_client, 'get_alerts') as mock_get_alerts:
            mock_get_alerts.return_value = {
                "data": {"affected_items": [], "total_affected_items": 0}
            }
            
            arguments = {"limit": 50, "level": 10}
            result = await server._handle_get_alerts(arguments)
            
            assert len(result) == 1
            assert result[0].type == "text"
            
            # Parse the JSON response
            response_data = json.loads(result[0].text)
            assert "total_alerts" in response_data
            assert "alerts" in response_data
    
    @pytest.mark.asyncio
    async def test_handle_analyze_threats(self, server, sample_alerts):
        """Test analyze_threats tool handler."""
        with patch.object(server.api_client, 'get_alerts') as mock_get_alerts:
            mock_get_alerts.return_value = {
                "data": {"affected_items": sample_alerts, "total_affected_items": len(sample_alerts)}
            }
            
            arguments = {"category": "all", "time_range": 3600}
            result = await server._handle_analyze_threats(arguments)
            
            assert len(result) == 1
            assert result[0].type == "text"
            
            # Parse the JSON response
            response_data = json.loads(result[0].text)
            assert "category" in response_data
            assert "total_alerts" in response_data
            assert "risk_assessment" in response_data
    
    @pytest.mark.asyncio
    async def test_handle_check_agent_health_specific(self, server, sample_agents):
        """Test check_agent_health tool handler for specific agent."""
        with patch.object(server.api_client, 'get_agents') as mock_get_agents:
            mock_get_agents.return_value = {
                "data": {"affected_items": sample_agents, "total_affected_items": len(sample_agents)}
            }
            
            arguments = {"agent_id": "001"}
            result = await server._handle_check_agent_health(arguments)
            
            assert len(result) == 1
            assert result[0].type == "text"
            
            # Parse the JSON response
            response_data = json.loads(result[0].text)
            assert response_data["agent_id"] == "001"
            assert "health_status" in response_data
    
    @pytest.mark.asyncio
    async def test_handle_check_agent_health_not_found(self, server, sample_agents):
        """Test check_agent_health tool handler for non-existent agent."""
        with patch.object(server.api_client, 'get_agents') as mock_get_agents:
            mock_get_agents.return_value = {
                "data": {"affected_items": sample_agents, "total_affected_items": len(sample_agents)}
            }
            
            arguments = {"agent_id": "999"}
            result = await server._handle_check_agent_health(arguments)
            
            assert len(result) == 1
            response_data = json.loads(result[0].text)
            assert "error" in response_data
            assert "Agent ID 999 not found" in response_data["error"]
    
    @pytest.mark.asyncio
    async def test_handle_compliance_check(self, server, sample_alerts, sample_agents):
        """Test compliance_check tool handler."""
        with patch.object(server.api_client, 'get_alerts') as mock_get_alerts, \
             patch.object(server.api_client, 'get_agents') as mock_get_agents, \
             patch.object(server.api_client, 'get_agent_vulnerabilities') as mock_get_vulns:
            
            mock_get_alerts.return_value = {
                "data": {"affected_items": sample_alerts, "total_affected_items": len(sample_alerts)}
            }
            mock_get_agents.return_value = {
                "data": {"affected_items": sample_agents, "total_affected_items": len(sample_agents)}
            }
            mock_get_vulns.return_value = {
                "data": {"affected_items": [], "total_affected_items": 0}
            }
            
            arguments = {"framework": "pci_dss", "include_evidence": True}
            result = await server._handle_compliance_check(arguments)
            
            assert len(result) == 1
            assert result[0].type == "text"
            
            # Parse the JSON response
            response_data = json.loads(result[0].text)
            assert "framework" in response_data
            assert "overall_score" in response_data
            assert "status" in response_data
            assert "requirements" in response_data
    
    @pytest.mark.asyncio
    async def test_handle_risk_assessment(self, server, sample_alerts, sample_agents):
        """Test risk_assessment tool handler."""
        with patch.object(server.api_client, 'get_alerts') as mock_get_alerts, \
             patch.object(server.api_client, 'get_agents') as mock_get_agents, \
             patch.object(server.api_client, 'get_agent_vulnerabilities') as mock_get_vulns:
            
            mock_get_alerts.return_value = {
                "data": {"affected_items": sample_alerts, "total_affected_items": len(sample_alerts)}
            }
            mock_get_agents.return_value = {
                "data": {"affected_items": sample_agents, "total_affected_items": len(sample_agents)}
            }
            mock_get_vulns.return_value = {
                "data": {"affected_items": [], "total_affected_items": 0}
            }
            
            arguments = {"time_window_hours": 24, "include_vulnerabilities": True}
            result = await server._handle_risk_assessment(arguments)
            
            assert len(result) == 1
            assert result[0].type == "text"
            
            # Parse the JSON response
            response_data = json.loads(result[0].text)
            assert "assessment_period" in response_data
            assert "risk_score" in response_data
            assert "risk_level" in response_data
            assert "factors" in response_data

    @pytest.mark.asyncio
    async def test_handle_get_agent_processes(self, server):
        """Test get_agent_processes tool handler."""
        with patch.object(server.api_client.server_client, 'get_agent_processes') as mock_get_agent_processes:
            mock_get_agent_processes.return_value = {
                "data": {"affected_items": [{"name": "test_process"}], "total_affected_items": 1}
            }

            arguments = {"agent_id": "001"}
            result = await server._handle_get_agent_processes(arguments)

            assert len(result) == 1
            assert result[0].type == "text"

            # Parse the JSON response
            response_data = json.loads(result[0].text)
            assert "data" in response_data
            assert "affected_items" in response_data["data"]
            assert len(response_data["data"]["affected_items"]) == 1
            assert response_data["data"]["affected_items"][0]["name"] == "test_process"
