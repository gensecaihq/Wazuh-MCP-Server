"""Tests for analyze_threats tool."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from tests.fixtures.mock_data import MockWazuhData


class TestAnalyzeThreats:
    """Test cases for analyze_threats tool."""
    
    @pytest.fixture
    def server(self):
        """Create a mock server instance."""
        from wazuh_mcp_server.wazuh_mcp_server.main import WazuhMCPServer
        with patch('src.wazuh_mcp_server.main.setup_logging'):
            with patch('src.wazuh_mcp_server.main.WazuhConfig'):
                server = WazuhMCPServer()
                server.client_manager = AsyncMock()
                server.security_analyzer = MagicMock()
                server.logger = AsyncMock()
                return server
    
    @pytest.mark.asyncio
    async def test_analyze_threats_basic(self, server):
        """Test basic threat analysis."""
        # Mock responses
        server.client_manager.alerts.search.return_value = MockWazuhData.get_mock_alerts(3)
        server.client_manager.agents.get_list.return_value = {
            "data": {
                "affected_items": [{"id": "001", "name": "agent1", "status": "active"}],
                "total_affected_items": 1
            }
        }
        server.security_analyzer.analyze_threats.return_value = {
            "risk_score": 75,
            "threat_level": "HIGH",
            "critical_alerts": 2,
            "recommendations": ["Enable MFA", "Update systems"]
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="analyze_threats",
            arguments={}
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Threat Analysis" in content
        assert "HIGH" in content
        
    @pytest.mark.asyncio
    async def test_analyze_threats_with_timeframe(self, server):
        """Test threat analysis with specific timeframe."""
        # Mock responses
        server.client_manager.alerts.search.return_value = MockWazuhData.get_mock_alerts(3)
        server.security_analyzer.analyze_threats.return_value = {
            "risk_score": 45,
            "threat_level": "MEDIUM",
            "critical_alerts": 1,
            "trending_threats": ["Brute force attempts", "SQL injection"]
        }
        
        # Call tool with timeframe
        result = await server.handle_tool_call(
            name="analyze_threats",
            arguments={
                "timeframe": "24h"
            }
        )
        
        # Verify
        assert result is not None
        server.security_analyzer.analyze_threats.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_analyze_threats_with_focus_area(self, server):
        """Test threat analysis with specific focus area."""
        # Mock responses
        server.client_manager.alerts.search.return_value = MockWazuhData.get_mock_alerts(3)
        server.security_analyzer.analyze_threats.return_value = {
            "risk_score": 85,
            "threat_level": "CRITICAL",
            "focus_area": "malware",
            "malware_detections": 5,
            "affected_systems": ["web-server-1", "db-server-2"]
        }
        
        # Call tool with focus area
        result = await server.handle_tool_call(
            name="analyze_threats",
            arguments={
                "focus_area": "malware"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "malware" in content.lower()
        
    @pytest.mark.asyncio
    async def test_analyze_threats_with_agent_filter(self, server):
        """Test threat analysis for specific agent."""
        # Mock responses
        agent_alerts = MockWazuhData.get_mock_alerts(1)
        server.client_manager.alerts.search.return_value = agent_alerts
        server.security_analyzer.analyze_threats.return_value = {
            "risk_score": 60,
            "threat_level": "MEDIUM",
            "agent_specific": True,
            "agent_id": "002"
        }
        
        # Call tool with agent filter
        result = await server.handle_tool_call(
            name="analyze_threats",
            arguments={
                "agent_id": "002"
            }
        )
        
        # Verify
        assert result is not None
        server.client_manager.alerts.search.assert_called()
        
    @pytest.mark.asyncio
    async def test_analyze_threats_no_threats(self, server):
        """Test threat analysis with no threats found."""
        # Mock empty response
        server.client_manager.alerts.search.return_value = {
            "data": {"affected_items": [], "total_affected_items": 0}
        }
        server.security_analyzer.analyze_threats.return_value = {
            "risk_score": 0,
            "threat_level": "LOW",
            "critical_alerts": 0,
            "message": "No significant threats detected"
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="analyze_threats",
            arguments={}
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "LOW" in content or "No significant threats" in content
        
    @pytest.mark.asyncio
    async def test_analyze_threats_error_handling(self, server):
        """Test error handling in threat analysis."""
        # Mock error
        server.client_manager.alerts.search.side_effect = Exception("Analysis failed")
        
        # Call tool
        result = await server.handle_tool_call(
            name="analyze_threats",
            arguments={}
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content