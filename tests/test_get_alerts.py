"""Tests for get_alerts tool."""

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime
from tests.fixtures.mock_data import MockWazuhData


class TestGetAlerts:
    """Test cases for get_alerts tool."""
    
    @pytest.fixture
    def server(self):
        """Create a mock server instance."""
        from wazuh_mcp_server.wazuh_mcp_server.main import WazuhMCPServer
        with patch('src.wazuh_mcp_server.main.setup_logging'):
            with patch('src.wazuh_mcp_server.main.WazuhConfig'):
                server = WazuhMCPServer()
                server.client_manager = AsyncMock()
                server.logger = AsyncMock()
                return server
    
    @pytest.mark.asyncio
    async def test_get_alerts_basic(self, server):
        """Test basic alert retrieval."""
        # Mock response
        server.client_manager.alerts.search.return_value = MockWazuhData.get_mock_alerts(3)
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_alerts",
            arguments={}
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Alerts" in content
        assert "Total: 3" in content
    
    @pytest.mark.asyncio
    async def test_get_alerts_with_filters(self, server):
        """Test alert retrieval with filters."""
        # Mock response
        filtered_alerts = MockWazuhData.get_mock_alerts(1)
        server.client_manager.alerts.search.return_value = filtered_alerts
        
        # Call tool with filters
        result = await server.handle_tool_call(
            name="get_alerts",
            arguments={
                "level": "10",
                "limit": "50"
            }
        )
        
        # Verify
        assert result is not None
        server.client_manager.alerts.search.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_get_alerts_with_time_range(self, server):
        """Test alert retrieval with time range."""
        # Mock response
        server.client_manager.alerts.search.return_value = MockWazuhData.get_mock_alerts(3)
        
        # Call tool with time range
        result = await server.handle_tool_call(
            name="get_alerts",
            arguments={
                "start_time": "2024-01-01T00:00:00Z",
                "end_time": "2024-01-02T00:00:00Z"
            }
        )
        
        # Verify
        assert result is not None
        server.client_manager.alerts.search.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_get_alerts_with_agent_filter(self, server):
        """Test alert retrieval filtered by agent."""
        # Mock response
        agent_alerts = MockWazuhData.get_mock_alerts(1)
        server.client_manager.alerts.search.return_value = agent_alerts
        
        # Call tool with agent filter
        result = await server.handle_tool_call(
            name="get_alerts",
            arguments={
                "agent_id": "001"
            }
        )
        
        # Verify
        assert result is not None
        server.client_manager.alerts.search.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_get_alerts_empty_response(self, server):
        """Test handling of empty alert response."""
        # Mock empty response
        empty_response = MockWazuhData.get_mock_alerts(0)
        server.client_manager.alerts.search.return_value = empty_response
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_alerts",
            arguments={}
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "No alerts found" in content
        
    @pytest.mark.asyncio
    async def test_get_alerts_error_handling(self, server):
        """Test error handling in alert retrieval."""
        # Mock error
        server.client_manager.alerts.search.side_effect = Exception("API Error")
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_alerts",
            arguments={}
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content