"""Tests for check_agent_health tool."""

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timedelta
from tests.fixtures.mock_data import MockWazuhData


class TestCheckAgentHealth:
    """Test cases for check_agent_health tool."""
    
    @pytest.fixture
    def server(self):
        """Create a mock server instance."""
        from wazuh_mcp_server.main import WazuhMCPServer
        with patch('wazuh_mcp_server.main.setup_logging'):
            with patch('wazuh_mcp_server.main.WazuhConfig'):
                server = WazuhMCPServer()
                server.client_manager = AsyncMock()
                server.logger = AsyncMock()
                return server
    
    @pytest.mark.asyncio
    async def test_check_agent_health_all_agents(self, server):
        """Test health check for all agents."""
        # Mock response
        agents_data = {
            "data": {
                "affected_items": [
                    {"id": "001", "status": "active", "name": "agent-001"},
                    {"id": "002", "status": "active", "name": "agent-002"},
                    {"id": "003", "status": "disconnected", "name": "agent-003"}
                ],
                "total_affected_items": 3
            }
        }
        server.client_manager.agents.get_list.return_value = agents_data
        
        # Mock individual agent stats
        server.client_manager.agents.get_stats.return_value = {
            "data": {
                "affected_items": [{
                    "cpu": {"usage": 45.2},
                    "memory": {"usage": 62.5},
                    "disk": {"usage": 35.0}
                }]
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="check_agent_health",
            arguments={}
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Agent Health Status" in content
        assert "Active: 2" in content
        assert "Disconnected: 1" in content
        
    @pytest.mark.asyncio
    async def test_check_agent_health_specific_agent(self, server):
        """Test health check for specific agent."""
        # Mock response
        agent_data = {
            "data": {
                "affected_items": [
                    {
                        "id": "001",
                        "status": "active",
                        "name": "agent-001",
                        "last_keepalive": (datetime.now() - timedelta(minutes=1)).isoformat()
                    }
                ],
                "total_affected_items": 1
            }
        }
        server.client_manager.agents.get_agent.return_value = agent_data
        
        # Mock agent stats
        server.client_manager.agents.get_stats.return_value = {
            "data": {
                "affected_items": [{
                    "cpu": {"usage": 25.5},
                    "memory": {"usage": 45.0, "total": 8192, "used": 3686},
                    "disk": {"usage": 40.0, "total": 500000, "used": 200000}
                }]
            }
        }
        
        # Call tool with agent_id
        result = await server.handle_tool_call(
            name="check_agent_health",
            arguments={
                "agent_id": "001"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Agent 001" in content
        assert "Status: active" in content
        assert "CPU Usage: 25.5%" in content
        
    @pytest.mark.asyncio
    async def test_check_agent_health_with_details(self, server):
        """Test health check with detailed information."""
        # Mock response
        agents_data = {
            "data": {
                "affected_items": [
                    {"id": "001", "status": "active", "name": "agent-001", "version": "4.8.0"}
                ],
                "total_affected_items": 1
            }
        }
        server.client_manager.agents.get_list.return_value = agents_data
        
        # Mock detailed stats
        server.client_manager.agents.get_stats.return_value = {
            "data": {
                "affected_items": [{
                    "cpu": {"usage": 55.0, "cores": 4},
                    "memory": {"usage": 70.0, "total": 16384, "used": 11469},
                    "disk": {"usage": 60.0, "total": 1000000, "used": 600000},
                    "network": {"rx_bytes": 1000000, "tx_bytes": 500000}
                }]
            }
        }
        
        # Call tool with include_details
        result = await server.handle_tool_call(
            name="check_agent_health",
            arguments={
                "include_details": "true"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Version: 4.8.0" in content
        assert "Network" in content
        
    @pytest.mark.asyncio
    async def test_check_agent_health_disconnected_agents(self, server):
        """Test health check focusing on disconnected agents."""
        # Mock response with disconnected agents
        agents_data = {
            "data": {
                "affected_items": [
                    {
                        "id": "001", 
                        "status": "disconnected",
                        "name": "agent-001",
                        "last_keepalive": (datetime.now() - timedelta(hours=2)).isoformat()
                    },
                    {
                        "id": "002", 
                        "status": "disconnected",
                        "name": "agent-002",
                        "last_keepalive": (datetime.now() - timedelta(days=1)).isoformat()
                    }
                ],
                "total_affected_items": 2
            }
        }
        server.client_manager.agents.get_list.return_value = agents_data
        
        # Call tool
        result = await server.handle_tool_call(
            name="check_agent_health",
            arguments={}
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "disconnected" in content.lower()
        assert "Last seen" in content
        
    @pytest.mark.asyncio
    async def test_check_agent_health_no_agents(self, server):
        """Test health check with no agents."""
        # Mock empty response
        server.client_manager.agents.get_list.return_value = {
            "data": {
                "affected_items": [],
                "total_affected_items": 0
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="check_agent_health",
            arguments={}
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "No agents found" in content
        
    @pytest.mark.asyncio
    async def test_check_agent_health_error_handling(self, server):
        """Test error handling in agent health check."""
        # Mock error
        server.client_manager.agents.get_list.side_effect = Exception("Connection failed")
        
        # Call tool
        result = await server.handle_tool_call(
            name="check_agent_health",
            arguments={}
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content