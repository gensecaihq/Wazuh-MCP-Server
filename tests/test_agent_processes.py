"""Tests for get_agent_processes tool."""

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime
from tests.fixtures.mock_data import MockWazuhData


class TestGetAgentProcesses:
    """Test cases for get_agent_processes tool."""
    
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
    async def test_get_agent_processes_basic(self, server):
        """Test basic process retrieval for an agent."""
        # Mock agent response
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "001", "status": "active", "name": "agent-001"}],
                "total_affected_items": 1
            }
        }
        
        # Mock processes response
        processes_data = {
            "data": {
                "affected_items": [
                    {
                        "pid": 1234,
                        "name": "chrome.exe",
                        "path": "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                        "user": "john.doe",
                        "cpu_percent": 15.5,
                        "memory_percent": 8.2,
                        "status": "running",
                        "ppid": 456
                    },
                    {
                        "pid": 5678,
                        "name": "python.exe",
                        "path": "C:\\Python39\\python.exe",
                        "user": "john.doe",
                        "cpu_percent": 25.0,
                        "memory_percent": 12.5,
                        "status": "running",
                        "ppid": 1
                    }
                ],
                "total_affected_items": 2
            }
        }
        server.client_manager.syscollector.get_processes.return_value = processes_data
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_processes",
            arguments={
                "agent_id": "001"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Processes for Agent 001" in content
        assert "chrome.exe" in content
        assert "python.exe" in content
        assert "Total processes: 2" in content
        
    @pytest.mark.asyncio
    async def test_get_agent_processes_with_filter(self, server):
        """Test process retrieval with name filter."""
        # Mock agent response
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "002", "status": "active", "name": "agent-002"}],
                "total_affected_items": 1
            }
        }
        
        # Mock filtered processes
        server.client_manager.syscollector.get_processes.return_value = {
            "data": {
                "affected_items": [
                    {
                        "pid": 2345,
                        "name": "svchost.exe",
                        "path": "C:\\Windows\\System32\\svchost.exe",
                        "user": "SYSTEM",
                        "cpu_percent": 0.5,
                        "memory_percent": 1.2
                    }
                ],
                "total_affected_items": 1
            }
        }
        
        # Call tool with filter
        result = await server.handle_tool_call(
            name="get_agent_processes",
            arguments={
                "agent_id": "002",
                "process_name": "svchost"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "svchost.exe" in content
        assert "SYSTEM" in content
        
    @pytest.mark.asyncio
    async def test_get_agent_processes_high_cpu(self, server):
        """Test retrieving high CPU processes."""
        # Mock agent response
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "003", "status": "active", "name": "agent-003"}],
                "total_affected_items": 1
            }
        }
        
        # Mock high CPU processes
        server.client_manager.syscollector.get_processes.return_value = {
            "data": {
                "affected_items": [
                    {
                        "pid": 9999,
                        "name": "heavy_app.exe",
                        "cpu_percent": 95.5,
                        "memory_percent": 45.0,
                        "user": "app_user"
                    },
                    {
                        "pid": 8888,
                        "name": "database.exe",
                        "cpu_percent": 78.2,
                        "memory_percent": 60.0,
                        "user": "db_user"
                    }
                ],
                "total_affected_items": 2
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_processes",
            arguments={
                "agent_id": "003"
            }
        )
        
        # Verify high CPU processes are shown
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "95.5" in content
        assert "78.2" in content
        assert "heavy_app.exe" in content
        
    @pytest.mark.asyncio
    async def test_get_agent_processes_disconnected_agent(self, server):
        """Test process retrieval for disconnected agent."""
        # Mock disconnected agent
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "004", "status": "disconnected", "name": "agent-004"}],
                "total_affected_items": 1
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_processes",
            arguments={
                "agent_id": "004"
            }
        )
        
        # Verify warning about disconnected status
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "disconnected" in content.lower() or "not active" in content.lower()
        
    @pytest.mark.asyncio
    async def test_get_agent_processes_no_processes(self, server):
        """Test when no processes are returned."""
        # Mock agent response
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "005", "status": "active", "name": "agent-005"}],
                "total_affected_items": 1
            }
        }
        
        # Mock empty processes
        server.client_manager.syscollector.get_processes.return_value = {
            "data": {
                "affected_items": [],
                "total_affected_items": 0
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_processes",
            arguments={
                "agent_id": "005"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "No processes found" in content or "0" in content
        
    @pytest.mark.asyncio
    async def test_get_agent_processes_invalid_agent(self, server):
        """Test process retrieval for non-existent agent."""
        # Mock agent not found
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [],
                "total_affected_items": 0
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_processes",
            arguments={
                "agent_id": "999"
            }
        )
        
        # Verify error
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "not found" in content.lower() or "error" in content.lower()
        
    @pytest.mark.asyncio
    async def test_get_agent_processes_error_handling(self, server):
        """Test error handling in process retrieval."""
        # Mock error
        server.client_manager.agents.get_agent.side_effect = Exception("API Error")
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_processes",
            arguments={
                "agent_id": "001"
            }
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content