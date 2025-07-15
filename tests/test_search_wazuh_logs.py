"""Tests for search_wazuh_logs tool."""

import pytest
from unittest.mock import AsyncMock, patch
from datetime import datetime, timedelta
from tests.fixtures.mock_data import MockWazuhData


class TestSearchWazuhLogs:
    """Test cases for search_wazuh_logs tool."""
    
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
    async def test_search_wazuh_logs_manager(self, server):
        """Test searching Wazuh manager logs."""
        # Mock log search response
        log_data = {
            "data": {
                "affected_items": [
                    {
                        "timestamp": "2024-01-15 10:30:00",
                        "level": "INFO",
                        "tag": "wazuh-manager",
                        "description": "Started wazuh-manager daemon",
                        "location": "wazuh-manager"
                    },
                    {
                        "timestamp": "2024-01-15 10:31:15",
                        "level": "ERROR",
                        "tag": "wazuh-analysisd",
                        "description": "Unable to connect to database",
                        "location": "wazuh-analysisd"
                    },
                    {
                        "timestamp": "2024-01-15 10:32:00",
                        "level": "WARNING",
                        "tag": "wazuh-remoted",
                        "description": "Agent 001 disconnected",
                        "location": "wazuh-remoted"
                    }
                ],
                "total_affected_items": 3
            }
        }
        server.client_manager.manager.get_logs.return_value = log_data
        
        # Call tool
        result = await server.handle_tool_call(
            name="search_wazuh_logs",
            arguments={
                "target": "manager",
                "pattern": "ERROR"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Manager Logs" in content
        assert "ERROR" in content
        assert "Unable to connect to database" in content
        
    @pytest.mark.asyncio
    async def test_search_wazuh_logs_agent(self, server):
        """Test searching agent logs."""
        # Mock agent log response
        agent_log_data = {
            "data": {
                "affected_items": [
                    {
                        "timestamp": "2024-01-15 10:30:00",
                        "level": "INFO",
                        "tag": "wazuh-agent",
                        "description": "Connected to manager",
                        "location": "wazuh-agent"
                    },
                    {
                        "timestamp": "2024-01-15 10:45:00",
                        "level": "DEBUG",
                        "tag": "wazuh-logcollector",
                        "description": "Reading file: /var/log/messages",
                        "location": "wazuh-logcollector"
                    }
                ],
                "total_affected_items": 2
            }
        }
        server.client_manager.agents.get_logs.return_value = agent_log_data
        
        # Call tool
        result = await server.handle_tool_call(
            name="search_wazuh_logs",
            arguments={
                "target": "agent",
                "agent_id": "001",
                "pattern": "Connected"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Agent 001 Logs" in content
        assert "Connected to manager" in content
        
    @pytest.mark.asyncio
    async def test_search_wazuh_logs_with_level_filter(self, server):
        """Test searching logs with specific level filter."""
        # Mock filtered log response
        error_logs = {
            "data": {
                "affected_items": [
                    {
                        "timestamp": "2024-01-15 10:31:15",
                        "level": "ERROR",
                        "tag": "wazuh-analysisd",
                        "description": "Memory allocation failed",
                        "location": "wazuh-analysisd"
                    },
                    {
                        "timestamp": "2024-01-15 10:35:22",
                        "level": "ERROR",
                        "tag": "wazuh-remoted",
                        "description": "Connection timeout",
                        "location": "wazuh-remoted"
                    }
                ],
                "total_affected_items": 2
            }
        }
        server.client_manager.manager.get_logs.return_value = error_logs
        
        # Call tool with level filter
        result = await server.handle_tool_call(
            name="search_wazuh_logs",
            arguments={
                "target": "manager",
                "level": "ERROR"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "ERROR" in content
        assert "Memory allocation failed" in content
        assert "Connection timeout" in content
        
    @pytest.mark.asyncio
    async def test_search_wazuh_logs_with_time_range(self, server):
        """Test searching logs with time range."""
        # Mock time-filtered logs
        time_filtered_logs = {
            "data": {
                "affected_items": [
                    {
                        "timestamp": "2024-01-15 09:00:00",
                        "level": "INFO",
                        "tag": "wazuh-manager",
                        "description": "System startup complete",
                        "location": "wazuh-manager"
                    }
                ],
                "total_affected_items": 1
            }
        }
        server.client_manager.manager.get_logs.return_value = time_filtered_logs
        
        # Call tool with time range
        result = await server.handle_tool_call(
            name="search_wazuh_logs",
            arguments={
                "target": "manager",
                "start_time": "2024-01-15T08:00:00Z",
                "end_time": "2024-01-15T10:00:00Z"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "System startup complete" in content
        server.client_manager.manager.get_logs.assert_called_once()
        
    @pytest.mark.asyncio
    async def test_search_wazuh_logs_with_limit(self, server):
        """Test searching logs with result limit."""
        # Mock large log response
        large_logs = {
            "data": {
                "affected_items": [
                    {
                        "timestamp": f"2024-01-15 10:{i:02d}:00",
                        "level": "INFO",
                        "tag": "wazuh-manager",
                        "description": f"Log entry {i}",
                        "location": "wazuh-manager"
                    }
                    for i in range(1, 26)  # 25 entries
                ],
                "total_affected_items": 25
            }
        }
        server.client_manager.manager.get_logs.return_value = large_logs
        
        # Call tool with limit
        result = await server.handle_tool_call(
            name="search_wazuh_logs",
            arguments={
                "target": "manager",
                "limit": "10"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Log entry 1" in content
        assert "Total: 25" in content or "25 entries" in content
        
    @pytest.mark.asyncio
    async def test_search_wazuh_logs_no_results(self, server):
        """Test searching logs with no matches."""
        # Mock empty response
        server.client_manager.manager.get_logs.return_value = {
            "data": {
                "affected_items": [],
                "total_affected_items": 0
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="search_wazuh_logs",
            arguments={
                "target": "manager",
                "pattern": "nonexistent_pattern"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "No logs found" in content or "No matches" in content
        
    @pytest.mark.asyncio
    async def test_search_wazuh_logs_invalid_target(self, server):
        """Test error handling for invalid target."""
        # Call tool with invalid target
        result = await server.handle_tool_call(
            name="search_wazuh_logs",
            arguments={
                "target": "invalid_target",
                "pattern": "test"
            }
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Invalid target" in content or "Error" in content
        
    @pytest.mark.asyncio
    async def test_search_wazuh_logs_complex_pattern(self, server):
        """Test searching with complex regex pattern."""
        # Mock logs with various patterns
        pattern_logs = {
            "data": {
                "affected_items": [
                    {
                        "timestamp": "2024-01-15 10:30:00",
                        "level": "WARNING",
                        "tag": "wazuh-remoted",
                        "description": "Agent 001 authentication failed",
                        "location": "wazuh-remoted"
                    },
                    {
                        "timestamp": "2024-01-15 10:31:00",
                        "level": "WARNING",
                        "tag": "wazuh-remoted",
                        "description": "Agent 002 authentication failed",
                        "location": "wazuh-remoted"
                    }
                ],
                "total_affected_items": 2
            }
        }
        server.client_manager.manager.get_logs.return_value = pattern_logs
        
        # Call tool with regex pattern
        result = await server.handle_tool_call(
            name="search_wazuh_logs",
            arguments={
                "target": "manager",
                "pattern": r"Agent \d+ authentication failed"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "authentication failed" in content
        assert "Agent 001" in content
        assert "Agent 002" in content
        
    @pytest.mark.asyncio
    async def test_search_wazuh_logs_error_handling(self, server):
        """Test error handling in log search."""
        # Mock error
        server.client_manager.manager.get_logs.side_effect = Exception("Log search failed")
        
        # Call tool
        result = await server.handle_tool_call(
            name="search_wazuh_logs",
            arguments={
                "target": "manager",
                "pattern": "test"
            }
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content