"""Tests for get_wazuh_stats tool."""

import pytest
from unittest.mock import AsyncMock, patch
from tests.fixtures.mock_data import MockWazuhData


class TestGetWazuhStats:
    """Test cases for get_wazuh_stats tool."""
    
    @pytest.fixture
    def mock_client_manager(self):
        """Create a mock client manager for testing."""
        client_manager = AsyncMock()
        # Set up the client_manager to have the expected methods
        client_manager.get_wazuh_stats = AsyncMock()
        client_manager.get_agents = AsyncMock()
        client_manager.get_cluster_info = AsyncMock()
        return client_manager
    
    @pytest.mark.asyncio
    async def test_get_wazuh_stats_manager(self, mock_client_manager):
        """Test getting Wazuh manager statistics."""
        # Mock manager stats response
        stats_data = {
            "data": {
                "affected_items": [{
                    "manager": {
                        "alerts": {
                            "total": 15000,
                            "high": 250,
                            "medium": 3000,
                            "low": 11750
                        },
                        "rules": {
                            "total": 4500,
                            "enabled": 4200,
                            "disabled": 300
                        },
                        "agents": {
                            "total": 50,
                            "active": 48,
                            "disconnected": 2
                        },
                        "decoders": {
                            "total": 850,
                            "enabled": 800
                        },
                        "uptime": "15 days, 8 hours, 30 minutes"
                    }
                }],
                "total_affected_items": 1
            }
        }
        server.client_manager.manager.get_stats.return_value = stats_data
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_wazuh_stats",
            arguments={
                "component": "manager"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Manager Statistics" in content
        assert "15000" in content  # Total alerts
        assert "48" in content  # Active agents
        assert "uptime" in content.lower()
        
    @pytest.mark.asyncio
    async def test_get_wazuh_stats_specific_agent(self, server):
        """Test getting statistics for a specific agent."""
        # Mock agent stats response
        agent_stats = {
            "data": {
                "affected_items": [{
                    "agent": {
                        "id": "001",
                        "name": "web-server-01",
                        "events": {
                            "total": 5000,
                            "today": 150,
                            "last_hour": 25
                        },
                        "files": {
                            "monitored": 350,
                            "total_size": "125MB"
                        },
                        "processes": {
                            "total": 120,
                            "running": 118,
                            "stopped": 2
                        },
                        "last_keepalive": "2024-01-15 10:30:00"
                    }
                }],
                "total_affected_items": 1
            }
        }
        server.client_manager.agents.get_stats.return_value = agent_stats
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_wazuh_stats",
            arguments={
                "component": "agent",
                "agent_id": "001"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Agent 001" in content
        assert "web-server-01" in content
        assert "5000" in content  # Total events
        assert "350" in content  # Monitored files
        
    @pytest.mark.asyncio
    async def test_get_wazuh_stats_analysisd(self, server):
        """Test getting analysis daemon statistics."""
        # Mock analysisd stats
        analysisd_stats = {
            "data": {
                "affected_items": [{
                    "analysisd": {
                        "events_processed": 125000,
                        "events_per_second": 45.2,
                        "rules_matched": 8500,
                        "alerts_generated": 2500,
                        "archives_stored": 122500,
                        "queue_size": 0,
                        "memory_usage": "45.2MB"
                    }
                }],
                "total_affected_items": 1
            }
        }
        server.client_manager.manager.get_stats.return_value = analysisd_stats
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_wazuh_stats",
            arguments={
                "component": "analysisd"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Analysis Daemon" in content
        assert "125000" in content  # Events processed
        assert "45.2" in content  # Events per second
        
    @pytest.mark.asyncio
    async def test_get_wazuh_stats_remoted(self, server):
        """Test getting remote daemon statistics."""
        # Mock remoted stats
        remoted_stats = {
            "data": {
                "affected_items": [{
                    "remoted": {
                        "queue_size": 0,
                        "total_queue_size": 131072,
                        "tcp_sessions": 48,
                        "events_received": 450000,
                        "events_per_second": 62.5,
                        "discarded_count": 0,
                        "control_messages": 1250
                    }
                }],
                "total_affected_items": 1
            }
        }
        server.client_manager.manager.get_stats.return_value = remoted_stats
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_wazuh_stats",
            arguments={
                "component": "remoted"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Remote Daemon" in content
        assert "48" in content  # TCP sessions
        assert "450000" in content  # Events received
        
    @pytest.mark.asyncio
    async def test_get_wazuh_stats_logcollector(self, server):
        """Test getting log collector statistics."""
        # Mock logcollector stats
        logcollector_stats = {
            "data": {
                "affected_items": [{
                    "logcollector": {
                        "files": {
                            "total": 25,
                            "monitored": 23,
                            "errors": 2
                        },
                        "events": {
                            "total": 85000,
                            "per_second": 35.8
                        },
                        "targets": [
                            {"file": "/var/log/messages", "events": 25000},
                            {"file": "/var/log/secure", "events": 15000},
                            {"file": "/var/log/httpd/access_log", "events": 45000}
                        ]
                    }
                }],
                "total_affected_items": 1
            }
        }
        server.client_manager.agents.get_stats.return_value = logcollector_stats
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_wazuh_stats",
            arguments={
                "component": "logcollector",
                "agent_id": "001"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Log Collector" in content
        assert "85000" in content  # Total events
        assert "/var/log/messages" in content
        
    @pytest.mark.asyncio
    async def test_get_wazuh_stats_invalid_component(self, server):
        """Test error handling for invalid component."""
        # Call tool with invalid component
        result = await server.handle_tool_call(
            name="get_wazuh_stats",
            arguments={
                "component": "invalid_component"
            }
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Invalid component" in content or "Error" in content
        
    @pytest.mark.asyncio
    async def test_get_wazuh_stats_no_data(self, server):
        """Test when no statistics are available."""
        # Mock empty response
        server.client_manager.manager.get_stats.return_value = {
            "data": {
                "affected_items": [],
                "total_affected_items": 0
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_wazuh_stats",
            arguments={
                "component": "manager"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "No statistics available" in content or "No data" in content
        
    @pytest.mark.asyncio
    async def test_get_wazuh_stats_error_handling(self, server):
        """Test error handling in statistics retrieval."""
        # Mock error
        server.client_manager.manager.get_stats.side_effect = Exception("Stats API error")
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_wazuh_stats",
            arguments={
                "component": "manager"
            }
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content