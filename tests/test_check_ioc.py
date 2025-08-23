"""Tests for check_ioc tool."""

import pytest
from unittest.mock import AsyncMock, patch
from tests.fixtures.mock_data import MockWazuhData


class TestCheckIOC:
    """Test cases for check_ioc tool."""
    
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
    async def test_check_ioc_ip_address_malicious(self, server):
        """Test checking malicious IP address IOC."""
        # Mock alerts with matching IP
        alerts_response = {
            "data": {
                "affected_items": [
                    {
                        "id": "alert_001",
                        "data": {"srcip": "192.168.1.100"},
                        "rule": {"description": "Malicious IP detected"}
                    },
                    {
                        "id": "alert_002",
                        "data": {"dstip": "192.168.1.100"},
                        "rule": {"description": "Connection to suspicious IP"}
                    }
                ],
                "total_affected_items": 2
            }
        }
        server.client_manager.alerts.search.return_value = alerts_response
        
        # Mock threat intel check
        server.client_manager.lists.get_file.return_value = {
            "data": {
                "affected_items": [{
                    "content": "192.168.1.100:malware_c2:high:2024-01-15"
                }]
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="check_ioc",
            arguments={
                "indicator": "192.168.1.100",
                "ioc_type": "ip"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "192.168.1.100" in content
        assert "FOUND" in content or "malicious" in content.lower()
        assert "2 alerts" in content or "2" in content
        
    @pytest.mark.asyncio
    async def test_check_ioc_file_hash_clean(self, server):
        """Test checking clean file hash IOC."""
        # Mock no alerts found
        server.client_manager.alerts.search.return_value = {
            "data": {
                "affected_items": [],
                "total_affected_items": 0
            }
        }
        
        # Mock no threat intel matches
        server.client_manager.lists.get_file.return_value = {
            "data": {
                "affected_items": []
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="check_ioc",
            arguments={
                "indicator": "a1b2c3d4e5f6789012345678901234567890abcd",
                "ioc_type": "hash"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "NOT FOUND" in content or "No matches" in content or "clean" in content.lower()
        
    @pytest.mark.asyncio
    async def test_check_ioc_domain_suspicious(self, server):
        """Test checking suspicious domain IOC."""
        # Mock alerts with domain
        alerts_response = {
            "data": {
                "affected_items": [
                    {
                        "id": "alert_001",
                        "data": {"url": "http://malicious-domain.com/payload"},
                        "rule": {"description": "Suspicious domain access"}
                    }
                ],
                "total_affected_items": 1
            }
        }
        server.client_manager.alerts.search.return_value = alerts_response
        
        # Call tool
        result = await server.handle_tool_call(
            name="check_ioc",
            arguments={
                "indicator": "malicious-domain.com",
                "ioc_type": "domain"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "malicious-domain.com" in content
        assert "1 alert" in content or "Suspicious" in content
        
    @pytest.mark.asyncio
    async def test_check_ioc_url_with_context(self, server):
        """Test checking URL IOC with context."""
        # Mock alerts
        alerts_response = {
            "data": {
                "affected_items": [
                    {
                        "id": "alert_001",
                        "data": {
                            "url": "http://bad-site.com/malware.exe",
                            "user": "john.doe"
                        },
                        "agent": {"id": "003", "name": "workstation-03"}
                    }
                ],
                "total_affected_items": 1
            }
        }
        server.client_manager.alerts.search.return_value = alerts_response
        
        # Call tool with context
        result = await server.handle_tool_call(
            name="check_ioc",
            arguments={
                "indicator": "http://bad-site.com/malware.exe",
                "ioc_type": "url",
                "include_context": "true"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "bad-site.com" in content
        assert "workstation-03" in content or "003" in content
        
    @pytest.mark.asyncio
    async def test_check_ioc_with_time_range(self, server):
        """Test checking IOC with specific time range."""
        # Mock alerts
        server.client_manager.alerts.search.return_value = {
            "data": {
                "affected_items": [
                    {
                        "id": "alert_001",
                        "data": {"srcip": "10.0.0.50"}
                    }
                ],
                "total_affected_items": 1
            }
        }
        
        # Call tool with time range
        result = await server.handle_tool_call(
            name="check_ioc",
            arguments={
                "indicator": "10.0.0.50",
                "ioc_type": "ip",
                "start_time": "2024-01-01T00:00:00Z",
                "end_time": "2024-01-02T00:00:00Z"
            }
        )
        
        # Verify
        assert result is not None
        server.client_manager.alerts.search.assert_called()
        
    @pytest.mark.asyncio
    async def test_check_ioc_invalid_format(self, server):
        """Test checking IOC with invalid format."""
        # Call tool with invalid IP
        result = await server.handle_tool_call(
            name="check_ioc",
            arguments={
                "indicator": "999.999.999.999",
                "ioc_type": "ip"
            }
        )
        
        # Verify validation error
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Invalid" in content or "Error" in content
        
    @pytest.mark.asyncio
    async def test_check_ioc_error_handling(self, server):
        """Test error handling in IOC check."""
        # Mock error
        server.client_manager.alerts.search.side_effect = Exception("API Error")
        
        # Call tool
        result = await server.handle_tool_call(
            name="check_ioc",
            arguments={
                "indicator": "192.168.1.1",
                "ioc_type": "ip"
            }
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content