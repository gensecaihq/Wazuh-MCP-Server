"""Tests for get_agent_ports tool."""

import pytest
from unittest.mock import AsyncMock, patch
from tests.fixtures.mock_data import MockWazuhData


class TestGetAgentPorts:
    """Test cases for get_agent_ports tool."""
    
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
    async def test_get_agent_ports_basic(self, server):
        """Test basic port retrieval for an agent."""
        # Mock agent response
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "001", "status": "active", "name": "agent-001"}],
                "total_affected_items": 1
            }
        }
        
        # Mock ports response
        ports_data = {
            "data": {
                "affected_items": [
                    {
                        "local_port": 80,
                        "local_ip": "0.0.0.0",
                        "protocol": "tcp",
                        "state": "listening",
                        "process": "nginx",
                        "pid": 1234
                    },
                    {
                        "local_port": 443,
                        "local_ip": "0.0.0.0",
                        "protocol": "tcp",
                        "state": "listening",
                        "process": "nginx",
                        "pid": 1234
                    },
                    {
                        "local_port": 22,
                        "local_ip": "0.0.0.0",
                        "protocol": "tcp",
                        "state": "listening",
                        "process": "sshd",
                        "pid": 456
                    },
                    {
                        "local_port": 3306,
                        "local_ip": "127.0.0.1",
                        "protocol": "tcp",
                        "state": "listening",
                        "process": "mysqld",
                        "pid": 789
                    }
                ],
                "total_affected_items": 4
            }
        }
        server.client_manager.syscollector.get_ports.return_value = ports_data
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_ports",
            arguments={
                "agent_id": "001"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Open Ports for Agent 001" in content
        assert "80" in content
        assert "443" in content
        assert "nginx" in content
        assert "Total ports: 4" in content
        
    @pytest.mark.asyncio
    async def test_get_agent_ports_with_state_filter(self, server):
        """Test port retrieval with state filter."""
        # Mock agent response
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "002", "status": "active", "name": "agent-002"}],
                "total_affected_items": 1
            }
        }
        
        # Mock established connections
        server.client_manager.syscollector.get_ports.return_value = {
            "data": {
                "affected_items": [
                    {
                        "local_port": 54321,
                        "local_ip": "192.168.1.100",
                        "remote_port": 443,
                        "remote_ip": "93.184.216.34",
                        "protocol": "tcp",
                        "state": "established",
                        "process": "chrome"
                    },
                    {
                        "local_port": 54322,
                        "local_ip": "192.168.1.100",
                        "remote_port": 80,
                        "remote_ip": "151.101.1.140",
                        "protocol": "tcp",
                        "state": "established",
                        "process": "firefox"
                    }
                ],
                "total_affected_items": 2
            }
        }
        
        # Call tool with state filter
        result = await server.handle_tool_call(
            name="get_agent_ports",
            arguments={
                "agent_id": "002",
                "state": "established"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "established" in content
        assert "93.184.216.34" in content
        
    @pytest.mark.asyncio
    async def test_get_agent_ports_with_protocol_filter(self, server):
        """Test port retrieval with protocol filter."""
        # Mock agent response
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "003", "status": "active", "name": "agent-003"}],
                "total_affected_items": 1
            }
        }
        
        # Mock UDP ports
        server.client_manager.syscollector.get_ports.return_value = {
            "data": {
                "affected_items": [
                    {
                        "local_port": 53,
                        "local_ip": "0.0.0.0",
                        "protocol": "udp",
                        "state": "listening",
                        "process": "dnsmasq"
                    },
                    {
                        "local_port": 123,
                        "local_ip": "0.0.0.0",
                        "protocol": "udp",
                        "state": "listening",
                        "process": "ntpd"
                    }
                ],
                "total_affected_items": 2
            }
        }
        
        # Call tool with protocol filter
        result = await server.handle_tool_call(
            name="get_agent_ports",
            arguments={
                "agent_id": "003",
                "protocol": "udp"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "udp" in content.lower()
        assert "53" in content
        assert "dnsmasq" in content
        
    @pytest.mark.asyncio
    async def test_get_agent_ports_security_analysis(self, server):
        """Test port retrieval with security concerns."""
        # Mock agent response
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "004", "status": "active", "name": "agent-004"}],
                "total_affected_items": 1
            }
        }
        
        # Mock risky ports
        server.client_manager.syscollector.get_ports.return_value = {
            "data": {
                "affected_items": [
                    {
                        "local_port": 23,
                        "local_ip": "0.0.0.0",
                        "protocol": "tcp",
                        "state": "listening",
                        "process": "telnetd"
                    },
                    {
                        "local_port": 445,
                        "local_ip": "0.0.0.0",
                        "protocol": "tcp",
                        "state": "listening",
                        "process": "smbd"
                    },
                    {
                        "local_port": 3389,
                        "local_ip": "0.0.0.0",
                        "protocol": "tcp",
                        "state": "listening",
                        "process": "TermService"
                    }
                ],
                "total_affected_items": 3
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_ports",
            arguments={
                "agent_id": "004"
            }
        )
        
        # Verify security warnings
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "23" in content  # Telnet
        assert "445" in content  # SMB
        assert "3389" in content  # RDP
        
    @pytest.mark.asyncio
    async def test_get_agent_ports_disconnected_agent(self, server):
        """Test port retrieval for disconnected agent."""
        # Mock disconnected agent
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "005", "status": "disconnected", "name": "agent-005"}],
                "total_affected_items": 1
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_ports",
            arguments={
                "agent_id": "005"
            }
        )
        
        # Verify warning
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "disconnected" in content.lower()
        
    @pytest.mark.asyncio
    async def test_get_agent_ports_no_ports(self, server):
        """Test when no ports are found."""
        # Mock agent response
        server.client_manager.agents.get_agent.return_value = {
            "data": {
                "affected_items": [{"id": "006", "status": "active", "name": "agent-006"}],
                "total_affected_items": 1
            }
        }
        
        # Mock empty ports
        server.client_manager.syscollector.get_ports.return_value = {
            "data": {
                "affected_items": [],
                "total_affected_items": 0
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_ports",
            arguments={
                "agent_id": "006"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "No ports found" in content or "0" in content
        
    @pytest.mark.asyncio
    async def test_get_agent_ports_error_handling(self, server):
        """Test error handling in port retrieval."""
        # Mock error
        server.client_manager.agents.get_agent.side_effect = Exception("Network error")
        
        # Call tool
        result = await server.handle_tool_call(
            name="get_agent_ports",
            arguments={
                "agent_id": "001"
            }
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content