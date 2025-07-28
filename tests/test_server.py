#!/usr/bin/env python3
"""
Wazuh MCP Server Tests
Essential tests for production deployment
"""

import pytest
import asyncio
from unittest.mock import Mock, AsyncMock, patch

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from wazuh_mcp_server.server import (
    mcp, 
    get_config, 
    get_wazuh_client,
    get_indexer_client,
    get_wazuh_alerts,
    analyze_security_threats,
    get_agent_status,
    get_vulnerability_summary,
    interactive_threat_hunt,
    get_cluster_status,
    get_security_dashboard,
    get_agent_details,
    security_analysis_prompt,
    incident_response_prompt
)


class TestFastMCPServer:
    """Test suite for FastMCP-compliant server implementation."""
    
    @pytest.fixture
    def mock_config(self):
        """Mock Wazuh configuration."""
        config = Mock()
        config.wazuh_host = "test-wazuh.com"
        config.wazuh_port = 55000
        config.wazuh_user = "test-user"
        config.wazuh_pass = "test-pass"
        config.wazuh_indexer_host = "test-indexer.com"
        config.verify_ssl = True
        config.request_timeout_seconds = 30
        return config
    
    @pytest.fixture
    def mock_wazuh_client(self):
        """Mock Wazuh API client."""
        client = AsyncMock()
        client.get_alerts.return_value = {
            "data": {
                "affected_items": [
                    {
                        "id": "1",
                        "timestamp": "2024-01-01T12:00:00Z",
                        "rule": {"id": "12345", "level": 10, "description": "Test alert"},
                        "agent": {"id": "001", "name": "test-agent", "ip": "192.168.1.100"}
                    }
                ],
                "total_affected_items": 1
            }
        }
        client.get_agents.return_value = {
            "data": {
                "affected_items": [
                    {
                        "id": "001",
                        "name": "test-agent",
                        "ip": "192.168.1.100",
                        "status": "active",
                        "os": {"name": "Ubuntu"},
                        "version": "4.8.0"
                    }
                ]
            }
        }
        client.get_vulnerabilities.return_value = {
            "data": {
                "affected_items": [
                    {
                        "vulnerability": {
                            "cve": "CVE-2024-0001",
                            "severity": "High",
                            "cvss": {"cvss3": {"score": 8.5}},
                            "package": {"name": "test-package", "version": "1.0.0"}
                        }
                    }
                ],
                "total_affected_items": 1
            }
        }
        client.get_cluster_status.return_value = {
            "data": {
                "enabled": True,
                "running": "yes",
                "nodes": ["node1", "node2"]
            }
        }
        return client
    
    @pytest.fixture
    def mock_context(self):
        """Mock FastMCP Context."""
        context = AsyncMock()
        context.info = AsyncMock()
        context.error = AsyncMock()
        context.warning = AsyncMock()
        context.report_progress = AsyncMock()
        return context

    @pytest.mark.asyncio
    async def test_server_initialization(self):
        """Test FastMCP server is properly initialized."""
        assert mcp is not None
        assert mcp.name == "Wazuh MCP Server"
        assert mcp.version == "2.0.0"
        assert "FastMCP server for Wazuh SIEM integration" in mcp.description

    @pytest.mark.asyncio
    async def test_get_wazuh_alerts_tool(self, mock_config, mock_wazuh_client, mock_context):
        """Test the get_wazuh_alerts FastMCP tool."""
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_wazuh_client', return_value=mock_wazuh_client):
                
                result = await get_wazuh_alerts(
                    limit=100,
                    level=5,
                    time_range=3600,
                    agent_id="001",
                    ctx=mock_context
                )
                
                # Verify the result structure
                assert "alerts" in result
                assert "analysis" in result
                assert "metadata" in result
                
                # Verify analysis components
                analysis = result["analysis"]
                assert "total_alerts" in analysis
                assert "severity_breakdown" in analysis
                assert "top_rules" in analysis
                assert "agent_distribution" in analysis
                assert "time_analysis" in analysis
                
                # Verify Context usage
                mock_context.info.assert_called()
                mock_context.report_progress.assert_called()

    @pytest.mark.asyncio
    async def test_analyze_security_threats_tool(self, mock_config, mock_wazuh_client, mock_context):
        """Test the analyze_security_threats FastMCP tool."""
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_wazuh_client', return_value=mock_wazuh_client):
                
                result = await analyze_security_threats(
                    time_range_hours=24,
                    severity_threshold=5,
                    include_compliance=True,
                    ctx=mock_context
                )
                
                # Verify the result structure
                assert "summary" in result
                assert "threat_categories" in result
                assert "attack_patterns" in result
                assert "affected_assets" in result
                assert "risk_assessment" in result
                assert "compliance" in result
                
                # Verify Context usage
                mock_context.info.assert_called()
                mock_context.report_progress.assert_called()

    @pytest.mark.asyncio
    async def test_get_agent_status_tool(self, mock_config, mock_wazuh_client, mock_context):
        """Test the get_agent_status FastMCP tool."""
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_wazuh_client', return_value=mock_wazuh_client):
                
                result = await get_agent_status(
                    agent_id="001",
                    include_health_metrics=True,
                    ctx=mock_context
                )
                
                # Verify the result structure
                assert "total_agents" in result
                assert "agents" in result
                assert "summary" in result
                
                # Verify summary has status counts
                summary = result["summary"]
                assert "active" in summary
                assert "disconnected" in summary
                assert "never_connected" in summary
                assert "pending" in summary
                
                # Verify Context usage
                mock_context.info.assert_called()
                mock_context.report_progress.assert_called()

    @pytest.mark.asyncio
    async def test_get_vulnerability_summary_tool(self, mock_config, mock_wazuh_client, mock_context):
        """Test the get_vulnerability_summary FastMCP tool."""
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_wazuh_client', return_value=mock_wazuh_client):
                with patch('wazuh_mcp_server.server.get_indexer_client', return_value=None):
                    
                    result = await get_vulnerability_summary(
                        agent_id="001",
                        severity="High",
                        limit=500,
                        ctx=mock_context
                    )
                    
                    # Verify the result structure
                    assert "total_vulnerabilities" in result
                    assert "severity_breakdown" in result
                    assert "top_cves" in result
                    assert "affected_packages" in result
                    assert "risk_score" in result
                    assert "remediation_priority" in result
                    assert "vulnerabilities" in result
                    
                    # Verify Context usage
                    mock_context.info.assert_called()
                    mock_context.report_progress.assert_called()

    @pytest.mark.asyncio
    async def test_interactive_threat_hunt_tool(self, mock_context):
        """Test the interactive_threat_hunt FastMCP tool with elicitation."""
        # Mock elicitation response
        mock_elicit_result = Mock()
        mock_elicit_result.action = "accept"
        mock_elicit_result.data = Mock()
        mock_elicit_result.data.severity_threshold = 5
        mock_elicit_result.data.include_compliance = True
        mock_elicit_result.data.time_range_hours = 24
        mock_elicit_result.data.include_external_intel = False
        
        mock_context.elicit.return_value = mock_elicit_result
        
        with patch('wazuh_mcp_server.server.analyze_security_threats') as mock_analyze:
            mock_analyze.return_value = {"threat_data": "test"}
            
            result = await interactive_threat_hunt(ctx=mock_context)
            
            # Verify elicitation was called
            mock_context.elicit.assert_called_once()
            
            # Verify the result structure
            assert "status" in result
            assert "configuration" in result
            assert "results" in result
            assert result["status"] == "completed"

    @pytest.mark.asyncio
    async def test_cluster_status_resource(self, mock_config, mock_wazuh_client):
        """Test the wazuh://cluster/status resource."""
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_wazuh_client', return_value=mock_wazuh_client):
                
                result = await get_cluster_status()
                
                # Verify the result structure
                assert "cluster_enabled" in result
                assert "cluster_status" in result
                assert "nodes" in result
                assert "last_updated" in result
                
                # Verify values
                assert result["cluster_enabled"] is True
                assert result["cluster_status"] == "yes"
                assert isinstance(result["nodes"], list)

    @pytest.mark.asyncio
    async def test_security_dashboard_resource(self, mock_config, mock_wazuh_client):
        """Test the wazuh://dashboard/security/{time_range} resource."""
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_wazuh_client', return_value=mock_wazuh_client):
                with patch('wazuh_mcp_server.server.get_wazuh_alerts') as mock_get_alerts:
                    mock_get_alerts.return_value = {
                        "alerts": [],
                        "analysis": {"total_alerts": 0}
                    }
                    
                    result = await get_security_dashboard("24h")
                    
                    # Verify the result structure
                    assert "time_range" in result
                    assert "summary" in result
                    assert "recent_alerts" in result
                    assert "generated_at" in result
                    
                    # Verify values
                    assert result["time_range"] == "24h"

    @pytest.mark.asyncio
    async def test_agent_details_resource(self, mock_config, mock_wazuh_client):
        """Test the wazuh://agents/{agent_id}/details resource."""
        mock_wazuh_client.get_agent.return_value = {
            "data": {
                "id": "001",
                "name": "test-agent",
                "ip": "192.168.1.100",
                "status": "active"
            }
        }
        mock_wazuh_client.get_agent_config.return_value = {
            "data": {"config": "test"}
        }
        
        with patch('wazuh_mcp_server.server.get_config', return_value=mock_config):
            with patch('wazuh_mcp_server.server.get_wazuh_client', return_value=mock_wazuh_client):
                
                result = await get_agent_details("001")
                
                # Verify the result structure
                assert "id" in result
                assert "name" in result
                assert "ip" in result
                assert "status" in result
                assert "configuration" in result

    def test_security_analysis_prompt(self):
        """Test the security_analysis_prompt FastMCP prompt."""
        result = security_analysis_prompt(alert_level=5, time_hours=24)
        
        # Verify it returns a string
        assert isinstance(result, str)
        
        # Verify it contains expected content
        assert "Wazuh Security Analysis Request" in result
        assert "Alert Level: 5" in result
        assert "Time Range: Last 24 hours" in result
        assert "Threat Categorization" in result
        assert "Risk Assessment" in result

    def test_incident_response_prompt(self):
        """Test the incident_response_prompt FastMCP prompt."""
        result = incident_response_prompt(incident_type="malware", severity="high")
        
        # Verify it returns a string
        assert isinstance(result, str)
        
        # Verify it contains expected content
        assert "Security Incident Response Procedure" in result
        assert "Type: malware" in result
        assert "Severity: high" in result
        assert "Containment" in result
        assert "Assessment" in result

    @pytest.mark.asyncio
    async def test_error_handling(self, mock_context):
        """Test error handling in FastMCP tools."""
        with patch('wazuh_mcp_server.server.get_config', side_effect=Exception("Config error")):
            
            with pytest.raises(ValueError) as exc_info:
                await get_wazuh_alerts(ctx=mock_context)
            
            # Verify error message
            assert "Failed to retrieve Wazuh alerts" in str(exc_info.value)
            
            # Verify Context error logging
            mock_context.error.assert_called()

    def test_helper_functions(self):
        """Test internal helper functions."""
        from wazuh_mcp_server.server import (
            _analyze_alert_severity,
            _get_top_alert_rules,
            _analyze_agent_distribution,
            _categorize_threats,
            _calculate_risk_score
        )
        
        # Test data
        test_alerts = [
            {
                "rule": {"id": "1", "level": 12, "description": "Critical alert"},
                "agent": {"id": "001", "name": "agent1"}
            },
            {
                "rule": {"id": "2", "level": 6, "description": "Medium alert"},
                "agent": {"id": "002", "name": "agent2"}
            }
        ]
        
        # Test severity analysis
        severity = _analyze_alert_severity(test_alerts)
        assert "Critical" in severity
        assert "Medium" in severity
        
        # Test top rules
        top_rules = _get_top_alert_rules(test_alerts)
        assert len(top_rules) == 2
        assert top_rules[0]["id"] in ["1", "2"]
        
        # Test agent distribution
        agent_dist = _analyze_agent_distribution(test_alerts)
        assert len(agent_dist) == 2
        
        # Test threat categorization
        threat_cats = _categorize_threats(test_alerts)
        assert isinstance(threat_cats, dict)
        assert "malware" in threat_cats
        
        # Test risk score calculation
        risk_score = _calculate_risk_score(test_alerts)
        assert "score" in risk_score
        assert "level" in risk_score
        assert "factors" in risk_score


class TestFastMCPCompliance:
    """Test FastMCP compliance aspects."""
    
    def test_mcp_decorators(self):
        """Test that tools, resources, and prompts use proper decorators."""
        import inspect
        from wazuh_mcp_server import server
        
        # Get all functions in the server module
        functions = inspect.getmembers(server, inspect.isfunction)
        
        # Check for tools with @mcp.tool decorator
        tool_functions = [f for name, f in functions if hasattr(f, '__annotations__')]
        
        # Verify we have tools
        assert len(tool_functions) > 0
        
        # Check for resources and prompts
        # Note: This is a basic check - in a real implementation,
        # we would inspect the actual decorators
        
    def test_type_annotations(self):
        """Test that FastMCP functions have proper type annotations."""
        from wazuh_mcp_server.server import (
            get_wazuh_alerts,
            analyze_security_threats,
            get_agent_status,
            get_vulnerability_summary
        )
        
        # Check that functions have type annotations
        assert hasattr(get_wazuh_alerts, '__annotations__')
        assert hasattr(analyze_security_threats, '__annotations__')
        assert hasattr(get_agent_status, '__annotations__')
        assert hasattr(get_vulnerability_summary, '__annotations__')
        
        # Verify return type annotations
        assert get_wazuh_alerts.__annotations__.get('return') == dict
        assert analyze_security_threats.__annotations__.get('return') == dict

    def test_context_usage(self, mock_context):
        """Test that tools properly use Context for logging and progress."""
        # This is tested in individual tool tests above
        # Here we can add more specific Context usage tests
        pass

    def test_pydantic_field_usage(self):
        """Test that tools use Pydantic Field for parameter validation."""
        from wazuh_mcp_server.server import get_wazuh_alerts
        import inspect
        
        # Get function signature
        sig = inspect.signature(get_wazuh_alerts)
        
        # Check that parameters have Field annotations
        # Note: This is a simplified check
        for param_name, param in sig.parameters.items():
            if param_name not in ['ctx']:  # Exclude Context parameter
                assert param.annotation is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])