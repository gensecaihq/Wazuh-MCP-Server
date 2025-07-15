"""Tests for risk_assessment tool."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from tests.fixtures.mock_data import MockWazuhData


class TestRiskAssessment:
    """Test cases for risk_assessment tool."""
    
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
    async def test_risk_assessment_comprehensive(self, server):
        """Test comprehensive risk assessment."""
        # Mock responses
        server.client_manager.alerts.search.return_value = MockWazuhData.get_mock_alerts(3)
        server.client_manager.vulnerabilities.search.return_value = MockWazuhData.get_mock_vulnerabilities("001", 3)
        server.client_manager.agents.get_list.return_value = MockWazuhData.get_mock_agents(5)
        
        # Mock risk analysis
        server.security_analyzer.assess_risk.return_value = {
            "overall_risk_score": 72.5,
            "risk_level": "HIGH",
            "risk_factors": {
                "vulnerabilities": {"score": 85, "count": 150},
                "alerts": {"score": 70, "critical": 5},
                "agent_coverage": {"score": 60, "inactive": 3},
                "compliance": {"score": 75, "issues": 12}
            },
            "top_risks": [
                "Critical unpatched vulnerabilities",
                "Active security incidents",
                "Insufficient agent coverage"
            ],
            "recommendations": [
                "Patch critical vulnerabilities immediately",
                "Investigate high-severity alerts",
                "Deploy agents to uncovered systems"
            ]
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="risk_assessment",
            arguments={}
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Risk Assessment" in content
        assert "72.5" in content or "HIGH" in content
        assert "recommendations" in content.lower()
        
    @pytest.mark.asyncio
    async def test_risk_assessment_with_scope(self, server):
        """Test risk assessment with specific scope."""
        # Mock responses
        server.client_manager.alerts.search.return_value = MockWazuhData.get_mock_alerts(3)
        server.client_manager.vulnerabilities.search.return_value = MockWazuhData.get_mock_vulnerabilities("001", 1)
        
        # Mock scoped risk analysis
        server.security_analyzer.assess_risk.return_value = {
            "overall_risk_score": 85.0,
            "risk_level": "CRITICAL",
            "scope": "vulnerabilities",
            "vulnerability_risk": {
                "critical_vulns": 15,
                "exploitable": 8,
                "public_exploits": 5,
                "average_age_days": 45
            }
        }
        
        # Call tool with scope
        result = await server.handle_tool_call(
            name="risk_assessment",
            arguments={
                "scope": "vulnerabilities"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "CRITICAL" in content
        assert "vulnerabilit" in content.lower()
        
    @pytest.mark.asyncio
    async def test_risk_assessment_network_focus(self, server):
        """Test risk assessment with network focus."""
        # Mock network-related data
        server.client_manager.alerts.search.return_value = {
            "data": {
                "affected_items": [
                    {
                        "id": "alert_001",
                        "rule": {"groups": ["network", "ids"]},
                        "data": {"srcip": "10.0.0.100", "dstport": "445"}
                    }
                ],
                "total_affected_items": 50
            }
        }
        
        # Mock network risk analysis
        server.security_analyzer.assess_risk.return_value = {
            "overall_risk_score": 68.0,
            "risk_level": "MEDIUM-HIGH",
            "scope": "network",
            "network_risks": {
                "suspicious_connections": 25,
                "open_ports": ["445", "3389", "22"],
                "external_threats": 10,
                "lateral_movement_indicators": 3
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="risk_assessment",
            arguments={
                "scope": "network"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "network" in content.lower()
        assert "68.0" in content or "MEDIUM-HIGH" in content
        
    @pytest.mark.asyncio
    async def test_risk_assessment_compliance_focus(self, server):
        """Test risk assessment with compliance focus."""
        # Mock compliance-related data
        server.security_analyzer.assess_risk.return_value = {
            "overall_risk_score": 55.0,
            "risk_level": "MEDIUM",
            "scope": "compliance",
            "compliance_risks": {
                "frameworks": {
                    "pci_dss": {"score": 70, "gaps": 5},
                    "hipaa": {"score": 85, "gaps": 2},
                    "gdpr": {"score": 60, "gaps": 8}
                },
                "audit_readiness": "Partial",
                "policy_violations": 15
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="risk_assessment",
            arguments={
                "scope": "compliance"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "compliance" in content.lower()
        assert "MEDIUM" in content
        
    @pytest.mark.asyncio
    async def test_risk_assessment_low_risk(self, server):
        """Test risk assessment with low risk environment."""
        # Mock minimal issues
        server.client_manager.alerts.search.return_value = {
            "data": {"affected_items": [], "total_affected_items": 0}
        }
        server.client_manager.vulnerabilities.search.return_value = {
            "data": {"affected_items": [], "total_affected_items": 0}
        }
        
        # Mock low risk analysis
        server.security_analyzer.assess_risk.return_value = {
            "overall_risk_score": 25.0,
            "risk_level": "LOW",
            "positive_indicators": [
                "No critical vulnerabilities",
                "No active security incidents",
                "All agents reporting"
            ],
            "recommendations": [
                "Maintain current security posture",
                "Continue regular patching schedule"
            ]
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="risk_assessment",
            arguments={}
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "LOW" in content
        assert "25.0" in content or "positive" in content.lower()
        
    @pytest.mark.asyncio
    async def test_risk_assessment_error_handling(self, server):
        """Test error handling in risk assessment."""
        # Mock error
        server.client_manager.alerts.search.side_effect = Exception("Risk assessment failed")
        
        # Call tool
        result = await server.handle_tool_call(
            name="risk_assessment",
            arguments={}
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content