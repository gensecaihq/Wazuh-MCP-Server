"""Tests for compliance_check tool."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from tests.fixtures.mock_data import MockWazuhData


class TestComplianceCheck:
    """Test cases for compliance_check tool."""
    
    @pytest.fixture
    def server(self):
        """Create a mock server instance."""
        from wazuh_mcp_server.main import WazuhMCPServer
        with patch('wazuh_mcp_server.main.setup_logging'):
            with patch('wazuh_mcp_server.main.WazuhConfig'):
                server = WazuhMCPServer()
                server.client_manager = AsyncMock()
                server.compliance_analyzer = MagicMock()
                server.logger = AsyncMock()
                return server
    
    @pytest.mark.asyncio
    async def test_compliance_check_pci_dss(self, server):
        """Test PCI DSS compliance check."""
        # Mock compliance analysis
        server.compliance_analyzer.assess_compliance.return_value = {
            "framework": "pci_dss",
            "compliance_score": 85.5,
            "status": "PARTIALLY_COMPLIANT",
            "passed_controls": 45,
            "failed_controls": 8,
            "total_controls": 53,
            "critical_findings": [
                "Unencrypted cardholder data found",
                "Missing network segmentation"
            ]
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="compliance_check",
            arguments={
                "framework": "pci_dss"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "PCI DSS" in content
        assert "85.5" in content
        assert "PARTIALLY_COMPLIANT" in content
        
    @pytest.mark.asyncio
    async def test_compliance_check_hipaa(self, server):
        """Test HIPAA compliance check."""
        # Mock compliance analysis
        server.compliance_analyzer.assess_compliance.return_value = {
            "framework": "hipaa",
            "compliance_score": 92.0,
            "status": "COMPLIANT",
            "passed_controls": 58,
            "failed_controls": 5,
            "total_controls": 63,
            "recommendations": [
                "Enable audit logging for all PHI access",
                "Implement data encryption at rest"
            ]
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="compliance_check",
            arguments={
                "framework": "hipaa"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "HIPAA" in content
        assert "COMPLIANT" in content
        
    @pytest.mark.asyncio
    async def test_compliance_check_gdpr(self, server):
        """Test GDPR compliance check."""
        # Mock compliance analysis
        server.compliance_analyzer.assess_compliance.return_value = {
            "framework": "gdpr",
            "compliance_score": 78.5,
            "status": "NEEDS_IMPROVEMENT",
            "data_protection_measures": {
                "encryption": "Partial",
                "access_controls": "Implemented",
                "data_retention": "Not configured",
                "consent_management": "Missing"
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="compliance_check",
            arguments={
                "framework": "gdpr"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "GDPR" in content
        assert "78.5" in content
        
    @pytest.mark.asyncio
    async def test_compliance_check_with_scope(self, server):
        """Test compliance check with specific scope."""
        # Mock scoped compliance analysis
        server.compliance_analyzer.assess_compliance.return_value = {
            "framework": "nist",
            "scope": "critical_controls",
            "compliance_score": 88.0,
            "critical_controls_status": {
                "inventory": "PASS",
                "secure_configuration": "PASS",
                "vulnerability_management": "FAIL",
                "controlled_access": "PASS"
            }
        }
        
        # Call tool with scope
        result = await server.handle_tool_call(
            name="compliance_check",
            arguments={
                "framework": "nist",
                "scope": "critical_controls"
            }
        )
        
        # Verify
        assert result is not None
        server.compliance_analyzer.assess_compliance.assert_called_with(
            framework="nist",
            scope="critical_controls"
        )
        
    @pytest.mark.asyncio
    async def test_compliance_check_iso27001(self, server):
        """Test ISO 27001 compliance check."""
        # Mock compliance analysis
        server.compliance_analyzer.assess_compliance.return_value = {
            "framework": "iso27001",
            "compliance_score": 90.0,
            "status": "COMPLIANT",
            "certification_ready": True,
            "control_objectives": {
                "A.5": "PASS",  # Information security policies
                "A.6": "PASS",  # Organization of information security
                "A.7": "PASS",  # Human resource security
                "A.8": "FAIL"   # Asset management
            }
        }
        
        # Call tool
        result = await server.handle_tool_call(
            name="compliance_check",
            arguments={
                "framework": "iso27001"
            }
        )
        
        # Verify
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "ISO 27001" in content
        assert "certification_ready" in content.lower() or "90.0" in content
        
    @pytest.mark.asyncio
    async def test_compliance_check_invalid_framework(self, server):
        """Test compliance check with invalid framework."""
        # Mock error response
        server.compliance_analyzer.assess_compliance.side_effect = ValueError("Invalid framework")
        
        # Call tool with invalid framework
        result = await server.handle_tool_call(
            name="compliance_check",
            arguments={
                "framework": "invalid_framework"
            }
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content or "Invalid" in content
        
    @pytest.mark.asyncio
    async def test_compliance_check_error_handling(self, server):
        """Test error handling in compliance check."""
        # Mock error
        server.compliance_analyzer.assess_compliance.side_effect = Exception("Compliance check failed")
        
        # Call tool
        result = await server.handle_tool_call(
            name="compliance_check",
            arguments={
                "framework": "pci_dss"
            }
        )
        
        # Verify error handling
        assert result is not None
        content = result[0].text if hasattr(result[0], 'text') else str(result[0])
        assert "Error" in content or "error" in content