"""
Test suite for v1.0.1 hotfix - Pydantic V1/V2 compatibility.
Tests the compatibility layer and Fedora-specific functionality.
"""

import pytest
import sys
import os
from unittest.mock import patch, mock_open


def test_platform_detection():
    """Test platform detection functionality."""
    from wazuh_mcp_server.utils.platform_compat import detect_platform, PLATFORM_INFO
    
    # Test that platform detection works
    assert isinstance(PLATFORM_INFO, dict)
    assert 'system' in PLATFORM_INFO
    assert 'is_fedora' in PLATFORM_INFO
    assert 'is_macos' in PLATFORM_INFO
    assert 'is_ubuntu' in PLATFORM_INFO
    assert 'pydantic_version' in PLATFORM_INFO
    assert 'pydantic_v2' in PLATFORM_INFO
    
    # Test detect_platform function
    platform_info = detect_platform()
    assert isinstance(platform_info, dict)
    assert len(platform_info) >= 6


@patch('builtins.open', mock_open(read_data='NAME="Fedora Linux"\nID=fedora\n'))
@patch('os.path.exists')
def test_fedora_detection(mock_exists):
    """Test Fedora detection logic."""
    mock_exists.return_value = False
    
    from wazuh_mcp_server.utils.platform_compat import detect_platform
    
    with patch('platform.system', return_value='Linux'):
        platform_info = detect_platform()
        assert platform_info['is_fedora'] == True
        assert platform_info['system'] == 'linux'


def test_pydantic_compatibility_layer():
    """Test Pydantic compatibility layer imports."""
    from wazuh_mcp_server.utils.pydantic_compat import (
        BaseModel, Field, validator, PYDANTIC_V2, pydantic_available
    )
    
    # Test imports work
    assert BaseModel is not None
    assert Field is not None
    assert validator is not None
    assert isinstance(PYDANTIC_V2, bool)
    assert isinstance(pydantic_available, bool)


def test_validation_models_v1_syntax():
    """Test that validation models work with V1 syntax."""
    from wazuh_mcp_server.utils.validation import AlertQuery, AgentQuery, ValidationError
    
    # Test AlertQuery
    query = AlertQuery()
    assert query.limit == 100
    assert query.sort == "-timestamp"
    
    # Test valid sort
    query = AlertQuery(sort="timestamp")
    assert query.sort == "timestamp"
    
    # Test invalid sort should raise ValueError (handled by Pydantic)
    with pytest.raises(Exception):  # Could be ValueError or ValidationError depending on Pydantic version
        AlertQuery(sort="invalid_sort")
    
    # Test AgentQuery
    agent_query = AgentQuery()
    assert agent_query.agent_id is None
    assert agent_query.status is None
    
    # Test valid agent ID
    agent_query = AgentQuery(agent_id="001")
    assert agent_query.agent_id == "001"


def test_config_models_v1_syntax():
    """Test configuration models work with V1 syntax."""
    from wazuh_mcp_server.config import WazuhConfig
    
    # Test basic configuration
    config = WazuhConfig(
        host="test.example.com",
        username="test_user",
        password="test_password_123"
    )
    
    assert config.host == "test.example.com"
    assert config.username == "test_user"
    assert config.password == "test_password_123"
    assert config.port == 55000  # Default value


def test_validation_functions():
    """Test validation utility functions."""
    from wazuh_mcp_server.utils.validation import (
        validate_alert_query,
        validate_agent_query,
        ValidationError
    )
    
    # Test alert query validation
    result = validate_alert_query({"limit": 50, "sort": "-timestamp"})
    assert result.limit == 50
    assert result.sort == "-timestamp"
    
    # Test agent query validation
    result = validate_agent_query({"agent_id": "001"})
    assert result.agent_id == "001"


def test_compatibility_with_both_pydantic_versions():
    """Test compatibility layer works with different Pydantic versions."""
    from wazuh_mcp_server.utils.pydantic_compat import PYDANTIC_V2
    
    # Import should work regardless of version
    from wazuh_mcp_server.utils.validation import AlertQuery
    
    # Basic functionality should work
    query = AlertQuery(limit=200)
    assert query.limit == 200
    
    # Version-specific behavior
    if PYDANTIC_V2:
        # V2 should use compatibility layer
        print("Testing with Pydantic V2 compatibility")
    else:
        # V1 should work natively
        print("Testing with native Pydantic V1")


def test_error_handling():
    """Test error handling in validators."""
    from wazuh_mcp_server.utils.validation import ValidationError, validate_alert_query
    
    # Test invalid parameters
    with pytest.raises(ValidationError):
        validate_alert_query({"sort": "invalid_sort"})


def test_installation_script_platform_detection():
    """Test installation script platform detection."""
    # Import the installation script functions
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    
    from install_hotfix import detect_platform
    
    platform_info = detect_platform()
    assert isinstance(platform_info, dict)
    assert 'system' in platform_info
    assert 'is_fedora' in platform_info


@pytest.mark.integration
def test_full_import_chain():
    """Integration test - full import chain should work."""
    # This tests the complete import chain works
    from wazuh_mcp_server.main import WazuhMCPServer
    from wazuh_mcp_server.config import WazuhConfig
    from wazuh_mcp_server.utils.validation import AlertQuery
    
    # Should be able to create instances
    config = WazuhConfig(
        host="test.example.com",
        username="test_user", 
        password="secure_password_123"
    )
    
    query = AlertQuery(limit=10)
    
    # Basic validation
    assert config.host == "test.example.com"
    assert query.limit == 10


def test_fedora_warning_mechanism():
    """Test that Fedora warning system works."""
    import warnings
    from wazuh_mcp_server.utils.platform_compat import PLATFORM_INFO
    
    # If we're on Fedora with V2, should have logged warning
    if PLATFORM_INFO.get('is_fedora') and PLATFORM_INFO.get('pydantic_v2'):
        # Warning should have been issued during import
        print("Fedora V2 compatibility mode active")
    
    # This test mainly verifies the mechanism doesn't crash


def test_version_information():
    """Test version information is correct for hotfix."""
    # Check that we have the right version
    import toml
    
    pyproject_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'pyproject.toml')
    if os.path.exists(pyproject_path):
        with open(pyproject_path, 'r') as f:
            config = toml.load(f)
            version = config['project']['version']
            assert version == "1.0.1", f"Expected version 1.0.1, got {version}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])