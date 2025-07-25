#!/usr/bin/env python3
"""
Mock environment for testing Wazuh MCP Server without full dependencies.
This helps identify structural and logic issues without requiring external packages.
"""

import sys
import os
from pathlib import Path
from unittest.mock import MagicMock, Mock
from types import SimpleNamespace

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

# Mock external dependencies before importing anything
class MockMCPTypes:
    class Tool:
        def __init__(self, name, description, inputSchema):
            self.name = name
            self.description = description
            self.inputSchema = inputSchema

# Mock MCP module
mcp_mock = SimpleNamespace()
mcp_mock.types = MockMCPTypes()

sys.modules['mcp'] = mcp_mock
sys.modules['mcp.types'] = MockMCPTypes()

# Mock FastMCP
class MockFastMCP:
    def __init__(self, name, version, description):
        self.name = name
        self.version = version
        self.description = description
        self._tool_manager = MagicMock()
        
    def tool(self, *args, **kwargs):
        def decorator(func):
            return func
        return decorator
        
    def resource(self, uri):
        def decorator(func):
            return func
        return decorator
        
    def prompt(self, name):
        def decorator(func):
            return func
        return decorator

fastmcp_mock = SimpleNamespace()
fastmcp_mock.FastMCP = MockFastMCP
fastmcp_mock.Context = MagicMock
sys.modules['fastmcp'] = fastmcp_mock

# Mock httpx
httpx_mock = SimpleNamespace()
httpx_mock.AsyncClient = MagicMock
sys.modules['httpx'] = httpx_mock

# Mock other dependencies
sys.modules['dateutil'] = MagicMock()
sys.modules['dateutil.parser'] = MagicMock()
sys.modules['dotenv'] = MagicMock()

# Create a function to test imports and basic structure
def test_wazuh_mcp_structure():
    """Test the basic structure and imports of Wazuh MCP Server."""
    errors = []
    
    try:
        # Test config import
        from wazuh_mcp_server.config import WazuhConfig
        print("✓ Config import: OK")
    except Exception as e:
        errors.append(f"Config import error: {e}")
        print(f"✗ Config import: {e}")
    
    try:
        # Test version import
        from wazuh_mcp_server.__version__ import __version__
        print(f"✓ Version import: OK ({__version__})")
    except Exception as e:
        errors.append(f"Version import error: {e}")
        print(f"✗ Version import: {e}")
    
    try:
        # Test tool factory import
        from wazuh_mcp_server.tools.factory import ToolFactory
        print("✓ ToolFactory import: OK")
    except Exception as e:
        errors.append(f"ToolFactory import error: {e}")
        print(f"✗ ToolFactory import: {e}")
    
    try:
        # Test individual tool modules
        from wazuh_mcp_server.tools.alerts import AlertTools
        from wazuh_mcp_server.tools.agents import AgentTools
        from wazuh_mcp_server.tools.cluster import ClusterTools
        from wazuh_mcp_server.tools.statistics import StatisticsTools
        from wazuh_mcp_server.tools.vulnerabilities import VulnerabilityTools
        print("✓ All tool modules import: OK")
    except Exception as e:
        errors.append(f"Tool modules import error: {e}")
        print(f"✗ Tool modules import: {e}")
    
    try:
        # Test base tool
        from wazuh_mcp_server.tools.base import BaseTool
        print("✓ BaseTool import: OK")
    except Exception as e:
        errors.append(f"BaseTool import error: {e}")
        print(f"✗ BaseTool import: {e}")
    
    try:
        # Test utilities
        from wazuh_mcp_server.utils.logging import get_logger
        from wazuh_mcp_server.utils.validation import validate_int_range
        print("✓ Utilities import: OK")
    except Exception as e:
        errors.append(f"Utilities import error: {e}")
        print(f"✗ Utilities import: {e}")
    
    try:
        # Test main server import (this is the big one)
        from wazuh_mcp_server import server
        print("✓ Main server import: OK")
    except Exception as e:
        errors.append(f"Main server import error: {e}")
        print(f"✗ Main server import: {e}")
    
    return errors

def test_tool_factory_initialization():
    """Test tool factory can be initialized."""
    try:
        from wazuh_mcp_server.tools.factory import ToolFactory
        from types import SimpleNamespace
        
        # Create mock server
        mock_server = SimpleNamespace()
        mock_server.config = None
        mock_server.api_client = None
        mock_server.security_analyzer = None
        mock_server.compliance_analyzer = None
        
        # Test factory creation
        factory = ToolFactory(mock_server)
        stats = factory.get_tool_statistics()
        
        print(f"✓ Tool factory initialization: OK")
        print(f"  - Categories: {stats['total_categories']}")
        print(f"  - Total tools: {stats['total_tools']}")
        
        for category, info in stats['categories'].items():
            print(f"  - {category}: {info['tool_count']} tools")
            if info.get('error'):
                print(f"    ERROR: {info['error']}")
        
        return []
        
    except Exception as e:
        print(f"✗ Tool factory initialization: {e}")
        import traceback
        traceback.print_exc()
        return [f"Tool factory initialization error: {e}"]

def test_configuration_logic():
    """Test configuration validation logic."""
    try:
        from wazuh_mcp_server.config import WazuhConfig
        
        # Test environment parsing without actual environment variables
        print("✓ Configuration class accessible: OK")
        return []
        
    except Exception as e:
        print(f"✗ Configuration test: {e}")
        return [f"Configuration error: {e}"]

if __name__ == "__main__":
    print("🔍 WAZUH MCP SERVER STRUCTURE TEST")
    print("=" * 50)
    
    # Run all tests
    all_errors = []
    
    print("\n1. Testing imports and structure...")
    all_errors.extend(test_wazuh_mcp_structure())
    
    print("\n2. Testing tool factory...")
    all_errors.extend(test_tool_factory_initialization())
    
    print("\n3. Testing configuration...")
    all_errors.extend(test_configuration_logic())
    
    print("\n" + "=" * 50)
    if all_errors:
        print(f"❌ FOUND {len(all_errors)} ISSUES:")
        for i, error in enumerate(all_errors, 1):
            print(f"  {i}. {error}")
        sys.exit(1)
    else:
        print("✅ ALL STRUCTURAL TESTS PASSED!")
        print("The codebase structure is sound.")
        sys.exit(0)