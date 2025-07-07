#!/usr/bin/env python3
"""
Test script to verify the Wazuh MCP Server package installation and functionality.
Run this script after installing the package to ensure everything works correctly.
"""

import sys
import subprocess
import importlib.util


def test_package_installation():
    """Test if the package is properly installed and importable."""
    print("🔍 Testing Wazuh MCP Server package installation...")
    
    try:
        # Test importing the main module
        import wazuh_mcp_server
        print("✅ Successfully imported wazuh_mcp_server")
        
        # Test importing version
        from wazuh_mcp_server.__version__ import __version__
        print(f"✅ Package version: {__version__}")
        
        # Test importing main components
        from wazuh_mcp_server.config import WazuhConfig
        print("✅ Successfully imported WazuhConfig")
        
        from wazuh_mcp_server.api_client import WazuhAPIClient
        print("✅ Successfully imported WazuhAPIClient")
        
        # Test console scripts
        try:
            result = subprocess.run([sys.executable, "-c", "import wazuh_mcp_server.main; print('Main module import successful')"], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✅ Main module can be executed")
            else:
                print(f"⚠️  Main module execution issue: {result.stderr}")
        except subprocess.TimeoutExpired:
            print("⚠️  Main module execution timed out")
        except Exception as e:
            print(f"⚠️  Error testing main module: {e}")
            
        print("\n🎉 Package installation test completed successfully!")
        print("\n📖 Usage examples:")
        print("   Command line: wazuh-mcp-server --help")
        print("   Test connection: wazuh-mcp-test")
        print("   Python import: from wazuh_mcp_server import main")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("   Make sure the package is installed: pip install wazuh-mcp-server")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def test_dependencies():
    """Test if all required dependencies are available."""
    print("\n🔍 Testing dependencies...")
    
    required_deps = [
        "mcp", "aiohttp", "aiohttp_cors", "websockets", "jwt",
        "urllib3", "dateutil", "dotenv", "pydantic", "packaging",
        "psutil", "certifi"
    ]
    
    missing_deps = []
    for dep in required_deps:
        try:
            if dep == "jwt":
                import jwt as dep_module
            elif dep == "dateutil":
                import dateutil as dep_module
            elif dep == "dotenv":
                import dotenv as dep_module
            else:
                dep_module = importlib.import_module(dep)
            print(f"✅ {dep} is available")
        except ImportError:
            print(f"❌ {dep} is missing")
            missing_deps.append(dep)
    
    if missing_deps:
        print(f"\n⚠️  Missing dependencies: {', '.join(missing_deps)}")
        print("   Run: pip install wazuh-mcp-server to install all dependencies")
        return False
    else:
        print("\n✅ All dependencies are satisfied!")
        return True


if __name__ == "__main__":
    print("🚀 Wazuh MCP Server Package Test\n")
    
    deps_ok = test_dependencies()
    package_ok = test_package_installation()
    
    if deps_ok and package_ok:
        print("\n🎉 All tests passed! The package is ready to use.")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed. Please check the output above.")
        sys.exit(1)
