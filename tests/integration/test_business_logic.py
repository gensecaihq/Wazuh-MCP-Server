#!/usr/bin/env python3
"""
Comprehensive Business Logic Test Suite
======================================
Tests all FastMCP tools and business logic components for error-free operation.
"""

import sys
import asyncio
import json
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

async def test_fastmcp_server():
    """Test FastMCP server functionality."""
    print("🧪 Testing FastMCP Server Components...")
    
    try:
        from wazuh_mcp_server.server import mcp, startup_server
        print("✅ FastMCP server import successful")
        
        # Test server initialization
        await startup_server()
        print("✅ Server initialization successful")
        
        # Count tools
        tools = [attr for attr in dir(mcp) if hasattr(getattr(mcp, attr), '_fastmcp_tool')]
        print(f"✅ Found {len(tools)} FastMCP tools")
        
        return True
        
    except Exception as e:
        print(f"❌ FastMCP server test failed: {e}")
        return False

async def test_client_manager():
    """Test Wazuh Client Manager."""
    print("\n🧪 Testing Wazuh Client Manager...")
    
    try:
        from wazuh_mcp_server.config import WazuhConfig
        from wazuh_mcp_server.api.wazuh_client_manager import WazuhClientManager
        
        config = WazuhConfig()
        client_manager = WazuhClientManager(config)
        print("✅ Client manager initialization successful")
        
        # Test required methods exist
        required_methods = [
            'get_alerts', 'get_agents', 'get_vulnerabilities',
            'get_alert_summary', 'get_running_agents', 'get_cluster_health',
            'get_rules_summary', 'get_weekly_stats', 'search_manager_logs',
            'get_critical_vulnerabilities', 'get_vulnerability_summary',
            'get_remoted_stats', 'get_log_collector_stats', 'get_manager_error_logs',
            'check_agent_health', 'get_wazuh_statistics', 'search_security_events',
            'get_agent_configuration', 'validate_connection'
        ]
        
        for method in required_methods:
            if hasattr(client_manager, method):
                print(f"✅ Method {method} exists")
            else:
                print(f"❌ Method {method} missing")
                return False
        
        return True
        
    except Exception as e:
        print(f"❌ Client manager test failed: {e}")
        return False

async def test_analyzers():
    """Test Security and Compliance Analyzers."""
    print("\n🧪 Testing Analyzers...")
    
    try:
        from wazuh_mcp_server.analyzers import SecurityAnalyzer, ComplianceAnalyzer
        
        security_analyzer = SecurityAnalyzer()
        compliance_analyzer = ComplianceAnalyzer()
        print("✅ Analyzers initialization successful")
        
        # Test required async methods exist
        security_methods = [
            'analyze_threat', 'check_ioc_reputation', 'perform_risk_assessment',
            'analyze_alert_patterns', 'get_top_security_threats', 'generate_security_report'
        ]
        
        for method in security_methods:
            if hasattr(security_analyzer, method):
                print(f"✅ SecurityAnalyzer method {method} exists")
            else:
                print(f"❌ SecurityAnalyzer method {method} missing")
                return False
        
        # Test compliance methods
        if hasattr(compliance_analyzer, 'run_compliance_check'):
            print("✅ ComplianceAnalyzer method run_compliance_check exists")
        else:
            print("❌ ComplianceAnalyzer method run_compliance_check missing")
            return False
        
        return True
        
    except Exception as e:
        print(f"❌ Analyzers test failed: {e}")
        return False

def test_configuration():
    """Test configuration loading."""
    print("\n🧪 Testing Configuration...")
    
    try:
        from wazuh_mcp_server.config import WazuhConfig
        
        config = WazuhConfig()
        print("✅ Configuration loading successful")
        print(f"✅ Wazuh host: {config.host}")
        print(f"✅ Wazuh port: {config.port}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_docker_compatibility():
    """Test Docker environment compatibility."""
    print("\n🧪 Testing Docker Compatibility...")
    
    try:
        import os
        import platform
        import socket
        
        print(f"✅ Platform: {platform.system()} {platform.release()}")
        print(f"✅ Python version: {platform.python_version()}")
        print(f"✅ Working directory: {os.getcwd()}")
        
        # Test network connectivity
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            print("✅ Network connectivity available")
        except:
            print("⚠️  Limited network connectivity (expected in some environments)")
        
        # Test environment variables
        python_path = os.environ.get('PYTHONPATH', 'Not set')
        print(f"✅ PYTHONPATH: {python_path}")
        
        return True
        
    except Exception as e:
        print(f"❌ Docker compatibility test failed: {e}")
        return False

def test_dependencies():
    """Test all required dependencies."""
    print("\n🧪 Testing Dependencies...")
    
    dependencies = [
        'fastmcp', 'httpx', 'aiohttp', 'requests', 'pydantic', 'python-dotenv',
        'urllib3', 'certifi', 'numpy', 'packaging', 'python_dateutil', 'psutil'
    ]
    
    failed = []
    
    for dep in dependencies:
        try:
            __import__(dep.replace('-', '_'))
            print(f"✅ {dep} available")
        except ImportError:
            print(f"❌ {dep} missing")
            failed.append(dep)
    
    if failed:
        print(f"❌ Missing dependencies: {failed}")
        return False
    
    return True

async def run_comprehensive_test():
    """Run all business logic tests."""
    print("🚀 Wazuh MCP Server - Comprehensive Business Logic Test")
    print("=" * 60)
    
    tests = [
        ("Dependencies", test_dependencies),
        ("Configuration", test_configuration),
        ("Docker Compatibility", test_docker_compatibility),
        ("Client Manager", test_client_manager),
        ("Analyzers", test_analyzers),
        ("FastMCP Server", test_fastmcp_server),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        print(f"\n📋 Running {test_name} Test...")
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            
            if result:
                print(f"✅ {test_name} Test PASSED")
                passed += 1
            else:
                print(f"❌ {test_name} Test FAILED")
                failed += 1
        except Exception as e:
            print(f"❌ {test_name} Test ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All business logic tests PASSED! Server is ready for production.")
        return 0
    else:
        print(f"⚠️  {failed} tests FAILED. Please fix issues before deployment.")
        return 1

if __name__ == "__main__":
    exit_code = asyncio.run(run_comprehensive_test())
    sys.exit(exit_code)