#!/usr/bin/env python3
"""
Wazuh MCP Server - Functionality Test Suite
Comprehensive testing of MCP server functionality and Wazuh integration
"""

import sys
import os
import asyncio
import json
import time
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

# Add src directory to Python path
current_dir = Path(__file__).resolve().parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

class TestResults:
    """Test results tracker."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.tests = []
    
    def add_test(self, name: str, status: str, message: str = "", duration: float = 0):
        """Add test result."""
        self.tests.append({
            "name": name,
            "status": status, 
            "message": message,
            "duration": duration,
            "timestamp": datetime.now().isoformat()
        })
        
        if status == "PASS":
            self.passed += 1
        elif status == "FAIL":
            self.failed += 1
        elif status == "WARN":
            self.warnings += 1
    
    def print_summary(self):
        """Print test summary."""
        total = self.passed + self.failed + self.warnings
        print("\n" + "="*60)
        print("📊 TEST SUMMARY")
        print("="*60)
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"⚠️  Warnings: {self.warnings}")
        print(f"Success Rate: {(self.passed/total*100):.1f}%" if total > 0 else "0%")
        print("="*60)
        
        return self.failed == 0

async def test_imports():
    """Test critical imports."""
    results = TestResults()
    
    print("🔍 Testing imports...")
    
    # Test FastMCP import
    start_time = time.time()
    try:
        from fastmcp import FastMCP
        results.add_test("FastMCP Import", "PASS", "FastMCP imported successfully", time.time() - start_time)
    except ImportError as e:
        results.add_test("FastMCP Import", "FAIL", f"FastMCP import failed: {e}", time.time() - start_time)
    
    # Test server imports
    start_time = time.time()
    try:
        from wazuh_mcp_server.server import mcp
        results.add_test("Server Import", "PASS", "Server module imported successfully", time.time() - start_time)
    except ImportError as e:
        results.add_test("Server Import", "FAIL", f"Server import failed: {e}", time.time() - start_time)
    
    # Test config imports
    start_time = time.time()
    try:
        from wazuh_mcp_server.config import WazuhConfig
        results.add_test("Config Import", "PASS", "Config module imported successfully", time.time() - start_time)
    except ImportError as e:
        results.add_test("Config Import", "FAIL", f"Config import failed: {e}", time.time() - start_time)
    
    # Test client imports
    start_time = time.time()
    try:
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        results.add_test("Client Import", "PASS", "Client module imported successfully", time.time() - start_time)
    except ImportError as e:
        results.add_test("Client Import", "FAIL", f"Client import failed: {e}", time.time() - start_time)
    
    return results

async def test_configuration():
    """Test configuration loading."""
    results = TestResults()
    
    print("⚙️  Testing configuration...")
    
    # Test config creation with minimal env
    start_time = time.time()
    try:
        # Clear any existing MCP_TRANSPORT to test default
        if "MCP_TRANSPORT" in os.environ:
            del os.environ["MCP_TRANSPORT"]
            
        os.environ.update({
            "WAZUH_HOST": "test-host.example.com",
            "WAZUH_USER": "test-user", 
            "WAZUH_PASS": "test-password"
        })
        
        from wazuh_mcp_server.config import WazuhConfig
        config = WazuhConfig.from_env()
        
        if config.wazuh_host == "test-host.example.com":
            results.add_test("Config Creation", "PASS", "Configuration created successfully", time.time() - start_time)
        else:
            results.add_test("Config Creation", "FAIL", "Configuration values not set correctly", time.time() - start_time)
            
    except Exception as e:
        results.add_test("Config Creation", "FAIL", f"Configuration creation failed: {e}", time.time() - start_time)
    
    # Test HTTP transport default
    start_time = time.time()
    try:
        if config.mcp_transport == "http":
            results.add_test("HTTP Default", "PASS", "Transport defaults to HTTP correctly", time.time() - start_time)
        else:
            results.add_test("HTTP Default", "FAIL", f"Transport default is {config.mcp_transport}, expected http", time.time() - start_time)
    except Exception as e:
        results.add_test("HTTP Default", "FAIL", f"Transport test failed: {e}", time.time() - start_time)
    
    return results

async def test_fastmcp_server():
    """Test FastMCP server functionality."""
    results = TestResults()
    
    print("🚀 Testing FastMCP server...")
    
    # Test server creation
    start_time = time.time()
    try:
        from wazuh_mcp_server.server import mcp
        
        if hasattr(mcp, 'get_tools') and hasattr(mcp, 'get_resources'):
            results.add_test("FastMCP Server", "PASS", "FastMCP server instance created", time.time() - start_time)
        else:
            results.add_test("FastMCP Server", "FAIL", "FastMCP server missing tools/resources methods", time.time() - start_time)
            
    except Exception as e:
        results.add_test("FastMCP Server", "FAIL", f"FastMCP server creation failed: {e}", time.time() - start_time)
    
    # Test tools registration
    start_time = time.time()
    try:
        tools = await mcp.get_tools()
        tool_count = len(tools)
        if tool_count > 0:
            results.add_test("Tools Registration", "PASS", f"{tool_count} tools registered", time.time() - start_time)
        else:
            results.add_test("Tools Registration", "FAIL", "No tools registered", time.time() - start_time)
            
    except Exception as e:
        results.add_test("Tools Registration", "FAIL", f"Tools check failed: {e}", time.time() - start_time)
    
    # Test resources registration
    start_time = time.time()
    try:
        resources = await mcp.get_resources()
        resource_count = len(resources)
        if resource_count > 0:
            results.add_test("Resources Registration", "PASS", f"{resource_count} resources registered", time.time() - start_time)
        else:
            results.add_test("Resources Registration", "WARN", "No resources registered", time.time() - start_time)
            
    except Exception as e:
        results.add_test("Resources Registration", "FAIL", f"Resources check failed: {e}", time.time() - start_time)
    
    return results

async def test_file_structure():
    """Test required file structure."""
    results = TestResults()
    
    print("📁 Testing file structure...")
    
    required_files = [
        "wazuh-mcp-server",
        "src/wazuh_mcp_server/server.py",
        "src/wazuh_mcp_server/config.py", 
        "src/wazuh_mcp_server/api/wazuh_client.py",
        "config/wazuh.env.example",
        "docker/entrypoint.sh",
        "compose.yml",
        "requirements.txt"
    ]
    
    for file_path in required_files:
        start_time = time.time()
        if Path(file_path).exists():
            results.add_test(f"File: {file_path}", "PASS", "File exists", time.time() - start_time)
        else:
            results.add_test(f"File: {file_path}", "FAIL", "File missing", time.time() - start_time)
    
    return results

async def test_script_permissions():
    """Test script permissions."""
    results = TestResults()
    
    print("🔐 Testing script permissions...")
    
    executable_files = [
        "wazuh-mcp-server",
        "configure-wazuh.sh",
        "quick-deploy.sh", 
        "deploy-prebuilt.sh",
        "build-image.sh",
        "verify-container.sh",
        "docker/entrypoint.sh"
    ]
    
    for script in executable_files:
        start_time = time.time()
        script_path = Path(script)
        if script_path.exists():
            if os.access(script_path, os.X_OK):
                results.add_test(f"Executable: {script}", "PASS", "Script is executable", time.time() - start_time)
            else:
                results.add_test(f"Executable: {script}", "FAIL", "Script not executable", time.time() - start_time)
        else:
            results.add_test(f"Executable: {script}", "FAIL", "Script missing", time.time() - start_time)
    
    return results

async def test_docker_configuration():
    """Test Docker configuration."""
    results = TestResults()
    
    print("🐳 Testing Docker configuration...")
    
    # Test compose.yml syntax
    start_time = time.time()
    try:
        import subprocess
        result = subprocess.run(
            ["docker", "compose", "config"], 
            capture_output=True, 
            text=True,
            cwd=current_dir
        )
        if result.returncode == 0:
            results.add_test("Docker Compose Syntax", "PASS", "compose.yml syntax valid", time.time() - start_time)
        else:
            results.add_test("Docker Compose Syntax", "FAIL", f"compose.yml syntax error: {result.stderr}", time.time() - start_time)
    except FileNotFoundError:
        results.add_test("Docker Compose Syntax", "WARN", "Docker not installed, skipping test", time.time() - start_time)
    except Exception as e:
        results.add_test("Docker Compose Syntax", "FAIL", f"Docker test failed: {e}", time.time() - start_time)
    
    return results

async def main():
    """Main test runner."""
    print("🧪 Wazuh MCP Server - Functionality Test Suite")
    print("=" * 60)
    print(f"Started at: {datetime.now().isoformat()}")
    print("=" * 60)
    
    all_results = TestResults()
    
    # Run all test suites
    test_suites = [
        ("Import Tests", test_imports),
        ("Configuration Tests", test_configuration), 
        ("FastMCP Server Tests", test_fastmcp_server),
        ("File Structure Tests", test_file_structure),
        ("Script Permissions Tests", test_script_permissions),
        ("Docker Configuration Tests", test_docker_configuration)
    ]
    
    for suite_name, test_func in test_suites:
        print(f"\n🔬 Running {suite_name}...")
        try:
            suite_results = await test_func()
            
            # Merge results
            all_results.passed += suite_results.passed
            all_results.failed += suite_results.failed
            all_results.warnings += suite_results.warnings
            all_results.tests.extend(suite_results.tests)
            
            # Print suite summary
            suite_total = suite_results.passed + suite_results.failed + suite_results.warnings
            print(f"   ✅ {suite_results.passed} passed, ❌ {suite_results.failed} failed, ⚠️ {suite_results.warnings} warnings")
            
        except Exception as e:
            print(f"   ❌ Test suite failed: {e}")
            all_results.add_test(suite_name, "FAIL", f"Suite execution failed: {e}")
    
    # Print final summary
    success = all_results.print_summary()
    
    # Save detailed results
    results_file = current_dir / "test-results.json"
    with open(results_file, 'w') as f:
        json.dump({
            "summary": {
                "passed": all_results.passed,
                "failed": all_results.failed,
                "warnings": all_results.warnings,
                "success": success
            },
            "tests": all_results.tests,
            "timestamp": datetime.now().isoformat()
        }, f, indent=2)
    
    print(f"📄 Detailed results saved to: {results_file}")
    
    if success:
        print("\n🎉 All tests passed! Server is ready for deployment.")
        sys.exit(0)
    else:
        print(f"\n⚠️  {all_results.failed} test(s) failed. Please review and fix issues before deployment.")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())