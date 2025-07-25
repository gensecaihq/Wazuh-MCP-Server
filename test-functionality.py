#!/usr/bin/env python3
"""
Comprehensive functionality test for Wazuh MCP Server
Tests all main objectives: Docker, FastMCP, Wazuh connection, and user interaction
"""

import asyncio
import sys
import os
import subprocess
from pathlib import Path

def print_section(title):
    """Print a formatted section header."""
    print(f"\n{'='*60}")
    print(f"🧪 {title}")
    print('='*60)

def print_status(message, success=True):
    """Print status with appropriate icon."""
    icon = "✅" if success else "❌"
    print(f"{icon} {message}")

async def test_configuration():
    """Test configuration loading."""
    print_section("TESTING CONFIGURATION")
    
    try:
        sys.path.insert(0, str(Path("src")))
        from wazuh_mcp_server.config import WazuhConfig
        
        # Test environment variables
        required_vars = ["WAZUH_HOST", "WAZUH_USER", "WAZUH_PASS"]
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        
        if missing_vars:
            print_status(f"Missing required environment variables: {', '.join(missing_vars)}", False)
            print("  Set them with: export WAZUH_HOST=your-server WAZUH_USER=user WAZUH_PASS=pass")
            return False
        
        config = WazuhConfig.from_env()
        print_status(f"Configuration loaded successfully")
        print_status(f"Wazuh Host: {config.wazuh_host}:{config.wazuh_port}")
        print_status(f"Wazuh User: {config.wazuh_user}")
        print_status(f"SSL Verification: {config.verify_ssl}")
        return True
        
    except Exception as e:
        print_status(f"Configuration test failed: {e}", False)
        return False

async def test_wazuh_connection():
    """Test Wazuh API connection."""
    print_section("TESTING WAZUH CONNECTION")
    
    try:
        from wazuh_mcp_server.config import WazuhConfig
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        
        config = WazuhConfig.from_env()
        client = WazuhClient(config)
        
        print_status("Initializing Wazuh client...")
        await client.initialize()
        print_status("Authentication successful")
        
        # Test basic API calls
        print_status("Testing cluster status API...")
        cluster_response = await client.get_cluster_status()
        print_status(f"Cluster API responded with {len(cluster_response.get('data', {}))} fields")
        
        print_status("Testing agents API...")
        agents_response = await client.get_agents(limit=5)
        agents = agents_response.get("data", {}).get("affected_items", [])
        print_status(f"Found {len(agents)} agents")
        
        print_status("Testing alerts API...")
        alerts_response = await client.get_alerts(limit=5)
        alerts = alerts_response.get("data", {}).get("affected_items", [])
        print_status(f"Found {len(alerts)} recent alerts")
        
        await client.close()
        print_status("Wazuh connection test completed successfully")
        return True
        
    except Exception as e:
        print_status(f"Wazuh connection test failed: {e}", False)
        return False

async def test_fastmcp_server():
    """Test FastMCP server functionality."""
    print_section("TESTING FASTMCP SERVER")
    
    try:
        from wazuh_mcp_server.server import mcp, initialize_server
        
        print_status("Initializing FastMCP server...")
        await initialize_server()
        
        # Check server metadata
        print_status(f"Server Name: {mcp.name}")
        print_status(f"Server Version: {mcp.version}")
        print_status(f"Server Description: {mcp.description}")
        
        # Count registered tools and resources
        tools_count = len(mcp._tools) if hasattr(mcp, '_tools') else 0
        resources_count = len(mcp._resources) if hasattr(mcp, '_resources') else 0
        
        print_status(f"Registered Tools: {tools_count}")
        print_status(f"Registered Resources: {resources_count}")
        
        # Test tool functionality
        print_status("Testing get_wazuh_alerts tool...")
        from wazuh_mcp_server.server import get_wazuh_alerts
        alerts_result = await get_wazuh_alerts(limit=3)
        print_status(f"Alerts tool returned {alerts_result.get('total', 0)} alerts")
        
        print_status("Testing analyze_security_threats tool...")
        from wazuh_mcp_server.server import analyze_security_threats
        threats_result = await analyze_security_threats(time_range_hours=24, severity_threshold=1)
        print_status(f"Threat analysis found {threats_result.get('summary', {}).get('total_threats', 0)} threats")
        
        print_status("FastMCP server test completed successfully")
        return True
        
    except Exception as e:
        print_status(f"FastMCP server test failed: {e}", False)
        return False

def test_docker_setup():
    """Test Docker configuration."""
    print_section("TESTING DOCKER SETUP")
    
    try:
        # Check if Docker is available
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print_status(f"Docker available: {result.stdout.strip()}")
        else:
            print_status("Docker not available", False)
            return False
        
        # Check if docker-compose is available
        result = subprocess.run(['docker', 'compose', 'version'], capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print_status(f"Docker Compose available: {result.stdout.strip()}")
        else:
            print_status("Docker Compose not available", False)
            return False
        
        # Validate Dockerfile
        dockerfile = Path("Dockerfile")
        if dockerfile.exists():
            content = dockerfile.read_text()
            checks = [
                ("Multi-stage build", "FROM python:3.12-slim as builder" in content),
                ("Non-root user", "USER wazuh" in content),
                ("Health check", "HEALTHCHECK" in content),
                ("Proper entrypoint", "ENTRYPOINT" in content),
                ("Exposed port", "EXPOSE 3000" in content)
            ]
            
            for check_name, passed in checks:
                print_status(f"Dockerfile {check_name}: {'✓' if passed else '✗'}", passed)
        else:
            print_status("Dockerfile not found", False)
            return False
        
        # Validate compose.yml
        compose_file = Path("compose.yml")
        if compose_file.exists():
            content = compose_file.read_text()
            checks = [
                ("Service definition", "wazuh-mcp-server:" in content),
                ("Environment variables", "WAZUH_HOST:" in content),
                ("Health check", "healthcheck:" in content),
                ("Resource limits", "deploy:" in content)
            ]
            
            for check_name, passed in checks:
                print_status(f"Compose file {check_name}: {'✓' if passed else '✗'}", passed)
        else:
            print_status("compose.yml not found", False)
            return False
        
        print_status("Docker setup validation completed successfully")
        return True
        
    except Exception as e:
        print_status(f"Docker setup test failed: {e}", False)
        return False

async def test_mcp_user_interaction():
    """Test MCP user interaction capabilities."""
    print_section("TESTING MCP USER INTERACTION")
    
    try:
        # Test resource endpoints
        print_status("Testing MCP resources...")
        from wazuh_mcp_server.server import get_server_status, get_dashboard_summary
        
        server_status = await get_server_status()
        print_status(f"Server status resource: {len(server_status)} characters")
        
        dashboard_summary = await get_dashboard_summary()
        print_status(f"Dashboard summary resource: {len(dashboard_summary)} characters")
        
        # Test tools with different parameters
        print_status("Testing tools with various parameters...")
        from wazuh_mcp_server.server import get_agent_status, get_vulnerability_summary
        
        agent_status = await get_agent_status()
        print_status(f"Agent status: {agent_status.get('total_agents', 0)} agents")
        
        vuln_summary = await get_vulnerability_summary()
        print_status(f"Vulnerability summary: {vuln_summary.get('total_vulnerabilities', 0)} vulnerabilities")
        
        print_status("MCP user interaction test completed successfully")
        return True
        
    except Exception as e:
        print_status(f"MCP user interaction test failed: {e}", False)
        return False

async def main():
    """Run all functionality tests."""
    print("🚀 WAZUH MCP SERVER - COMPREHENSIVE FUNCTIONALITY TEST")
    print("Testing all main objectives: Docker, FastMCP, Wazuh connection, user interaction")
    
    tests = [
        ("Docker Setup", test_docker_setup),
        ("Configuration", test_configuration),
        ("Wazuh Connection", test_wazuh_connection),
        ("FastMCP Server", test_fastmcp_server),
        ("MCP User Interaction", test_mcp_user_interaction)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        try:
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
            results[test_name] = result
        except Exception as e:
            print_status(f"{test_name} test failed with exception: {e}", False)
            results[test_name] = False
    
    # Summary
    print_section("TEST SUMMARY")
    passed = sum(1 for result in results.values() if result)
    total = len(results)
    
    for test_name, result in results.items():
        print_status(f"{test_name}: {'PASSED' if result else 'FAILED'}", result)
    
    print(f"\n📊 Overall Result: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 ALL TESTS PASSED - Wazuh MCP Server is fully functional and production-ready!")
        print("\n📋 Ready for deployment:")
        print("   1. docker compose up -d")
        print("   2. Connect your MCP client to the server")
        print("   3. Start querying Wazuh through natural language")
    else:
        print("⚠️  Some tests failed - please address the issues above before deployment")
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n❌ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Test suite failed: {e}")
        sys.exit(1)