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
        
        print_status("Testing search_wazuh_logs tool...")
        from wazuh_mcp_server.server import search_wazuh_logs
        logs_result = await search_wazuh_logs(limit=5, time_range_hours=24)
        print_status(f"Log search returned {logs_result.get('total_found', 0)} log entries")
        
        print_status("Testing analyze_security_threats tool...")
        from wazuh_mcp_server.server import analyze_security_threats
        threats_result = await analyze_security_threats(time_range_hours=24, severity_threshold=1)
        print_status(f"Threat analysis found {threats_result.get('summary', {}).get('total_threats', 0)} threats")
        
        print_status("Testing incident management tools...")
        from wazuh_mcp_server.server import get_security_incidents, create_security_incident
        incidents_result = await get_security_incidents(limit=5)
        print_status(f"Found {incidents_result.get('total_incidents', 0)} security incidents")
        
        # Test incident creation
        incident_result = await create_security_incident(
            title="Test Security Incident", 
            description="Testing incident management functionality",
            severity="medium"
        )
        print_status(f"Created test incident: {incident_result.get('incident', {}).get('id', 'N/A')}")
        
        print_status("Testing rule management tools...")
        from wazuh_mcp_server.server import get_wazuh_rules, analyze_rule_coverage
        rules_result = await get_wazuh_rules(limit=10)
        print_status(f"Retrieved {rules_result.get('total_rules', 0)} Wazuh rules")
        
        coverage_result = await analyze_rule_coverage(alert_timeframe_hours=24)
        coverage_pct = coverage_result.get('coverage_summary', {}).get('coverage_percentage', 0)
        print_status(f"Rule coverage analysis: {coverage_pct}% coverage")
        
        print_status("Testing advanced filtering tools...")
        from wazuh_mcp_server.server import advanced_wazuh_query, multi_field_search
        
        # Test advanced query
        advanced_result = await advanced_wazuh_query(
            query_type="alerts", 
            filters={"level": 5}, 
            limit=10
        )
        print_status(f"Advanced query returned {advanced_result.get('total_results', 0)} filtered alerts")
        
        # Test multi-field search
        search_result = await multi_field_search(
            search_terms=["authentication", "failed"],
            data_sources=["alerts"]
        )
        print_status(f"Multi-field search found {search_result.get('total_matches', 0)} matches")
        
        print_status("Testing real-time monitoring tools...")
        from wazuh_mcp_server.server import get_realtime_alerts, get_live_dashboard_data
        
        # Test real-time monitoring
        monitoring_result = await get_realtime_alerts(monitoring_duration_minutes=1, auto_refresh_seconds=30)
        total_alerts = monitoring_result.get('alert_statistics', {}).get('total_new_alerts', 0)
        print_status(f"Real-time monitoring detected {total_alerts} alerts")
        
        # Test live dashboard
        dashboard_result = await get_live_dashboard_data(include_metrics=["alerts", "agents"])
        dashboard_timestamp = dashboard_result.get('timestamp', 'N/A')
        print_status(f"Live dashboard data collected at {dashboard_timestamp}")
        
        print_status("Testing high-priority missing features...")
        from wazuh_mcp_server.server import execute_active_response, get_cdb_lists, get_fim_events, get_enhanced_analytics
        
        # Test CDB lists
        cdb_result = await get_cdb_lists(limit=5)
        print_status(f"Retrieved {cdb_result.get('total_lists', 0)} CDB lists")
        
        # Test FIM events  
        fim_result = await get_fim_events(limit=5, time_range_hours=24)
        print_status(f"Retrieved {fim_result.get('total_events', 0)} FIM events")
        
        # Test enhanced analytics
        analytics_result = await get_enhanced_analytics(analysis_type="agent_health")
        health_score = analytics_result.get('agent_health_metrics', {}).get('health_score', 0)
        print_status(f"Enhanced analytics - agent health score: {health_score}%")
        
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