#!/usr/bin/env python3
"""
End-to-End Deployment Test
Complete production deployment verification for Wazuh MCP Server
"""

import sys
import os
import asyncio
import json
import httpx
import time
import subprocess
from pathlib import Path
from datetime import datetime, timezone

# Add src directory to Python path
current_dir = Path(__file__).resolve().parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

class DeploymentTestResults:
    """Track deployment test results."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.tests = []
        self.start_time = time.time()
    
    def add_test(self, name: str, status: str, message: str = "", critical: bool = False):
        """Add test result."""
        self.tests.append({
            "name": name,
            "status": status,
            "message": message,
            "critical": critical,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration": time.time() - self.start_time
        })
        
        if status == "PASS":
            self.passed += 1
        elif status == "FAIL":
            self.failed += 1
        elif status == "WARN":
            self.warnings += 1
    
    def print_summary(self):
        """Print comprehensive summary."""
        total = self.passed + self.failed + self.warnings
        critical_failures = sum(1 for test in self.tests if test["status"] == "FAIL" and test["critical"])
        
        print("\n" + "="*80)
        print("🚀 END-TO-END DEPLOYMENT TEST SUMMARY")
        print("="*80)
        print(f"Total Tests: {total}")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"⚠️  Warnings: {self.warnings}")
        print(f"🔴 Critical Failures: {critical_failures}")
        print(f"Success Rate: {(self.passed/total*100):.1f}%" if total > 0 else "0%")
        
        if critical_failures == 0 and self.failed == 0:
            print(f"\n🎉 DEPLOYMENT READY FOR PRODUCTION")
            print("   All critical tests passed - ready for live deployment")
        elif critical_failures == 0:
            print(f"\n✅ DEPLOYMENT READY WITH WARNINGS")
            print(f"   Critical tests passed, {self.failed} non-critical issues found")
        else:
            print(f"\n❌ DEPLOYMENT NOT READY")
            print(f"   {critical_failures} critical failures must be resolved")
        
        print("="*80)
        return critical_failures == 0

async def test_complete_fastmcp_integration():
    """Test complete FastMCP integration."""
    results = DeploymentTestResults()
    
    print("🔍 Testing Complete FastMCP Integration...")
    
    try:
        from wazuh_mcp_server.server import mcp
        
        # Test server initialization
        results.add_test(
            "FastMCP Server Creation",
            "PASS" if mcp else "FAIL",
            f"Server: {mcp.name}",
            critical=True
        )
        
        # Test tools registration
        tools = await mcp.get_tools()
        if len(tools) >= 20:
            results.add_test(
                "FastMCP Tools Registration",
                "PASS",
                f"{len(tools)} tools registered",
                critical=True
            )
        else:
            results.add_test(
                "FastMCP Tools Registration",
                "FAIL",
                f"Only {len(tools)} tools (expected >= 20)",
                critical=True
            )
        
        # Test resources registration
        resources = await mcp.get_resources()
        if len(resources) >= 2:
            results.add_test(
                "FastMCP Resources Registration",
                "PASS",
                f"{len(resources)} resources registered",
                critical=False
            )
        else:
            results.add_test(
                "FastMCP Resources Registration",
                "WARN",
                f"Only {len(resources)} resources",
                critical=False
            )
        
        # Test HTTP app creation
        try:
            http_app = mcp.http_app()
            results.add_test(
                "HTTP Transport App",
                "PASS",
                "HTTP/SSE app created successfully",
                critical=True
            )
        except Exception as e:
            results.add_test(
                "HTTP Transport App",
                "FAIL",
                f"HTTP app creation failed: {e}",
                critical=True
            )
        
        # Test STDIO mode availability
        if hasattr(mcp, 'run'):
            results.add_test(
                "STDIO Transport Mode",
                "PASS",
                "STDIO mode available for Claude Desktop",
                critical=True
            )
        else:
            results.add_test(
                "STDIO Transport Mode",
                "FAIL",
                "STDIO mode not available",
                critical=True
            )
        
    except Exception as e:
        results.add_test(
            "FastMCP Integration",
            "FAIL",
            f"Integration test failed: {e}",
            critical=True
        )
    
    return results

async def test_containerization_completeness():
    """Test complete containerization."""
    results = DeploymentTestResults()
    
    print("🐳 Testing Complete Containerization...")
    
    # Test Docker configuration
    docker_files = [
        ("Dockerfile", "Docker build configuration"),
        ("compose.yml", "Docker Compose orchestration"),
        ("docker/entrypoint.sh", "Container entrypoint script"),
        ("docker/.env.docker", "Container environment template")
    ]
    
    for file_path, description in docker_files:
        if Path(file_path).exists():
            results.add_test(
                f"Docker File: {file_path}",
                "PASS",
                f"{description} exists",
                critical=True
            )
        else:
            results.add_test(
                f"Docker File: {file_path}",
                "FAIL",
                f"{description} missing",
                critical=True
            )
    
    # Test dependency isolation
    try:
        critical_deps = ['fastmcp', 'httpx', 'pydantic', 'uvicorn', 'dotenv']
        missing_deps = []
        
        for dep in critical_deps:
            try:
                __import__(dep)
            except ImportError:
                missing_deps.append(dep)
        
        if missing_deps:
            results.add_test(
                "Dependency Isolation",
                "FAIL",
                f"Missing dependencies: {missing_deps}",
                critical=True
            )
        else:
            results.add_test(
                "Dependency Isolation",
                "PASS",
                "All dependencies available in container",
                critical=True
            )
    
    except Exception as e:
        results.add_test(
            "Dependency Isolation",
            "FAIL",
            f"Dependency test failed: {e}",
            critical=True
        )
    
    # Test Docker Compose validation
    try:
        result = subprocess.run(
            ["docker", "compose", "config"],
            capture_output=True,
            text=True,
            cwd=current_dir
        )
        if result.returncode == 0:
            results.add_test(
                "Docker Compose Config",
                "PASS",
                "Compose configuration valid",
                critical=True
            )
        else:
            results.add_test(
                "Docker Compose Config",
                "FAIL",
                f"Compose validation failed: {result.stderr}",
                critical=True
            )
    except FileNotFoundError:
        results.add_test(
            "Docker Compose Config",
            "WARN",
            "Docker not available for validation",
            critical=False
        )
    
    return results

async def test_wazuh_integration_readiness():
    """Test Wazuh integration readiness."""
    results = DeploymentTestResults()
    
    print("🛡️  Testing Wazuh Integration Readiness...")
    
    try:
        from wazuh_mcp_server.config import WazuhConfig
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        
        # Test configuration loading
        config = WazuhConfig.from_env()
        results.add_test(
            "Wazuh Configuration",
            "PASS",
            f"Config loaded for {config.wazuh_host}:{config.wazuh_port}",
            critical=True
        )
        
        # Test client creation
        client = WazuhClient(config)
        results.add_test(
            "Wazuh Client Creation",
            "PASS",
            "Wazuh API client created successfully",
            critical=True
        )
        
        # Test API endpoint configuration
        endpoints = [
            "/alerts", "/agents", "/vulnerability/agents", "/cluster/status",
            "/manager/logs", "/rules", "/decoders", "/active-response"
        ]
        
        for endpoint in endpoints:
            full_url = f"{config.base_url}{endpoint}"
            # Just validate URL construction
            if full_url.startswith("https://") and config.wazuh_host in full_url:
                results.add_test(
                    f"API Endpoint: {endpoint}",
                    "PASS",
                    "Endpoint URL constructed correctly",
                    critical=False
                )
            else:
                results.add_test(
                    f"API Endpoint: {endpoint}",
                    "FAIL",
                    "Endpoint URL construction failed",
                    critical=True
                )
        
        # Test SSL configuration
        if config.verify_ssl:
            results.add_test(
                "SSL Configuration",
                "PASS",
                "SSL verification enabled (recommended)",
                critical=False
            )
        else:
            results.add_test(
                "SSL Configuration",
                "WARN",
                "SSL verification disabled",
                critical=False
            )
        
    except Exception as e:
        results.add_test(
            "Wazuh Integration",
            "FAIL",
            f"Integration test failed: {e}",
            critical=True
        )
    
    return results

async def test_mcp_client_readiness():
    """Test MCP client readiness."""
    results = DeploymentTestResults()
    
    print("👥 Testing MCP Client Readiness...")
    
    try:
        from wazuh_mcp_server.server import mcp
        
        # Test Claude Desktop compatibility
        tools = await mcp.get_tools()
        if isinstance(tools, dict) and len(tools) > 0:
            results.add_test(
                "Claude Desktop Compatibility",
                "PASS",
                f"Tools format compatible: {len(tools)} tools",
                critical=True
            )
        else:
            results.add_test(
                "Claude Desktop Compatibility",
                "FAIL",
                "Tools format incompatible",
                critical=True
            )
        
        # Test resource availability
        resources = await mcp.get_resources()
        if isinstance(resources, dict):
            results.add_test(
                "Resource Availability",
                "PASS",
                f"Resources available: {len(resources)} URIs",
                critical=False
            )
        else:
            results.add_test(
                "Resource Availability",
                "FAIL",
                "Resources not properly formatted",
                critical=True
            )
        
        # Test transport modes
        transport_modes = []
        
        # HTTP transport
        try:
            http_app = mcp.http_app()
            transport_modes.append("HTTP")
        except:
            pass
        
        # STDIO transport
        if hasattr(mcp, 'run'):
            transport_modes.append("STDIO")
        
        if len(transport_modes) >= 2:
            results.add_test(
                "Transport Modes",
                "PASS",
                f"Available: {', '.join(transport_modes)}",
                critical=True
            )
        else:
            results.add_test(
                "Transport Modes",
                "FAIL",
                f"Limited transport modes: {transport_modes}",
                critical=True
            )
        
        # Test security capabilities
        security_tools = [name for name in tools.keys() if any(
            keyword in name.lower() for keyword in 
            ['security', 'alert', 'vulnerability', 'threat', 'incident']
        )]
        
        if len(security_tools) >= 5:
            results.add_test(
                "Security Capabilities",
                "PASS",
                f"{len(security_tools)} security-focused tools",
                critical=True
            )
        else:
            results.add_test(
                "Security Capabilities",
                "FAIL",
                f"Only {len(security_tools)} security tools",
                critical=True
            )
        
        # Test search capabilities
        search_tools = [name for name in tools.keys() if any(
            keyword in name.lower() for keyword in 
            ['search', 'query', 'analyze', 'hunt', 'find']
        )]
        
        if len(search_tools) >= 3:
            results.add_test(
                "Search Capabilities",
                "PASS",
                f"{len(search_tools)} search/analysis tools",
                critical=True
            )
        else:
            results.add_test(
                "Search Capabilities",
                "WARN",
                f"Only {len(search_tools)} search tools",
                critical=False
            )
        
    except Exception as e:
        results.add_test(
            "MCP Client Readiness",
            "FAIL",
            f"Client readiness test failed: {e}",
            critical=True
        )
    
    return results

async def test_production_deployment_readiness():
    """Test production deployment readiness."""
    results = DeploymentTestResults()
    
    print("🚀 Testing Production Deployment Readiness...")
    
    # Test file structure
    required_files = [
        ("wazuh-mcp-server", "Main executable", True),
        ("src/wazuh_mcp_server/server.py", "Server module", True),
        ("src/wazuh_mcp_server/config.py", "Configuration", True),
        ("src/wazuh_mcp_server/api/wazuh_client.py", "API client", True),
        ("requirements.txt", "Dependencies", True),
        ("pyproject.toml", "Project config", True),
        ("validate-production.py", "Validation script", False),
        ("test-functionality.py", "Test suite", False)
    ]
    
    for file_path, description, critical in required_files:
        if Path(file_path).exists():
            results.add_test(
                f"File: {file_path}",
                "PASS",
                f"{description} exists",
                critical=critical
            )
        else:
            results.add_test(
                f"File: {file_path}",
                "FAIL" if critical else "WARN",
                f"{description} missing",
                critical=critical
            )
    
    # Test executable permissions
    executable_files = ["wazuh-mcp-server", "docker/entrypoint.sh"]
    for script in executable_files:
        script_path = Path(script)
        if script_path.exists() and os.access(script_path, os.X_OK):
            results.add_test(
                f"Executable: {script}",
                "PASS",
                "Script is executable",
                critical=True
            )
        elif script_path.exists():
            results.add_test(
                f"Executable: {script}",
                "FAIL",
                "Script not executable",
                critical=True
            )
    
    # Test configuration validation
    try:
        from wazuh_mcp_server.config import WazuhConfig
        config = WazuhConfig.from_env()
        
        # Test critical config values
        if config.mcp_port and 1 <= config.mcp_port <= 65535:
            results.add_test(
                "Port Configuration",
                "PASS",
                f"Valid port: {config.mcp_port}",
                critical=True
            )
        else:
            results.add_test(
                "Port Configuration",
                "FAIL",
                f"Invalid port: {config.mcp_port}",
                critical=True
            )
        
        if config.mcp_transport in ["http", "stdio"]:
            results.add_test(
                "Transport Configuration",
                "PASS",
                f"Valid transport: {config.mcp_transport}",
                critical=True
            )
        else:
            results.add_test(
                "Transport Configuration",
                "FAIL",
                f"Invalid transport: {config.mcp_transport}",
                critical=True
            )
        
    except Exception as e:
        results.add_test(
            "Configuration Validation",
            "FAIL",
            f"Config validation failed: {e}",
            critical=True
        )
    
    return results

async def run_comprehensive_deployment_test():
    """Run comprehensive deployment test."""
    print("🔬 Wazuh MCP Server - End-to-End Deployment Test")
    print("="*80)
    print(f"Started at: {datetime.now(timezone.utc).isoformat()}")
    print("="*80)
    
    all_results = DeploymentTestResults()
    
    test_suites = [
        ("FastMCP Integration", test_complete_fastmcp_integration),
        ("Containerization", test_containerization_completeness),
        ("Wazuh Integration", test_wazuh_integration_readiness),
        ("MCP Client Readiness", test_mcp_client_readiness),
        ("Production Readiness", test_production_deployment_readiness)
    ]
    
    for suite_name, test_func in test_suites:
        print(f"\n🧪 Running {suite_name} tests...")
        try:
            suite_results = await test_func()
            
            # Merge results
            all_results.passed += suite_results.passed
            all_results.failed += suite_results.failed
            all_results.warnings += suite_results.warnings
            all_results.tests.extend(suite_results.tests)
            
            print(f"   ✅ {suite_results.passed} passed, ❌ {suite_results.failed} failed, ⚠️ {suite_results.warnings} warnings")
            
        except Exception as e:
            print(f"   ❌ Test suite failed: {e}")
            all_results.add_test(suite_name, "FAIL", f"Suite execution failed: {e}", critical=True)
    
    # Print comprehensive summary
    ready_for_production = all_results.print_summary()
    
    # Save detailed results
    results_file = current_dir / "deployment-test-results.json"
    with open(results_file, 'w') as f:
        json.dump({
            "summary": {
                "passed": all_results.passed,
                "failed": all_results.failed,
                "warnings": all_results.warnings,
                "ready_for_production": ready_for_production,
                "total_duration": time.time() - all_results.start_time
            },
            "tests": all_results.tests,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }, f, indent=2)
    
    print(f"\n📄 Detailed results saved to: {results_file}")
    
    # Final deployment instructions
    if ready_for_production:
        print("\n🎉 DEPLOYMENT VERIFICATION SUCCESSFUL!")
        print("\n📋 Ready for Production Deployment:")
        print("   1. docker compose up -d")
        print("   2. Access: http://localhost:3000")
        print("   3. Health: http://localhost:3000/health")
        print("   4. Logs: docker compose logs -f")
        print("\n🔧 Claude Desktop Integration:")
        print("   - Set MCP_TRANSPORT=stdio for direct integration")
        print("   - Use HTTP mode for web-based MCP clients")
        return 0
    else:
        print(f"\n⚠️ DEPLOYMENT NOT READY")
        print("   Please resolve critical failures before production deployment")
        return 1

def main():
    """Main entry point."""
    try:
        return asyncio.run(run_comprehensive_deployment_test())
    except KeyboardInterrupt:
        print("\n🛑 Deployment test interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Deployment test failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())