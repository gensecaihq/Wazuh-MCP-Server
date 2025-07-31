#!/usr/bin/env python3
"""
Wazuh MCP Server - Container Validation Suite
Comprehensive validation for OS-agnostic containerized deployment
"""

import sys
import os
import asyncio
import json
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import argparse

# Add src directory to Python path
current_dir = Path(__file__).resolve().parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

class ContainerValidationResults:
    """Container validation results tracker."""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.checks = []
        self.start_time = time.time()
    
    def add_check(self, name: str, status: str, message: str = "", details: dict = None):
        """Add validation check result."""
        self.checks.append({
            "name": name,
            "status": status,
            "message": message,
            "details": details or {},
            "timestamp": datetime.now().isoformat(),
            "duration": time.time() - self.start_time
        })
        
        if status == "PASS":
            self.passed += 1
        elif status == "FAIL":
            self.failed += 1
        elif status == "WARN":
            self.warnings += 1
    
    def print_summary(self):
        """Print validation summary."""
        total = self.passed + self.failed + self.warnings
        print("\n" + "="*80)
        print("🐳 CONTAINER DEPLOYMENT VALIDATION SUMMARY")
        print("="*80)
        print(f"Total Checks: {total}")
        print(f"✅ Passed: {self.passed}")
        print(f"❌ Failed: {self.failed}")
        print(f"⚠️  Warnings: {self.warnings}")
        print(f"Success Rate: {(self.passed/total*100):.1f}%" if total > 0 else "0%")
        
        if self.failed == 0:
            print(f"\n🎉 CONTAINER READY FOR DEPLOYMENT")
            print("   All validations passed - container is production-ready")
        else:
            print(f"\n❌ CONTAINER NOT READY")
            print(f"   {self.failed} critical issues must be resolved")
        
        print("="*80)
        return self.failed == 0

async def validate_container_imports():
    """Validate all imports work in container environment."""
    results = ContainerValidationResults()
    
    print("📦 Validating container imports...")
    
    critical_imports = [
        ("fastmcp", "FastMCP framework"),
        ("pydantic", "Data validation"),
        ("dotenv", "Environment configuration"),
        ("httpx", "HTTP client"),
        ("uvicorn", "ASGI server"),
        ("asyncio", "Async runtime"),
        ("json", "JSON handling"),
        ("datetime", "Date/time handling"),
        ("uuid", "UUID generation"),
        ("typing", "Type hints"),
        ("pathlib", "Path handling"),
        ("os", "OS interface"),
        ("sys", "System interface")
    ]
    
    for module, description in critical_imports:
        try:
            __import__(module)
            results.add_check(
                f"Import {module}", 
                "PASS", 
                f"{description} imported successfully"
            )
        except ImportError as e:
            results.add_check(
                f"Import {module}", 
                "FAIL", 
                f"Failed to import {description}: {e}"
            )
    
    # Test application imports
    app_imports = [
        ("wazuh_mcp_server.config", "Configuration module"),
        ("wazuh_mcp_server.api.wazuh_client", "Wazuh API client"),
        ("wazuh_mcp_server.server", "MCP server")
    ]
    
    for module, description in app_imports:
        try:
            __import__(module)
            results.add_check(
                f"Import {module}", 
                "PASS", 
                f"{description} imported successfully"
            )
        except ImportError as e:
            results.add_check(
                f"Import {module}", 
                "FAIL", 
                f"Failed to import {description}: {e}"
            )
    
    return results

async def validate_container_configuration():
    """Validate container configuration."""
    results = ContainerValidationResults()
    
    print("⚙️ Validating container configuration...")
    
    # Check environment detection
    try:
        env_type = os.environ.get("ENVIRONMENT", "unknown")
        if env_type == "docker":
            results.add_check(
                "Container Environment", 
                "PASS", 
                "Running in Docker container"
            )
        else:
            results.add_check(
                "Container Environment", 
                "WARN", 
                f"Environment type: {env_type} (expected: docker)"
            )
    except Exception as e:
        results.add_check(
            "Container Environment", 
            "FAIL", 
            f"Failed to detect environment: {e}"
        )
    
    # Check Python configuration
    try:
        python_version = sys.version_info
        if python_version >= (3, 10):
            results.add_check(
                "Python Version", 
                "PASS", 
                f"Python {python_version.major}.{python_version.minor}.{python_version.micro}"
            )
        else:
            results.add_check(
                "Python Version", 
                "FAIL", 
                f"Python {python_version.major}.{python_version.minor} < 3.10 (required)"
            )
    except Exception as e:
        results.add_check(
            "Python Version", 
            "FAIL", 
            f"Failed to check Python version: {e}"
        )
    
    # Check container optimizations
    container_env_vars = [
        ("PYTHONUNBUFFERED", "Python output buffering disabled"),
        ("PYTHONDONTWRITEBYTECODE", "Python bytecode writing disabled"),
        ("PYTHONHASHSEED", "Python hash seed randomization")
    ]
    
    for var, description in container_env_vars:
        value = os.environ.get(var)
        if value:
            results.add_check(
                f"Container Env {var}", 
                "PASS", 
                f"{description}: {value}"
            )
        else:
            results.add_check(
                f"Container Env {var}", 
                "WARN", 
                f"{description} not set"
            )
    
    return results

async def validate_mcp_server():
    """Validate MCP server functionality."""
    results = ContainerValidationResults()
    
    print("🚀 Validating MCP server functionality...")
    
    try:
        from wazuh_mcp_server.server import mcp
        
        # Test server creation
        results.add_check(
            "MCP Server Creation", 
            "PASS", 
            "FastMCP server instance created successfully"
        )
        
        # Test tools registration
        tools = await mcp.get_tools()
        if len(tools) >= 20:
            results.add_check(
                "MCP Tools Registration", 
                "PASS", 
                f"{len(tools)} tools registered"
            )
        else:
            results.add_check(
                "MCP Tools Registration", 
                "FAIL", 
                f"Only {len(tools)} tools registered (expected >= 20)"
            )
        
        # Test resources registration
        resources = await mcp.get_resources()
        if len(resources) >= 2:
            results.add_check(
                "MCP Resources Registration", 
                "PASS", 
                f"{len(resources)} resources registered"
            )
        else:
            results.add_check(
                "MCP Resources Registration", 
                "WARN", 
                f"Only {len(resources)} resources registered"
            )
        
        # Test critical tools
        critical_tools = [
            "get_wazuh_alerts",
            "get_agent_status", 
            "get_vulnerability_summary",
            "search_wazuh_logs",
            "analyze_security_threats"
        ]
        
        for tool_name in critical_tools:
            if tool_name in tools:
                results.add_check(
                    f"Critical Tool {tool_name}", 
                    "PASS", 
                    "Tool available"
                )
            else:
                results.add_check(
                    f"Critical Tool {tool_name}", 
                    "FAIL", 
                    "Tool not found"
                )
    
    except Exception as e:
        results.add_check(
            "MCP Server Validation", 
            "FAIL", 
            f"MCP server validation failed: {e}"
        )
    
    return results

async def validate_container_files():
    """Validate container file structure."""
    results = ContainerValidationResults()
    
    print("📁 Validating container file structure...")
    
    required_files = [
        ("wazuh-mcp-server", "Main executable script"),
        ("src/wazuh_mcp_server/server.py", "Server module"),
        ("src/wazuh_mcp_server/config.py", "Configuration module"),
        ("src/wazuh_mcp_server/api/wazuh_client.py", "Wazuh client"),
        ("docker/entrypoint.sh", "Container entrypoint"),
        ("validate-production.py", "Production validation"),
        ("test-functionality.py", "Functionality tests"),
        ("requirements.txt", "Dependencies"),
        ("pyproject.toml", "Project configuration")
    ]
    
    for file_path, description in required_files:
        if Path(file_path).exists():
            results.add_check(
                f"File {file_path}", 
                "PASS", 
                f"{description} exists"
            )
        else:
            results.add_check(
                f"File {file_path}", 
                "FAIL", 
                f"{description} missing"
            )
    
    # Check executable permissions
    executable_files = [
        "wazuh-mcp-server",
        "docker/entrypoint.sh",
        "validate-production.py",
        "test-functionality.py"
    ]
    
    for script in executable_files:
        script_path = Path(script)
        if script_path.exists():
            if os.access(script_path, os.X_OK):
                results.add_check(
                    f"Executable {script}", 
                    "PASS", 
                    "Script is executable"
                )
            else:
                results.add_check(
                    f"Executable {script}", 
                    "FAIL", 
                    "Script not executable"
                )
    
    return results

async def validate_health_checks():
    """Validate container health check functionality."""
    results = ContainerValidationResults()
    
    print("🏥 Validating health check functionality...")
    
    try:
        # Test configuration loading (health check logic)
        from wazuh_mcp_server.config import WazuhConfig
        config = WazuhConfig.from_env()
        results.add_check(
            "Health Check - Config", 
            "PASS", 
            "Configuration loads successfully"
        )
        
        # Test server creation (health check logic)  
        from wazuh_mcp_server.server import mcp
        results.add_check(
            "Health Check - Server", 
            "PASS", 
            "MCP server creates successfully"
        )
        
        # Test transport mode validation
        transport = config.mcp_transport
        if transport in ["http", "stdio"]:
            results.add_check(
                "Health Check - Transport", 
                "PASS", 
                f"Valid transport mode: {transport}"
            )
        else:
            results.add_check(
                "Health Check - Transport", 
                "FAIL", 
                f"Invalid transport mode: {transport}"
            )
        
        # Test port validation
        if 1 <= config.mcp_port <= 65535:
            results.add_check(
                "Health Check - Port", 
                "PASS", 
                f"Valid port: {config.mcp_port}"
            )
        else:
            results.add_check(
                "Health Check - Port", 
                "FAIL", 
                f"Invalid port: {config.mcp_port}"
            )
    
    except Exception as e:
        results.add_check(
            "Health Check Validation", 
            "FAIL", 
            f"Health check failed: {e}"
        )
    
    return results

async def validate_os_agnostic():
    """Validate OS-agnostic deployment."""
    results = ContainerValidationResults()
    
    print("🌐 Validating OS-agnostic deployment...")
    
    # Check for OS-specific code
    os_specific_patterns = [
        ("subprocess.run", "System command execution"),
        ("os.system", "System command execution"),
        ("platform", "Platform detection"),
        ("sys.platform", "Platform detection"),
        ("shell=True", "Shell execution")
    ]
    
    # Scan source files for OS-specific patterns
    src_files = list(Path("src").rglob("*.py"))
    for pattern, description in os_specific_patterns:
        found_files = []
        for src_file in src_files:
            try:
                content = src_file.read_text()
                if pattern in content and "# OS-agnostic approved" not in content:
                    found_files.append(str(src_file))
            except Exception:
                continue
        
        if found_files:
            results.add_check(
                f"OS-Specific Pattern {pattern}", 
                "WARN", 
                f"{description} found in: {', '.join(found_files[:3])}"
            )
        else:
            results.add_check(
                f"OS-Specific Pattern {pattern}", 
                "PASS", 
                f"No {description} found in source code"
            )
    
    # Check container-specific configurations
    container_configs = [
        ("PYTHONPATH", "Python path set correctly"),
        ("HOME", "Home directory available"),
        ("USER", "User context available")
    ]
    
    for var, description in container_configs:
        if os.environ.get(var):
            results.add_check(
                f"Container Config {var}", 
                "PASS", 
                f"{description}: {os.environ.get(var)}"
            )
        else:
            results.add_check(
                f"Container Config {var}", 
                "WARN", 
                f"{description} not set"
            )
    
    return results

async def run_all_validations(quick_mode=False):
    """Run all container validations."""
    print("🐳 Wazuh MCP Server - Container Validation Suite")
    print("=" * 80)
    print(f"Started at: {datetime.now().isoformat()}")
    print(f"Mode: {'Quick' if quick_mode else 'Comprehensive'}")
    print("=" * 80)
    
    all_results = ContainerValidationResults()
    
    # Core validations (always run)
    validations = [
        ("Container Imports", validate_container_imports),
        ("Container Configuration", validate_container_configuration),
        ("MCP Server", validate_mcp_server),
        ("Container Files", validate_container_files),
        ("Health Checks", validate_health_checks),
        ("OS-Agnostic", validate_os_agnostic)
    ]
    
    for validation_name, validation_func in validations:
        print(f"\n🔬 Running {validation_name} validation...")
        try:
            results = await validation_func()
            
            # Merge results
            all_results.passed += results.passed
            all_results.failed += results.failed
            all_results.warnings += results.warnings
            all_results.checks.extend(results.checks)
            
            # Print validation summary
            total = results.passed + results.failed + results.warnings
            print(f"   ✅ {results.passed} passed, ❌ {results.failed} failed, ⚠️ {results.warnings} warnings")
            
        except Exception as e:
            print(f"   ❌ Validation suite failed: {e}")
            all_results.add_check(validation_name, "FAIL", f"Suite execution failed: {e}")
    
    # Print final summary
    success = all_results.print_summary()
    
    # Save detailed results
    results_file = current_dir / "container-validation-results.json"
    with open(results_file, 'w') as f:
        json.dump({
            "summary": {
                "passed": all_results.passed,
                "failed": all_results.failed,
                "warnings": all_results.warnings,
                "success": success,
                "total_duration": time.time() - all_results.start_time
            },
            "checks": all_results.checks,
            "timestamp": datetime.now().isoformat(),
            "mode": "quick" if quick_mode else "comprehensive"
        }, f, indent=2)
    
    print(f"📄 Detailed results saved to: {results_file}")
    
    if success:
        print("\n🎉 Container validation successful! Ready for OS-agnostic deployment.")
        return 0
    else:
        print(f"\n⚠️ {all_results.failed} validation(s) failed. Please review and fix issues.")
        return 1

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Wazuh MCP Server Container Validation Suite"
    )
    parser.add_argument(
        "--quick", 
        action="store_true",
        help="Run quick validation (essential checks only)"
    )
    
    args = parser.parse_args()
    
    try:
        return asyncio.run(run_all_validations(quick_mode=args.quick))
    except KeyboardInterrupt:
        print("\n🛑 Validation interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Validation failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())