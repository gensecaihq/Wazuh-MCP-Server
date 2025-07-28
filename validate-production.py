#!/usr/bin/env python3
"""
Wazuh MCP Server - Production Validation
Comprehensive production readiness validation and security audit
"""

import sys
import os
import asyncio
import json
import time
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Tuple
from datetime import datetime
import argparse

# Add src directory to Python path
current_dir = Path(__file__).resolve().parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

class ValidationResults:
    """Validation results tracker."""
    def __init__(self):
        self.critical = 0
        self.high = 0 
        self.medium = 0
        self.low = 0
        self.passed = 0
        self.checks = []
    
    def add_check(self, name: str, severity: str, status: str, message: str = "", recommendation: str = ""):
        """Add validation check result."""
        self.checks.append({
            "name": name,
            "severity": severity,
            "status": status,
            "message": message,
            "recommendation": recommendation,
            "timestamp": datetime.now().isoformat()
        })
        
        if status == "PASS":
            self.passed += 1
        elif severity == "CRITICAL":
            self.critical += 1
        elif severity == "HIGH":
            self.high += 1
        elif severity == "MEDIUM":
            self.medium += 1
        elif severity == "LOW":
            self.low += 1
    
    def print_summary(self):
        """Print validation summary."""
        total_issues = self.critical + self.high + self.medium + self.low
        total_checks = self.passed + total_issues
        
        print("\n" + "="*70)
        print("🔍 PRODUCTION READINESS VALIDATION SUMMARY")
        print("="*70)
        print(f"Total Checks: {total_checks}")
        print(f"✅ Passed: {self.passed}")
        print(f"🔴 Critical Issues: {self.critical}")
        print(f"🟠 High Issues: {self.high}")
        print(f"🟡 Medium Issues: {self.medium}")
        print(f"🔵 Low Issues: {self.low}")
        
        if self.critical > 0:
            print(f"\n❌ PRODUCTION READINESS: BLOCKED")
            print("   Critical issues must be resolved before production deployment")
        elif self.high > 0:
            print(f"\n⚠️  PRODUCTION READINESS: NOT RECOMMENDED")
            print("   High priority issues should be resolved before production")
        elif self.medium > 0:
            print(f"\n✅ PRODUCTION READINESS: READY WITH WARNINGS")
            print("   Consider resolving medium priority issues for optimal production")
        else:
            print(f"\n🎉 PRODUCTION READINESS: FULLY READY")
            print("   All validations passed - ready for production deployment")
        
        readiness_score = (self.passed / total_checks * 100) if total_checks > 0 else 0
        print(f"\nReadiness Score: {readiness_score:.1f}%")
        print("="*70)
        
        return self.critical == 0

async def validate_security():
    """Validate security configuration."""
    results = ValidationResults()
    
    print("🔒 Validating security configuration...")
    
    # Check for exposed secrets (excluding examples and docs)
    try:
        result = subprocess.run(
            ["grep", "-r", "-E", "(password|secret|api_key|token)\\s*=\\s*['\"][^'\"]{8,}['\"]", ".", 
             "--include=*.py", "--include=*.sh", "--exclude-dir=.venv", "--exclude-dir=docs", 
             "--exclude=*.example", "--exclude=*.md"],
            capture_output=True, text=True, cwd=current_dir
        )
        
        exposed_secrets = []
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines:
                # Filter out common false positives and lambda functions
                if not any(false_positive in line.lower() for false_positive in [
                    "your-password", "your-secret", "your-key", "example", "placeholder", 
                    "template", "sample", "test", "demo", "********", "lambda", "key=", "def "
                ]):
                    exposed_secrets.append(line)
        
        if exposed_secrets:
            results.add_check(
                "Secret Exposure", "CRITICAL", "FAIL",
                f"Found {len(exposed_secrets)} potential hardcoded secrets",
                "Remove hardcoded secrets and use environment variables"
            )
        else:
            results.add_check("Secret Exposure", "HIGH", "PASS", "No hardcoded secrets found")
            
    except Exception as e:
        results.add_check("Secret Exposure", "HIGH", "FAIL", f"Security scan failed: {e}")
    
    # Check SSL configuration
    try:
        if os.path.exists("config/wazuh.env"):
            with open("config/wazuh.env", 'r') as f:
                config_content = f.read()
                if "VERIFY_SSL=false" in config_content:
                    results.add_check(
                        "SSL Configuration", "HIGH", "FAIL",
                        "SSL verification is disabled",
                        "Enable SSL verification for production: VERIFY_SSL=true"
                    )
                else:
                    results.add_check("SSL Configuration", "HIGH", "PASS", "SSL verification enabled")
        else:
            results.add_check(
                "SSL Configuration", "MEDIUM", "FAIL",
                "Configuration file missing",
                "Create config/wazuh.env with proper SSL settings"
            )
    except Exception as e:
        results.add_check("SSL Configuration", "HIGH", "FAIL", f"SSL check failed: {e}")
    
    # Check file permissions
    try:
        sensitive_files = ["config/wazuh.env", ".env", ".env.production"]
        for file_path in sensitive_files:
            if Path(file_path).exists():
                stat_info = os.stat(file_path)
                permissions = oct(stat_info.st_mode)[-3:]
                if permissions in ["600", "644"]:
                    results.add_check(f"File Permissions: {file_path}", "MEDIUM", "PASS", f"Secure permissions: {permissions}")
                else:
                    results.add_check(
                        f"File Permissions: {file_path}", "HIGH", "FAIL",
                        f"Insecure permissions: {permissions}",
                        f"Set secure permissions: chmod 600 {file_path}"
                    )
    except Exception as e:
        results.add_check("File Permissions", "MEDIUM", "FAIL", f"Permission check failed: {e}")
    
    return results

async def validate_dependencies():
    """Validate dependencies and imports."""
    results = ValidationResults()
    
    print("📦 Validating dependencies...")
    
    # Check requirements.txt
    if not Path("requirements.txt").exists():
        results.add_check(
            "Requirements File", "CRITICAL", "FAIL",
            "requirements.txt missing",
            "Create requirements.txt with all dependencies"
        )
    else:
        results.add_check("Requirements File", "HIGH", "PASS", "requirements.txt found")
    
    # Check critical imports
    critical_modules = ["fastmcp", "httpx", "pydantic", "uvicorn", "python-dotenv"]
    
    for module in critical_modules:
        try:
            if module == "python-dotenv":
                import dotenv
            else:
                __import__(module)
            results.add_check(f"Module: {module}", "HIGH", "PASS", f"{module} available")
        except ImportError:
            results.add_check(
                f"Module: {module}", "CRITICAL", "FAIL",
                f"{module} not installed",
                f"Install with: pip install {module}"
            )
    
    # Check version compatibility
    try:
        import sys
        python_version = sys.version_info
        if python_version >= (3, 10):
            results.add_check("Python Version", "HIGH", "PASS", f"Python {python_version.major}.{python_version.minor}")
        else:
            results.add_check(
                "Python Version", "CRITICAL", "FAIL",
                f"Python {python_version.major}.{python_version.minor} detected",
                "Upgrade to Python 3.10 or higher"
            )
    except Exception as e:
        results.add_check("Python Version", "HIGH", "FAIL", f"Version check failed: {e}")
    
    return results

async def validate_configuration():
    """Validate configuration files and settings."""
    results = ValidationResults()
    
    print("⚙️  Validating configuration...")
    
    # Check configuration template
    if Path("config/wazuh.env.example").exists():
        results.add_check("Config Template", "MEDIUM", "PASS", "Configuration template exists")
    else:
        results.add_check(
            "Config Template", "HIGH", "FAIL",
            "Configuration template missing",
            "Create config/wazuh.env.example"
        )
    
    # Check actual configuration
    if Path("config/wazuh.env").exists():
        results.add_check("Config File", "HIGH", "PASS", "Configuration file exists")
        
        # Validate configuration values
        try:
            from wazuh_mcp_server.config import WazuhConfig
            config = WazuhConfig.from_env()
            
            # Check required fields
            if config.wazuh_host and config.wazuh_user and config.wazuh_pass:
                results.add_check("Required Config", "CRITICAL", "PASS", "All required configuration present")
            else:
                results.add_check(
                    "Required Config", "CRITICAL", "FAIL",
                    "Missing required configuration",
                    "Set WAZUH_HOST, WAZUH_USER, WAZUH_PASS"
                )
            
            # Check transport mode
            if config.mcp_transport == "http":
                results.add_check("Transport Mode", "MEDIUM", "PASS", "HTTP transport configured")
            else:
                results.add_check("Transport Mode", "LOW", "PASS", f"{config.mcp_transport} transport configured")
                
        except Exception as e:
            results.add_check("Config Validation", "HIGH", "FAIL", f"Configuration validation failed: {e}")
    else:
        results.add_check(
            "Config File", "HIGH", "FAIL",
            "Configuration file missing",
            "Copy config/wazuh.env.example to config/wazuh.env and configure"
        )
    
    return results

async def validate_docker():
    """Validate Docker configuration."""
    results = ValidationResults()
    
    print("🐳 Validating Docker configuration...")
    
    # Check Docker files
    docker_files = ["compose.yml", "Dockerfile", "docker/entrypoint.sh"]
    for file_path in docker_files:
        if Path(file_path).exists():
            results.add_check(f"Docker File: {file_path}", "HIGH", "PASS", f"{file_path} exists")
        else:
            results.add_check(
                f"Docker File: {file_path}", "HIGH", "FAIL",
                f"{file_path} missing",
                f"Create required Docker file: {file_path}"
            )
    
    # Check compose.yml syntax
    try:
        result = subprocess.run(
            ["docker", "compose", "config"],
            capture_output=True, text=True, cwd=current_dir
        )
        if result.returncode == 0:
            results.add_check("Docker Compose Syntax", "HIGH", "PASS", "compose.yml syntax valid")
        else:
            results.add_check(
                "Docker Compose Syntax", "HIGH", "FAIL",
                f"compose.yml syntax error: {result.stderr}",
                "Fix compose.yml syntax errors"
            )
    except FileNotFoundError:
        results.add_check("Docker Installation", "MEDIUM", "FAIL", "Docker not installed", "Install Docker")
    except Exception as e:
        results.add_check("Docker Validation", "MEDIUM", "FAIL", f"Docker check failed: {e}")
    
    return results

async def validate_scripts():
    """Validate scripts and executables."""
    results = ValidationResults()
    
    print("📜 Validating scripts...")
    
    # Check main executable
    if Path("wazuh-mcp-server").exists():
        if os.access("wazuh-mcp-server", os.X_OK):
            results.add_check("Main Executable", "CRITICAL", "PASS", "wazuh-mcp-server exists and is executable")
        else:
            results.add_check(
                "Main Executable", "CRITICAL", "FAIL",
                "wazuh-mcp-server not executable",
                "chmod +x wazuh-mcp-server"
            )
    else:
        results.add_check(
            "Main Executable", "CRITICAL", "FAIL",
            "wazuh-mcp-server missing",
            "Create main executable file"
        )
    
    # Check Docker deployment scripts
    docker_scripts = [
        "configure-wazuh.sh",
        "quick-deploy.sh", 
        "deploy-prebuilt.sh",
        "build-image.sh",
        "verify-container.sh"
    ]
    
    for script in docker_scripts:
        if Path(script).exists():
            if os.access(script, os.X_OK):
                results.add_check(f"Script: {script}", "MEDIUM", "PASS", f"{script} executable")
            else:
                results.add_check(
                    f"Script: {script}", "MEDIUM", "FAIL",
                    f"{script} not executable",
                    f"chmod +x {script}"
                )
        else:
            results.add_check(
                f"Script: {script}", "HIGH", "FAIL",
                f"{script} missing",
                f"Create {script}"
            )
    
    return results

async def validate_fastmcp():
    """Validate FastMCP integration."""
    results = ValidationResults()
    
    print("🚀 Validating FastMCP integration...")
    
    try:
        from wazuh_mcp_server.server import mcp
        
        # Check FastMCP server instance
        if hasattr(mcp, 'get_tools') and hasattr(mcp, 'get_resources'):
            results.add_check("FastMCP Instance", "CRITICAL", "PASS", "FastMCP server properly initialized")
        else:
            results.add_check(
                "FastMCP Instance", "CRITICAL", "FAIL",
                "FastMCP server not properly initialized",
                "Fix FastMCP server initialization"
            )
        
        # Check tools registration
        try:
            tools = await mcp.get_tools()
            tool_count = len(tools)
            if tool_count >= 10:
                results.add_check("Tools Registration", "HIGH", "PASS", f"{tool_count} tools registered")
            elif tool_count > 0:
                results.add_check("Tools Registration", "MEDIUM", "PASS", f"{tool_count} tools registered (consider adding more)")
            else:
                results.add_check(
                    "Tools Registration", "CRITICAL", "FAIL",
                    "No tools registered",
                    "Register MCP tools properly"
                )
        except Exception as e:
            results.add_check("Tools Registration", "HIGH", "FAIL", f"Could not check tools: {e}")
        
        # Check resources registration
        try:
            resources = await mcp.get_resources()
            resource_count = len(resources)
            if resource_count > 0:
                results.add_check("Resources Registration", "MEDIUM", "PASS", f"{resource_count} resources registered")
            else:
                results.add_check("Resources Registration", "LOW", "PASS", "No resources registered (optional)")
        except Exception as e:
            results.add_check("Resources Registration", "LOW", "FAIL", f"Could not check resources: {e}")
        
    except ImportError as e:
        results.add_check(
            "FastMCP Import", "CRITICAL", "FAIL",
            f"Cannot import FastMCP components: {e}",
            "Fix import issues and ensure FastMCP is installed"
        )
    except Exception as e:
        results.add_check("FastMCP Validation", "HIGH", "FAIL", f"FastMCP validation failed: {e}")
    
    return results

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Wazuh MCP Server Production Validation")
    parser.add_argument("--quick", action="store_true", help="Run quick validation (essential checks only)")
    parser.add_argument("--full", action="store_true", help="Run full comprehensive validation")
    parser.add_argument("--output", "-o", help="Output results to JSON file")
    return parser.parse_args()

async def main():
    """Main validation runner."""
    args = parse_arguments()
    
    print("🔍 Wazuh MCP Server - Production Validation")
    print("=" * 70)
    print(f"Started at: {datetime.now().isoformat()}")
    print(f"Mode: {'Quick' if args.quick else 'Comprehensive'}")
    print("=" * 70)
    
    all_results = ValidationResults()
    
    # Define validation suites
    if args.quick:
        validation_suites = [
            ("Critical Dependencies", validate_dependencies),
            ("FastMCP Integration", validate_fastmcp),
            ("Essential Scripts", validate_scripts)
        ]
    else:
        validation_suites = [
            ("Security Configuration", validate_security),
            ("Dependencies", validate_dependencies),
            ("Configuration", validate_configuration),
            ("Docker Setup", validate_docker),
            ("Scripts & Executables", validate_scripts),
            ("FastMCP Integration", validate_fastmcp)
        ]
    
    # Run validation suites
    for suite_name, validate_func in validation_suites:
        print(f"\n🔬 Running {suite_name} validation...")
        try:
            suite_results = await validate_func()
            
            # Merge results
            all_results.critical += suite_results.critical
            all_results.high += suite_results.high
            all_results.medium += suite_results.medium
            all_results.low += suite_results.low
            all_results.passed += suite_results.passed
            all_results.checks.extend(suite_results.checks)
            
            # Print suite summary
            total_issues = suite_results.critical + suite_results.high + suite_results.medium + suite_results.low
            print(f"   ✅ {suite_results.passed} passed, ❌ {total_issues} issues found")
            
        except Exception as e:
            print(f"   ❌ Validation suite failed: {e}")
            all_results.add_check(suite_name, "CRITICAL", "FAIL", f"Suite execution failed: {e}")
    
    # Print final summary
    production_ready = all_results.print_summary()
    
    # Print detailed issues
    if all_results.critical > 0 or all_results.high > 0:
        print(f"\n🔍 CRITICAL/HIGH ISSUES REQUIRING ATTENTION:")
        print("-" * 70)
        for check in all_results.checks:
            if check['status'] != 'PASS' and check['severity'] in ['CRITICAL', 'HIGH']:
                print(f"❌ {check['severity']}: {check['name']}")
                print(f"   Issue: {check['message']}")
                if check['recommendation']:
                    print(f"   Fix: {check['recommendation']}")
                print()
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                "summary": {
                    "production_ready": production_ready,
                    "critical": all_results.critical,
                    "high": all_results.high,
                    "medium": all_results.medium,
                    "low": all_results.low,
                    "passed": all_results.passed
                },
                "checks": all_results.checks,
                "timestamp": datetime.now().isoformat()
            }, f, indent=2)
        print(f"📄 Detailed results saved to: {args.output}")
    
    # Exit with appropriate code
    if production_ready:
        print("\n🎉 Production validation successful!")
        sys.exit(0)
    elif all_results.critical > 0:
        print("\n❌ Production validation failed - critical issues found!")
        sys.exit(2)
    else:
        print("\n⚠️  Production validation completed with warnings!")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())