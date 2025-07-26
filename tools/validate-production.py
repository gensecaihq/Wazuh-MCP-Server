#!/usr/bin/env python3
"""
Production Readiness Validation Script for Wazuh MCP Server
Validates all components, dependencies, and configurations for production deployment.
"""

import sys
import os
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple

# Colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def success(msg: str) -> str:
    return f"{Colors.GREEN}✓{Colors.RESET} {msg}"

def error(msg: str) -> str:
    return f"{Colors.RED}✗{Colors.RESET} {msg}"

def warning(msg: str) -> str:
    return f"{Colors.YELLOW}⚠{Colors.RESET} {msg}"

def info(msg: str) -> str:
    return f"{Colors.BLUE}ℹ{Colors.RESET} {msg}"

def header(msg: str) -> str:
    return f"\n{Colors.BOLD}{Colors.BLUE}{'='*50}{Colors.RESET}\n{Colors.BOLD}{msg}{Colors.RESET}\n{Colors.BOLD}{Colors.BLUE}{'='*50}{Colors.RESET}"

class ProductionValidator:
    """Comprehensive production readiness validator."""
    
    def __init__(self):
        self.results = {
            "timestamp": datetime.now().isoformat(),
            "python_version": sys.version,
            "checks": {},
            "warnings": [],
            "errors": [],
            "overall_status": "unknown"
        }
        self.project_root = Path(__file__).parent
        self.src_dir = self.project_root / "src"
    
    def check_python_version(self) -> bool:
        """Check Python version requirements."""
        print(header("Python Environment"))
        
        version_info = sys.version_info
        required_major, required_minor = 3, 10
        
        current_version = f"{version_info.major}.{version_info.minor}.{version_info.micro}"
        print(f"Python Version: {current_version}")
        print(f"Python Executable: {sys.executable}")
        
        if version_info >= (required_major, required_minor):
            print(success(f"Python {current_version} meets requirement (>= {required_major}.{required_minor})"))
            self.results["checks"]["python_version"] = {
                "status": "pass",
                "version": current_version,
                "required": f"{required_major}.{required_minor}+"
            }
            return True
        else:
            print(error(f"Python {current_version} does not meet requirement (>= {required_major}.{required_minor})"))
            self.results["errors"].append(f"Python version {current_version} < {required_major}.{required_minor}")
            self.results["checks"]["python_version"] = {
                "status": "fail",
                "version": current_version,
                "required": f"{required_major}.{required_minor}+"
            }
            return False
    
    def check_dependencies(self) -> bool:
        """Check required dependencies."""
        print(header("Dependencies"))
        
        # Core dependencies from requirements.txt
        required_deps = [
            ("fastmcp", ">=2.10.6", "FastMCP framework"),
            ("httpx", ">=0.27.0", "HTTP client with HTTP/2 support"),
            ("mcp", ">=1.10.1", "MCP protocol"),
            ("python-dateutil", ">=2.8.2", "Date utilities"),
            ("python-dotenv", ">=0.19.0", "Environment variables"),
            ("pydantic", ">=1.10.0", "Data validation"),
            ("pyjwt", ">=2.8.0", "JWT authentication"),
            ("certifi", ">=2021.0.0", "SSL certificates"),
            ("packaging", ">=21.0", "Version utilities")
        ]
        
        all_deps_available = True
        installed_deps = []
        missing_deps = []
        
        for dep_name, version_req, description in required_deps:
            try:
                # Handle different import names
                import_name = dep_name
                if dep_name == "python-dateutil":
                    import_name = "dateutil"
                elif dep_name == "python-dotenv":
                    import_name = "dotenv"
                
                if import_name == "dateutil":
                    import dateutil.parser
                elif import_name == "httpx":
                    import httpx
                elif import_name == "fastmcp":
                    import fastmcp
                elif import_name == "mcp":
                    import mcp
                elif import_name == "dotenv":
                    import dotenv
                elif import_name == "pydantic":
                    import pydantic
                elif import_name == "pyjwt":
                    import jwt
                elif import_name == "certifi":
                    import certifi
                elif import_name == "packaging":
                    import packaging
                else:
                    __import__(import_name)
                
                print(success(f"{dep_name} - {description}"))
                installed_deps.append(dep_name)
                
            except ImportError as e:
                print(error(f"{dep_name} - {description} (MISSING)"))
                missing_deps.append(dep_name)
                all_deps_available = False
        
        self.results["checks"]["dependencies"] = {
            "status": "pass" if all_deps_available else "fail",
            "installed": installed_deps,
            "missing": missing_deps,
            "total_required": len(required_deps)
        }
        
        if missing_deps:
            print(warning(f"Missing dependencies: {', '.join(missing_deps)}"))
            print(info("Install with: pip install -r requirements.txt"))
            self.results["errors"].extend([f"Missing dependency: {dep}" for dep in missing_deps])
        
        return all_deps_available
    
    def check_file_structure(self) -> bool:
        """Check project file structure."""
        print(header("File Structure"))
        
        required_files = [
            ("src/wazuh_mcp_server/server.py", "Main server implementation"),
            ("src/wazuh_mcp_server/config.py", "Configuration management"),
            ("src/wazuh_mcp_server/utils/logging.py", "Logging utilities"),
            ("src/wazuh_mcp_server/utils/validation.py", "Input validation"),
            ("src/wazuh_mcp_server/__version__.py", "Version information"),
            ("requirements.txt", "Python dependencies"),
            ("wazuh-mcp-server", "Entry point script"),
            (".env.production", "Production configuration template")
        ]
        
        all_files_exist = True
        existing_files = []
        missing_files = []
        
        for file_path, description in required_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                print(success(f"{file_path} - {description}"))
                existing_files.append(file_path)
            else:
                print(error(f"{file_path} - {description} (MISSING)"))
                missing_files.append(file_path)
                all_files_exist = False
        
        # Check if entry script is executable
        entry_script = self.project_root / "wazuh-mcp-server"
        if entry_script.exists():
            if os.access(entry_script, os.X_OK):
                print(success("Entry script is executable"))
            else:
                print(warning("Entry script is not executable (run: chmod +x wazuh-mcp-server)"))
                self.results["warnings"].append("Entry script not executable")
        
        self.results["checks"]["file_structure"] = {
            "status": "pass" if all_files_exist else "fail",
            "existing": existing_files,
            "missing": missing_files,
            "total_required": len(required_files)
        }
        
        if missing_files:
            self.results["errors"].extend([f"Missing file: {file}" for file in missing_files])
        
        return all_files_exist
    
    def check_configuration(self) -> bool:
        """Check configuration setup."""
        print(header("Configuration"))
        
        config_valid = True
        
        # Check for .env file
        env_file = self.project_root / ".env"
        env_example = self.project_root / ".env.production"
        
        if env_file.exists():
            print(success(".env file exists"))
            
            # Check for required environment variables
            required_vars = [
                "WAZUH_HOST", "WAZUH_USER", "WAZUH_PASS"
            ]
            
            with open(env_file, 'r') as f:
                env_content = f.read()
            
            missing_vars = []
            for var in required_vars:
                # Check if variable exists and has a value
                var_line = None
                for line in env_content.split('\n'):
                    if line.strip().startswith(f"{var}=") and not line.strip().startswith('#'):
                        var_line = line.strip()
                        break
                
                if var_line is None:
                    # Variable not found
                    missing_vars.append(var)
                elif var_line == f"{var}=" or "your-" in var_line:
                    # Variable found but has placeholder or empty value
                    missing_vars.append(var)
            
            if missing_vars:
                print(warning(f"Incomplete configuration - missing or placeholder values: {', '.join(missing_vars)}"))
                self.results["warnings"].append("Configuration has placeholder values")
            else:
                print(success("All required configuration variables are set"))
                
        else:
            print(warning(".env file not found"))
            if env_example.exists():
                print(info("Copy .env.production to .env and configure your settings"))
            config_valid = False
            self.results["warnings"].append("No .env configuration file")
        
        # Check configuration module can be imported
        if self.src_dir.exists():
            sys.path.insert(0, str(self.src_dir))
            try:
                from wazuh_mcp_server.config import WazuhConfig
                print(success("Configuration module loads successfully"))
            except ImportError as e:
                print(error(f"Configuration module import failed: {e}"))
                config_valid = False
                self.results["errors"].append(f"Config import failed: {e}")
        
        self.results["checks"]["configuration"] = {
            "status": "pass" if config_valid else "fail",
            "env_file_exists": env_file.exists(),
            "has_template": env_example.exists()
        }
        
        return config_valid
    
    def check_server_module(self) -> bool:
        """Check server module integrity."""
        print(header("Server Module"))
        
        if not self.src_dir.exists():
            print(error("Source directory not found"))
            self.results["errors"].append("Source directory missing")
            return False
        
        sys.path.insert(0, str(self.src_dir))
        
        try:
            # Test server module import
            from wazuh_mcp_server import server
            print(success("Server module imports successfully"))
            
            # Check required functions
            required_functions = [
                "get_config", "get_http_client", "wazuh_api_request",
                "get_wazuh_alerts", "analyze_security_threats", 
                "check_wazuh_agent_health", "get_server_health",
                "initialize_server", "cleanup_server", "main"
            ]
            
            missing_functions = []
            available_functions = []
            
            for func_name in required_functions:
                if hasattr(server, func_name):
                    available_functions.append(func_name)
                    print(success(f"Function: {func_name}"))
                else:
                    missing_functions.append(func_name)
                    print(error(f"Function: {func_name} (MISSING)"))
            
            # Check FastMCP instance
            if hasattr(server, 'mcp'):
                print(success("FastMCP instance available"))
            else:
                print(error("FastMCP instance missing"))
                missing_functions.append("mcp")
            
            self.results["checks"]["server_module"] = {
                "status": "pass" if not missing_functions else "fail",
                "available_functions": available_functions,
                "missing_functions": missing_functions,
                "total_required": len(required_functions) + 1  # +1 for mcp instance
            }
            
            if missing_functions:
                self.results["errors"].extend([f"Missing function: {func}" for func in missing_functions])
                return False
            
            return True
            
        except ImportError as e:
            print(error(f"Server module import failed: {e}"))
            self.results["errors"].append(f"Server module import failed: {e}")
            self.results["checks"]["server_module"] = {
                "status": "fail",
                "error": str(e)
            }
            return False
    
    def check_tests(self) -> bool:
        """Check test suite."""
        print(header("Test Suite"))
        
        test_file = self.project_root / "tests" / "test_production_server.py"
        if test_file.exists():
            print(success("Test suite exists"))
            
            # Try to run a basic syntax check on tests
            try:
                with open(test_file, 'r') as f:
                    test_content = f.read()
                
                compile(test_content, str(test_file), 'exec')
                print(success("Test file compiles successfully"))
                
                self.results["checks"]["tests"] = {
                    "status": "pass",
                    "test_file_exists": True,
                    "syntax_valid": True
                }
                return True
                
            except SyntaxError as e:
                print(error(f"Test file syntax error: {e}"))
                self.results["errors"].append(f"Test syntax error: {e}")
                self.results["checks"]["tests"] = {
                    "status": "fail",
                    "test_file_exists": True,
                    "syntax_valid": False,
                    "error": str(e)
                }
                return False
        else:
            print(warning("Test suite not found"))
            self.results["warnings"].append("No test suite available")
            self.results["checks"]["tests"] = {
                "status": "warning",
                "test_file_exists": False
            }
            return True  # Not a critical failure
    
    def check_transport_options(self) -> bool:
        """Validate MCP transport options and HTTP/SSE support."""
        print(header("MCP Transport Options"))
        
        transport_checks = []
        
        # Check FastMCP version for HTTP/SSE support
        try:
            import fastmcp
            print(success(f"FastMCP version: {fastmcp.__version__}"))
            transport_checks.append("fastmcp_available")
        except ImportError:
            print(error("FastMCP not available"))
            self.results["errors"].append("FastMCP not installed")
            return False
        except AttributeError:
            print(warning("FastMCP version not detectable"))
        
        # Check HTTP transport dependencies
        http_deps = ["fastapi", "uvicorn", "starlette"]
        missing_http_deps = []
        
        for dep in http_deps:
            try:
                __import__(dep)
                print(success(f"HTTP transport dependency available: {dep}"))
                transport_checks.append(f"http_dep_{dep}")
            except ImportError:
                print(warning(f"HTTP transport dependency missing: {dep}"))
                missing_http_deps.append(dep)
        
        # Check transport configuration in .env files
        env_files = [".env", ".env.production"]
        transport_config_valid = False
        
        for env_file in env_files:
            env_path = self.project_root / env_file
            if env_path.exists():
                with open(env_path, 'r') as f:
                    content = f.read()
                
                if "MCP_TRANSPORT" in content:
                    print(success(f"Transport configuration found in {env_file}"))
                    transport_config_valid = True
                    transport_checks.append("transport_config")
                    
                if "MCP_HOST" in content and "MCP_PORT" in content:
                    print(success(f"HTTP transport settings found in {env_file}"))
                    transport_checks.append("http_config")
        
        if not transport_config_valid:
            print(info("Transport configuration not found (will use defaults)"))
        
        # Check entry point supports transport selection
        entry_point = self.project_root / "wazuh-mcp-server"
        if entry_point.exists():
            with open(entry_point, 'r') as f:
                content = f.read()
            
            if "--http" in content and "--stdio" in content:
                print(success("Entry point supports transport selection"))
                transport_checks.append("entry_point_transport")
            else:
                print(warning("Entry point may not support transport selection"))
        
        # Summary
        if missing_http_deps:
            print(warning(f"HTTP transport will not work without: {', '.join(missing_http_deps)}"))
            self.results["warnings"].append(f"Missing HTTP dependencies: {missing_http_deps}")
        else:
            print(success("All transport modes supported"))
        
        self.results["checks"]["transport"] = {
            "status": "pass",
            "checks_passed": transport_checks,
            "total_checks": len(transport_checks),
            "missing_http_deps": missing_http_deps
        }
        
        return True
    
    def check_security(self) -> bool:
        """Check security configurations."""
        print(header("Security Configuration"))
        
        security_checks = []
        
        # Check for .env file permissions (if exists)
        env_file = self.project_root / ".env"
        if env_file.exists():
            stat_info = env_file.stat()
            permissions = oct(stat_info.st_mode)[-3:]
            
            if permissions == "600":  # Only owner can read/write
                print(success(f".env file permissions: {permissions} (secure)"))
                security_checks.append("env_permissions_secure")
            else:
                print(warning(f".env file permissions: {permissions} (consider 600 for security)"))
                self.results["warnings"].append(f".env permissions too open: {permissions}")
        
        # Check for sensitive data in git (if .git exists)
        git_dir = self.project_root / ".git"
        if git_dir.exists():
            gitignore = self.project_root / ".gitignore"
            if gitignore.exists():
                with open(gitignore, 'r') as f:
                    gitignore_content = f.read()
                
                if ".env" in gitignore_content:
                    print(success(".env file is gitignored"))
                    security_checks.append("env_gitignored")
                else:
                    print(warning(".env file not in .gitignore"))
                    self.results["warnings"].append(".env file not gitignored")
            else:
                print(warning(".gitignore file not found"))
        
        # Check for default/weak configurations in templates
        env_production = self.project_root / ".env.production"
        if env_production.exists():
            with open(env_production, 'r') as f:
                template_content = f.read()
            
            if "your-secure-password" in template_content:
                print(success("Template uses placeholder passwords"))
                security_checks.append("secure_template")
            
            if "VERIFY_SSL=true" in template_content:
                print(success("SSL verification enabled by default"))
                security_checks.append("ssl_enabled")
        
        self.results["checks"]["security"] = {
            "status": "pass",
            "checks_passed": security_checks,
            "total_checks": len(security_checks)
        }
        
        return True
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate final production readiness report."""
        print(header("Production Readiness Report"))
        
        # Calculate overall status
        all_checks = self.results["checks"]
        failed_checks = [name for name, check in all_checks.items() if check.get("status") == "fail"]
        warning_checks = [name for name, check in all_checks.items() if check.get("status") == "warning"]
        
        if failed_checks:
            self.results["overall_status"] = "FAIL"
            status_color = Colors.RED
        elif warning_checks:
            self.results["overall_status"] = "WARN"
            status_color = Colors.YELLOW
        else:
            self.results["overall_status"] = "PASS"
            status_color = Colors.GREEN
        
        print(f"\n{Colors.BOLD}Overall Status: {status_color}{self.results['overall_status']}{Colors.RESET}")
        
        # Summary
        total_checks = len(all_checks)
        passed_checks = len([c for c in all_checks.values() if c.get("status") == "pass"])
        
        print(f"\nChecks: {passed_checks}/{total_checks} passed")
        print(f"Errors: {len(self.results['errors'])}")
        print(f"Warnings: {len(self.results['warnings'])}")
        
        if failed_checks:
            print(f"\n{Colors.RED}Failed Checks:{Colors.RESET}")
            for check in failed_checks:
                print(f"  - {check}")
        
        if warning_checks:
            print(f"\n{Colors.YELLOW}Warnings:{Colors.RESET}")
            for warning in self.results['warnings']:
                print(f"  - {warning}")
        
        if self.results["overall_status"] == "PASS":
            print(f"\n{Colors.GREEN}{Colors.BOLD}✓ System is production-ready!{Colors.RESET}")
            print("\nNext steps:")
            print("1. Configure your .env file with actual Wazuh credentials")
            print("2. Test connectivity: ./wazuh-mcp-server")
            print("3. Configure Claude Desktop with the server path")
        elif self.results["overall_status"] == "WARN":
            print(f"\n{Colors.YELLOW}{Colors.BOLD}⚠ System is mostly ready with warnings{Colors.RESET}")
            print("Address warnings before production deployment")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}✗ System is not production-ready{Colors.RESET}")
            print("Fix the errors above before deployment")
        
        return self.results
    
    def save_report(self, filename: str = "production-readiness-report.json"):
        """Save detailed report to JSON file."""
        report_path = self.project_root / filename
        with open(report_path, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n{info(f'Detailed report saved to: {report_path}')}")
    
    def run_all_checks(self) -> bool:
        """Run all production readiness checks."""
        print(f"{Colors.BOLD}{Colors.BLUE}Wazuh MCP Server - Production Readiness Validation{Colors.RESET}")
        print(f"Timestamp: {self.results['timestamp']}")
        
        checks = [
            self.check_python_version,
            self.check_dependencies,
            self.check_file_structure,
            self.check_configuration,
            self.check_transport_options,
            self.check_server_module,
            self.check_tests,
            self.check_security
        ]
        
        overall_success = True
        for check in checks:
            try:
                if not check():
                    overall_success = False
            except Exception as e:
                print(error(f"Check failed with exception: {e}"))
                self.results["errors"].append(f"Check exception: {e}")
                overall_success = False
        
        self.generate_report()
        self.save_report()
        
        return self.results["overall_status"] == "PASS"


def main():
    """Main validation function."""
    # Check for quick validation flag (for Docker health checks)
    quick_mode = "--quick" in sys.argv
    
    validator = ProductionValidator()
    
    if quick_mode:
        # Quick validation for Docker containers
        print("🚀 Quick Docker validation...")
        success = (
            validator.check_python_version() and
            validator.check_file_structure()
        )
        if success:
            print("✅ Quick validation passed")
        else:
            print("❌ Quick validation failed")
    else:
        # Full validation
        success = validator.run_all_checks()
        validator.generate_report()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()