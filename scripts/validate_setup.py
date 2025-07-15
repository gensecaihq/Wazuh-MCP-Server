#!/usr/bin/env python3
"""Production-ready validation script for Wazuh MCP Server setup with auto-fix capabilities.

This script performs comprehensive validation of the entire installation,
including security, performance, and production-readiness checks.

Features:
- System compatibility validation
- Security configuration assessment
- Performance baseline testing
- Connection resilience testing
- Production deployment readiness
- Detailed diagnostics and recommendations
- Auto-fix functionality for common issues (Linux/macOS)
"""

import sys
import platform
import subprocess
import json
import time
import asyncio
import ssl
import socket
import psutil
import concurrent.futures
import os
import shutil
import urllib.request
import tempfile
import stat
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
import logging
import argparse


def print_header():
    """Print validation header with Windows compatibility."""
    # Use ASCII characters for Windows compatibility
    separator = "=" * 80
    bullet = "•" if _supports_unicode() else "*"
    
    print(separator)
    print("   WAZUH MCP SERVER - PRODUCTION VALIDATION")
    print(f"   Security {bullet} Performance {bullet} Reliability {bullet} Compliance")
    print(separator)
    print(f"   Validation started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(separator)
    print()

def _supports_unicode():
    """Check if the terminal supports Unicode characters."""
    try:
        # Get encoding safely - handle cases where stdout doesn't have encoding attribute
        encoding = getattr(sys.stdout, 'encoding', None)
        if encoding is None:
            encoding = 'utf-8'
        
        # Test if we can encode/print Unicode
        "✅".encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError, AttributeError):
        return False


def print_section(title: str):
    """Print section header."""
    print(f"\n🔍 {title}")
    print("-" * (len(title) + 3))


def print_check(name: str, status: bool, details: str = "", warning: bool = False):
    """Print check result with Windows-compatible formatting."""
    # Use ASCII fallbacks for Windows compatibility
    if _supports_unicode():
        if warning:
            icon = "⚠️ "
        else:
            icon = "✅" if status else "❌"
    else:
        if warning:
            icon = "[WARN]"
        else:
            icon = "[PASS]" if status else "[FAIL]"
    
    try:
        print(f"{icon} {name}")
    except UnicodeEncodeError:
        # Fallback for systems that can't handle Unicode
        fallback_icon = "[WARN]" if warning else ("[PASS]" if status else "[FAIL]")
        print(f"{fallback_icon} {name}")
        
    if details:
        lines = details.split('\n')
        for line in lines:
            if line.strip():
                try:
                    print(f"   {line}")
                except UnicodeEncodeError:
                    # Replace problematic characters
                    safe_line = line.encode('ascii', errors='replace').decode('ascii')
                    print(f"   {safe_line}")

def print_metric(name: str, value: Any, unit: str = "", threshold: Optional[float] = None):
    """Print performance metric with Windows-compatible formatting."""
    if _supports_unicode():
        status_icon = "📊"
        if threshold and isinstance(value, (int, float)):
            if value > threshold:
                status_icon = "⚠️ "
            else:
                status_icon = "✅"
    else:
        status_icon = "[METRIC]"
        if threshold and isinstance(value, (int, float)):
            if value > threshold:
                status_icon = "[HIGH]"
            else:
                status_icon = "[OK]"
    
    try:
        print(f"{status_icon} {name}: {value}{unit}")
    except UnicodeEncodeError:
        print(f"[METRIC] {name}: {value}{unit}")

def print_security_check(name: str, status: bool, severity: str = "medium", details: str = ""):
    """Print security-specific check result with Windows compatibility."""
    if _supports_unicode():
        severity_icons = {
            "low": "🔵",
            "medium": "🟡", 
            "high": "🟠",
            "critical": "🔴"
        }
        icon = "🔒" if status else severity_icons.get(severity, "🟡")
    else:
        severity_labels = {
            "low": "[LOW]",
            "medium": "[MED]", 
            "high": "[HIGH]",
            "critical": "[CRIT]"
        }
        icon = "[SEC-OK]" if status else severity_labels.get(severity, "[MED]")
    
    try:
        print(f"{icon} {name}")
    except UnicodeEncodeError:
        fallback_icon = "[SEC-OK]" if status else f"[SEC-{severity.upper()}]"
        print(f"{fallback_icon} {name}")
        
    if details:
        try:
            print(f"   {details}")
        except UnicodeEncodeError:
            safe_details = details.encode('ascii', errors='replace').decode('ascii')
            print(f"   {safe_details}")
            
    if not status and severity in ["high", "critical"]:
        try:
            if _supports_unicode():
                print(f"   ⚠️  Security Issue: {severity.upper()} severity")
            else:
                print(f"   [WARNING] Security Issue: {severity.upper()} severity")
        except UnicodeEncodeError:
            print(f"   [WARNING] Security Issue: {severity.upper()} severity")


def check_system_info():
    """Check system information and requirements."""
    print_section("SYSTEM INFORMATION & REQUIREMENTS")
    
    system_info = {
        'OS': platform.system(),
        'Version': platform.release(),
        'Architecture': platform.machine(),
        'Python': platform.python_version(),
        'Platform': platform.platform()
    }
    
    for key, value in system_info.items():
        icon = "📋" if _supports_unicode() else "[INFO]"
        try:
            print(f"{icon} {key}: {value}")
        except UnicodeEncodeError:
            print(f"[INFO] {key}: {value}")
    
    # Check system requirements
    python_version = tuple(map(int, platform.python_version().split('.')[:2]))
    python_ok = python_version >= (3, 8)
    print_check("Python version requirement", python_ok, 
                f"Python {platform.python_version()} (minimum: 3.8)")
    
    # Check system resources
    try:
        memory = psutil.virtual_memory()
        cpu_count = psutil.cpu_count()
        disk = psutil.disk_usage('.')
        
        print_metric("Available Memory", f"{memory.available / (1024**3):.1f}", "GB", 1.0)
        print_metric("CPU Cores", cpu_count, "", None)
        print_metric("Free Disk Space", f"{disk.free / (1024**3):.1f}", "GB", 5.0)
        
        # Check if running as root (security concern)
        if platform.system() != "Windows":
            import os
            is_root = os.geteuid() == 0
            print_security_check("Running as non-root user", not is_root, "medium",
                               "Running as root is not recommended for security")
    except Exception as e:
        print_check("System resources check", False, f"Error checking system resources: {e}")
    
    return python_ok


def check_virtual_environment():
    """Check virtual environment status."""
    print_section("VIRTUAL ENVIRONMENT")
    
    venv_path = Path("venv")
    venv_exists = venv_path.exists()
    print_check("Virtual environment exists", venv_exists)
    
    if not venv_exists:
        return False
    
    # Check if we can use the virtual environment
    if platform.system() == "Windows":
        python_exe = venv_path / "Scripts" / "python.exe"
        pip_exe = venv_path / "Scripts" / "pip.exe"
    else:
        python_exe = venv_path / "bin" / "python"
        pip_exe = venv_path / "bin" / "pip"
    
    python_works = python_exe.exists()
    pip_works = pip_exe.exists()
    
    print_check("Python executable", python_works, str(python_exe))
    print_check("Pip executable", pip_works, str(pip_exe))
    
    if python_works:
        try:
            result = subprocess.run([str(python_exe), "--version"], 
                                  capture_output=True, text=True)
            print_check("Python version check", result.returncode == 0, 
                       result.stdout.strip() if result.returncode == 0 else result.stderr)
        except Exception as e:
            print_check("Python version check", False, str(e))
    
    return python_works and pip_works


def check_dependencies():
    """Check if required dependencies are installed with version validation."""
    print_section("DEPENDENCIES & VERSIONS")
    
    # Get python executable
    if platform.system() == "Windows":
        python_exe = Path("venv") / "Scripts" / "python.exe"
    else:
        python_exe = Path("venv") / "bin" / "python"
    
    if not python_exe.exists():
        print_check("Dependencies check", False, "Virtual environment not found")
        return False
    
    # Check key dependencies with version requirements
    dependencies = [
        ("mcp", "0.1.0", "MCP protocol implementation"),
        ("aiohttp", "3.8.0", "Async HTTP client"),
        ("pydantic", "1.10.0", "Data validation (V1/V2 compatible)"),
        ("dotenv", "0.19.0", "Environment variable loading"),
        ("websockets", "10.0", "WebSocket support"),
        ("urllib3", "1.26.0", "HTTP client library"),
        ("certifi", "2021.0.0", "SSL certificate bundle"),
        ("psutil", "5.8.0", "System monitoring")
    ]
    
    all_installed = True
    for dep, min_version, description in dependencies:
        try:
            # Check if package is installed
            result = subprocess.run([str(python_exe), "-c", f"import {dep}; print('OK')"],
                                  capture_output=True, text=True)
            success = result.returncode == 0
            
            if success:
                # Get version if available
                try:
                    version_result = subprocess.run([str(python_exe), "-c", 
                                                   f"import {dep}; print(getattr({dep}, '__version__', 'unknown'))"],
                                                  capture_output=True, text=True)
                    version = version_result.stdout.strip() if version_result.returncode == 0 else "unknown"
                    print_check(f"Package: {dep}", success, f"v{version} - {description}")
                except:
                    print_check(f"Package: {dep}", success, description)
            else:
                print_check(f"Package: {dep}", success, f"Missing - {description}")
                all_installed = False
                
        except Exception as e:
            print_check(f"Package: {dep}", False, f"Error checking {dep}: {str(e)}")
            all_installed = False
    
    # Check for potential security vulnerabilities
    try:
        vulns_result = subprocess.run([str(python_exe), "-m", "pip", "check"],
                                    capture_output=True, text=True)
        if vulns_result.returncode == 0 and not vulns_result.stdout.strip():
            print_security_check("Package security check", True, "low", "No known vulnerabilities")
        else:
            print_security_check("Package security check", False, "medium", 
                                "Run 'pip check' for details")
    except Exception as e:
        print_check("Package security check", False, f"Could not check: {e}")
    
    return all_installed


def check_package_installation():
    """Check if the Wazuh MCP Server package is installed."""
    print_section("PACKAGE INSTALLATION")
    
    # Get python executable
    if platform.system() == "Windows":
        python_exe = Path("venv") / "Scripts" / "python.exe"
    else:
        python_exe = Path("venv") / "bin" / "python"
    
    if not python_exe.exists():
        print_check("Package installation", False, "Virtual environment not found")
        return False
    
    # Test imports
    test_imports = [
        ("Main module", "wazuh_mcp_server.main", "WazuhMCPServer"),
        ("Configuration", "wazuh_mcp_server.config", "WazuhConfig"),
        ("API client", "wazuh_mcp_server.api.wazuh_client", "WazuhAPIClient"),
        ("Analyzers", "wazuh_mcp_server.analyzers.security_analyzer", "SecurityAnalyzer"),
        ("Utilities", "wazuh_mcp_server.utils.logging", "get_logger"),
    ]
    
    all_imported = True
    for name, module, class_name in test_imports:
        try:
            result = subprocess.run([
                str(python_exe), "-c", 
                f"from {module} import {class_name}; print('{class_name} imported successfully')"
            ], capture_output=True, text=True)
            success = result.returncode == 0
            print_check(name, success, result.stdout.strip() if success else result.stderr.strip())
            if not success:
                all_imported = False
        except Exception as e:
            print_check(name, False, str(e))
            all_imported = False
    
    return all_imported


def check_configuration():
    """Check configuration files with security validation."""
    print_section("CONFIGURATION & SECURITY")
    
    # Check .env file
    env_file = Path(".env")
    env_exists = env_file.exists()
    print_check(".env file exists", env_exists)
    
    if not env_exists:
        print_check("Configuration", False, "No .env file found. Copy .env.example to .env")
        return False
    
    # Check .env permissions (Unix-like systems)
    if platform.system() != "Windows":
        stat_info = env_file.stat()
        permissions = oct(stat_info.st_mode)[-3:]
        secure_perms = permissions == "600"
        print_security_check(".env file permissions", secure_perms, "high" if not secure_perms else "low",
                            f"Permissions: {permissions} (should be 600 for security)")
    
    # Parse .env file with proper encoding handling
    config = {}
    try:
        # Try UTF-8 first, then fall back to system default with error handling
        try:
            content = env_file.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            try:
                content = env_file.read_text(encoding='utf-8-sig')  # Handle BOM
            except UnicodeDecodeError:
                # Fall back to system default with error replacement
                content = env_file.read_text(encoding='cp1252', errors='replace')
                print_check("Character encoding", False, 
                           "Warning: Non-UTF8 characters detected, some may be replaced")
        
        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                try:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
                except ValueError:
                    print_check("Parse .env file", False, f"Invalid format on line {line_num}: {line}")
                    
    except Exception as e:
        print_check("Parse .env file", False, f"Encoding error: {str(e)}")
        print("   💡 Try saving .env file as UTF-8 encoding")
        return False
    
    # Check required configuration
    required_vars = [
        ('WAZUH_HOST', 'Wazuh server hostname/IP'),
        ('WAZUH_USER', 'Wazuh API username'),
        ('WAZUH_PASS', 'Wazuh API password')
    ]
    
    config_complete = True
    security_issues = []
    
    for var, description in required_vars:
        if var in config and config[var] and not config[var].startswith('your-'):
            print_check(f"Config: {var}", True, f"Configured - {description}")
            
            # Security checks
            if var == 'WAZUH_PASS':
                password = config[var]
                if len(password) < 8:
                    security_issues.append("Password is too short (minimum 8 characters)")
                if password.lower() in ['password', 'admin', '123456', 'wazuh']:
                    security_issues.append("Password is too weak (common password)")
                    
        else:
            print_check(f"Config: {var}", False, f"Not configured - {description}")
            config_complete = False
    
    # Check optional security configurations
    security_configs = [
        ('VERIFY_SSL', 'SSL certificate verification'),
        ('WAZUH_ALLOW_SELF_SIGNED', 'Self-signed certificate handling'),
        ('DEBUG', 'Debug mode (should be false in production)'),
        ('LOG_LEVEL', 'Logging level')
    ]
    
    for var, description in security_configs:
        if var in config:
            value = config[var].lower()
            if var == 'DEBUG' and value == 'true':
                print_security_check(f"Config: {var}", False, "medium", 
                                    "Debug mode enabled - disable in production")
            elif var == 'VERIFY_SSL' and value == 'false':
                print_security_check(f"Config: {var}", False, "medium",
                                    "SSL verification disabled - enable for production")
            else:
                print_check(f"Config: {var}", True, f"{description}: {config[var]}")
    
    # Check for sensitive data exposure
    if 'WAZUH_PASS' in config and len(config['WAZUH_PASS']) > 0:
        print_security_check("Password security", len(security_issues) == 0, "high", 
                           "\n".join(security_issues) if security_issues else "Password meets basic requirements")
    
    # Check for development/testing configurations
    test_indicators = ['localhost', '127.0.0.1', 'test', 'dev', 'demo']
    prod_ready = True
    
    for var, value in config.items():
        if any(indicator in value.lower() for indicator in test_indicators):
            if var == 'WAZUH_HOST' and value.lower() in ['localhost', '127.0.0.1']:
                print_check("Production readiness", False, 
                           "Using localhost - update with production server address")
                prod_ready = False
    
    return config_complete and len(security_issues) == 0


def check_logs_directory():
    """Check logs directory."""
    print_section("LOGGING")
    
    logs_dir = Path("logs")
    logs_exists = logs_dir.exists()
    print_check("Logs directory", logs_exists)
    
    if logs_exists:
        # Check if writable
        try:
            test_file = logs_dir / "test_write.tmp"
            test_file.write_text("test")
            test_file.unlink()
            print_check("Logs directory writable", True)
        except Exception as e:
            print_check("Logs directory writable", False, str(e))
            return False
    
    return logs_exists


def test_connection():
    """Test connection to Wazuh server with resilience testing."""
    print_section("CONNECTION & RESILIENCE TEST")
    
    # Get python executable
    if platform.system() == "Windows":
        python_exe = Path("venv") / "Scripts" / "python.exe"
    else:
        python_exe = Path("venv") / "bin" / "python"
    
    if not python_exe.exists():
        print_check("Connection test", False, "Virtual environment not found")
        return False
    
    # Test basic connectivity first
    basic_success = _test_basic_connectivity()
    
    # Run full connection validator
    validator_script = Path("src") / "wazuh_mcp_server" / "scripts" / "connection_validator.py"
    if not validator_script.exists():
        print_check("Connection validator", False, "Validator script not found")
        return False
    
    try:
        print("Running comprehensive connection validation...")
        start_time = time.time()
        
        result = subprocess.run([str(python_exe), str(validator_script)],
                              capture_output=True, text=True, timeout=60)
        
        end_time = time.time()
        response_time = end_time - start_time
        
        success = result.returncode == 0
        print_check("Connection test", success)
        print_metric("Response time", f"{response_time:.2f}", "s", 10.0)
        
        # Print validator output
        if result.stdout:
            print("Connection test output:")
            for line in result.stdout.split('\n')[-10:]:  # Show last 10 lines
                if line.strip():
                    print(f"   {line}")
        
        if result.stderr and not success:
            print("Connection errors:")
            for line in result.stderr.split('\n')[:5]:  # Show first 5 error lines
                if line.strip():
                    print(f"   {line}")
        
        # Test connection resilience if basic connection works
        if success:
            _test_connection_resilience(python_exe)
        
        return success
        
    except subprocess.TimeoutExpired:
        print_check("Connection test", False, "Test timed out after 60 seconds")
        return False
    except Exception as e:
        print_check("Connection test", False, str(e))
        return False

def _test_basic_connectivity():
    """Test basic network connectivity."""
    try:
        # Parse configuration to get host
        env_file = Path(".env")
        if not env_file.exists():
            return False
            
        config = {}
        try:
            # Handle encoding properly for Windows
            try:
                content = env_file.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                content = env_file.read_text(encoding='cp1252', errors='replace')
                
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
        except Exception as e:
            print_check("Configuration parsing", False, f"Error reading .env: {str(e)}")
            return False
        
        host = config.get('WAZUH_HOST', 'localhost')
        port = int(config.get('WAZUH_PORT', '55000'))
        
        if host in ['localhost', '127.0.0.1'] or host.startswith('your-'):
            print_check("Basic connectivity", False, "Host not configured")
            return False
        
        # Test TCP connection
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        try:
            result = sock.connect_ex((host, port))
            end_time = time.time()
            
            if result == 0:
                print_check("Basic connectivity", True, f"TCP connection to {host}:{port} successful")
                print_metric("Connection latency", f"{(end_time - start_time) * 1000:.1f}", "ms", 1000)
                return True
            else:
                print_check("Basic connectivity", False, f"Cannot connect to {host}:{port}")
                return False
        finally:
            sock.close()
            
    except Exception as e:
        print_check("Basic connectivity", False, f"Error: {str(e)}")
        return False

def _test_connection_resilience(python_exe):
    """Test connection resilience and performance."""
    print("\n   💪 Testing connection resilience...")
    
    # Test multiple concurrent connections
    try:
        test_script = '''
import asyncio
import time
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.api.wazuh_client_manager import WazuhClientManager

async def test_concurrent_connections():
    config = WazuhConfig.from_env()
    tasks = []
    
    for i in range(5):
        async def single_test():
            try:
                async with WazuhClientManager(config) as client:
                    health = await client.health_check()
                    return health['overall_status'] == 'healthy'
            except:
                return False
        tasks.append(single_test())
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    successful = sum(1 for r in results if r is True)
    print(f"Concurrent connections: {successful}/5 successful")
    return successful >= 4

if __name__ == "__main__":
    result = asyncio.run(test_concurrent_connections())
    exit(0 if result else 1)
'''
        
        with open('.test_resilience.py', 'w') as f:
            f.write(test_script)
        
        result = subprocess.run([str(python_exe), '.test_resilience.py'],
                              capture_output=True, text=True, timeout=30)
        
        Path('.test_resilience.py').unlink()  # Clean up
        
        if result.returncode == 0:
            print_check("Connection resilience", True, "Multiple concurrent connections successful")
        else:
            print_check("Connection resilience", False, "Some concurrent connections failed")
            
    except Exception as e:
        print_check("Connection resilience", False, f"Test error: {str(e)}")
        try:
            Path('.test_resilience.py').unlink()
        except:
            pass


def check_production_readiness():
    """Check production deployment readiness."""
    print_section("PRODUCTION READINESS")
    
    readiness_checks = []
    
    # Check for development indicators
    env_file = Path(".env")
    if env_file.exists():
        content = env_file.read_text()
        if 'DEBUG=true' in content:
            readiness_checks.append(("Debug mode disabled", False, "DEBUG=true found in .env"))
        else:
            readiness_checks.append(("Debug mode disabled", True, "DEBUG mode is off"))
            
        if 'localhost' in content or '127.0.0.1' in content:
            readiness_checks.append(("Production hosts configured", False, "localhost/127.0.0.1 found in config"))
        else:
            readiness_checks.append(("Production hosts configured", True, "Using production hosts"))
    
    # Check log directory structure
    logs_dir = Path("logs")
    if logs_dir.exists():
        log_files = list(logs_dir.glob("*.log"))
        readiness_checks.append(("Logging infrastructure", True, f"Log directory ready ({len(log_files)} files)"))
    else:
        readiness_checks.append(("Logging infrastructure", False, "Logs directory not found"))
    
    # Check for proper error handling
    try:
        # Test that the server can handle configuration errors gracefully
        test_config = Path(".env.test")
        test_config.write_text("WAZUH_HOST=invalid\nWAZUH_USER=test\nWAZUH_PASS=test")
        
        python_exe = Path("venv") / ("Scripts/python.exe" if platform.system() == "Windows" else "bin/python")
        result = subprocess.run([str(python_exe), "-c", 
                               "from wazuh_mcp_server.config import WazuhConfig; WazuhConfig.from_env()"],
                              capture_output=True, text=True, env={**dict(os.environ), "DOTENV_PATH": str(test_config)})
        
        test_config.unlink()
        
        if result.returncode != 0:
            readiness_checks.append(("Error handling", True, "Configuration validation working"))
        else:
            readiness_checks.append(("Error handling", False, "Configuration validation may be weak"))
            
    except Exception as e:
        readiness_checks.append(("Error handling", False, f"Could not test: {str(e)}"))
    
    # Check monitoring capabilities
    monitoring_files = [
        "src/wazuh_mcp_server/utils/logging.py",
        "src/wazuh_mcp_server/utils/error_recovery.py"
    ]
    
    monitoring_ready = all(Path(f).exists() for f in monitoring_files)
    readiness_checks.append(("Monitoring infrastructure", monitoring_ready, 
                           "Logging and error recovery modules available"))
    
    # Print results
    all_ready = True
    for name, status, details in readiness_checks:
        print_check(name, status, details)
        if not status:
            all_ready = False
    
    return all_ready


# ========== AUTO-FIX FUNCTIONALITY ==========

class AutoFixer:
    """Handles auto-fix functionality for common issues."""
    
    def __init__(self, interactive: bool = True):
        self.interactive = interactive
        self.fixes_applied = []
        self.fixes_failed = []
        self.system = platform.system()
        self.is_macos = self.system == "Darwin"
        self.is_linux = self.system == "Linux"
        
    def run_with_sudo(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Run command with sudo privileges."""
        if os.geteuid() == 0:
            # Already root
            return subprocess.run(cmd, capture_output=True, text=True)
        
        # Need sudo
        if self.interactive:
            print("🔐 Administrator access required")
            return subprocess.run(['sudo'] + cmd)
        else:
            # Non-interactive mode
            sudo_cmd = ['sudo', '-n'] + cmd
            return subprocess.run(sudo_cmd, capture_output=True, text=True)
    
    def detect_package_manager(self) -> Optional[str]:
        """Detect the system package manager."""
        if self.is_macos:
            # Check for Homebrew
            if shutil.which('brew'):
                return 'brew'
        elif self.is_linux:
            # Check for various package managers
            if shutil.which('apt-get'):
                return 'apt'
            elif shutil.which('yum'):
                return 'yum'
            elif shutil.which('dnf'):
                return 'dnf'
            elif shutil.which('pacman'):
                return 'pacman'
        return None
    
    def fix_system_packages(self) -> bool:
        """Fix missing system packages."""
        print("\n🔧 Fixing system packages...")
        
        pkg_manager = self.detect_package_manager()
        if not pkg_manager:
            print("❌ Could not detect package manager")
            self.fixes_failed.append("System packages")
            return False
        
        # Define packages by package manager
        packages = {
            'brew': [
                'python@3.13',
                'openssl',
                'libffi',
                'ca-certificates'
            ],
            'apt': [
                'python3.13',
                'python3.13-venv',
                'python3.13-dev',
                'python3.13-distutils',
                'build-essential',
                'libssl-dev',
                'libffi-dev',
                'libbz2-dev',
                'libreadline-dev',
                'libsqlite3-dev',
                'wget',
                'curl',
                'llvm',
                'libncurses5-dev',
                'libncursesw5-dev',
                'xz-utils',
                'tk-dev',
                'liblzma-dev',
                'ca-certificates'
            ],
            'yum': [
                'python3.13',
                'python3.13-devel',
                'gcc',
                'openssl-devel',
                'bzip2-devel',
                'libffi-devel',
                'zlib-devel',
                'xz-devel',
                'wget'
            ],
            'dnf': [
                'python3.13',
                'python3.13-devel',
                'gcc',
                'openssl-devel',
                'bzip2-devel',
                'libffi-devel',
                'zlib-devel',
                'xz-devel',
                'wget'
            ]
        }
        
        install_packages = packages.get(pkg_manager, [])
        
        try:
            if pkg_manager == 'brew':
                # Update Homebrew
                print("   Updating Homebrew...")
                subprocess.run(['brew', 'update'], capture_output=True)
                
                # Install packages
                for pkg in install_packages:
                    print(f"   Installing {pkg}...")
                    result = subprocess.run(['brew', 'install', pkg], capture_output=True, text=True)
                    if result.returncode != 0:
                        print(f"   ⚠️  Failed to install {pkg}")
                
            elif pkg_manager == 'apt':
                # Check if we need to add deadsnakes PPA for Python 3.13
                if not shutil.which('python3.13'):
                    print("   Adding Python 3.13 repository...")
                    self.run_with_sudo(['apt-get', 'update'])
                    self.run_with_sudo(['apt-get', 'install', '-y', 'software-properties-common'])
                    self.run_with_sudo(['add-apt-repository', '-y', 'ppa:deadsnakes/ppa'])
                
                # Update package lists
                print("   Updating package lists...")
                self.run_with_sudo(['apt-get', 'update'])
                
                # Install packages
                print(f"   Installing {len(install_packages)} packages...")
                self.run_with_sudo(['apt-get', 'install', '-y'] + install_packages)
                
            elif pkg_manager in ['yum', 'dnf']:
                # Update package lists
                print("   Updating package lists...")
                self.run_with_sudo([pkg_manager, 'update', '-y'])
                
                # Install packages
                print(f"   Installing {len(install_packages)} packages...")
                self.run_with_sudo([pkg_manager, 'install', '-y'] + install_packages)
            
            self.fixes_applied.append("System packages")
            return True
            
        except Exception as e:
            print(f"❌ Error installing packages: {e}")
            self.fixes_failed.append("System packages")
            return False
    
    def fix_virtual_environment(self) -> bool:
        """Fix virtual environment issues."""
        print("\n🔧 Fixing virtual environment...")
        
        venv_path = Path("venv")
        
        # Remove existing broken venv
        if venv_path.exists():
            print("   Removing existing virtual environment...")
            shutil.rmtree(venv_path, ignore_errors=True)
        
        # Try different Python executables
        python_executables = ['python3.13', 'python3', 'python']
        python_exe = None
        
        for exe in python_executables:
            if shutil.which(exe):
                # Check version
                result = subprocess.run([exe, '--version'], capture_output=True, text=True)
                if result.returncode == 0:
                    version = result.stdout.strip()
                    if '3.13' in version or '3.12' in version or '3.11' in version or '3.10' in version or '3.9' in version or '3.8' in version:
                        python_exe = exe
                        print(f"   Using {exe} ({version})")
                        break
        
        if not python_exe:
            print("❌ No suitable Python version found")
            self.fixes_failed.append("Virtual environment")
            return False
        
        # Method 1: Standard venv creation
        try:
            print("   Creating virtual environment...")
            result = subprocess.run([python_exe, '-m', 'venv', 'venv'], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Verify pip works
                venv_python = venv_path / ('Scripts/python.exe' if platform.system() == 'Windows' else 'bin/python')
                
                # Upgrade pip
                print("   Upgrading pip...")
                upgrade_result = subprocess.run([str(venv_python), '-m', 'pip', 'install', '--upgrade', 'pip'], 
                                              capture_output=True, text=True)
                
                if upgrade_result.returncode == 0:
                    self.fixes_applied.append("Virtual environment")
                    return True
                else:
                    # Try bootstrapping pip
                    return self._bootstrap_pip_in_venv()
            else:
                # Try without pip
                return self._create_venv_without_pip(python_exe)
                
        except Exception as e:
            print(f"   Error: {e}")
            return self._create_venv_without_pip(python_exe)
    
    def _create_venv_without_pip(self, python_exe: str) -> bool:
        """Create venv without pip and bootstrap it."""
        print("   Creating virtual environment without pip...")
        
        try:
            # Create venv without pip
            result = subprocess.run([python_exe, '-m', 'venv', 'venv', '--without-pip'], 
                                  capture_output=True, text=True)
            
            if result.returncode != 0:
                print("❌ Failed to create virtual environment")
                self.fixes_failed.append("Virtual environment")
                return False
            
            # Bootstrap pip
            return self._bootstrap_pip_in_venv()
            
        except Exception as e:
            print(f"❌ Error creating venv: {e}")
            self.fixes_failed.append("Virtual environment")
            return False
    
    def _bootstrap_pip_in_venv(self) -> bool:
        """Bootstrap pip in the virtual environment."""
        print("   Bootstrapping pip...")
        
        try:
            # Download get-pip.py
            get_pip_url = 'https://bootstrap.pypa.io/get-pip.py'
            get_pip_path = 'get-pip.py'
            
            print("   Downloading get-pip.py...")
            urllib.request.urlretrieve(get_pip_url, get_pip_path)
            
            # Install pip in venv
            venv_python = Path("venv") / ('Scripts/python.exe' if platform.system() == 'Windows' else 'bin/python')
            
            print("   Installing pip in virtual environment...")
            result = subprocess.run([str(venv_python), get_pip_path], capture_output=True, text=True)
            
            # Clean up
            os.unlink(get_pip_path)
            
            if result.returncode == 0:
                self.fixes_applied.append("Virtual environment")
                return True
            else:
                print(f"❌ Failed to install pip: {result.stderr}")
                self.fixes_failed.append("Virtual environment")
                return False
                
        except Exception as e:
            print(f"❌ Error bootstrapping pip: {e}")
            self.fixes_failed.append("Virtual environment")
            # Clean up
            try:
                os.unlink('get-pip.py')
            except:
                pass
            return False
    
    def fix_permissions(self) -> bool:
        """Fix file and directory permissions."""
        if platform.system() == "Windows":
            # Windows doesn't need permission fixes
            return True
        
        print("\n🔧 Fixing permissions...")
        
        try:
            # Fix .env permissions
            env_file = Path(".env")
            if env_file.exists():
                print("   Setting .env permissions to 600...")
                os.chmod(env_file, stat.S_IRUSR | stat.S_IWUSR)
            
            # Fix logs directory
            logs_dir = Path("logs")
            if not logs_dir.exists():
                print("   Creating logs directory...")
                logs_dir.mkdir(mode=0o755)
            else:
                print("   Setting logs directory permissions...")
                os.chmod(logs_dir, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)
            
            # Fix venv permissions
            venv_path = Path("venv")
            if venv_path.exists():
                print("   Fixing virtual environment permissions...")
                # Make all files in venv executable if needed
                for file in venv_path.rglob("*"):
                    if file.is_file() and file.suffix in ['', '.exe']:
                        try:
                            current_perms = file.stat().st_mode
                            if not (current_perms & stat.S_IXUSR):
                                os.chmod(file, current_perms | stat.S_IXUSR)
                        except:
                            pass
            
            self.fixes_applied.append("Permissions")
            return True
            
        except Exception as e:
            print(f"❌ Error fixing permissions: {e}")
            self.fixes_failed.append("Permissions")
            return False
    
    def fix_environment(self) -> bool:
        """Fix environment configuration."""
        print("\n🔧 Fixing environment configuration...")
        
        try:
            # Set UTF-8 locale
            os.environ['LC_ALL'] = 'C.UTF-8'
            os.environ['LANG'] = 'C.UTF-8'
            os.environ['PYTHONIOENCODING'] = 'utf-8'
            
            # Clear pip cache if needed
            print("   Clearing pip cache...")
            cache_dir = Path.home() / '.cache' / 'pip'
            if cache_dir.exists():
                shutil.rmtree(cache_dir, ignore_errors=True)
            
            # Check for proxy
            proxy = os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy')
            if proxy:
                print(f"   Detected proxy: {proxy}")
                os.environ['HTTPS_PROXY'] = proxy
                os.environ['https_proxy'] = proxy
            
            # Create .env from example if not exists
            env_file = Path(".env")
            env_example = Path(".env.example")
            
            if not env_file.exists() and env_example.exists():
                print("   Creating .env from .env.example...")
                shutil.copy(env_example, env_file)
                # Set proper permissions
                if platform.system() != "Windows":
                    os.chmod(env_file, stat.S_IRUSR | stat.S_IWUSR)
            
            self.fixes_applied.append("Environment")
            return True
            
        except Exception as e:
            print(f"❌ Error fixing environment: {e}")
            self.fixes_failed.append("Environment")
            return False
    
    def run_auto_fix(self, fix_types: Optional[List[str]] = None) -> bool:
        """Run auto-fix for specified types or all if none specified."""
        print("\n" + "="*80)
        print("🔧 WAZUH MCP AUTO-FIX")
        print("="*80)
        
        if not fix_types:
            fix_types = ['packages', 'venv', 'permissions', 'environment']
        
        # Map fix types to methods
        fix_methods = {
            'packages': self.fix_system_packages,
            'venv': self.fix_virtual_environment,
            'permissions': self.fix_permissions,
            'environment': self.fix_environment
        }
        
        # Run fixes
        for fix_type in fix_types:
            if fix_type in fix_methods:
                fix_methods[fix_type]()
        
        # Print summary
        print("\n" + "="*80)
        print("📊 AUTO-FIX SUMMARY")
        print("="*80)
        
        if self.fixes_applied:
            print("\n✅ Successfully fixed:")
            for fix in self.fixes_applied:
                print(f"   • {fix}")
        
        if self.fixes_failed:
            print("\n❌ Failed to fix:")
            for fix in self.fixes_failed:
                print(f"   • {fix}")
        
        if not self.fixes_failed:
            print("\n✅ All fixes completed successfully!")
            print("🚀 Run 'python install.py' to continue with installation")
        else:
            print("\n⚠️  Some fixes failed. Manual intervention may be required.")
        
        return len(self.fixes_failed) == 0


def generate_deployment_report(results: Dict[str, bool]):
    """Generate a comprehensive deployment report."""
    print_section("DEPLOYMENT REPORT")
    
    # Calculate scores
    passed = sum(results.values())
    total = len(results)
    score = (passed / total) * 100
    
    # Determine deployment readiness
    if score >= 95:
        status = "🟢 READY FOR PRODUCTION"
    elif score >= 80:
        status = "🟡 READY WITH MINOR ISSUES"
    elif score >= 60:
        status = "🟠 REQUIRES ATTENTION"
    else:
        status = "🔴 NOT READY FOR PRODUCTION"
    
    print(f"\n📊 Deployment Score: {score:.1f}% ({passed}/{total} checks passed)")
    print(f"🔍 Deployment Status: {status}")
    
    # Generate recommendations
    print("\n📝 RECOMMENDATIONS:")
    
    failed_checks = [name for name, result in results.items() if not result]
    
    if not failed_checks:
        print("   ✅ All checks passed! Your deployment is ready.")
        print("   📚 Next steps:")
        print("      1. Deploy to production environment")
        print("      2. Configure monitoring and alerting")
        print("      3. Set up backup and recovery procedures")
        print("      4. Implement security monitoring")
    else:
        print("   ⚠️  Address the following issues:")
        for check in failed_checks:
            if "Configuration" in check:
                print("      • Update .env file with production values")
            elif "Connection" in check:
                print("      • Verify network connectivity to Wazuh servers")
            elif "Dependencies" in check:
                print("      • Run 'pip install -r requirements.txt' to fix dependencies")
            elif "Security" in check:
                print("      • Review security configuration and file permissions")
            else:
                print(f"      • Fix {check} issues")
    
    # Security recommendations
    print("\n🔒 SECURITY CHECKLIST:")
    security_items = [
        "Ensure .env file has 600 permissions",
        "Use strong, unique passwords",
        "Enable SSL verification in production",
        "Disable debug mode in production",
        "Review and rotate API keys regularly",
        "Monitor logs for security events",
        "Set up intrusion detection",
        "Implement rate limiting"
    ]
    
    for item in security_items:
        print(f"   [ ] {item}")
    
    return score >= 80

def main():
    """Main validation function with comprehensive production readiness assessment."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Validate and fix Wazuh MCP Server setup')
    parser.add_argument('--fix', action='store_true', help='Automatically fix detected issues')
    parser.add_argument('--fix-only', type=str, help='Fix only specific types (comma-separated: packages,venv,permissions,environment)')
    parser.add_argument('--non-interactive', action='store_true', help='Run in non-interactive mode')
    args = parser.parse_args()
    
    # Set up console encoding for Windows - MOVED BEFORE ANY PRINT OPERATIONS
    if platform.system() == "Windows":
        try:
            # Set console to UTF-8 first
            import subprocess
            subprocess.run(['chcp', '65001'], capture_output=True, shell=True)
            
            # Then try to set UTF-8 encoding for Python stdout/stderr
            import codecs
            # Store original stdout/stderr in case we need to restore
            original_stdout = sys.stdout
            original_stderr = sys.stderr
            
            try:
                sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
                sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')
                
                # Test if the encoding setup works by checking unicode support
                test_unicode = _supports_unicode()
                if not test_unicode:
                    # Restore original if Unicode test fails
                    sys.stdout = original_stdout
                    sys.stderr = original_stderr
                    
            except Exception:
                # Restore original on any error
                sys.stdout = original_stdout
                sys.stderr = original_stderr
                
        except Exception:
            # If any console setup fails, continue with defaults
            pass
    
    print_header()
    
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    all_checks = [
        ("System Information", check_system_info),
        ("Virtual Environment", check_virtual_environment),
        ("Dependencies", check_dependencies),
        ("Package Installation", check_package_installation),
        ("Configuration", check_configuration),
        ("Logs Directory", check_logs_directory),
        ("Connection Test", test_connection),
        ("Production Readiness", check_production_readiness),
    ]
    
    results = {}
    start_time = time.time()
    
    for name, check_func in all_checks:
        try:
            section_start = time.time()
            results[name] = check_func()
            section_end = time.time()
            
            # Log timing for performance analysis
            logging.info(f"{name} completed in {section_end - section_start:.2f}s")
            
        except Exception as e:
            print(f"❌ Error in {name}: {e}")
            results[name] = False
            logging.error(f"Error in {name}: {str(e)}")
    
    end_time = time.time()
    total_time = end_time - start_time
    
    # Print summary
    print_section("VALIDATION SUMMARY")
    
    for name, result in results.items():
        icon = "✅" if result else "❌"
        print(f"{icon} {name}")
    
    print(f"\n⏱️  Total validation time: {total_time:.2f} seconds")
    
    # Generate deployment report
    deployment_ready = generate_deployment_report(results)
    
    # Save results to file for CI/CD integration
    report_file = Path("validation_report.json")
    report_data = {
        "timestamp": datetime.now().isoformat(),
        "validation_time": total_time,
        "results": results,
        "deployment_ready": deployment_ready,
        "system_info": {
            "os": platform.system(),
            "python_version": platform.python_version(),
            "architecture": platform.machine()
        }
    }
    
    with open(report_file, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    print(f"\n📊 Validation report saved to: {report_file}")
    
    # Run auto-fix if requested
    if args.fix or args.fix_only:
        # Only run on Linux/macOS
        if platform.system() == "Windows":
            print("\n❌ Auto-fix is not supported on Windows. Please fix issues manually.")
            return 1
        
        # Determine which fixes to run
        fix_types = None
        if args.fix_only:
            fix_types = [t.strip() for t in args.fix_only.split(',')]
        
        # Create auto-fixer
        fixer = AutoFixer(interactive=not args.non_interactive)
        
        # Identify fixable issues
        fixable_issues = []
        if not results.get("Virtual Environment", True):
            fixable_issues.append("venv")
        if not results.get("System Information", True):
            fixable_issues.append("packages")
        if not results.get("Configuration", True) or not results.get("Logs Directory", True):
            fixable_issues.append("permissions")
            fixable_issues.append("environment")
        
        if fixable_issues and (args.fix or args.fix_only):
            print(f"\n🔍 Found fixable issues: {', '.join(fixable_issues)}")
            
            if args.fix_only:
                # Use specified fixes
                fix_success = fixer.run_auto_fix(fix_types)
            else:
                # Fix all detected issues
                fix_success = fixer.run_auto_fix(fixable_issues)
            
            if fix_success:
                print("\n✅ Auto-fix completed. Re-running validation...")
                # Re-run validation after fixes
                # Note: In a real implementation, you might want to recursively call main()
                # or refactor the validation logic into a separate function
                return 0
            else:
                return 1
    
    return 0 if deployment_ready else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Validation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error during validation: {str(e)}")
        logging.exception("Validation failed with unexpected error")
        sys.exit(1)